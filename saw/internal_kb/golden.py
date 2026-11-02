"""Internal golden records: an analyst saves and edits the investigation's analysis directly.

No pseudonymisation, approver or manual hash check is required for internal use. Access stays tied to every
investigation the record draws on (read to view, write to save), rechecked on each read, so a reply that cites
another investigation stays hidden from readers who cannot open that investigation. Every save is a new version.

The record separates what was known first from what came later. The first-known state is fixed at the cutoff,
the moment the first follow-up question was asked: check records, files and evidence as they stood then. Replies,
later files, changed judgements and later evidence go to the later section, and the final judgement and open
questions stand apart from both.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, access_of, declared_period, list_for, require
from saw.internal_kb.models import InternalGolden, InternalGoldenVersion
from saw.storage.db import utcnow
from saw.storage.models import Check, Evidence, EvidenceFile, Finding

Line = Annotated[str, Field(max_length=4000)]
LongLine = Annotated[str, Field(max_length=8000)]  # follow-up questions and replies accept up to 8,000 characters
Status = Literal["", "normal", "attack_attempt", "compromise_confirmed", "insufficient_evidence", "data_quality_limited",
                 "attack", "false_positive", "unknown"]
MAX_ITEMS = 200
CHECK_STATUS = {"normal": "normal", "malicious": "attack_attempt", "suspicious": "insufficient_evidence",
                "undetermined": "insufficient_evidence"}
CHECK_LABEL = {"normal": "정상", "malicious": "악성", "suspicious": "의심", "undetermined": "판단 보류", None: "판단 없음"}
OUTCOME_LABEL = {"not_confirmed": "확인되지 않음", "insufficient_data": "자료 부족", "partially_confirmed": "일부만 확인"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Judgement(Strict):
    status: Status = ""
    rationale: LongLine = ""
    scope: Line = ""  # what the judgement covers (affiliate, period, targets) and what it does not


class FollowUpItem(Strict):
    followup_id: Annotated[str, Field(max_length=36)] = ""
    question: LongLine
    target: Line = ""
    period: Line = ""
    reply: LongLine = ""
    reply_scope_result: Line = ""
    outcome: Line = ""
    remaining: list[Line] = Field(default_factory=list, max_length=50)
    evidence_refs: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)


class Lineage(Strict):
    synthetic: bool = False
    source: Line = "investigation"
    variant_group_id: Line = ""
    split_group_id: Line = ""
    split: Literal["unassigned", "train", "validation", "test"] = "unassigned"


class Provenance(Strict):
    """Server-computed on every save; what a client sends here is replaced."""
    cutoff: str | None = None
    source_investigation_ids: list[str] = Field(default_factory=list, max_length=500)
    followup_ids: list[str] = Field(default_factory=list, max_length=MAX_ITEMS)
    hidden_followups: int = 0
    hidden_checks: int = 0


class Content(Strict):
    schema_version: Literal["saw.internal-golden/1"] = "saw.internal-golden/1"
    title: Line
    scope: dict = Field(default_factory=dict)
    initial_logs: list[dict] = Field(default_factory=list, max_length=MAX_ITEMS)
    initial_evidence_refs: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    observed_facts: list[LongLine] = Field(default_factory=list, max_length=MAX_ITEMS)
    initial_judgement: Judgement = Field(default_factory=Judgement)
    questions: list[LongLine] = Field(default_factory=list, max_length=MAX_ITEMS)
    followups: list[FollowUpItem] = Field(default_factory=list, max_length=MAX_ITEMS)
    later_logs: list[dict] = Field(default_factory=list, max_length=MAX_ITEMS)
    later_evidence_refs: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    later_facts: list[LongLine] = Field(default_factory=list, max_length=MAX_ITEMS)
    alert_meanings: list[dict] = Field(default_factory=list, max_length=MAX_ITEMS)  # which registered meaning version applied
    final_judgement: Judgement = Field(default_factory=Judgement)
    unresolved: list[LongLine] = Field(default_factory=list, max_length=MAX_ITEMS)
    notes: LongLine = ""
    lineage: Lineage = Field(default_factory=Lineage)
    provenance: Provenance = Field(default_factory=Provenance)


class SaveIn(Strict):
    content: Content
    change_note: Annotated[str, Field(max_length=2000)] = ""
    expected_version: int | None = None


def _aware(value):
    return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)


def _period_text(payload: dict) -> str:
    period = payload.get("period") or {}
    return f"{period.get('start', '')} ~ {period.get('end', '')}".strip(" ~")


def _target_text(payload: dict) -> str:
    target = payload.get("target") or {}
    parts = [f"출발지 {', '.join(target.get('src_ips') or [])}" if target.get("src_ips") else "",
             f"목적지 {', '.join(target.get('dst_ips') or [])}" if target.get("dst_ips") else "",
             f"포트 {', '.join(str(x) for x in target.get('dst_ports') or [])}" if target.get("dst_ports") else "",
             target.get("behavior") or ""]
    return " · ".join(p for p in parts if p)


def _fit(text: str, limit: int = 8000) -> str:
    """Never cut silently: an over-long text says where the full original is."""
    marker = " …(이하 생략: 원문은 확인 기록에서 보세요)"
    return text if len(text) <= limit else text[: limit - len(marker)] + marker


def _readable(s, p, ids) -> bool:
    from saw.core.application.identity import principal_of
    from saw.core.security.authz import can
    from saw.storage.models import Investigation, User

    user = s.get(User, p.user_id) if p else None
    if user is None or user.status != "active":
        return False
    actor = principal_of(user)
    for iid in sorted(set(ids)):
        if s.get(Investigation, iid) is None or not can(actor, "investigation.read", access_of(s, actor, iid)):
            return False
    return True


def _ref_sources(refs) -> set[str]:
    return {str(ref).split("/", 1)[0] for ref in refs if "/" in str(ref)}


def _refs(inv_id: str, check: Check) -> list[str]:
    ids = [*(check.evidence or []), *((check.scope or {}).get("event_ids") or [])]
    return [f"{inv_id}/{r}" for r in dict.fromkeys(ids)]


def _families(s, inv_id):
    """Check records grouped by edit chain (an edit supersedes the previous record), oldest first."""
    rows = list(s.scalars(select(Check).where(Check.investigation_id == inv_id).order_by(Check.created_at, Check.id)))
    by_id = {r.id: r for r in rows}
    root = {}
    for r in rows:
        cur, seen = r, set()
        while cur.supersedes_id and cur.supersedes_id in by_id and cur.id not in seen:
            seen.add(cur.id)
            cur = by_id[cur.supersedes_id]
        root[r.id] = cur.id
    families: dict[str, list[Check]] = {}
    for r in rows:
        families.setdefault(root[r.id], []).append(r)
    return list(families.values())


def _view(s, p, inv) -> dict:
    """What the investigation holds, split at the cutoff, limited to what this user can read."""
    from saw import container
    from saw.followups.check_revisions import collect_check_sources
    from saw.followups.models import FollowUp, FollowUpVersion

    inv_id = inv.id
    first_question = s.scalar(select(func.min(FollowUp.created_at)).where(FollowUp.investigation_id == inv_id))
    cutoff = _aware(first_question)
    sources, hidden_checks = {inv_id}, 0
    initial_checks, later_lines, later_refs = [], [], []
    for family in _families(s, inv_id):
        readable = []
        for row in family:
            try:
                row_sources = collect_check_sources(s, row)
            except (ValueError, NotFound):
                row_sources = None
            if row_sources is None or not _readable(s, p, row_sources):
                hidden_checks += 1
                continue
            sources |= row_sources
            readable.append(row)
        if not readable:
            continue
        before = [r for r in readable if cutoff is None or _aware(r.created_at) <= cutoff]
        first = before[-1] if before else None
        if cutoff is None:
            first = next((r for r in reversed(readable) if r.state == "active"), None)
        elif first is not None and first.state == "cancelled" and _aware(first.updated_at) <= cutoff:
            first = None
        if first is not None:
            initial_checks.append(first)
        for row in readable:
            if cutoff is None or _aware(row.created_at) <= cutoff:
                continue
            label = row.target_label or row.target_key
            previous = first.judgement if first is not None else None
            change = (f"판단 {CHECK_LABEL.get(previous, previous)} → {CHECK_LABEL.get(row.judgement, row.judgement)}"
                      if row.judgement != previous else "판단 변경 없음")
            when = _aware(row.created_at).isoformat()
            later_lines.append(_fit(f"{label}: {change} ({when}) {row.note}".strip()))
            later_refs += _refs(inv_id, row)
            first = row
    initial_refs = list(dict.fromkeys(ref for c in initial_checks for ref in _refs(inv_id, c)))
    later_refs = [r for r in dict.fromkeys(later_refs) if r not in initial_refs]

    created = {f.id: _aware(e.uploaded_at) for f, e in s.execute(
        select(EvidenceFile, Evidence).join(Evidence).where(Evidence.investigation_id == inv_id))}
    files = []
    try:
        for f in container.get().events.file_state(s, inv_id):
            if f.get("parser_id") or f.get("parse_status") in ("failed", "skipped"):
                files.append(({"file": f.get("display_name") or f.get("name"), "parser": f.get("parser_id"),
                               "events": int(f.get("events_parsed") or 0), "failed": int(f.get("events_failed") or 0)},
                              created.get(f.get("id") or f.get("file_id"))))
    except Exception:  # noqa: BLE001 - a draft without file details is still a useful starting point
        files = [({"file": e.title or e.id, "kind": e.kind}, _aware(e.uploaded_at))
                 for e in s.scalars(select(Evidence).where(Evidence.investigation_id == inv_id))]
    initial_logs = [f for f, at in files if cutoff is None or at is None or at <= cutoff]
    later_logs = [f for f, at in files if cutoff is not None and at is not None and at > cutoff]

    followups, hidden_followups = [], 0
    for row in s.scalars(select(FollowUp).where(FollowUp.investigation_id == inv_id).order_by(FollowUp.created_at)):
        version = s.get(FollowUpVersion, row.current_version_id) if row.current_version_id else None
        if version is None:
            continue
        row_sources = {inv_id, *(version.source_investigation_ids or [])}
        payload = version.payload
        for field in ("reply", "verification"):
            row_sources |= {e["investigation_id"] for e in (payload.get(field) or {}).get("evidence") or []}
        if not _readable(s, p, row_sources):
            hidden_followups += 1
            continue
        sources |= row_sources
        followups.append((row, payload, row_sources))
    first_status = next((CHECK_STATUS.get(c.judgement, "") for c in initial_checks if c.judgement), "")
    first_note = next((c.note for c in initial_checks if c.judgement), "")
    return {"cutoff": cutoff, "initial_checks": initial_checks, "initial_refs": initial_refs,
            "initial_status": first_status, "initial_rationale": first_note, "later_lines": later_lines,
            "later_refs": later_refs, "initial_logs": initial_logs, "later_logs": later_logs,
            "followups": followups, "sources": sources, "hidden_followups": hidden_followups,
            "hidden_checks": hidden_checks}


def _followup_item(row, payload) -> tuple[dict, str | None]:
    reply = payload.get("reply") or {}
    verification = payload.get("verification") or {}
    check = verification.get("scope_check") or reply.get("scope_check") or {}
    remaining = list(verification.get("remaining_questions") or [])
    question = payload.get("question") or ""
    status = payload.get("status")
    outcome = verification.get("outcome") or ""
    open_reason = None
    if status in ("open", "replied"):
        open_reason = "; ".join(remaining) if remaining else "회신·검증 미완료"
    elif status == "verified" and outcome != "confirmed":
        # Verified is not answered: a reply that could not confirm keeps the question open.
        open_reason = "; ".join([f"검증 결과 {OUTCOME_LABEL.get(outcome, outcome)}", *remaining])
    elif status == "closed_with_limits":
        open_reason = "한계를 두고 종결: " + str((payload.get("disposition") or {}).get("reason") or "")
    item = {"followup_id": row.id, "question": _fit(question), "target": _target_text(payload),
            "period": _period_text(payload), "reply": _fit(reply.get("note") or ""),
            "reply_scope_result": check.get("summary") or "", "outcome": outcome or status or "",
            "remaining": remaining[:50],
            "evidence_refs": [f"{e['investigation_id']}/{e['event_id']}"
                              for e in [*(reply.get("evidence") or []), *(verification.get("evidence") or [])]]}
    return item, (f"{question}: {open_reason}" if open_reason is not None and status != "cancelled" else None)


def _fact(c) -> str:
    """A check as an observed fact; a question result keeps its condition, run and count so it can be re-run."""
    line = f"{c.target_label or c.target_key}: {c.note}".strip(": ")
    origin = (c.scope or {}).get("origin") or {}
    if origin:
        run = origin.get("scope") or {}
        line += (f" [질문 {origin.get('title', '')} · 조건 {origin.get('description', '')} · 계산 {origin.get('completeness', '')}"
                 f" · 버전 {run.get('version', '')} · 실행 {run.get('run_at', '')}]")
    return line


def draft(s, p, inv_id: str) -> dict:
    """Prefill from what the investigation already holds; the analyst edits before saving."""
    inv = require(s, p, "investigation.read", inv_id)
    start, end = declared_period(inv)
    view = _view(s, p, inv)
    facts = [_fit(_fact(c)) for c in view["initial_checks"] if c.note or (c.scope or {}).get("origin")]
    cutoff = view["cutoff"]
    findings = list(s.scalars(select(Finding).where(Finding.investigation_id == inv_id)
                              .order_by(Finding.risk_score.desc()).limit(10)))
    facts += [f"탐지 후보 {f.display_id} {f.title} ({f.time_start or '시각 미상'})" for f in findings
              if cutoff is None or f.created_at is None or _aware(f.created_at) <= cutoff]
    items, questions, unresolved = [], [], []
    for row, payload, _sources in view["followups"]:
        item, open_line = _followup_item(row, payload)
        items.append(item)
        questions.append(item["question"])
        if open_line:
            unresolved.append(_fit(open_line))
    if view["hidden_followups"]:
        unresolved.append(f"열람 권한이 없는 조사를 근거로 쓴 확인 요청 {view['hidden_followups']}건은 이 초안에서 제외했습니다.")
    from saw.internal_kb.signatures import investigation_alerts

    try:
        alerts = investigation_alerts(s, p, inv_id)["items"]
    except Exception:  # noqa: BLE001 - a draft without alert meanings is still useful; the list says so
        alerts = []
    meanings = [{"alert_name": a["alert_name"], "vendor": a["vendor"], "product": a["product"], "count": a["count"],
                 "registry": a["registry"], "meaning_id": (a["applied"] or {}).get("id"),
                 "meaning_version": (a["applied"] or {}).get("version")} for a in alerts]
    detail = inv.close_detail or {}
    guidance = detail.get("guidance") or {}
    unresolved += [line for line in str(detail.get("limits") or "").splitlines() if line.strip()]
    content = {
        "title": inv.title,
        "scope": {"org_unit": inv.org_unit or "", "org_unit_id": inv.org_unit_id, "period_start": start,
                  "period_end": end, "observed_start": inv.time_start.isoformat() if inv.time_start else None,
                  "observed_end": inv.time_end.isoformat() if inv.time_end else None},
        "initial_logs": view["initial_logs"][:MAX_ITEMS],
        "initial_evidence_refs": view["initial_refs"][:MAX_ITEMS],
        "observed_facts": facts[:MAX_ITEMS],
        "initial_judgement": {"status": view["initial_status"], "rationale": _fit(view["initial_rationale"]), "scope": ""},
        "questions": [q for q in questions if q][:MAX_ITEMS],
        "followups": items[:MAX_ITEMS],
        "later_logs": view["later_logs"][:MAX_ITEMS],
        "later_evidence_refs": view["later_refs"][:MAX_ITEMS],
        "later_facts": view["later_lines"][:MAX_ITEMS],
        "alert_meanings": meanings[:MAX_ITEMS],
        "final_judgement": {"status": inv.verdict or "", "rationale": _fit(inv.verdict_reason or ""),
                            "scope": " ".join(x for x in (guidance.get("behavior_assessment"),
                                                          guidance.get("impact_assessment")) if x)[:4000]},
        "unresolved": unresolved[:MAX_ITEMS],
        "notes": "",
        "lineage": {"synthetic": False, "source": "investigation", "variant_group_id": "", "split_group_id": "",
                    "split": "unassigned"},
        "provenance": _provenance(view, items),
    }
    return Content.model_validate(content).model_dump()


def _provenance(view, items) -> dict:
    refs = [r for item in items for r in item["evidence_refs"]]
    return {"cutoff": view["cutoff"].isoformat() if view["cutoff"] else None,
            "source_investigation_ids": sorted(view["sources"] | _ref_sources(refs)),
            "followup_ids": [row.id for row, _payload, _src in view["followups"]],
            "hidden_followups": view["hidden_followups"], "hidden_checks": view["hidden_checks"]}


def _version_sources(row: InternalGolden, version: InternalGoldenVersion) -> set[str]:
    content = version.content or {}
    refs = [*(content.get("initial_evidence_refs") or []), *(content.get("later_evidence_refs") or []),
            *(r for item in content.get("followups") or [] for r in item.get("evidence_refs") or [])]
    stored = (content.get("provenance") or {}).get("source_investigation_ids") or []
    return {row.investigation_id, *stored, *_ref_sources(refs)}


def _out(s, p, row: InternalGolden, version: InternalGoldenVersion | None, *, with_versions=None) -> dict:
    out = {"id": row.id, "investigation_id": row.investigation_id, "org_unit_id": row.org_unit_id, "title": row.title,
           "final_status": row.final_status, "version": row.current_version, "created_at": row.created_at,
           "updated_at": row.updated_at}
    if version is not None:
        if _readable(s, p, _version_sources(row, version)):
            out["content"] = version.content
            out["change_note"] = version.change_note
            out["restricted"] = False
        else:
            out["restricted"] = True
            out["restricted_reason"] = "이 버전은 열람 권한이 없는 다른 조사의 근거를 포함합니다."
    if with_versions is not None:
        out["versions"] = [{"version": v.version, "changed_by": v.changed_by, "change_note": v.change_note
                            if _readable(s, p, _version_sources(row, v)) else "", "created_at": v.created_at,
                            "restricted": not _readable(s, p, _version_sources(row, v))} for v in with_versions]
    return out


def _current(s, row):
    return s.scalar(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id,
                                                        InternalGoldenVersion.version == row.current_version))


def _event_known_by(inv_id: str, ref: str, cutoff: datetime, s) -> bool:
    from saw import container

    owner, _, event_id = ref.partition("/")
    if owner != inv_id or not event_id:
        return False
    event = container.get().events.get(inv_id, event_id)
    evidence = s.get(Evidence, event.get("evidence_id")) if event and event.get("evidence_id") else None
    return evidence is not None and _aware(evidence.uploaded_at) <= cutoff


def save(s, p, inv_id: str, body: SaveIn | dict) -> dict:
    body = SaveIn.model_validate(body)
    inv = require(s, p, "investigation.write", inv_id)
    row = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == inv_id))
    # The first save is conditional too: a screen opened before any record existed cannot overwrite one.
    if (row is None and body.expected_version not in (None, 0)) or (
            row is not None and body.expected_version != row.current_version):
        raise ValueError("다른 사람이 먼저 수정했습니다. 최신 내용을 다시 불러온 뒤 저장하세요.")
    content = body.content.model_dump()
    view = _view(s, p, inv)
    cutoff = view["cutoff"]
    if cutoff is not None:
        if content["initial_judgement"]["status"] != view["initial_status"]:
            raise ValueError("최초 판단은 첫 확인 요청 시점의 기록으로 고정됩니다. 바뀐 판단은 최종 판단과 후속 내용에 적으세요.")
        late = [r for r in content["initial_evidence_refs"]
                if r not in view["initial_refs"] and not _event_known_by(inv_id, r, cutoff, s)]
        if late:
            raise ValueError(f"첫 확인 요청 이후에 확인한 근거 {len(late)}건은 최초 근거가 아니라 후속 근거에 넣으세요.")
    # Sources: everything the draft drew on for this user, plus every reference left in the text.
    known = {r.id: (r, payload, src) for r, payload, src in view["followups"]}
    by_question = {payload.get("question"): src for _r, payload, src in view["followups"]}
    sources = set(view["sources"])
    for item in content["followups"]:
        if item["followup_id"] and item["followup_id"] in known:
            sources |= known[item["followup_id"]][2]
        elif item["followup_id"]:
            raise Forbidden("internal_golden_followup_unavailable")
        if item["question"] in by_question:
            sources |= by_question[item["question"]]
    refs = [*content["initial_evidence_refs"], *content["later_evidence_refs"],
            *(r for item in content["followups"] for r in item["evidence_refs"])]
    sources |= _ref_sources(refs)
    if not _readable(s, p, sources):
        raise Forbidden("investigation.read")
    content["provenance"] = {**_provenance(view, []), "source_investigation_ids": sorted(sources),
                             "followup_ids": [i["followup_id"] for i in content["followups"] if i["followup_id"]]}
    # The affiliate and declared period always come from the investigation, never from the edited text.
    start, end = declared_period(inv)
    content["scope"] = {**content["scope"], "org_unit": inv.org_unit or "", "org_unit_id": inv.org_unit_id,
                        "period_start": start, "period_end": end}
    now = utcnow()
    if row is None:
        row = InternalGolden(investigation_id=inv_id, org_unit_id=inv.org_unit_id, title=content["title"][:256],
                             created_by=p.user_id, updated_by=p.user_id, current_version=0)
        s.add(row)
        try:
            with s.begin_nested():
                s.flush()
        except IntegrityError:
            raise ValueError("다른 사람이 먼저 저장했습니다. 최신 내용을 다시 불러온 뒤 저장하세요.") from None
    row.current_version += 1
    row.title = content["title"][:256]
    row.org_unit_id = inv.org_unit_id
    row.final_status = content["final_judgement"]["status"]
    row.updated_by, row.updated_at = p.user_id, now
    version = InternalGoldenVersion(record_id=row.id, version=row.current_version, content=content,
                                    change_note=body.change_note, changed_by=p.user_id)
    s.add(version)
    s.flush()
    audit.record(s, "internal_golden.save", actor_id=p.user_id, actor_name=p.username, target_type="internal_golden",
                 target_id=row.id, investigation_id=inv_id, detail={"version": row.current_version})
    return _out(s, p, row, version)


def for_investigation(s, p, inv_id: str) -> dict | None:
    require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == inv_id))
    if row is None:
        return None
    versions = list(s.scalars(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id)
                              .order_by(InternalGoldenVersion.version.desc())))
    return _out(s, p, row, _current(s, row), with_versions=versions)


def get(s, p, record_id: str, version: int | None = None) -> dict:
    row = s.get(InternalGolden, record_id)
    if row is None:
        raise NotFound("internal golden record not found")
    require(s, p, "investigation.read", row.investigation_id)
    chosen = (s.scalar(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id,
                                                           InternalGoldenVersion.version == version))
              if version is not None else _current(s, row))
    if chosen is None:
        raise NotFound("internal golden version not found")
    if not _readable(s, p, _version_sources(row, chosen)):
        raise Forbidden("investigation.read")
    versions = list(s.scalars(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id)
                              .order_by(InternalGoldenVersion.version.desc())))
    out = _out(s, p, row, chosen, with_versions=versions)
    out["shown_version"] = chosen.version
    return out


def list_records(s, p, *, org_unit_id: str | None = None, limit: int = 100) -> list[dict]:
    readable = {inv.id for inv in list_for(s, p, 500, org_unit_id=org_unit_id)}
    q = select(InternalGolden).order_by(InternalGolden.updated_at.desc())
    if org_unit_id is not None:
        q = q.where(InternalGolden.org_unit_id == org_unit_id)
    out = []
    for row in s.scalars(q.limit(max(1, min(limit, 500)) * 3)):
        current = _current(s, row) if row.investigation_id in readable else None
        if current is not None and _readable(s, p, _version_sources(row, current)):
            out.append(_out(s, p, row, None))
    return out[:limit]


INITIAL_FIELDS = ("title", "scope", "initial_logs", "initial_evidence_refs", "observed_facts", "questions")
ANSWER_FIELDS = ("initial_judgement", "followups", "later_logs", "later_evidence_refs", "later_facts",
                 "alert_meanings", "final_judgement", "unresolved")


def export(s, p, *, audience: str, split: str | None = None, org_unit_id: str | None = None) -> bytes:
    """Current readable versions as the existing evaluation files: what an agent may see, and the answers.

    agent-input lines hold only what was known at the first question (no reply, later file, changed or
    final judgement). evaluator-answer lines hold the rest. Variants of one case (same lineage group) must
    sit in one split, so a case cannot be trained on and tested with. This is a data export for evaluation;
    it does not train or grade anything by itself.
    """
    import hashlib
    import json

    if audience not in ("agent", "evaluator"):
        raise ValueError("audience must be agent or evaluator")
    rows = []
    for item in list_records(s, p, org_unit_id=org_unit_id, limit=500):
        row = s.get(InternalGolden, item["id"])
        version = _current(s, row)
        content = version.content or {}
        lineage = content.get("lineage") or {}
        rows.append((row, version, content, lineage))
    groups: dict[str, set] = {}
    for _row, _v, _c, lineage in rows:
        if lineage.get("variant_group_id"):
            groups.setdefault(lineage["variant_group_id"], set()).add(lineage.get("split", "unassigned"))
    crossing = sorted(g for g, splits in groups.items() if len(splits) > 1)
    if crossing:
        raise ValueError("같은 계보 그룹의 사례가 서로 다른 분할(학습·검증·평가)에 있습니다: " + ", ".join(crossing[:10]))
    lines = []
    for row, version, content, lineage in rows:
        if split is not None and lineage.get("split", "unassigned") != split:
            continue
        example_id = f"internal:{row.id}:v{version.version}"
        if audience == "agent":
            body = {"schema": "saw.golden.agent-input.v1", "example_id": example_id, "source": "internal_golden",
                    "as_of": (content.get("provenance") or {}).get("cutoff"), "retrieval": "snapshot_only",
                    "observations": {k: content.get(k) for k in INITIAL_FIELDS}}
        else:
            answers = {k: content.get(k) for k in ANSWER_FIELDS}
            sha = hashlib.sha256(json.dumps(answers, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            body = {"schema": "saw.golden.evaluator-answer.v2", "example_id": example_id, "content_sha256": sha,
                    "lineage": lineage, "answers": answers}
        lines.append(json.dumps(body, ensure_ascii=False, sort_keys=True))
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")

