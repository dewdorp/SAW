"""Internal golden records: an analyst saves and edits the investigation's analysis directly.

No pseudonymisation, approver or manual hash check is required for internal use. Access stays tied to the
source investigation (read to view, write to save) and to its affiliate; every save is a new version.
The record separates what was known first (scope, initial logs, facts, initial judgement and questions)
from what came later (follow-up replies and evidence) and from the final judgement and open questions.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from saw.core.application import audit
from saw.core.application.investigations import NotFound, declared_period, list_for, require
from saw.internal_kb.models import InternalGolden, InternalGoldenVersion
from saw.storage.db import utcnow
from saw.storage.models import Check, Evidence, Finding

Line = Annotated[str, Field(max_length=4000)]
Status = Literal["", "normal", "attack_attempt", "compromise_confirmed", "insufficient_evidence", "data_quality_limited",
                 "attack", "false_positive", "unknown"]
MAX_ITEMS = 200


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Judgement(Strict):
    status: Status = ""
    rationale: Line = ""
    scope: Line = ""  # what the judgement covers (affiliate, period, targets) and what it does not


class FollowUpItem(Strict):
    question: Line
    target: Line = ""
    period: Line = ""
    reply: Line = ""
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


class Content(Strict):
    schema_version: Literal["saw.internal-golden/1"] = "saw.internal-golden/1"
    title: Line
    scope: dict = Field(default_factory=dict)
    initial_logs: list[dict] = Field(default_factory=list, max_length=MAX_ITEMS)
    initial_evidence_refs: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    observed_facts: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    initial_judgement: Judgement = Field(default_factory=Judgement)
    questions: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    followups: list[FollowUpItem] = Field(default_factory=list, max_length=MAX_ITEMS)
    final_judgement: Judgement = Field(default_factory=Judgement)
    unresolved: list[Line] = Field(default_factory=list, max_length=MAX_ITEMS)
    notes: Line = ""
    lineage: Lineage = Field(default_factory=Lineage)


class SaveIn(Strict):
    content: Content
    change_note: Annotated[str, Field(max_length=2000)] = ""
    expected_version: int | None = None


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


def draft(s, p, inv_id: str) -> dict:
    """Prefill from what the investigation already holds; the analyst edits before saving."""
    from saw import container
    from saw.followups.models import FollowUp, FollowUpVersion

    inv = require(s, p, "investigation.read", inv_id)
    start, end = declared_period(inv)
    files = []
    try:
        for f in container.get().events.file_state(s, inv_id):
            if f.get("parser_id") or f.get("parse_status") in ("failed", "skipped"):
                files.append({"file": f.get("display_name") or f.get("name"), "parser": f.get("parser_id"),
                              "events": int(f.get("events_parsed") or 0), "failed": int(f.get("events_failed") or 0)})
    except Exception:  # noqa: BLE001 - a draft without file details is still a useful starting point
        files = [{"file": e.title or e.id, "kind": e.kind} for e in s.scalars(select(Evidence).where(
            Evidence.investigation_id == inv_id))]
    checks = list(s.scalars(select(Check).where(Check.investigation_id == inv_id, Check.state == "active")
                            .order_by(Check.created_at)))
    refs = list(dict.fromkeys(ref for c in checks for ref in [*(c.evidence or []), *((c.scope or {}).get("event_ids") or [])]))
    facts = [f"{c.target_label or c.target_key}: {c.note}".strip(": ") for c in checks if c.note][:MAX_ITEMS]
    findings = list(s.scalars(select(Finding).where(Finding.investigation_id == inv_id)
                              .order_by(Finding.risk_score.desc()).limit(10)))
    facts += [f"탐지 후보 {f.display_id} {f.title} ({f.time_start or '시각 미상'})" for f in findings]
    first = next((c for c in checks if c.judgement), None)
    judgement_map = {"normal": "normal", "malicious": "attack_attempt", "suspicious": "insufficient_evidence",
                     "undetermined": "insufficient_evidence"}
    followups, questions, unresolved = [], [], []
    for row in s.scalars(select(FollowUp).where(FollowUp.investigation_id == inv_id).order_by(FollowUp.created_at)):
        version = s.get(FollowUpVersion, row.current_version_id) if row.current_version_id else None
        if version is None:
            continue
        payload = version.payload
        reply = payload.get("reply") or {}
        verification = payload.get("verification") or {}
        check = verification.get("scope_check") or reply.get("scope_check") or {}
        remaining = list(verification.get("remaining_questions") or [])
        questions.append(payload.get("question") or "")
        followups.append({"question": payload.get("question") or "", "target": _target_text(payload),
                          "period": _period_text(payload), "reply": reply.get("note") or "",
                          "reply_scope_result": check.get("summary") or "",
                          "outcome": verification.get("outcome") or payload.get("status") or "",
                          "remaining": remaining,
                          "evidence_refs": [f"{e['investigation_id']}/{e['event_id']}"
                                            for e in [*(reply.get("evidence") or []), *(verification.get("evidence") or [])]]})
        if payload.get("status") in ("open", "replied") or remaining:
            unresolved.append(f"{payload.get('question')}: " + ("; ".join(remaining) if remaining else "회신·검증 미완료"))
    detail = inv.close_detail or {}
    guidance = detail.get("guidance") or {}
    unresolved += [line for line in str(detail.get("limits") or "").splitlines() if line.strip()]
    content = {
        "title": inv.title,
        "scope": {"org_unit": inv.org_unit or "", "org_unit_id": inv.org_unit_id, "period_start": start,
                  "period_end": end, "observed_start": inv.time_start.isoformat() if inv.time_start else None,
                  "observed_end": inv.time_end.isoformat() if inv.time_end else None},
        "initial_logs": files[:MAX_ITEMS],
        "initial_evidence_refs": [f"{inv_id}/{r}" for r in refs][:MAX_ITEMS],
        "observed_facts": facts[:MAX_ITEMS],
        "initial_judgement": {"status": judgement_map.get(first.judgement, "") if first else "",
                              "rationale": first.note if first else "", "scope": ""},
        "questions": [q for q in questions if q][:MAX_ITEMS],
        "followups": followups[:MAX_ITEMS],
        "final_judgement": {"status": inv.verdict or "", "rationale": inv.verdict_reason or "",
                            "scope": " ".join(x for x in (guidance.get("behavior_assessment"),
                                                          guidance.get("impact_assessment")) if x)[:4000]},
        "unresolved": unresolved[:MAX_ITEMS],
        "notes": "",
        "lineage": {"synthetic": False, "source": "investigation", "variant_group_id": "", "split_group_id": "",
                    "split": "unassigned"},
    }
    return Content.model_validate(content).model_dump()


def _out(row: InternalGolden, version: InternalGoldenVersion | None, *, with_versions=None) -> dict:
    out = {"id": row.id, "investigation_id": row.investigation_id, "org_unit_id": row.org_unit_id, "title": row.title,
           "final_status": row.final_status, "version": row.current_version, "created_at": row.created_at,
           "updated_at": row.updated_at}
    if version is not None:
        out["content"] = version.content
        out["change_note"] = version.change_note
    if with_versions is not None:
        out["versions"] = [{"version": v.version, "changed_by": v.changed_by, "change_note": v.change_note,
                            "created_at": v.created_at} for v in with_versions]
    return out


def _current(s, row):
    return s.scalar(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id,
                                                        InternalGoldenVersion.version == row.current_version))


def save(s, p, inv_id: str, body: SaveIn | dict) -> dict:
    body = SaveIn.model_validate(body)
    inv = require(s, p, "investigation.write", inv_id)
    row = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == inv_id))
    if row is not None and body.expected_version is not None and body.expected_version != row.current_version:
        raise ValueError("다른 사람이 먼저 수정했습니다. 최신 내용을 다시 불러온 뒤 저장하세요.")
    content = body.content.model_dump()
    # The affiliate and declared period always come from the investigation, never from the edited text.
    start, end = declared_period(inv)
    content["scope"] = {**content["scope"], "org_unit": inv.org_unit or "", "org_unit_id": inv.org_unit_id,
                        "period_start": start, "period_end": end}
    now = utcnow()
    if row is None:
        row = InternalGolden(investigation_id=inv_id, org_unit_id=inv.org_unit_id, title=content["title"][:256],
                             created_by=p.user_id, updated_by=p.user_id, current_version=0)
        s.add(row)
        s.flush()
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
    return _out(row, version)


def for_investigation(s, p, inv_id: str) -> dict | None:
    require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == inv_id))
    if row is None:
        return None
    versions = list(s.scalars(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id)
                              .order_by(InternalGoldenVersion.version.desc())))
    return _out(row, _current(s, row), with_versions=versions)


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
    versions = list(s.scalars(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == row.id)
                              .order_by(InternalGoldenVersion.version.desc())))
    out = _out(row, chosen, with_versions=versions)
    out["shown_version"] = chosen.version
    return out


def list_records(s, p, *, org_unit_id: str | None = None, limit: int = 100) -> list[dict]:
    readable = {inv.id for inv in list_for(s, p, 500, org_unit_id=org_unit_id)}
    q = select(InternalGolden).order_by(InternalGolden.updated_at.desc())
    if org_unit_id is not None:
        q = q.where(InternalGolden.org_unit_id == org_unit_id)
    return [_out(row, None) for row in s.scalars(q.limit(max(1, min(limit, 500)) * 3))
            if row.investigation_id in readable][:limit]
