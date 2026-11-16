"""Golden-set candidate inbox: cases an analyst sets aside before the investigation or answer is finished.

A candidate points at a reproducible source and never copies its logs:
- a synthetic casebook case (W01-W60): the case file shipped with the web UI, versioned by its SHA-256;
- an investigation: its evidence files, versioned by their SHA-256 values.
Adding the same source at the same version again returns the existing candidate. Investigation candidates follow
the investigation's read access everywhere (list, save, export); a reader without access sees neither the title nor
the evidence. Removing a candidate deletes only the pointer.

Saving to the golden set reuses the internal golden records and their append-only versions. An investigation is
saved through the existing internal golden draft and save, so its first-known/later split and access rules hold.
A casebook case is saved as a synthetic record keyed "casebook:<id>": its first steps (the lead, the queries and
the original rows) become the agent input; the follow-up evidence, the model judgement and what stays open become
the evaluator answer. Nothing here writes checks, findings or investigation verdicts.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.security.authz import has_permission
from saw.internal_kb import golden
from saw.internal_kb.models import GoldenCandidate, InternalGolden, InternalGoldenVersion
from saw.storage.db import utcnow
from saw.storage.models import Evidence, EvidenceFile

CASE_ID = re.compile(r"W\d{2}")
CASEBOOK_PREFIX = "casebook:"
SPLITS = ("unassigned", "train", "validation", "test")
# How each casebook classification reads as a golden judgement status; the original label is kept in the scope.
CLASS_STATUS = {"침해 확인": "compromise_confirmed", "정상 확인": "normal", "승인된 활동": "normal",
                "정상 · 확인된 배포 범위": "normal", "운영 장애": "normal", "차단 확인": "attack_attempt",
                "접속 시도 확인": "attack_attempt", "판단 보류": "insufficient_evidence"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AddIn(Strict):
    source_kind: Literal["casebook", "investigation"]
    source_id: Annotated[str, Field(min_length=1, max_length=64)]
    note: Annotated[str, Field(max_length=2000)] = ""


class UpdateIn(Strict):
    note: Annotated[str, Field(max_length=2000)] | None = None
    split: Literal["unassigned", "train", "validation", "test"] | None = None


class IdsIn(Strict):
    ids: list[Annotated[str, Field(max_length=36)]] = Field(min_length=1, max_length=200)


def casebook_dir() -> Path:
    """The case files served with the web UI; the source tree's public copy when no build is present."""
    from saw.config import ROOT, get_settings

    for base in (Path(get_settings().web_dist), ROOT / "apps" / "web" / "public"):
        folder = base / "reference-data" / "platform-cases"
        if (folder / "index.json").is_file():
            return folder
    raise NotFound("casebook not installed")


def _casebook_case(case_id: str) -> tuple[dict, str, bytes]:
    if not CASE_ID.fullmatch(case_id):
        raise NotFound("casebook case not found")
    path = casebook_dir() / f"{case_id}.json"
    if not path.is_file():
        raise NotFound("casebook case not found")
    raw = path.read_bytes()
    case = json.loads(raw.decode("utf-8"))
    if case.get("id") != case_id or len(case.get("steps") or []) != 5:
        raise ValueError("사례 파일이 완전하지 않습니다.")
    return case, hashlib.sha256(raw).hexdigest(), raw


def _investigation_version(s, inv_id: str) -> tuple[str, dict]:
    """The investigation's evidence as file names, sizes and SHA-256: enough to reproduce, nothing copied."""
    files = []
    for ev in s.scalars(select(Evidence).where(Evidence.investigation_id == inv_id).order_by(Evidence.uploaded_at)):
        for f in s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev.id).order_by(EvidenceFile.id)):
            files.append({"evidence_id": ev.id, "file_id": f.id, "name": f.display_name, "size": f.size, "sha256": f.sha256})
    key = json.dumps(sorted((f["evidence_id"], f["file_id"], f["sha256"]) for f in files), separators=(",", ":"))
    return hashlib.sha256(key.encode()).hexdigest(), {"evidence_files": files}


def _readable(s, p, row: GoldenCandidate) -> bool:
    if row.source_kind == "casebook":
        return True
    return golden._readable(s, p, {row.source_id})


def _need(p, permission: str):
    if not has_permission(p, permission):
        raise Forbidden(permission)


def _out(row: GoldenCandidate) -> dict:
    saved = row.golden_record_id is not None
    link = (f"/casebook?worked={row.source_id}" if row.source_kind == "casebook"
            else f"/inv/{row.source_id}")
    return {"id": row.id, "source_kind": row.source_kind, "source_id": row.source_id,
            "source_version": row.source_version, "source_refs": row.source_refs, "title": row.title,
            "origin_label": "합성 예제" if row.source_kind == "casebook" else "실제 조사",
            "org_unit_id": row.org_unit_id, "org_label": row.org_label, "note": row.note, "split": row.split,
            "status": "saved" if saved else "candidate", "status_label": "골든셋 저장됨" if saved else "후보",
            "golden_record_id": row.golden_record_id, "golden_version": row.golden_version,
            "created_at": row.created_at, "updated_at": row.updated_at, "link": link}


def add(s, p, body: AddIn | dict) -> dict:
    body = AddIn.model_validate(body)
    _need(p, "knowledge.write")
    if body.source_kind == "casebook":
        case, version, _raw = _casebook_case(body.source_id)
        title, org_id, org_label = case["title"], None, "합성 예제(사례집)"
        refs = {"case_file": f"reference-data/platform-cases/{case['id']}.json", "case_sha256": version,
                "archive": f"reference-data/platform-cases/{case['id']}.zip", "synthetic": True}
    else:
        inv = require(s, p, "investigation.write", body.source_id)
        version, refs = _investigation_version(s, inv.id)
        title, org_id, org_label = inv.title, inv.org_unit_id, inv.org_unit or ""
    key = f"{body.source_kind}:{body.source_id}:{version}"
    row = s.scalar(select(GoldenCandidate).where(GoldenCandidate.source_key == key))
    if row is not None:
        return {"item": _out(row), "created": False}
    row = GoldenCandidate(source_key=key, source_kind=body.source_kind, source_id=body.source_id,
                          source_version=version, source_refs=refs, title=title[:256], org_unit_id=org_id,
                          org_label=org_label[:256], note=body.note, created_by=p.user_id)
    s.add(row)
    try:
        with s.begin_nested():
            s.flush()
    except IntegrityError:
        # Two clicks at once: the other request made it; still one candidate.
        row = s.scalar(select(GoldenCandidate).where(GoldenCandidate.source_key == key))
        return {"item": _out(row), "created": False}
    audit.record(s, "golden_candidate.add", actor_id=p.user_id, actor_name=p.username, target_type="golden_candidate",
                 target_id=row.id, investigation_id=row.source_id if row.source_kind == "investigation" else None,
                 detail={"source": key})
    return {"item": _out(row), "created": True}


def list_items(s, p, *, q: str = "", source_kind: str | None = None, status: str | None = None,
               source_id: str | None = None) -> list[dict]:
    _need(p, "knowledge.read")
    query = select(GoldenCandidate).order_by(GoldenCandidate.created_at.desc())
    if source_kind:
        query = query.where(GoldenCandidate.source_kind == source_kind)
    if source_id:
        query = query.where(GoldenCandidate.source_id == source_id)
    term = q.strip().lower()
    out = []
    for row in s.scalars(query.limit(2000)):
        if not _readable(s, p, row):
            continue  # an unreadable investigation is not even counted or named
        item = _out(row)
        if status and item["status"] != status:
            continue
        if term and term not in " ".join([row.title, row.source_id, row.org_label, row.note]).lower():
            continue
        out.append(item)
    return out


def _get(s, p, candidate_id: str) -> GoldenCandidate:
    row = s.get(GoldenCandidate, candidate_id)
    if row is None or not _readable(s, p, row):
        raise NotFound("golden candidate not found")
    return row


def update(s, p, candidate_id: str, body: UpdateIn | dict) -> dict:
    body = UpdateIn.model_validate(body)
    _need(p, "knowledge.write")
    row = _get(s, p, candidate_id)
    if body.note is not None:
        row.note = body.note
    if body.split is not None:
        row.split = body.split
    row.updated_at = utcnow()
    return _out(row)


def remove(s, p, candidate_id: str) -> None:
    """Only the pointer goes; the source investigation, its logs and saved golden versions stay."""
    _need(p, "knowledge.write")
    row = _get(s, p, candidate_id)
    audit.record(s, "golden_candidate.remove", actor_id=p.user_id, actor_name=p.username,
                 target_type="golden_candidate", target_id=row.id,
                 investigation_id=row.source_id if row.source_kind == "investigation" else None,
                 detail={"source": row.source_key, "golden_record_id": row.golden_record_id})
    s.delete(row)
    s.flush()


LATER_MARKERS = ("followup", "회신", "후속")


def _first_known(text: str) -> str:
    """Drop the sentences and " · " parts that point at later material (follow-up files, replies)."""
    kept = []
    for sentence in re.split(r"(?<=[.다])\s+", text):
        parts = [x for x in sentence.split(" · ") if not any(m in x.lower() for m in LATER_MARKERS)]
        if parts:
            kept.append(" · ".join(parts))
    return " ".join(kept).strip()


def _without_case_id(value, case_id: str):
    """The case id names the public file that holds the verdict; first-known material must not carry it."""
    text = json.dumps(value, ensure_ascii=False)
    return json.loads(text.replace(f"{case_id} · ", "").replace(case_id, "이 사례"))


def _rows(step: dict) -> list[dict]:
    return [{k: v for k, v in r.items()} for r in step.get("rows") or []]


def _facts(step: dict) -> list[str]:
    return [f"{f['label']}: {f['value']}" for f in step.get("facts") or []]


def casebook_content(case: dict, split: str = "unassigned") -> dict:
    """The first three steps (lead, queries, original rows) are what was known first; the rest is the answer.

    The agent-side fields carry no case id (it names the public file that holds the verdict) and no step-two
    narrative (it can describe the later verification); the id stays in the evaluator-side lineage.
    """
    steps = case["steps"]
    run = case.get("run") or {}
    initial = steps[:3]
    # File names that announce later material (followup.json) are not part of the first-known state.
    first_facts = [_first_known(line) for st in initial for line in _facts(st)]
    observed = [_first_known(steps[0]["finding"]), *first_facts]
    status = CLASS_STATUS.get(case["classification"])
    if status is None:
        status = "insufficient_evidence" if case["classification"].startswith(("의심", "판단")) else "unknown"
    later, judged = steps[3], steps[4]
    followups = [{"question": f"{r.get('자료 출처', '후속 자료')} 대조", "reply": str(r.get("대조할 값", "")),
                  "evidence_refs": [str(r["근거 ID"])] if r.get("근거 ID") else []} for r in later.get("rows") or []]
    if not followups:
        followups = [{"question": "후속 자료 대조", "reply": " / ".join([later["finding"], *_facts(later)])}]
    unresolved = [f["value"] for st in (later, judged) for f in st.get("facts") or []
                  if any(k in f["label"] for k in ("미확인", "다음"))]
    lead = run.get("lead_time") or run.get("evidence_time") or {}
    content = {
        "title": case["title"],
        "scope": {"org_unit": "합성 예제(사례집)", "synthetic": True,
                  "period_start": lead.get("start"), "period_end": lead.get("end"),
                  "source_counts": run.get("counts") or {}},
        "initial_logs": [row for st in initial for row in _rows(st)][: golden.MAX_ITEMS],
        "initial_evidence_refs": [f"fw.csv:{n}" for n in run.get("evidence_rows") or []][: golden.MAX_ITEMS],
        "observed_facts": [golden._fit(x) for x in observed if x][: golden.MAX_ITEMS],
        "initial_judgement": {"status": "", "rationale": "", "scope": ""},
        "questions": ["관측된 활동이 승인된 업무인지, 공격 시도·침해인지 판단하고 근거와 남은 확인을 적으세요."],
        "followups": followups[: golden.MAX_ITEMS],
        "later_logs": _rows(later)[: golden.MAX_ITEMS],
        "later_evidence_refs": [str(r["근거 ID"]) for r in later.get("rows") or [] if r.get("근거 ID")],
        "later_facts": [golden._fit(later["finding"]), *_facts(later)][: golden.MAX_ITEMS],
        "alert_meanings": [],
        "final_judgement": {"status": status, "rationale": golden._fit(judged["finding"]),
                            "scope": f"사례 판단: {case['classification']}"},
        "unresolved": unresolved[: golden.MAX_ITEMS],
        "notes": "합성 사례집에서 저장한 골든 기록입니다. 실제 관계사·실제 로그가 아닙니다.",
        "lineage": {"synthetic": True, "source": "casebook", "variant_group_id": f"casebook:{case['id']}",
                    "split_group_id": f"casebook:{case['id']}", "split": split},
        "provenance": {"cutoff": None, "source_investigation_ids": [], "followup_ids": [], "hidden_followups": 0,
                       "hidden_checks": 0},
    }
    for field in ("scope", "initial_logs", "observed_facts"):
        content[field] = _without_case_id(content[field], case["id"])
    return golden.Content.model_validate(content).model_dump()


def _save_casebook(s, p, row: GoldenCandidate) -> tuple[str, int]:
    case, version, _raw = _casebook_case(row.source_id)
    if version != row.source_version:
        raise ValueError(f"{row.source_id} 사례 파일이 후보로 담은 버전과 다릅니다. 후보를 다시 담으세요.")
    content = casebook_content(case, row.split)
    key = f"{CASEBOOK_PREFIX}{row.source_id}"
    record = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == key))
    if record is None:
        record = InternalGolden(investigation_id=key, org_unit_id=None, title=content["title"][:256],
                                created_by=p.user_id, updated_by=p.user_id, current_version=0)
        s.add(record)
        try:
            with s.begin_nested():
                s.flush()
        except IntegrityError:
            raise ValueError("다른 사용자가 같은 사례를 방금 저장했습니다. 다시 저장하세요.") from None
    record.current_version += 1
    record.title = content["title"][:256]
    record.final_status = content["final_judgement"]["status"]
    record.updated_by, record.updated_at = p.user_id, utcnow()
    s.add(InternalGoldenVersion(record_id=record.id, version=record.current_version, content=content,
                                change_note=f"골든셋 후보함에서 저장 (사례 파일 SHA-256 {version[:12]})",
                                changed_by=p.user_id))
    s.flush()
    return record.id, record.current_version


def _save_investigation(s, p, row: GoldenCandidate) -> tuple[str, int]:
    require(s, p, "investigation.write", row.source_id)
    current, _refs = _investigation_version(s, row.source_id)
    if current != row.source_version:
        raise ValueError("조사의 증거 파일이 후보로 담은 뒤 바뀌었습니다. 후보를 다시 담으세요.")
    existing = s.scalar(select(InternalGolden).where(InternalGolden.investigation_id == row.source_id))
    if existing is not None:
        # An analyst may have curated this record by hand; a fresh draft must never silently replace it.
        # The candidate is linked to the current version as it stands; the split is applied at export.
        return existing.id, existing.current_version
    content = golden.draft(s, p, row.source_id)
    lineage = content["lineage"]
    lineage["variant_group_id"] = lineage["variant_group_id"] or f"investigation:{row.source_id}"
    lineage["split_group_id"] = lineage["split_group_id"] or lineage["variant_group_id"]
    lineage["split"] = row.split
    saved = golden.save(s, p, row.source_id, {"content": content, "change_note": "골든셋 후보함에서 저장",
                                              "expected_version": None})
    return saved["id"], saved["version"]


def save(s, p, body: IdsIn | dict) -> list[dict]:
    """Save only the selected candidates as new golden versions; nothing else is touched."""
    body = IdsIn.model_validate(body)
    _need(p, "knowledge.write")
    out = []
    for candidate_id in dict.fromkeys(body.ids):
        row = _get(s, p, candidate_id)
        record_id, version = (_save_casebook(s, p, row) if row.source_kind == "casebook"
                              else _save_investigation(s, p, row))
        row.golden_record_id, row.golden_version, row.updated_at = record_id, version, utcnow()
        audit.record(s, "golden_candidate.save", actor_id=p.user_id, actor_name=p.username,
                     target_type="golden_candidate", target_id=row.id,
                     investigation_id=row.source_id if row.source_kind == "investigation" else None,
                     detail={"golden_record_id": record_id, "version": version})
        out.append(_out(row))
    return out


NEUTRAL_TITLE = "사례 {n}"


def export(s, p, body: IdsIn | dict, audience: str) -> bytes:
    """Only the selected, saved candidates at the saved version, with one example ID in both files.

    The agent input carries the first-known observations under a neutral title (a case title can announce the
    answer); the evaluator answer carries the judgement, follow-up evidence and open questions. Cases derived from
    one source share a lineage group and must sit in one split.
    """
    if audience not in ("agent", "evaluator"):
        raise ValueError("audience must be agent or evaluator")
    body = IdsIn.model_validate(body)
    _need(p, "knowledge.read")
    picked = []
    for candidate_id in dict.fromkeys(body.ids):
        row = _get(s, p, candidate_id)
        if row.golden_record_id is None:
            raise ValueError(f"골든셋으로 저장한 후보만 내보낼 수 있습니다: {row.title}")
        record = s.get(InternalGolden, row.golden_record_id)
        if record is None:
            raise NotFound("golden version not found")
        version = s.scalar(select(InternalGoldenVersion).where(InternalGoldenVersion.record_id == record.id,
                                                               InternalGoldenVersion.version == row.golden_version))
        if version is None:
            raise NotFound("golden version not found")
        if row.source_kind == "investigation" and not golden._readable(s, p, golden._version_sources(record, version)):
            raise NotFound("golden candidate not found")
        picked.append((row, record, version))
    groups: dict[str, set] = {}
    for row, _record, version in picked:
        lineage = (version.content or {}).get("lineage") or {}
        if lineage.get("variant_group_id"):
            # The split shown in the inbox is the split exported; no re-save is needed after changing it.
            groups.setdefault(lineage["variant_group_id"], set()).add(row.split)
    crossing = sorted(g for g, splits in groups.items() if len(splits) > 1)
    if crossing:
        raise ValueError("같은 원본에서 나온 사례가 서로 다른 분할에 있습니다: " + ", ".join(crossing[:10]))
    lines = []
    for n, (row, record, version) in enumerate(picked, 1):
        content = version.content or {}
        example_id = f"golden:{record.id}:v{version.version}"
        if audience == "agent":
            observations = {k: content.get(k) for k in golden.INITIAL_FIELDS}
            observations["title"] = NEUTRAL_TITLE.format(n=n)
            # Versions saved before 0.2.5 final kept the case id in the scope; it must not reach the agent.
            observations["scope"] = {k: v for k, v in (observations.get("scope") or {}).items() if k != "case_id"}
            if row.source_kind == "casebook":
                observations = _without_case_id(observations, row.source_id)
            body_out = {"schema": "saw.golden.agent-input.v1", "example_id": example_id, "source": "golden_candidate",
                        "synthetic": bool((content.get("lineage") or {}).get("synthetic")),
                        "as_of": (content.get("provenance") or {}).get("cutoff"), "retrieval": "snapshot_only",
                        "observations": observations}
        else:
            answers = {k: content.get(k) for k in golden.ANSWER_FIELDS}
            answers["title"] = content.get("title")
            sha = hashlib.sha256(json.dumps(answers, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            body_out = {"schema": "saw.golden.evaluator-answer.v2", "example_id": example_id, "content_sha256": sha,
                        "lineage": {**(content.get("lineage") or {}), "split": row.split}, "source": {"kind": row.source_kind, "id": row.source_id,
                                                                           "version": row.source_version},
                        "answers": answers}
        lines.append(json.dumps(body_out, ensure_ascii=False, sort_keys=True, default=str))
    audit.record(s, "golden_candidate.export", actor_id=p.user_id, actor_name=p.username,
                 target_type="golden_candidate", target_id="export",
                 detail={"audience": audience, "candidate_ids": [r.id for r, _x, _y in picked]})
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
