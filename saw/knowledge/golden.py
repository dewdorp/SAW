"""Bounded, immutable golden examples: reviewed answers never enter agent input or knowledge search."""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, access_of, require
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_event, mask_text
from saw.core.security.sanitize import csv_safe
from saw.detection.derived_access import (
    require_investigation_results,
    require_snapshot,
)
from saw.knowledge import experience
from saw.knowledge.golden_models import GoldenBlob, GoldenFamily, GoldenFamilyMember, GoldenVersion
from saw.knowledge.models import Experience, KnowledgeRevision
from saw.storage.db import utcnow
from saw.storage.models import (
    AttackStory,
    Case,
    CaseItem,
    Check,
    Evidence,
    EvidenceFile,
    Finding,
    Investigation,
    Note,
    ProcessingRun,
    User,
)

MAX_BLOB = 256 * 1024
MAX_CASE = 4 * 1024 * 1024
MAX_EVENTS = 200
MAX_EXPORT = 20 * 1024 * 1024
CONFIRMATIONS = {"required_facts_actions", "judgement_evidence", "followups", "forbidden_claims"}
SPLITS = {"train", "dev", "holdout"}
SCOPE_KEYS = {"target_type", "target_key", "role", "filters", "time", "effective_time", "as_of", "scope_key"}
EVENT_KEYS = {"event_id", "timestamp", "timestamp_raw", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
              "transport", "enforcement_action", "status_code", "http_status", "method", "http_method", "uri", "url_path",
              "url_query", "hostname", "bytes_sent", "bytes_received", "bytes_in", "bytes_out", "raw_event",
              "data_source", "user_agent", "params", "duration", "direction", "process", "account"}
ANSWER_KEYS = {"required_facts_actions", "judgement", "followups", "forbidden_claims", "limits", "no_followups_reason",
               "analyst_records"}
_SECRET_KEY = re.compile(r"(?i)(password|passwd|cookie|authorization|api.?key|secret|token)")


_REFERENCE_KEYS = {"sha256", "digest", "run_digest", "evidence_refs", "evidence_ids",
                   "event_id", "result_id", "check_id", "check_ids", "job_id", "id",
                   "evidence_id", "file_id", "created_by", "check_author_id"}
_HEX_DIGEST = re.compile(r"^[a-fA-F0-9]{64}$")
_UUID = re.compile(r"^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$")


def masked(value, _key=None):
    if isinstance(value, dict):
        if _key in {"user_agents", "methods", "status_codes", "actions"} and all(type(v) is int for v in value.values()):
            counts = {}
            for key, count in value.items():
                safe_key = mask_text(str(key)).text
                counts[safe_key] = counts.get(safe_key, 0) + count
            return counts
        return {mask_text(str(k)).text: "[MASKED]" if _SECRET_KEY.search(str(k)) else masked(v, str(k))
                for k, v in value.items()}
    if isinstance(value, list):
        return [masked(v, _key) for v in value]
    # Opaque server references can accidentally contain phone/card-shaped digits.
    # Preserve only strictly shaped metadata identifiers, never arbitrary free text.
    if isinstance(value, str):
        reference = _key in _REFERENCE_KEYS or bool(_key and _key.endswith("_sha256"))
        if reference and (_HEX_DIGEST.fullmatch(value) or _UUID.fullmatch(value)):
            return value
        return mask_text(value).text
    return value


def _aware(value) -> datetime:
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError, AttributeError):
        raise ValueError("golden_missing_capture_time") from None


def _bytes(value) -> bytes:
    return canonical(value).encode("utf-8")


def _log(s, p, action, g=None, **detail):
    audit.record(s, "golden." + action, actor_id=p.user_id, actor_name=p.username,
                 target_type="golden", target_id=g.id if g else "",
                 investigation_id=g.source_investigation_id if g else None, detail=detail)


def _experience(s, p, eid, write=False):
    e = s.get(Experience, eid)
    if e is None:
        raise NotFound("experience not found")
    if not can(p, "knowledge.write" if write else "knowledge.read"):
        raise Forbidden("knowledge.write" if write else "knowledge.read")
    if not e.source_investigation_id:
        raise ValueError("golden_source_investigation_required")
    require(s, p, "investigation.read", e.source_investigation_id)
    require_snapshot(s, p, [e.data, e.approved_data])
    require_investigation_results(s, p, e.source_investigation_id)
    if write and e.analyst_id != p.user_id and not can(p, "knowledge.approve"):
        raise Forbidden("only the author or a reviewer can edit golden")
    if not experience.visible(e, p):
        raise NotFound("experience not found")
    return e


def _lock_experience(s, eid):
    # A write lock also works in SQLite; lock precedes read/compare to reject concurrent stale edits.
    s.execute(update(Experience).where(Experience.id == eid).values(rev=Experience.rev)
              .execution_options(synchronize_session=False))
    s.expire_all()


def _get(s, p, vid, write=False):
    g = s.get(GoldenVersion, vid)
    if g is None:
        raise NotFound("golden version not found")
    e = _experience(s, p, g.experience_id, write)
    return g, e


def _revision_contributors(s, e, rev):
    rows = s.scalars(select(KnowledgeRevision).where(KnowledgeRevision.kind == "experience",
        KnowledgeRevision.ref_id == e.id, KnowledgeRevision.rev <= rev))
    names = {r.actor for r in rows if (r.note or "").startswith(("created", "edited", "auto-draft"))}
    return {e.analyst_id, *s.scalars(select(User.id).where(User.username.in_(names)))}


def _payload(g):
    return {"experience_id": g.experience_id, "experience_rev": g.experience_rev, "version": g.version,
            "source_investigation_id": g.source_investigation_id, "methodology_version": g.methodology_version,
            "as_of": _aware(g.as_of).isoformat(), "input": g.input, "answers": g.answers,
            "manifest": g.manifest, "metadata": g.metadata_json,
            "author_id": g.author_id, "contributor_ids": sorted(g.contributor_ids)}


def _seal(g):
    g.content_sha256 = digest(_payload(g))


def _blob(s, content, kind):
    content = masked(content)
    raw = _bytes(content)
    if len(raw) > MAX_BLOB:
        raise ValueError("golden_snapshot_too_large")
    sha = digest(content)
    row = s.get(GoldenBlob, sha)
    if row is None:
        s.add(GoldenBlob(sha256=sha, content=content, size_bytes=len(raw)))
        s.flush()
    elif digest(row.content) != sha or row.size_bytes != len(raw):
        raise ValueError("golden_snapshot_corrupt")
    return {"sha256": sha, "kind": kind, "size_bytes": len(raw)}


def _capture(s, inv_id, c):
    capture = (c.context or {}).get("guidance")
    if not isinstance(capture, dict) or capture.get("schema_version") != 1 or not capture.get("temporally_valid"):
        raise ValueError("golden_temporal_snapshot_required")
    cutoff = _aware(capture.get("as_of"))
    if _aware(capture.get("known_at")) > cutoff or _aware(capture.get("captured_at")) > cutoff or cutoff > utcnow():
        raise ValueError("golden_capture_after_cutoff")
    methodology = capture.get("methodology") or {}
    if not methodology.get("version") or not methodology.get("digest"):
        raise ValueError("golden_methodology_required")
    scope = capture.get("scope") or {}
    for ev in scope.get("evidence_manifest", []):
        row = s.get(Evidence, ev.get("evidence_id"))
        if row is None or row.investigation_id != inv_id or _aware(row.uploaded_at) > cutoff:
            raise ValueError("golden_evidence_unavailable_at_cutoff")
        for item in ev.get("files", []):
            f = s.get(EvidenceFile, item.get("id"))
            if f is None or f.evidence_id != row.id or f.sha256 != item.get("sha256"):
                raise ValueError("golden_source_evidence_changed")
            processing = item.get("processing_run")
            if processing:
                run = s.get(ProcessingRun, processing.get("id"))
                if (run is None or run.file_id != f.id or run.input_sha256 != f.sha256
                        or run.run_digest != processing.get("run_digest") or _aware(run.finished_at) > cutoff):
                    raise ValueError("golden_processing_unavailable_at_cutoff")
    inp = capture.get("input") or {}
    # Only server-defined observations cross this boundary. No whole Check/Experience serialization.
    safe = {"schema": "saw.golden.observation.v1",
            "captured_at": capture["captured_at"], "known_at": capture["known_at"], "as_of": capture["as_of"],
            "methodology": {k: methodology[k] for k in ("id", "version", "digest") if k in methodology},
            "request": {k: v for k, v in scope.items() if k in SCOPE_KEYS},
            "source_manifest": deepcopy(scope.get("evidence_manifest", [])),
            "facts": [{k: v for k, v in row.items() if k in
                       {"id", "label", "value", "data_state", "query_ref", "evidence_refs"}} for row in inp.get("facts", [])],
            "unknowns": [{k: v for k, v in row.items() if k in {"source", "state", "reason"}}
                         for row in inp.get("unknowns", [])],
            "queries": [{k: v for k, v in row.items() if k in
                         {"id", "query", "executed_at", "data_state", "matched_count", "sampled_count", "limit", "truncated"}}
                        for row in inp.get("queries", [])], "limits": inp.get("limits", [])}
    for query in safe["queries"]:
        if query.get("executed_at") and _aware(query["executed_at"]) > cutoff:
            raise ValueError("golden_query_after_cutoff")
    events = capture.get("selected_events") or []
    refs = set(capture.get("evidence_refs") or [])
    if len(events) > MAX_EVENTS or {x.get("event_id") for x in events} != refs:
        raise ValueError("golden_selected_snapshot_missing")
    for item in events:
        if _aware(item.get("known_at")) > cutoff or digest(item.get("event")) != item.get("sha256"):
            raise ValueError("golden_selected_snapshot_corrupt")
    return capture, safe, events


def prepare(s: Session, p: Principal, eid: str, expected_experience_rev: int, check_ids=None):
    _lock_experience(s, eid)
    e = _experience(s, p, eid, True)
    if e.rev != expected_experience_rev:
        raise ValueError("golden_experience_changed")
    checks = list(s.scalars(select(Check).where(Check.investigation_id == e.source_investigation_id,
                                               Check.state == "active").order_by(Check.created_at)))
    if check_ids:
        checks = [c for c in checks if c.id in set(check_ids)]
        if len(checks) != len(set(check_ids)):
            raise ValueError("golden_check_outside_source")
    else:
        checks = [c for c in checks if (c.context or {}).get("guidance") or (c.scope or {}).get("behavior")]
    if not checks or len(checks) > 100:
        raise ValueError("golden_recorded_guidance_required")
    manifests, observations, contributors, methods, cutoffs = [], [], {e.analyst_id}, set(), []
    records, followups, required_facts, forbidden = [], [], [], []
    event_ids = set()
    pinned = {(r["check_id"], r["result_id"], r["result_sha256"])
              for r in (e.data or {}).get("behavior_results", [])}
    methodologies = []
    for c in checks:
        captures = []
        if (c.context or {}).get("guidance"):
            capture, safe, events = _capture(s, e.source_investigation_id, c)
            captures.append((safe, events, capture["methodology"], capture["as_of"], (c.scope or {}).get("guidance") or {}))
        if (c.scope or {}).get("behavior"):
            from saw.behavior.service import golden_capture
            meta = c.scope["behavior"]
            if (c.id, meta["result_id"], meta["result_sha256"]) not in pinned:
                raise ValueError("golden_behavior_not_in_experience_revision")
            result, safe, events = golden_capture(s, e.source_investigation_id, c)
            contributors.add(result.created_by)
            captures.append((safe, events, safe["methodology"], safe["captured_at"], meta))
        if not captures:
            raise ValueError("golden_temporal_snapshot_required")
        for safe, events, method, cutoff, meta in captures:
            row = _blob(s, safe, "observation")
            manifests.append(row)
            observations.append(row["sha256"])
            methods.add(method.get("version") or method["definitions_version"])
            methodologies.append(method)
            cutoffs.append(_aware(cutoff))
            for item in events:
                event = mask_event(item["event"])[0]
                projection = {k: v for k, v in event.items() if k in EVENT_KEYS}
                manifests.append(_blob(s, {"schema": "saw.golden.event.v1", "event": projection,
                                         "known_at": item["known_at"]}, "event"))
                event_ids.add(item["event_id"])
            follow = meta.get("follow_up")
            if follow:
                followups.extend(follow if isinstance(follow, list) else [follow])
            facts = safe.get("facts", safe.get("observations", {}).get("metrics", []))
            required_facts.extend({"text": f"{r.get('label', '')}: {r.get('value')}",
                                   "evidence_refs": [row["sha256"]]} for r in facts)
            forbidden.extend(meta.get("forbidden_claims") or [])
        contributors.add(c.author_id)
        records.append({"check_id": c.id, "questions": c.questions, "judgement": c.judgement, "note": c.note,
                        "evidence_refs": c.evidence, "recorded_at": c.created_at.isoformat()})
    if len(event_ids) > MAX_EVENTS or not methods:
        raise ValueError("golden_capture_limit_or_methodology_conflict")
    unique = {m["sha256"]: m for m in manifests}
    manifests = list(unique.values())
    if sum(m["size_bytes"] for m in manifests) > MAX_CASE:
        raise ValueError("golden_case_too_large")
    approved = e.data or {}
    # The Experience revision owns its closure snapshot. A later investigation
    # re-close must not inject another actor's judgement into this revision.
    answers = {"required_facts_actions": required_facts,
               "judgement": {"behavior": approved.get("final_verdict", "unknown"),
                             "impact": approved.get("impact_assessment") or "미확인",
                             "reason": approved.get("reason", ""), "evidence_refs": list(unique)},
               "followups": _meaningful_followups(followups), "no_followups_reason": "",
               "forbidden_claims": list(dict.fromkeys(forbidden or ["미확인 사항을 확인 완료로 단정하지 않는다."])),
               "limits": approved.get("limits") or [],
               "analyst_records": records}
    contributors |= _revision_contributors(s, e, e.rev)
    # Preparing an automatic projection adds no new interpretation.
    number = (s.scalar(select(func.max(GoldenVersion.version)).where(GoldenVersion.experience_id == eid)) or 0) + 1
    g = GoldenVersion(experience_id=eid, experience_rev=e.rev, version=number,
        source_investigation_id=e.source_investigation_id, status="draft", methodology_version=next(iter(methods)) if len(methods) == 1 else "saw.mixed-observations/1",
        as_of=max(cutoffs), input={"schema": "saw.golden.agent-input.v1", "observations": observations,
                                 "evidence": [m["sha256"] for m in manifests if m["kind"] == "event"],
                                 "retrieval": "snapshot_only"},
        answers=masked(answers), manifest=manifests, metadata_json=masked({
            "title": approved.get("title", ""), "category": approved.get("category", ""),
            "verdict": approved.get("final_verdict", "unknown"), "check_ids": [c.id for c in checks],
            "methodologies": list({digest(m): m for m in methodologies}.values())}),
        author_id=e.analyst_id, contributor_ids=sorted(contributors))
    _seal(g)
    s.add(g)
    s.flush()
    _log(s, p, "prepare", g, version=g.version, experience_rev=g.experience_rev, snapshots=len(manifests))
    return g


def _verify(s, g):
    if digest(_payload(g)) != g.content_sha256:
        raise ValueError("golden_version_corrupt")
    if not g.manifest or len(g.manifest) > MAX_EVENTS + 100:
        raise ValueError("golden_snapshot_missing")
    total = 0
    blobs = {}
    for item in g.manifest:
        b = s.get(GoldenBlob, item["sha256"])
        if b is None:
            raise ValueError("golden_snapshot_missing")
        raw = _bytes(b.content)
        if digest(b.content) != b.sha256 or len(raw) != b.size_bytes or b.size_bytes != item["size_bytes"]:
            raise ValueError("golden_snapshot_corrupt")
        if len(raw) > MAX_BLOB:
            raise ValueError("golden_snapshot_too_large")
        total += len(raw)
        blobs[b.sha256] = b.content
    if total > MAX_CASE:
        raise ValueError("golden_case_too_large")
    allowed = set(blobs)
    if not set(g.input.get("observations", []) + g.input.get("evidence", [])).issubset(allowed):
        raise ValueError("golden_input_snapshot_missing")
    for sha in g.input.get("observations", []):
        if blobs[sha].get("schema") == "saw.golden.behavior-observation.v1":
            from saw.behavior.service import verify_golden_reference
            verify_golden_reference(s, g.source_investigation_id, blobs[sha])
    return blobs


def edit(s, p, vid, expected_content_sha256, answers):
    old, e = _get(s, p, vid, True)
    _lock_experience(s, e.id)
    s.refresh(old)
    if expected_content_sha256 != old.content_sha256:
        raise ValueError("golden_version_changed")
    _verify(s, old)
    if e.rev != old.experience_rev:
        raise ValueError("golden_experience_changed_prepare_required")
    clean = _answers(answers)
    # Every edit is a new draft; both an approved record and earlier drafts remain reviewable.
    number = (s.scalar(select(func.max(GoldenVersion.version)).where(GoldenVersion.experience_id == e.id)) or 0) + 1
    g = GoldenVersion(experience_id=e.id, experience_rev=e.rev, version=number,
        source_investigation_id=old.source_investigation_id, status="draft",
        methodology_version=old.methodology_version, as_of=old.as_of, input=deepcopy(old.input),
        answers=clean, manifest=deepcopy(old.manifest), metadata_json=deepcopy(old.metadata_json),
        author_id=old.author_id, contributor_ids=sorted(set(old.contributor_ids) | {p.user_id}))
    _seal(g)
    s.add(g)
    s.flush()
    _log(s, p, "edit", g, previous=old.id, version=g.version)
    return g


def _meaningful_followups(values):
    def text(value):
        return isinstance(value, str) and bool(value.strip())

    def meaningful(item):
        if isinstance(item, str):
            return text(item)
        if not isinstance(item, dict) or not text(item.get("target")):
            return False
        return any(isinstance(item.get(key), list) and any(text(value) for value in item[key])
                   for key in ("needed_data", "items"))

    # An untouched FollowUp has a nonempty priority but contains no work.
    return [item for item in values if meaningful(item)]


def _answers(value):
    if not isinstance(value, dict) or set(value) - ANSWER_KEYS:
        raise ValueError("golden_invalid_answers")
    out = masked(deepcopy(value))
    if not isinstance(out.get("required_facts_actions"), list) or not isinstance(out.get("judgement"), dict):
        raise ValueError("golden_invalid_answers")
    if not isinstance(out.get("followups"), list) or not isinstance(out.get("forbidden_claims"), list):
        raise ValueError("golden_invalid_answers")
    out["followups"] = _meaningful_followups(out["followups"])
    if len(_bytes(out)) > MAX_BLOB:
        raise ValueError("golden_answers_too_large")
    return out


def _component(s, inv_id):
    # Existing Case links plus retained memberships form a transitive event family.
    by_case = {c.id: set(c.investigation_ids or []) for c in s.scalars(select(Case))}
    sources = {"finding": Finding, "evidence": Evidence, "story_snapshot": AttackStory, "note": Note}
    for item in s.scalars(select(CaseItem)):
        group = by_case.setdefault(item.case_id, set())
        snap = item.snapshot or {}
        if snap.get("investigation_id"):
            group.add(snap["investigation_id"])
        model = sources.get(item.item_type)
        source = s.get(model, item.ref_id) if model else None
        if source is not None:
            group.add(source.investigation_id)
    groups = list(by_case.values())
    members = list(s.scalars(select(GoldenFamilyMember)))
    for family_id in {m.family_id for m in members}:
        groups.append({m.investigation_id for m in members if m.family_id == family_id})
    found = {inv_id}
    while True:
        more = set().union(*(g for g in groups if g & found)) if groups else set()
        if more <= found:
            break
        found |= more
    family_ids = {m.family_id for m in members if m.investigation_id in found}
    families = list(s.scalars(select(GoldenFamily).where(GoldenFamily.id.in_(family_ids)))) if family_ids else []
    if len({f.split for f in families}) > 1:
        raise ValueError("golden_family_split_conflict")
    return found, families


def _family(s, p, inv_id, split, assign=False):
    if split not in SPLITS:
        raise ValueError("golden_invalid_split")
    found, _ = _component(s, inv_id)
    if assign:
        # Stable ordered source locks serialize two adoptions of the same connected case.
        for iid in sorted(found):
            s.execute(update(Investigation).where(Investigation.id == iid).values(status=Investigation.status)
                      .execution_options(synchronize_session=False))
        s.expire_all()
    found, families = _component(s, inv_id)
    if any(f.split != split for f in families):
        raise ValueError("golden_family_split_conflict")
    if not assign:
        return found, families
    f = min(families, key=lambda x: x.id) if families else GoldenFamily(split=split, created_by=p.user_id)
    if not families:
        s.add(f)
        s.flush()
    for iid in sorted(found):
        member = s.get(GoldenFamilyMember, iid)
        if member is None:
            s.add(GoldenFamilyMember(investigation_id=iid, family_id=f.id))
        else:
            member.family_id = f.id
    s.flush()
    return f


def review(s, p, vid, expected_content_sha256, decision, split, confirmations, review_answers=None):
    g, e = _get(s, p, vid)
    _lock_experience(s, e.id)
    s.refresh(g)
    if not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    if p.user_id == g.author_id or p.user_id in g.contributor_ids or p.username in experience._contributors(s, e):
        raise Forbidden("golden reviewer must differ from all contributors (4-eyes)")
    if expected_content_sha256 != g.content_sha256 or g.status != "draft":
        raise ValueError("golden_version_changed")
    if e.deprecated or not e.approved_data or e.approved_rev != g.experience_rev:
        raise ValueError("golden_exact_approved_experience_required")
    if e.expires_at and _aware(e.expires_at) <= utcnow():
        raise ValueError("golden_experience_expired")
    if decision == "decline":
        g.status = "declined"
    elif decision == "adopt":
        if set(confirmations) != CONFIRMATIONS or any(confirmations[k] is not True for k in CONFIRMATIONS):
            raise ValueError("golden_four_review_confirmations_required")
        _verify(s, g)
        if review_answers is not None:
            # Reviewer findings are recorded as review work, not changes to the frozen input/analyst record.
            answer = _answers({**g.answers, **review_answers})
            if any(answer.get(key) != g.answers.get(key) for key in ("judgement", "analyst_records", "limits")):
                raise ValueError("golden_judgement_edit_requires_new_draft_and_other_reviewer")
            g.answers = answer
        answers = _answers(g.answers)
        if not answers["required_facts_actions"] or not answers["forbidden_claims"] or not answers["judgement"].get("reason"):
            raise ValueError("golden_review_content_required")
        no_followups_reason = answers.get("no_followups_reason")
        if not answers["followups"] and not (isinstance(no_followups_reason, str) and no_followups_reason.strip()):
            raise ValueError("golden_followups_or_reviewed_reason_required")
        for item in answers["required_facts_actions"] + [answers["judgement"]]:
            if not isinstance(item, dict) or not set(item.get("evidence_refs", [])).issubset({m["sha256"] for m in g.manifest}):
                raise ValueError("golden_answer_evidence_missing")
        g.answers = answers
        f = _family(s, p, g.source_investigation_id, split, assign=True)
        g.family_id, g.status = f.id, "adopted"
        g.confirmations = dict(confirmations)
        _seal(g)
    else:
        raise ValueError("golden_invalid_decision")
    g.reviewer_id, g.reviewer_name, g.reviewed_at = p.user_id, p.username, utcnow()
    _log(s, p, decision, g, version=g.version, experience_rev=g.experience_rev, split=split)
    return g


def to_dict(s, p, g, full=False):
    _experience(s, p, g.experience_id)
    f = s.get(GoldenFamily, g.family_id) if g.family_id else None
    d = {"id": g.id, "experience_id": g.experience_id, "experience_rev": g.experience_rev, "version": g.version,
         "status": g.status, "methodology_version": g.methodology_version, "as_of": g.as_of,
         "source_investigation_id": g.source_investigation_id, "family_id": g.family_id,
         "split": f.split if f else None, "content_sha256": g.content_sha256,
         "reviewer": g.reviewer_name, "reviewed_at": g.reviewed_at, "created_at": g.created_at,
         **{k: g.metadata_json.get(k) for k in ("title", "category", "verdict")},
         "can_edit": p.user_id == g.author_id or can(p, "knowledge.approve"),
         "can_review": can(p, "knowledge.approve") and p.user_id not in g.contributor_ids and p.user_id != g.author_id}
    d["evaluable"], d["evaluation_blocker"] = False, "golden_adopted_version_required"
    if g.status == "adopted":
        try:
            _exportable(s, p, g.id, f.split if f else "", False, retain_family=False)
            d["evaluable"], d["evaluation_blocker"] = True, None
        except (ValueError, Forbidden, NotFound) as exc:
            d["evaluation_blocker"] = str(exc)
    if full:
        d.update(input=g.input, answers=g.answers, manifest=g.manifest, confirmations=g.confirmations)
    return d


def for_experience(s, p, eid):
    e = _experience(s, p, eid)
    if e.analyst_id != p.user_id and not can(p, "knowledge.approve"):
        raise Forbidden("golden review details require author or reviewer")
    rows = list(s.scalars(select(GoldenVersion).where(GoldenVersion.experience_id == eid)
                          .order_by(GoldenVersion.version.desc())))
    return {"experience_id": eid, "versions": [to_dict(s, p, g, True) for g in rows]}


def list_for(s, p, **filters):
    if not can(p, "knowledge.read"):
        raise Forbidden("knowledge.read")
    out = []
    for g in s.scalars(select(GoldenVersion).order_by(GoldenVersion.created_at.desc())):
        if not can(p, "investigation.read", access_of(s, p, g.source_investigation_id)):
            continue
        inv = s.get(Investigation, g.source_investigation_id)
        if inv is None or (inv.settings or {}).get("data_deletion"):
            continue
        if g.status != "adopted" and p.user_id != g.author_id and not can(p, "knowledge.approve"):
            continue
        try:
            row = to_dict(s, p, g)
        except (Forbidden, NotFound):
            continue
        if any(value and (str(value).lower() not in str(row.get("title", "")).lower() if key == "q"
                         else row.get(key) != value) for key, value in filters.items()):
            continue
        out.append(row)
    return out[:500]


def _exportable(s, p, vid, split, evaluator, *, retain_family=True):
    g, e = _get(s, p, vid)
    if evaluator and not can(p, "knowledge.approve"):
        raise Forbidden("knowledge.approve")
    if g.status != "adopted" or not g.reviewer_id or g.reviewer_id in g.contributor_ids:
        raise ValueError("golden_adopted_version_required")
    reviewer = s.get(User, g.reviewer_id)
    if reviewer is None or reviewer.status != "active" or not can(principal_of(reviewer), "knowledge.approve"):
        raise ValueError("golden_reviewer_no_longer_authorized")
    if e.deprecated or (e.expires_at and _aware(e.expires_at) <= utcnow()):
        raise ValueError("golden_experience_expired_or_deprecated")
    # Later drafts do not erase the exact previously approved revision.
    approved = s.scalar(select(KnowledgeRevision.id).where(KnowledgeRevision.kind == "experience",
        KnowledgeRevision.ref_id == e.id, KnowledgeRevision.rev == g.experience_rev, KnowledgeRevision.status == "approved"))
    if not approved:
        raise ValueError("golden_exact_approved_experience_required")
    family = s.get(GoldenFamily, g.family_id)
    if family is None or family.split != split:
        raise ValueError("golden_family_split_conflict")
    _family(s, p, g.source_investigation_id, split, assign=retain_family)
    return g, _verify(s, g)


def agent_input(g, blobs):
    # No database lookup, search, closure, Note, Experience, or optional live retrieval exists here.
    return {"schema": "saw.golden.agent-input.v1", "example_id": g.id, "version": g.version,
            "methodology_version": g.methodology_version, "as_of": _aware(g.as_of).isoformat(),
            "retrieval": "snapshot_only",
            "observations": [blobs[sha] for sha in g.input["observations"]],
            "evidence": [{"sha256": sha, "path": f"evidence/{sha}.json"} for sha in g.input["evidence"]]}


def export(s, p, version_ids, split, format, audience):
    if not version_ids or len(version_ids) > 100 or len(set(version_ids)) != len(version_ids):
        raise ValueError("golden_export_limit")
    if split not in SPLITS or format not in {"csv", "jsonl", "bundle"} or audience not in {"agent", "evaluator"}:
        raise ValueError("golden_invalid_export")
    if (format == "csv" and audience != "evaluator") or (format == "bundle" and audience != "agent"):
        raise ValueError("golden_export_audience_mismatch")
    rows, all_blobs = [], {}
    for vid in version_ids:
        g, blobs = _exportable(s, p, vid, split, audience == "evaluator")
        rows.append(g)
        all_blobs.update(blobs)
    if sum(len(_bytes(b)) for b in all_blobs.values()) > MAX_EXPORT:
        raise ValueError("golden_export_too_large")
    if format == "csv":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        fields = ["id", "title", "category", "verdict", "status", "reviewer", "methodology_version", "split", "version"]
        writer.writerow(fields)
        for g in rows:
            row = to_dict(s, p, g)
            writer.writerow([csv_safe(row.get(k)) for k in fields])
        data, media, filename = stream.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", "golden-list.csv"
    else:
        items = [agent_input(g, all_blobs) if audience == "agent" else {
            "schema": "saw.golden.evaluator-answer.v1", "example_id": g.id, "version": g.version,
            "family_id": g.family_id, "split": split, "answers": g.answers,
            "reviewer": g.reviewer_name, "reviewed_at": _aware(g.reviewed_at).isoformat(),
            "content_sha256": g.content_sha256} for g in rows]
        data = ("\n".join(json.dumps(x, ensure_ascii=False, sort_keys=True) for x in items) + "\n").encode("utf-8")
        media, filename = "application/x-ndjson", "agent-input.jsonl" if audience == "agent" else "evaluator-answer.jsonl"
        if format == "bundle":
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("agent-input.jsonl", data)
                evidence = {sha for g in rows for sha in g.input["evidence"]}
                for sha in sorted(evidence):
                    z.writestr(f"evidence/{sha}.json", _bytes(all_blobs[sha]))
                z.writestr("manifest.json", _bytes({"schema": "saw.golden.bundle.v1", "audience": "agent",
                    "retrieval": "snapshot_only", "examples": [g.id for g in rows],
                    "evidence": [{"sha256": sha, "size_bytes": len(_bytes(all_blobs[sha]))} for sha in sorted(evidence)]}))
            data, media, filename = out.getvalue(), "application/zip", "golden-agent-evidence.zip"
    if len(data) > MAX_EXPORT:
        raise ValueError("golden_export_too_large")
    _log(s, p, "export", version_ids=version_ids, split=split, format=format, audience=audience,
         bytes=len(data), sha256=__import__("hashlib").sha256(data).hexdigest())
    return data, media, filename
