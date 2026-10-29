"""Server-created exact source pins for newly captured Experience revisions."""
from __future__ import annotations
from copy import deepcopy
from fastapi import HTTPException
from sqlalchemy import select
from saw.analysis_runs import service as runs
from saw.analysis_runs.models import AnalysisRun
from saw.core.application.provenance import digest
from saw.detection.derived_access import source_ids
from saw.followups import check_revisions as checks
from saw.followups.models import CheckRevision, FollowUp, FollowUpVersion
from saw.storage.db import utcnow
from saw.storage.models import Check


def run_matches_check(run, payload):
    """Require a provable exact source/selector/time relation in the frozen Check capture."""
    from saw.core.schemas.query import Filter
    from saw.knowledge.golden import _aware
    capture = (payload.get("context") or {}).get("guidance") or {}
    scope = capture.get("scope") or {}
    if (payload.get("investigation_id") != run.investigation_id or run.finished_at is None
            or run.status != "complete" or not scope or not capture.get("captured_at")):
        return False
    if scope.get("investigation_id", run.investigation_id) != run.investigation_id:
        return False
    try:
        if _aware(run.finished_at) > min(_aware(capture["captured_at"]), _aware(capture["as_of"])):
            return False
        filters = list(scope.get("filters") or [])
        target = scope.get("target_type")
        if target == "entity":
            if (payload.get("target_type") != "entity" or payload.get("target_key") != scope.get("target_key")
                    or scope.get("role") not in {"src", "dst"} or not scope.get("target_key", "").startswith("ip:")):
                return False
            filters.append({"field": scope["role"] + "_ip", "op": "is", "value": scope["target_key"][3:]})
        elif target == "investigation":
            if scope.get("target_key") != run.investigation_id or payload.get("target_type") != "set":
                return False
        else:
            return False
        run_scope = run.scope or {}
        if set(run_scope) - {"filters", "time", "org_unit_id", "device_id", "detector_id"}:
            return False
        run_filters = list(run_scope.get("filters") or [])
        for name in ("org_unit_id", "device_id"):
            if run_scope.get(name):
                run_filters.append({"field": "ext.observation.context." + name, "op": "is", "value": run_scope[name]})
        def normalized(values):
            return sorted({digest(Filter.model_validate(item).model_dump()) for item in values})
        def window(value):
            value = value or {}
            return {key: _aware(value[key]).isoformat() if value.get(key) else None for key in ("start", "end")}
        return (normalized(filters) == normalized(run_filters)
                and window(scope.get("effective_time", scope.get("time"))) == window(run_scope.get("time")))
    except (KeyError, TypeError, ValueError):
        return False


def capture(s, p, investigation_id, data):
    ids = data.get("check_ids") or []
    if not isinstance(ids, list) or len(ids) > 100 or len(set(ids)) != len(ids):
        raise ValueError("golden_check_selection_limit")
    rows = list(s.scalars(select(Check).where(Check.investigation_id == investigation_id,
        Check.id.in_(ids)).order_by(Check.id)))
    if {c.id for c in rows} != set(ids):
        raise ValueError("golden_check_outside_source")
    run_rows = list(s.scalars(select(AnalysisRun).where(AnalysisRun.investigation_id == investigation_id,
        AnalysisRun.finished_at.is_not(None)).order_by(AnalysisRun.created_at.desc()).limit(101)))
    if len(run_rows) > 100:
        raise HTTPException(413, "golden_experience_run_limit")
    run_rows = [run for run in run_rows if any(run_matches_check(run, checks._payload(c)) for c in rows)]
    followups = list(s.scalars(select(FollowUp).where(FollowUp.investigation_id == investigation_id).limit(101)))
    if len(followups) > 100:
        raise HTTPException(413, "golden_experience_followup_limit")
    sources, contributors = {investigation_id}, {p.user_id}
    for c in rows:
        sources |= checks.collect_check_sources(s, c)
    for run in run_rows:
        sources |= source_ids([run.input_manifest, run.scope, run.summary]) | runs._derived_sources(s, run)
    selected_fu = []
    for fu in followups:
        v = s.get(FollowUpVersion, fu.current_version_id)
        if v is not None and (v.payload.get("check_ref") or {}).get("check_id") in ids:
            if digest(v.payload) != v.payload_sha256:
                raise HTTPException(409, "golden_followup_corrupt")
            selected_fu.append(v)
            sources |= set(v.source_investigation_ids)
    checks.authorize(s, p, sources)
    prior = s.info.get("snapshot_source_ids")
    if prior is not None and not sources <= set(prior):
        raise HTTPException(409, "golden_source_scope_changed")
    s.info["snapshot_source_ids"] = sources
    try:
        refs = []
        for c in rows:
            revision = checks.capture_check(s, p, c, reason="experience_closure")
            refs.append({k: v for k, v in checks.check_revision_dict(revision).items()
                         if k in {"check_id", "revision_id", "revision", "payload_sha256"}})
            contributors.add(c.author_id)
            contributors.add(revision.created_by)
            source_ref = revision.payload.get("source_check_revision")
            while source_ref:
                r = s.get(CheckRevision, source_ref["revision_id"])
                if r is None:
                    raise HTTPException(409, "golden_check_reference_missing")
                contributors.update([r.created_by, r.payload.get("author_id")])
                source_ref = r.payload.get("source_check_revision")
        fu_refs = []
        for v in selected_fu:
            fu_refs.append({"followup_id": v.followup_id, "version_id": v.id,
                "revision": v.revision, "payload_sha256": v.payload_sha256})
            contributors.update(s.scalars(select(FollowUpVersion.created_by).where(
                FollowUpVersion.followup_id == v.followup_id, FollowUpVersion.revision <= v.revision)))
        run_refs = []
        for run in run_rows:
            runs.get(s, p, investigation_id, run.id)
            run_refs.append({"id": run.id, "sha256": run.input_sha256, "scope_sha256": digest(run.scope)})
            contributors.add(run.created_by)
        return {"schema": "saw.experience.golden-capture.v1", "captured_at": utcnow().isoformat(),
            "check_revisions": refs, "followup_versions": fu_refs, "analysis_runs": run_refs,
            "source_investigation_ids": sorted(sources), "contributor_ids": sorted(x for x in contributors if x)}
    finally:
        if prior is None:
            s.info.pop("snapshot_source_ids", None)
        else:
            s.info["snapshot_source_ids"] = prior


def selected_checks(s, p, e, check_ids=None, check_revision_ids=None):
    pins = (e.data or {}).get("golden_capture")
    if not isinstance(pins, dict) or pins.get("schema") != "saw.experience.golden-capture.v1":
        raise HTTPException(409, "golden_historic_pin_missing")
    refs = pins["check_revisions"]
    if check_ids is not None:
        refs = [r for r in refs if r["check_id"] in check_ids]
        if {r["check_id"] for r in refs} != set(check_ids):
            raise HTTPException(409, "golden_check_not_in_experience")
    if check_revision_ids is not None:
        refs = [r for r in refs if r["revision_id"] in check_revision_ids]
        if {r["revision_id"] for r in refs} != set(check_revision_ids):
            raise HTTPException(409, "golden_revision_not_in_experience")
    checks.authorize(s, p, set(pins["source_investigation_ids"]))
    if not refs:
        raise ValueError("golden_recorded_guidance_required")
    out = []
    for ref in refs:
        revision = checks.get_check_revision(s, p, e.source_investigation_id, ref["revision_id"])
        if revision.payload_sha256 != ref["payload_sha256"] or revision.revision != ref["revision"]:
            raise HTTPException(409, "golden_check_reference_changed")
        current = s.get(Check, ref["check_id"], populate_existing=True)
        if current is None:
            raise HTTPException(409, "golden_check_changed")
        actual = checks._payload(current)
        expected = {k: v for k, v in revision.payload.items()
            if k not in {"evaluated_at", "expired_at_capture", "source_investigation_ids", "source_check_revision"}}
        if actual != expected:
            raise HTTPException(409, "golden_check_changed")
        out.append(revision)
    return pins, out


def incident_groups(s):
    """Incident edges use actual citations/evidence, never generic policy ACL dependencies."""
    from saw.storage.models import Evidence, EvidenceFile
    from saw.detection.truth_models import DetectionCaseVersion
    groups = []
    by_check = {c.id: c for c in s.scalars(select(Check))}
    for check in by_check.values():
        if check.kind == "cited" and check.source_check_id in by_check:
            groups.append({check.investigation_id, by_check[check.source_check_id].investigation_id})
        events = ((check.context or {}).get("guidance") or {}).get("selected_events", [])
        for captured in events:
            iid = (captured.get("event") or {}).get("investigation_id")
            if iid:
                groups.append({check.investigation_id, iid})
    for row in s.scalars(select(CheckRevision)):
        ref = row.payload.get("source_check_revision")
        cited = s.get(CheckRevision, ref.get("revision_id")) if ref else None
        if cited is not None:
            groups.append({row.investigation_id, cited.investigation_id})
        for captured in (row.payload.get("context", {}).get("guidance") or {}).get("selected_events", []):
            iid = (captured.get("event") or {}).get("investigation_id")
            if iid:
                groups.append({row.investigation_id, iid})
    for row in s.scalars(select(FollowUpVersion)):
        fu = s.get(FollowUp, row.followup_id)
        if fu is None:
            continue
        for field in ("reply", "verification"):
            for ref in (row.payload.get(field) or {}).get("evidence", []):
                if ref.get("investigation_id"):
                    groups.append({fu.investigation_id, ref["investigation_id"]})
    by_bytes = {}
    for file, iid in s.execute(select(EvidenceFile, Evidence.investigation_id).join(
            Evidence, Evidence.id == EvidenceFile.evidence_id)):
        if file.sha256 and len(file.sha256) == 64:
            by_bytes.setdefault(file.sha256, set()).add(iid)
    groups.extend(by_bytes.values())
    by_truth = {}
    for row in s.scalars(select(DetectionCaseVersion)):
        if row.input_count > 0 and row.input_sha256:
            by_truth.setdefault(row.input_sha256, set()).add(row.investigation_id)
    groups.extend(by_truth.values())
    return groups
