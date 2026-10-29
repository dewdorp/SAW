"""V2 extends newly captured Golden graphs without resealing historic v1 rows."""
from __future__ import annotations
from copy import deepcopy
from fastapi import HTTPException
from sqlalchemy import select
from saw.core.application.provenance import digest, canonical
from saw.core.application.investigations import require
from saw.detection.derived_access import source_ids
from saw.detection.truth_models import DetectionCaseVersion
from saw.knowledge import golden_context
from saw.knowledge.golden_profiles import actor
from saw.storage.db import utcnow


def is_v2(g):
    return (g.input or {}).get("schema") == "saw.golden.agent-input.v2"


def sources(g):
    return {g.source_investigation_id, *g.metadata_json.get("source_investigation_ids", [])}


def input_digest(g, blobs):
    from saw.knowledge.golden_projection import input_graph_sha256
    return input_graph_sha256(g.input, blobs)


# Immutable selected_truth_v1 semantics implemented by saw.detection.testing.
# A future semantic change adds a new contract version instead of editing this definition.
MATCHING_V1 = {
    "version": "selected_truth_v1",
    "selectors": {
        "source": "exact_case_investigation",
        "filters": "case_and_unit_and_org_unit_and_device",
        "event_ids": "intersection_with_case_and_unit_selectors",
        "time": "case_unit_intersection_start_inclusive_end_exclusive",
        "empty_or_missing_required_members": "insufficient_data",
    },
    "engines": {
        "sigma": {"supported_units": ["event", "window", "entity"], "sequence": "unsupported_unit",
            "prediction": "any_unit_member_matches_after_case_threshold",
            "unknown_required_fields": "insufficient_data",
            "threshold_with_unknown_case_members": "insufficient_data",
            "exclusions": "rule_or_policy", "disabled": "no_match_when_input_known"},
        "signature": {"supported_units": ["event", "window", "entity"], "sequence": "unsupported_unit",
            "prediction": "any_matching_unit_member_after_signature_success_gate",
            "unknown_required_fields": "insufficient_data",
            "exclusions": "policy", "disabled": "no_match_when_input_known"},
        "device_policy": {"supported_units": ["window"], "explicit_event_ids": "unsupported_unit",
            "prediction": "complete_nonempty_window_has_candidate",
            "candidate_event_refs": "representative_not_membership",
            "exclusions": "policy_before_engine", "disabled": "count_complete_input_then_no_match"},
    },
    "duplicate_policy": {"key": ["case_version_id", "unit_id"], "selected_duplicates": "rejected",
        "unit_event_ids": "unique", "membership": "set", "overlapping_units": "scored_independently"},
    "scoring": {"axis": "detection_truth", "positive": "expected_match", "negative": "expected_no_match",
        "unlabeled": "counted_but_not_scored", "investigation_truth": "never_changes_detection_label",
        "eligible": "complete_and_prediction_not_null",
        "unsupported_partial_failed_insufficient": "excluded_never_true_negative",
        "zero_denominator": "null"},
}


def matching_policy(truths):
    if not truths:
        return {}
    return {"schema": "saw.detection.selected-truth-matching.v1", "method": "selected_truth_v1",
        "definition": deepcopy(MATCHING_V1), "definition_sha256": digest(MATCHING_V1),
        "case_scopes": [{"case_version_id": row.id, "scope": {
            key: deepcopy(row.payload.get(key, [] if key == "filters" else None))
            for key in ("investigation_id", "filters", "time", "org_unit_id", "device_id")}}
            for row in truths]}


def verify_matching_policy(s, truth):
    rows = []
    for ref in truth.get("case_versions", []):
        row = s.get(DetectionCaseVersion, ref["id"], populate_existing=True)
        if row is None or row.sha256 != ref["sha256"] or digest(row.payload) != row.sha256:
            raise HTTPException(409, "golden_truth_case_changed")
        rows.append(row)
    if (truth.get("matching_policy") != matching_policy(rows)
            or truth.get("duplicate_policy") != "exact_case_version_unit_id"):
        raise HTTPException(409, "golden_matching_policy_changed_or_unsupported")


def prepare(s, p, eid, expected_experience_rev, check_ids=None, check_revision_ids=None,
            analysis_run_id=None, truth_case_version_ids=None):
    from saw.knowledge import golden
    from saw.knowledge.golden_projection import project_event_v2
    from saw.analysis_runs import service as runs
    from saw.analysis_runs.models import AnalysisRun
    from saw.followups.models import FollowUpVersion
    p = actor(s, p, "knowledge.write")
    e = golden._experience(s, p, eid, True)
    if e.rev != expected_experience_rev:
        raise HTTPException(409, "golden_experience_changed")
    pins, revisions = golden_context.selected_checks(s, p, e, check_ids, check_revision_ids)
    truths = []
    all_sources = set(pins["source_investigation_ids"])
    for tid in truth_case_version_ids or []:
        row = s.get(DetectionCaseVersion, tid)
        if row is None:
            raise ValueError("golden_truth_case_missing")
        require(s, p, "investigation.read", row.investigation_id)
        if row.investigation_id != e.source_investigation_id:
            raise ValueError("golden_truth_case_outside_source")
        if digest(row.payload) != row.sha256:
            raise HTTPException(409, "golden_truth_case_changed")
        all_sources |= {row.investigation_id} | source_ids([row.payload, row.source_manifest])
        truths.append(row)
    for iid in sorted(all_sources):
        require(s, p, "investigation.read", iid)
    run = None
    if analysis_run_id:
        ref = next((r for r in pins["analysis_runs"] if r["id"] == analysis_run_id), None)
        if ref is None:
            raise HTTPException(409, "golden_analysis_run_not_in_experience")
        run = runs.get(s, p, e.source_investigation_id, analysis_run_id)
        if run.finished_at is None or run.input_sha256 != ref["sha256"] or digest(run.scope) != ref["scope_sha256"]:
            raise HTTPException(409, "golden_analysis_run_changed")
        if not all(golden_context.run_matches_check(run, revision.payload) for revision in revisions):
            raise HTTPException(409, "golden_analysis_run_scope_mismatch")
    g = golden._prepare_v1(s, p, eid, expected_experience_rev, [r.check_id for r in revisions])
    observations = [m for m in g.manifest if m["kind"] != "event"]
    event_manifests, contexts = [], []
    cutoff = golden._aware(g.as_of)
    for revision in revisions:
        capture = revision.payload.get("context", {}).get("guidance") or {}
        for item in capture.get("selected_events") or []:
            event = project_event_v2(item["event"])
            event_manifests.append(golden._blob(s, {"schema": "saw.golden.event.v2",
                "event": event, "known_at": item["known_at"]}, "event"))
            context = ((event.get("ext") or {}).get("observation") or {}).get("context") or {}
            contexts.append(context)
    # Behavior events originate from the same frozen behavior result capture.
    for revision in revisions:
        if revision.payload.get("scope", {}).get("behavior"):
            from saw.behavior.service import golden_capture
            from saw.storage.models import Check
            _, _, events = golden_capture(s, e.source_investigation_id, s.get(Check, revision.check_id))
            for item in events:
                event_manifests.append(golden._blob(s, {"schema": "saw.golden.event.v2",
                    "event": project_event_v2(item["event"]), "known_at": item["known_at"]}, "event"))
    g.manifest = list({m["sha256"]: m for m in observations + event_manifests}.values())
    if sum(m["size_bytes"] for m in g.manifest) > golden.MAX_CASE:
        raise HTTPException(413, "golden_case_too_large")
    if run is not None and golden._aware(run.finished_at) > cutoff:
        raise HTTPException(409, "golden_analysis_unavailable_at_cutoff")
    run_data = runs.run_dict(s, run) if run else {}
    manifests = run.input_manifest if run else {}
    methods = g.metadata_json.get("methodologies", [])
    rule_refs = []
    runtime = manifests.get("runtime_pin") or {}
    for kind in ("devices", "signatures", "rules"):
        for entry in runtime.get(kind, []):
            for layer in (entry.get("policy") or {}).get("layers", []):
                if layer.get("version_id") and layer.get("payload_sha256"):
                    rule_refs.append({"id": layer["version_id"], "sha256": layer["payload_sha256"]})
            for id_key, sha_key in (("version_id", "payload_sha256"), ("rule_version_id", "rule_sha256")):
                if entry.get(id_key) and entry.get(sha_key):
                    rule_refs.append({"id": entry[id_key], "sha256": entry[sha_key]})
    rule_refs = list({(x["id"], x["sha256"]): x for x in rule_refs}.values())
    g.input = {"schema": "saw.golden.agent-input.v2", "retrieval": "snapshot_only",
        "observations": [m["sha256"] for m in observations], "evidence": [m["sha256"] for m in event_manifests],
        "context": {"org_units": sorted({x["org_unit_id"] for x in contexts if x.get("org_unit_id")}),
            "devices": sorted({x["device_id"] for x in contexts if x.get("device_id")}),
            "networks": sorted({x["network"] for x in contexts if x.get("network")}),
            "identity_scope": "org_network", "data_meanings": {"capture": "representative"}},
        "versions": {"analysis_run": {"id": run.id, "sha256": run.input_sha256} if run else None,
            "normalization": manifests.get("normalization_version"), "parsers": [],
            "methodology": [{"id": m.get("id", "methodology"), "sha256": m.get("digest", m.get("sha256"))}
                            for m in methods if m.get("digest", m.get("sha256"))],
            "engines": [{"id": x["detector_id"], "version": x["detector_version"]}
                        for x in run_data.get("executions", [])], "rule_policy_refs": rule_refs},
        "cutoff": {"as_of": cutoff.isoformat(), "known_at_basis": "recorded_capture",
                   "captured_at": max((golden._aware((r.payload.get("context", {}).get("guidance") or {}).get("captured_at", cutoff)) for r in revisions), default=cutoff).isoformat()},
        "applicability": {"mode": "interpretation_only", "reasons": ["representative_input"]},
        "limits": ["representative_input"] + ([] if run else ["analysis_version_not_captured"])}
    legacy = g.answers
    units = [{**deepcopy(unit), "case_version_id": row.id}
             for row in truths for unit in row.payload.get("units", [])]
    g.answers = {"schema": "saw.golden.answers.v2",
        "detection_truth": {"status": "available" if truths else "not_labeled",
            "case_versions": [{"id": t.id, "sha256": t.sha256} for t in truths], "units": units,
            "matching_policy": matching_policy(truths), "duplicate_policy": "exact_case_version_unit_id",
            "limits": [] if truths else ["matching_policy_not_captured"]},
        "investigation_truth": {"behavior": (e.data or {}).get("behavior_assessment") or legacy["judgement"]["behavior"],
            "impact": legacy["judgement"]["impact"], "reason": legacy["judgement"]["reason"],
            "evidence_refs": [m["sha256"] for m in g.manifest],
            "required_facts_actions": legacy["required_facts_actions"],
            "followups": legacy["followups"], "no_followups_reason": legacy.get("no_followups_reason", ""),
            "forbidden_claims": legacy["forbidden_claims"], "limits": legacy["limits"]},
        "later_confirmed_facts": [],
        "analyst_records": [{"check_id": r.check_id, "revision_id": r.id, "revision": r.revision,
                             "payload_sha256": r.payload_sha256} for r in revisions]}
    people = set(g.contributor_ids) | set(pins["contributor_ids"])
    for t in truths:
        people |= {t.created_by, *t.contributor_ids}
    for ref in pins["followup_versions"]:
        v = s.get(FollowUpVersion, ref["version_id"])
        if v is None or v.payload_sha256 != ref["payload_sha256"] or digest(v.payload) != v.payload_sha256:
            raise HTTPException(409, "golden_followup_reference_changed")
        g.answers["investigation_truth"]["followups"].append({**deepcopy(ref), "payload": deepcopy(v.payload)})
        # Later facts carry actual verified evidence and are never added to the input graph.
        verification = v.payload.get("verification") or {}
        if (verification.get("outcome") == "confirmed" and verification.get("verified_at")
                and verification.get("basis") and verification.get("evidence")):
            from saw import container
            when = verification["verified_at"]
            golden._aware(when)
            evidence_refs = []
            for evidence in verification["evidence"]:
                event = container.get().events.get(evidence["investigation_id"], evidence["event_id"])
                if event is None or digest(event) != evidence["sha256"]:
                    raise HTTPException(409, "golden_followup_evidence_changed")
                if evidence["investigation_id"] not in all_sources:
                    raise HTTPException(409, "golden_source_scope_changed")
                item = golden._blob(s, {"schema": "saw.golden.event.v2",
                    "event": project_event_v2(event), "known_at": when}, "answer_evidence")
                g.manifest = list({m["sha256"]: m for m in g.manifest + [item]}.values())
                evidence_refs.append(item["sha256"])
            g.answers["later_confirmed_facts"].append({"fact": verification["basis"], "evidence_refs": evidence_refs,
                "confirmed_at": when, "known_at": when})
    g.contributor_ids = sorted(people)
    g.metadata_json = {**g.metadata_json, "schema_version": "saw.golden.v2",
        "source_investigation_ids": sorted(all_sources), "golden_capture": deepcopy(pins),
        "truth_case_version_ids": [t.id for t in truths],
        "analysis_run_id": run.id if run else None}
    golden._seal(g)
    golden._verify(s, g)
    return g


def answers(value, old=None):
    from saw.knowledge import golden
    required = {"schema", "detection_truth", "investigation_truth", "later_confirmed_facts", "analyst_records"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != "saw.golden.answers.v2":
        raise ValueError("golden_invalid_answers_v2")
    if old is not None and any(value[k] != old[k] for k in
            ("detection_truth", "later_confirmed_facts", "analyst_records")):
        raise ValueError("golden_exact_truth_references_immutable")
    inv = value["investigation_truth"]
    if old is not None:
        def pinned(items):
            return [x for x in items if isinstance(x, dict) and "version_id" in x]
        if pinned(inv.get("followups", [])) != pinned(old["investigation_truth"]["followups"]):
            raise ValueError("golden_exact_followup_references_immutable")
    if not isinstance(inv, dict) or set(inv) != {"behavior", "impact", "reason", "evidence_refs",
            "required_facts_actions", "followups", "no_followups_reason", "forbidden_claims", "limits"}:
        raise ValueError("golden_invalid_investigation_truth")
    for field in ("behavior", "impact", "reason", "no_followups_reason"):
        if not isinstance(inv[field], str) or len(inv[field]) > 4000:
            raise ValueError("golden_answer_text_invalid")
    for field in ("evidence_refs", "required_facts_actions", "followups", "forbidden_claims"):
        if not isinstance(inv[field], list) or len(inv[field]) > 200:
            raise ValueError("golden_answer_list_invalid")
    if len(canonical(value).encode()) > golden.MAX_BLOB:
        raise HTTPException(413, "golden_answers_too_large")
    return deepcopy(value)


def review_content(s, g):
    checked = answers(g.answers)
    inv = checked["investigation_truth"]
    if not inv["required_facts_actions"] or not inv["forbidden_claims"] or not inv["reason"].strip():
        raise ValueError("golden_review_content_required")
    if not inv["followups"] and not inv["no_followups_reason"].strip():
        raise ValueError("golden_followups_or_reviewed_reason_required")
    refs = {m["sha256"] for m in g.manifest}
    for item in inv["required_facts_actions"] + [inv]:
        if not isinstance(item, dict) or not set(item.get("evidence_refs", [])).issubset(refs):
            raise ValueError("golden_answer_evidence_missing")
    for ref in checked["detection_truth"]["case_versions"]:
        row = s.get(DetectionCaseVersion, ref["id"])
        if row is None or row.sha256 != ref["sha256"] or digest(row.payload) != row.sha256:
            raise HTTPException(409, "golden_truth_case_changed")
    return checked


def holdout_references(s):
    from saw.knowledge.golden_models import GoldenVersion, GoldenFamily, GoldenFamilyMember
    from saw.knowledge.models import Experience
    family_ids = set(s.scalars(select(GoldenFamily.id).where(GoldenFamily.split == "holdout")))
    investigations = set(s.scalars(select(GoldenFamilyMember.investigation_id).where(
        GoldenFamilyMember.family_id.in_(family_ids)))) if family_ids else set()
    adopted = list(s.scalars(select(GoldenVersion).where(GoldenVersion.status == "adopted",
        GoldenVersion.family_id.in_(family_ids)))) if family_ids else []
    investigations |= {g.source_investigation_id for g in adopted}
    experiences = set(s.scalars(select(Experience.id).where(Experience.source_investigation_id.in_(investigations))))
    return {"experience": experiences | {g.experience_id for g in adopted}, "investigation": investigations}


def experience_is_holdout(s, eid):
    return eid in holdout_references(s)["experience"]


def verify_references(s, g):
    """Verify immutable references without substituting the current mutable record."""
    from saw.followups.models import CheckRevision, FollowUpVersion
    from saw.followups.check_revisions import _verify_revision_tree
    pins = g.metadata_json.get("golden_capture") or {}
    allowed_sources = sources(g)
    verify_matching_policy(s, g.answers.get("detection_truth") or {})
    for ref in g.answers.get("analyst_records", []):
        row = s.get(CheckRevision, ref["revision_id"], populate_existing=True)
        if (row is None or row.check_id != ref["check_id"] or row.revision != ref["revision"]
                or row.payload_sha256 != ref["payload_sha256"]):
            raise HTTPException(409, "golden_check_reference_changed")
        try:
            revision_sources = _verify_revision_tree(s, row)
        except ValueError as exc:
            raise HTTPException(409, "golden_check_reference_changed") from exc
        if not revision_sources <= allowed_sources:
            raise HTTPException(409, "golden_source_scope_changed")
    for ref in pins.get("followup_versions", []):
        row = s.get(FollowUpVersion, ref["version_id"], populate_existing=True)
        if (row is None or row.followup_id != ref["followup_id"] or row.revision != ref["revision"]
                or row.payload_sha256 != ref["payload_sha256"] or digest(row.payload) != row.payload_sha256):
            raise HTTPException(409, "golden_followup_reference_changed")
        if not set(row.source_investigation_ids) <= allowed_sources:
            raise HTTPException(409, "golden_source_scope_changed")
    for ref in g.answers.get("detection_truth", {}).get("case_versions", []):
        row = s.get(DetectionCaseVersion, ref["id"], populate_existing=True)
        if row is None or row.sha256 != ref["sha256"] or digest(row.payload) != row.sha256:
            raise HTTPException(409, "golden_truth_case_changed")
    run_id = g.metadata_json.get("analysis_run_id")
    if run_id:
        from saw.analysis_runs.models import AnalysisRun
        row = s.get(AnalysisRun, run_id, populate_existing=True)
        ref = next((r for r in pins.get("analysis_runs", []) if r["id"] == run_id), None)
        if (row is None or ref is None or row.finished_at is None
                or row.input_sha256 != ref["sha256"] or digest(row.scope) != ref["scope_sha256"]):
            raise HTTPException(409, "golden_analysis_run_changed")
        selected = [s.get(CheckRevision, ref["revision_id"]) for ref in g.answers["analyst_records"]]
        if not selected or not all(golden_context.run_matches_check(row, revision.payload) for revision in selected):
            raise HTTPException(409, "golden_analysis_run_scope_mismatch")
