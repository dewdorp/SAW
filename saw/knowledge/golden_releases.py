"""Exact immutable release admission and publication; no storage I/O."""
from __future__ import annotations
import json
from copy import deepcopy
from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy import select, update
from saw.core.application.investigations import Forbidden, NotFound, access_of
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import can
from saw.detection.derived_access import source_ids
from saw.knowledge import golden, golden_profiles, golden_v2
from saw.knowledge.golden_governance_models import GoldenRelease, GoldenReleaseVersion, GoldenReleaseSource, GoldenValidation
from saw.knowledge.golden_schemas import ReleaseRequest
from saw.storage.db import utcnow
from saw.storage.models import Investigation

MAX_PRIVATE_BYTES = 20 * 1024 * 1024


def normalize_request(raw):
    model = raw if isinstance(raw, ReleaseRequest) else ReleaseRequest.model_validate(raw)
    value = model.model_dump()
    value["expires_at"] = model.expires_at.isoformat()
    value["examples"] = [{k: v for k, v in item.items() if v is not None} for item in value["examples"]]
    return value


def request_hash(raw):
    return digest({k: v for k, v in normalize_request(raw).items() if k != "idempotency_key"})


def authorize_sources(s, p, ids, *, permission=None, lock=False):
    p = golden_profiles.actor(s, p, permission)
    ids = set(ids)
    if not ids or len(ids) > 1000:
        raise HTTPException(413, "golden_source_limit")
    fence = s.info.get("snapshot_source_ids")
    if fence is not None and not ids <= set(fence):
        raise HTTPException(409, "golden_source_scope_changed")
    for iid in sorted(ids):
        row = s.get(Investigation, iid, populate_existing=True)
        if row is None:
            raise NotFound("source investigation not found")
        if not can(p, "investigation.read", access_of(s, p, iid)):
            raise Forbidden("investigation.read")
        if (row.settings or {}).get("data_deletion"):
            raise HTTPException(409, "golden_source_deleting")
    if lock:
        from saw.core.application.data_deletion import lock_investigation
        for iid in sorted(ids):
            lock_investigation(s, iid)
    return p


def _profiles(s, p, request):
    from saw.knowledge.golden_projection import validate_profile
    out = {}
    for kind, key in (("pseudonymization", "pseudonymization_profile"), ("model_conversion", "model_conversion_profile")):
        ref = request[key]
        row = golden_profiles.get(s, p, ref["id"])
        if row.kind != kind or row.payload_sha256 != ref["sha256"]:
            raise HTTPException(409, "golden_profile_reference_changed")
        validate_profile(kind, row.implementation, row.payload)
        out[kind] = {"id": row.id, "sha256": row.payload_sha256, "implementation": row.implementation,
                     "payload": deepcopy(row.payload), "contributor_ids": list(row.contributor_ids)}
    if request["split"] == "holdout" and out["model_conversion"]["implementation"] != "golden-native/1":
        raise ValueError("golden_holdout_input_native_required")
    return out


def family_snapshot(s, rows, split):
    investigations, families = set(), set()
    for g in rows:
        members, groups = golden._family(s, None, g.source_investigation_id, split, assign=False)
        investigations |= members
        families |= {f.id for f in groups}
    payload = {"investigation_ids": sorted(investigations), "family_ids": sorted(families), "split": split}
    return payload, digest(payload)


def _collect(s, p, request, *, freeze, require_create=True):
    from saw.knowledge.models import Experience
    from saw.analysis_runs import service as runs
    from saw.detection.truth_models import DetectionCaseVersion
    p = golden_profiles.actor(s, p, "golden.release.create" if require_create else "knowledge.read")
    profiles = _profiles(s, p, request)
    sources, contributors, rows, examples = set(), {p.user_id}, [], []
    budget = len(canonical({"request": request, "profiles": profiles}).encode())
    for item in request["examples"]:
        g, blobs = golden._exportable(s, p, item["version_id"], request["split"], False, retain_family=False)
        if request["projection"] == "v2" and not golden_v2.is_v2(g):
            raise ValueError("golden_v2_projection_requires_v2_source")
        input_sha = golden_v2.input_digest(g, blobs)
        key = "input_sha256" if request["split"] == "holdout" else "content_sha256"
        if item.get(key) != (input_sha if key == "input_sha256" else g.content_sha256):
            raise HTTPException(409, "golden_selection_changed")
        e = s.get(Experience, g.experience_id)
        own_sources = golden_v2.sources(g) | source_ids([e.data, e.approved_data])
        sources |= own_sources
        people = set(g.contributor_ids) | {g.author_id} | golden._revision_contributors(s, e, g.experience_rev)
        if not golden_v2.is_v2(g) and g.reviewer_id:
            people.add(g.reviewer_id)
        contributors |= people
        rows.append(g)
        if not freeze:
            continue
        complete_scope = None
        scope_ref = next((x for x in request["applicability_request"]["complete_scopes"] if x["golden_version_id"] == g.id), None)
        if scope_ref:
            if g.metadata_json.get("analysis_run_id") != scope_ref["analysis_run_id"]:
                raise HTTPException(409, "golden_complete_run_not_pinned")
            run = runs.get(s, p, g.source_investigation_id, scope_ref["analysis_run_id"])
            if digest(run.scope) != scope_ref["scope_sha256"]:
                raise HTTPException(409, "golden_complete_scope_changed")
            truth_cases = []
            for ref in g.answers["detection_truth"]["case_versions"]:
                truth = s.get(DetectionCaseVersion, ref["id"])
                if truth is None or truth.sha256 != ref["sha256"] or digest(truth.payload) != truth.sha256:
                    raise HTTPException(409, "golden_truth_case_changed")
                truth_cases.append({"id": truth.id, "sha256": truth.sha256, "payload": truth.payload,
                    "input_sha256": truth.input_sha256, "input_count": truth.input_count, "source_manifest": truth.source_manifest})
            complete_scope = {"golden_ref": {"id": g.id, "content_sha256": g.content_sha256},
                "scope_sha256": scope_ref["scope_sha256"],
                "analysis_run": {**runs.run_dict(s, run), "investigation_id": run.investigation_id,
                    "finished_at": golden._aware(run.finished_at).isoformat(),
                    "created_at": golden._aware(run.created_at).isoformat()},
                "truth_units": g.answers["detection_truth"]["units"], "cutoff": g.input["cutoff"]["as_of"],
                "truth_cases": truth_cases}
        entry = {"version_id": g.id, "content_sha256": g.content_sha256, "input_sha256": input_sha,
            "schema_version": "saw.golden.v2" if golden_v2.is_v2(g) else "saw.golden.v1", "split": request["split"],
            "payload": golden._payload(g), "blobs": blobs, "source_investigation_ids": sorted(own_sources),
            "contributor_ids": sorted(people), "complete_scope": complete_scope}
        budget += len(canonical(entry).encode())
        if budget > MAX_PRIVATE_BYTES - 65536:
            raise HTTPException(413, "golden_private_input_limit")
        examples.append(json.loads(canonical(entry)))
    for profile in profiles.values():
        contributors |= set(profile["contributor_ids"])
    family, family_sha = family_snapshot(s, rows, request["split"])
    sources |= set(family["investigation_ids"])
    authorize_sources(s, p, sources)
    return {"anchor_investigation_id": rows[0].source_investigation_id,
        "source_investigation_ids": sorted(sources), "contributor_ids": sorted(contributors),
        "request_sha256": request_hash(request), "examples": examples, "profiles": profiles,
        "family_snapshot": family, "family_snapshot_sha256": family_sha}


def preflight_sources(s, p, request):
    value = _collect(s, p, normalize_request(request), freeze=False)
    return {k: value[k] for k in ("anchor_investigation_id", "source_investigation_ids", "contributor_ids", "request_sha256")}


def reserve_build(s, p, request, *, release_id=None):
    p = golden_profiles.actor(s, p, "golden.release.create")
    request = normalize_request(request)
    expiry = golden._aware(request["expires_at"])
    if not utcnow() < expiry <= utcnow() + timedelta(days=365):
        raise ValueError("golden_release_expiry_invalid")
    if release_id is None:
        if request["expected_current_version_id"] is not None:
            raise HTTPException(409, "golden_release_current_conflict")
        row = GoldenRelease(created_by=p.user_id)
        s.add(row)
        s.flush()
    else:
        row = s.get(GoldenRelease, release_id)
        if row is None:
            raise NotFound("release not found")
        if row.current_version_id:
            authorize_version(s, p, row.current_version_id, "read")
        elif row.created_by != p.user_id:
            raise Forbidden("golden_release_creator_required")
        s.execute(update(GoldenRelease).where(GoldenRelease.id == release_id).values(id=release_id)
                  .execution_options(synchronize_session=False))
        s.refresh(row)
        if row.current_version_id != request["expected_current_version_id"] or row.pending_job_id:
            raise HTTPException(409, "golden_release_current_conflict")
    return row


def freeze_build(s, p, request):
    request = normalize_request(request)
    value = _collect(s, p, request, freeze=True)
    result = {"schema": "saw.golden.build-input.v1", "request": request,
        **{k: value[k] for k in ("request_sha256", "examples", "profiles", "source_investigation_ids",
                               "contributor_ids", "family_snapshot_sha256")},
        "source_epochs": {iid: int((s.get(Investigation, iid).settings or {}).get("data_epoch", 0))
                          for iid in value["source_investigation_ids"]},
        "limits": ["private_frozen_inputs", "external_approval_required"]}
    if len(canonical(result).encode()) > MAX_PRIVATE_BYTES:
        raise HTTPException(413, "golden_private_input_limit")
    return result


def publish_version(s, p, release, job, build_result, privateobjectrefs):
    frozen = build_result.get("frozen_inputs")
    if not isinstance(frozen, dict):
        raise HTTPException(409, "golden_verified_frozen_inputs_required")
    request = frozen["request"]
    fresh = freeze_build(s, p, request)
    for key in ("request_sha256", "source_epochs", "source_investigation_ids", "contributor_ids", "family_snapshot_sha256"):
        if fresh[key] != frozen[key]:
            raise HTTPException(409, "golden_publication_source_changed")
    s.refresh(release)
    s.refresh(job)
    stage = (job.stages or {}).get("golden_export") or {}
    if (release.pending_job_id != job.id or release.current_version_id != request["expected_current_version_id"]
            or job.state not in {"QUEUED", "RUNNING", "ANALYZING"} or (job.stages or {}).get("input_state") != "input_ready"):
        raise HTTPException(409, "golden_publication_reservation_changed")
    artifact = privateobjectrefs.get("artifact") or {}
    if (artifact.get("sha256") != build_result["artifact_sha256"] or
            artifact.get("size_bytes") != build_result["size_bytes"] or not 0 < artifact.get("size_bytes", 0) <= MAX_PRIVATE_BYTES):
        raise HTTPException(409, "golden_artifact_reference_changed")
    validation = build_result.get("validation") or {}
    if validation.get("passed") is not True:
        raise HTTPException(409, "golden_artifact_validation_required")
    attestations = []
    for value in build_result.get("validations", []):
        ref = value.get("golden_ref") or {}
        if ref.get("id") not in {e["version_id"] for e in frozen["examples"]}:
            raise HTTPException(409, "golden_validation_subject_changed")
        row = GoldenValidation(golden_version_id=ref["id"], subject_sha256=ref["content_sha256"],
            payload=value, payload_sha256=digest(value), source_investigation_ids=frozen["source_investigation_ids"],
            validator_version=value.get("validator_version", "saw.golden.validation/1"), created_by=p.user_id)
        s.add(row)
        s.flush()
        attestations.append({"id": row.id, "sha256": row.payload_sha256})
    if request["applicability_request"]["mode"] == "full_recalculation" and len(attestations) != len(request["examples"]):
        raise HTTPException(409, "golden_full_validation_required")
    public_validation = validation
    if request["split"] == "holdout":
        public_validation = {"passed": True, "checks": [
            {"code": check["code"], "state": check["state"], "detail": ""}
            for check in validation.get("checks", [])]}
    payload = {k: deepcopy(request[k]) for k in ("schema_version", "purpose", "purpose_text", "recipient",
        "usage_conditions", "expires_at", "examples", "split", "artifact_kind", "projection")}
    payload.update(profiles={"pseudonymization": request["pseudonymization_profile"],
        "model_conversion": request["model_conversion_profile"]},
        applicability={"mode": request["applicability_request"]["mode"], "reasons":
            ["representative_input"] if request["applicability_request"]["mode"] == "interpretation_only" else [],
            "validations": [] if request["split"] == "holdout" else attestations}, manifest=build_result["manifest"],
        artifact={"sha256": artifact["sha256"], "size_bytes": artifact["size_bytes"], "media_type": "application/zip"},
        validation=public_validation, family_snapshot_sha256=frozen["family_snapshot_sha256"])
    version = GoldenReleaseVersion(release_id=release.id, revision=release.current_revision + 1,
        request=deepcopy(request), request_sha256=frozen["request_sha256"], payload=payload, payload_sha256=digest(payload),
        source_investigation_ids=frozen["source_investigation_ids"], contributor_ids=frozen["contributor_ids"],
        private_objects=deepcopy(privateobjectrefs), validation_refs=attestations, artifact_sha256=artifact["sha256"], size_bytes=artifact["size_bytes"],
        family_snapshot_sha256=frozen["family_snapshot_sha256"], created_by=p.user_id)
    s.add(version)
    s.flush()
    for iid in version.source_investigation_ids:
        s.add(GoldenReleaseSource(release_version_id=version.id, investigation_id=iid))
    release.current_version_id, release.current_revision, release.pending_job_id = version.id, version.revision, None
    return version


# The access module imports this module lazily to keep lifecycle boundaries explicit.
from saw.knowledge.golden_release_access import (  # noqa: E402,F401
    authorize_version, to_dict, list_for, versions_for, record_preview, decide, revoke,
)


def consume_input(s, p, attempt_id, version_id, artifact_sha256):
    from saw.knowledge.golden_holdout import consume_input as consume
    return consume(s, p, attempt_id, version_id, artifact_sha256)
