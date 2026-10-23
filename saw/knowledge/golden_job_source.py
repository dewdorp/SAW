"""Server-owned known-at and source state for complete Golden recalculation."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from saw.analysis_runs import scoped, service
from saw.core.application.provenance import digest
from saw.detection.policy_models import Activation, Approval, PolicyVersion
from saw.source_context.models import DeviceProfileVersion, EvidenceContextSnapshot
from saw.storage.db import session_scope
from saw.storage.models import Evidence, EvidenceFile, Investigation, Job, ProcessingRun


def _time(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("golden_known_at_unavailable")
    # SQL SQLite timestamps are UTC even though that adapter drops tzinfo.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _stamp(value, cutoff):
    moment = _time(value)
    if moment > cutoff:
        raise ValueError("golden_source_after_cutoff")
    return moment.isoformat()


def known_at(s, frozen_scope):
    run = frozen_scope["analysis_run"]
    cutoff = _time(frozen_scope["cutoff"])
    manifest = run["input_manifest"]
    evidence = manifest.get("evidence") or []
    if not evidence:
        raise ValueError("golden_acquisition_provenance_missing")
    result = {"basis": "server_records", "acquired_at": [], "processed_at": [],
              "profile_available_at": [], "policy_available_at": []}
    for item in evidence:
        ev = s.get(Evidence, item["evidence_id"], populate_existing=True)
        if ev is None or ev.investigation_id != run["investigation_id"] or _time(ev.uploaded_at) != _time(item["uploaded_at"]):
            raise ValueError("golden_acquisition_provenance_changed")
        result["acquired_at"].append(_stamp(ev.uploaded_at, cutoff))
        context_ref = item.get("source_context") or {}
        context = s.get(EvidenceContextSnapshot, ev.context_snapshot_id) if ev.context_snapshot_id else None
        if (context is None or context.id != context_ref.get("id")
                or context.evidence_id != ev.id or context.investigation_id != ev.investigation_id
                or context.sha256 != context_ref.get("sha256") or digest(context.snapshot) != context.sha256):
            raise ValueError("golden_profile_provenance_missing")
        result["profile_available_at"].append(_stamp(context.created_at, cutoff))
        profile = s.get(DeviceProfileVersion, context.device_profile_version_id) if context.device_profile_version_id else None
        if profile is None or digest(profile.payload) != profile.sha256:
            raise ValueError("golden_profile_provenance_missing")
        result["profile_available_at"].append(_stamp(profile.created_at, cutoff))
        for file in item.get("files") or []:
            expected = file.get("processing_run") or {}
            parsed = s.get(ProcessingRun, expected.get("id"), populate_existing=True) if expected.get("id") else None
            current = s.get(EvidenceFile, file["id"], populate_existing=True)
            if (parsed is None or current is None or current.evidence_id != ev.id
                    or parsed.investigation_id != ev.investigation_id or parsed.evidence_id != ev.id
                    or parsed.file_id != current.id or parsed.run_digest != expected.get("run_digest")
                    or parsed.input_sha256 != file["sha256"] or current.sha256 != file["sha256"]
                    or parsed.parser_id != file["parser_id"] or parsed.parser_version != file["parser_version"]
                    or current.parse_status != "done" or parsed.status != "done" or parsed.failed != 0
                    or parsed.events != current.events_parsed or current.events_failed != 0
                    or _time(parsed.finished_at) != _time(expected.get("finished_at"))):
                raise ValueError("golden_processing_provenance_missing_or_changed")
            if (len(parsed.parser_digest or "") != 64 or digest(parsed.settings) != parsed.settings_digest
                    or digest({"input_sha256":parsed.input_sha256,"settings_digest":parsed.settings_digest,
                               "events":parsed.events,"failed":parsed.failed,"coverage":parsed.coverage}) != parsed.run_digest):
                raise ValueError("golden_processing_provenance_corrupt")
            result["processed_at"].append(_stamp(parsed.finished_at, cutoff))
        if not item.get("files"):
            raise ValueError("golden_processing_provenance_missing")
    for item in manifest.get("source_jobs", []):
        job = s.get(Job, item["id"], populate_existing=True)
        if (job is None or job.state != "COMPLETED" or job.attempt != item["attempt"]
                or job.investigation_id != run["investigation_id"]
                or _time(job.finished_at) != _time(item.get("finished_at"))):
            raise ValueError("golden_processing_job_incomplete")
        _stamp(job.finished_at, cutoff)
    for pin in manifest.get("runtime_pin", {}).get("devices", []):
        if pin.get("detector_id") != "fw.observation":
            continue
        policy = pin.get("policy") or {}
        for layer in policy.get("layers", []):
            version = s.get(PolicyVersion, layer.get("version_id"))
            approval = s.get(Approval, layer.get("approval_id"))
            if (version is None or approval is None or version.binding_id != layer["binding_id"]
                    or version.payload_sha256 != layer["payload_sha256"] or digest(version.payload) != version.payload_sha256
                    or approval.subject_kind != "policy" or approval.subject_version_id != version.id
                    or approval.subject_id != version.binding_id or approval.payload_sha256 != version.payload_sha256):
                raise ValueError("golden_policy_provenance_missing")
            activation = s.scalar(select(Activation).where(Activation.subject_kind == "policy",
                Activation.subject_id == version.binding_id, Activation.revision == layer["revision"],
                Activation.to_version_id == version.id, Activation.approval_id == approval.id))
            if activation is None:
                raise ValueError("golden_policy_activation_missing")
            for value in (version.created_at, approval.reviewed_at, activation.created_at):
                result["policy_available_at"].append(_stamp(value, cutoff))
    return result


def source_state(job_id, epoch, frozen_scope):
    from saw.knowledge.golden_jobs import _checkpoint
    with session_scope() as s:
        job, p = _checkpoint(s, job_id, epoch)
        expected = frozen_scope["analysis_run"]
        row = service.get(s, p, expected["investigation_id"], expected["id"])
        if (row.status != "complete" or row.input_sha256 != expected["input_sha256"]
                or row.scope != expected["scope"] or _time(row.finished_at) != _time(expected["finished_at"])
                or digest(row.input_manifest) != row.input_sha256):
            raise ValueError("golden_analysis_run_changed")
        actual = service.run_dict(s, row)
        if digest(actual["executions"]) != digest(expected["executions"]):
            raise ValueError("golden_analysis_execution_changed")
        scoped._idle(s, row.investigation_id)
        manifest = scoped._manifest(s, row.investigation_id)
        return {"source_manifest": manifest, "source_epochs": {
                    inv_id:int((s.get(Investigation,inv_id,populate_existing=True).settings or {}).get("data_epoch",0))
                    for inv_id in job.stages["source_ids"]},
                "processing_complete": True, "known_at": known_at(s, frozen_scope)}
