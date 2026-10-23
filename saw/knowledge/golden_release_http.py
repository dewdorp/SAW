"""Verified private Golden previews and exact approved byte downloads."""
from __future__ import annotations

import hashlib
import tempfile
import time
from copy import deepcopy

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from saw import container
from saw.core.application.provenance import digest
from saw.knowledge import golden_jobs
from saw.knowledge.golden_archive import inspect_archive
from saw.knowledge.golden_governance_models import GoldenRelease


def _summary(s, p, job):
    from saw.apps.api.routers.evidence import job_out
    release = s.get(GoldenRelease, job.stages["golden_export"]["release_id"], populate_existing=True)
    public = job_out(job, p=p)
    actions = public["stages"]["golden_export"]["actions"]
    return {"release_id": release.id, "job_id": job.id,
            "request_sha256": job.stages["request_sha256"],
            "current_version_id": release.current_version_id,
            "job": {"id": job.id, "kind": job.kind, "state": job.state,
                "current_item": job.current_item,
                "progress": public["stages"]["golden_export"]["progress"],
                "can_cancel": actions["cancel"]["enabled"], "can_retry": actions["retry"]["enabled"]}}


def submit_release(body, ctx, s, release_id=None):
    raw = body.model_dump(mode="json") if hasattr(body, "model_dump") else body
    job, created = golden_jobs.submit(s, ctx.principal, raw, release_id=release_id)
    s.commit()
    if created and job.state == "QUEUED" and job.stages.get("input_state") == "input_ready":
        container.get().runner.submit("golden_export.run", job_id=job.id)
    s.refresh(job)
    return _summary(s, golden_jobs.actor(s, ctx.principal.user_id, session_id=ctx.session.id), job)


def _reference(s, p, release_id, version_id, action):
    from saw.knowledge import golden_releases
    authorized = golden_releases.authorize_version(s, p, version_id, action)
    version = authorized["version"]
    if version.release_id != release_id:
        raise HTTPException(404, "golden_release_version_not_found")
    artifact = deepcopy(version.private_objects["artifact"])
    if (artifact["sha256"] != version.artifact_sha256 or artifact["size_bytes"] != version.size_bytes
            or artifact["bucket"] != "saw-exports" or not artifact["key"].startswith("golden/")):
        raise ValueError("golden_artifact_reference_corrupt")
    return version, {"payload_sha256": version.payload_sha256,
        "artifact_sha256": version.artifact_sha256, "size_bytes": version.size_bytes,
        "artifact": artifact, "manifest": deepcopy(version.payload["manifest"]),
        "split": version.request["split"]}


def _verified(s, p, release_id, version_id, action, session_id):
    p = golden_jobs.actor(s, p.user_id, session_id=session_id)
    _, frozen = _reference(s, p, release_id, version_id, action)
    s.commit()
    deadline = time.monotonic() + golden_jobs.MAX_SECONDS
    def cancelled():
        if time.monotonic() > deadline:
            raise ValueError("golden_download_time_limit")
        return False
    stream = tempfile.SpooledTemporaryFile(max_size=4*1024*1024, mode="w+b")  # noqa: SIM115
    try:
        size, sha = 0, hashlib.sha256()
        ref = frozen["artifact"]
        if type(ref["size_bytes"]) is not int or not 0 < ref["size_bytes"] <= golden_jobs.MAX_ARTIFACT_BYTES:
            raise ValueError("golden_artifact_size_limit")
        with container.get().objects.open(ref["bucket"], ref["key"]) as source:
            while block := source.read(65536):
                cancelled()
                size += len(block); sha.update(block)
                if size > ref["size_bytes"] or size > golden_jobs.MAX_ARTIFACT_BYTES:
                    raise ValueError("golden_artifact_size_mismatch")
                stream.write(block)
        if size != ref["size_bytes"] or sha.hexdigest() != ref["sha256"]:
            raise ValueError("golden_artifact_digest_mismatch")
        stream.seek(0)
        inspection = inspect_archive(stream, expected_manifest=frozen["manifest"],
                                     holdout=frozen["split"] == "holdout", cancelled=cancelled)
        p = golden_jobs.actor(s, p.user_id, session_id=session_id)
        version, current = _reference(s, p, release_id, version_id, action)
        if current != frozen:
            raise HTTPException(409, "golden_download_reference_changed")
        cancelled()
        stream.seek(0)
        return stream, version, inspection, p
    except Exception:
        stream.close()
        raise


def preview_release(release_id, vid, ctx, s):
    from saw.knowledge import golden_releases
    stream, version, inspected, p = _verified(s, ctx.principal, release_id, vid, "preview", ctx.session.id)
    try:
        result = {"release_id": release_id, "version_id": vid,
            "payload_sha256": version.payload_sha256, "artifact_sha256": version.artifact_sha256,
            "manifest": inspected["manifest"], "validation": version.payload["validation"],
            "samples": inspected["samples"], "omitted": inspected["omitted"], "limits": inspected["limits"]}
        golden_releases.record_preview(s, p, vid, version.artifact_sha256, digest(result))
        return result
    finally:
        stream.close()


def decide_release(release_id, vid, body, ctx, s):
    from saw.knowledge import golden_releases
    raw = body.model_dump(mode="json") if hasattr(body, "model_dump") else body
    # Both approval and decline operate on the exact verified candidate.
    action = "approve" if raw["decision"] == "approve" else "read"
    stream, _, _, p = _verified(s, ctx.principal, release_id, vid, action, ctx.session.id)
    try:
        return golden_releases.decide(s, p, vid, raw)
    finally:
        stream.close()


def download_release(release_id, vid, ctx, s, attempt_id=None):
    from saw.knowledge import golden_releases
    stream, version, _, p = _verified(s, ctx.principal, release_id, vid, "download", ctx.session.id)
    try:
        if version.request["split"] == "holdout":
            if not attempt_id:
                raise HTTPException(409, "golden_holdout_attempt_required")
            golden_releases.consume_input(s, p, attempt_id, vid, version.artifact_sha256)
        elif attempt_id:
            raise HTTPException(400, "golden_holdout_attempt_for_wrong_split")
        filename = f"SAW-golden-v{version.revision}-{version.id[:8]}.zip"
        size = version.size_bytes
        s.commit()
        def chunks():
            while block := stream.read(65536):
                yield block
        return StreamingResponse(chunks(), media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"',
                     "Content-Length": str(size), "Cache-Control": "no-store",
                     "X-Content-Type-Options": "nosniff"},
            background=BackgroundTask(stream.close))
    except Exception:
        stream.close()
        raise
