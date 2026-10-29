"""Receipt-owned generation cleanup. Local single-server advisory locks are not distributed leases."""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from copy import deepcopy

from fastapi import HTTPException
from sqlalchemy import delete, select, update

from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.investigations import NotFound
from saw.core.security.authz import can
from saw.event_generations import service as life
from saw.event_generations.models import (
    AnalysisRunGeneration,
    EventGeneration,
    InvestigationHead,
    WriterReservation,
)
from saw.event_generations.retention_targets import remove_target, safe_path, validate_target
from saw.storage.db import new_id, utcnow
from saw.storage.generations import GenerationRef, GenerationUnavailable
from saw.storage.models import DataDeletion, Evidence, EvidenceFile, Investigation, Job, UploadSession, User
from saw.storage.objectstore import LocalFSObjectStore


def legacy_store(c):
    return c.legacy_events


def fresh_admin(s, principal):
    if principal is None:
        raise HTTPException(403, "현재 관리자 인증이 필요합니다.")
    user = s.get(User, principal.user_id, populate_existing=True)
    if user is None or user.status != "active" or not can(principal_of(user), "admin.data.delete"):
        raise HTTPException(403, "현재 관리자 권한을 확인할 수 없습니다.")
    if user.locked_until is not None:
        from datetime import UTC

        until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=UTC)
        if until > utcnow():
            raise HTTPException(403, "현재 관리자 계정을 사용할 수 없습니다.")
    return principal_of(user)


def _entry(g):
    return {
        "generation_id": g.id,
        "job_id": g.job_id,
        "attempt": g.attempt,
        "purpose": g.purpose,
        "storage_targets": deepcopy(g.storage_targets),
        "raw_objects": deepcopy(g.raw_objects),
        "input_sha256": g.input_sha256,
        "output_sha256": g.output_sha256,
        "revision": g.revision,
        "status": g.status,
    }


def _ref(iid, entry):
    return GenerationRef(
        iid,
        entry["generation_id"],
        entry["revision"],
        entry["output_sha256"],
        tuple(entry["storage_targets"]),
        False,
    )


def closure(s, c, iid, removed, whole):
    rows = list(
        s.scalars(
            select(EventGeneration)
            .where(EventGeneration.investigation_id == iid)
            .order_by(EventGeneration.id)
        )
    )
    head = s.get(InvestigationHead, iid)
    store = getattr(c, "generations", None)
    if (rows or head) and store is None:
        raise GenerationUnavailable("generation store missing")
    entries = [_entry(g) for g in rows]
    for entry in entries:
        validate_target(store, _ref(iid, entry))
    if head is None and any(g.status in life.READABLE for g in rows):
        raise GenerationUnavailable("published generation head is missing")
    current = next((g for g in rows if head and g.id == head.generation_id), None)
    if head and (current is None or current.status not in life.READABLE or current.revision != head.revision):
        raise GenerationUnavailable("generation head unavailable")
    keep = set()
    count = None
    if current:
        life._validate_ready(current, current.output_manifest, current.file_results)
        if life._hash(current.input_manifest) != current.input_sha256:
            raise GenerationUnavailable("generation input corrupt")
        count = sum(
            f["unique_count"]
            for f in current.output_manifest["files"]
            if whole or f["evidence_id"] in removed
        )
        if not whole:
            for f in current.output_manifest["files"]:
                if f["evidence_id"] not in removed:
                    keep.update((x["bucket"], x["key"]) for x in f["raw_objects"])
            # Preserve every surviving input original/derived object, including zero-event files.
            for ev in current.input_manifest["source"]["evidence"]:
                if ev["id"] not in removed:
                    keep.update(
                        (
                            "saw-evidence-extracted" if f.get("parent_file_id") else "saw-evidence-original",
                            f["object_key"],
                        )
                        for f in ev["files"]
                    )
    if not whole:
        for f in s.scalars(
            select(EvidenceFile)
            .join(Evidence)
            .where(Evidence.investigation_id == iid, Evidence.id.notin_(removed))
        ):
            keep.add(
                ("saw-evidence-extracted" if f.parent_file_id else "saw-evidence-original", f.object_key)
            )
    # Replacement inventories inherit baseline raw objects even when their current
    # file output has replaced that PCAP. Keep the original exact file association.
    legacy_transfers = set()
    for baseline in rows:
        if life._hash(baseline.input_manifest) != baseline.input_sha256:
            raise GenerationUnavailable("generation input corrupt")
        if baseline.purpose != "baseline" or baseline.status not in life.READABLE:
            continue
        validated = False
        for f in baseline.output_manifest.get("files", []):
            for obj in f["raw_objects"]:
                if (life.legacy_transfer_owned(iid, baseline.input_manifest, obj, (f["evidence_id"], f["file_id"]))
                        and obj in baseline.raw_objects):
                    if not validated:
                        try:
                            life._validate_ready(baseline, baseline.output_manifest, baseline.file_results)
                        except life.GenerationVerificationError as exc:
                            raise ValueError("legacy transfer association invalid") from exc
                        validated = True
                    legacy_transfers.add(life._hash(obj))
    objects = {}
    for g in rows:
        if life._hash(g.input_manifest) != g.input_sha256:
            raise GenerationUnavailable("generation input corrupt")
        known_originals = {
            (
                ("saw-evidence-extracted" if f.get("parent_file_id") else "saw-evidence-original"),
                f["object_key"],
            )
            for ev in g.input_manifest["source"]["evidence"]
            for f in ev["files"]
        }
        for evidence in g.input_manifest["source"]["evidence"]:
            for source in evidence["files"]:
                expected = (
                    f"{iid}/{source['id']}"
                    if source.get("parent_file_id")
                    else f"{iid}/{evidence['id']}/{source['id']}"
                )
                if source["object_key"] != expected:
                    raise ValueError("retained original ownership invalid")
        known_legacy = tuple(
            f"{iid}/{ev['id']}/{f['id']}/"
            for ev in g.input_manifest["source"]["evidence"]
            for f in ev["files"]
        )
        for obj in g.raw_objects:
            identity = (obj["bucket"], obj["key"])
            owner, attempt = obj.get("owner_generation_id"), obj.get("owner_attempt")
            owned = (
                isinstance(owner, str)
                and bool(owner)
                and type(attempt) is int
                and attempt > 0
                and obj["key"].startswith(f"generations/{owner}/{attempt}/")
            )
            legacy = (
                owner is None
                and attempt is None
                and obj["bucket"] == "saw-artifacts"
                and (obj["key"].startswith(known_legacy) or life._hash(obj) in legacy_transfers)
            )
            if identity not in known_originals and not owned and not legacy:
                raise ValueError("raw object ownership invalid")
            safe_path(c.objects.safe_delete_path(*identity))
            prior = objects.get(identity)
            item = {
                "bucket": identity[0],
                "key": identity[1],
                "size": obj["byte_length"],
                "sha256": obj["sha256"],
            }
            if prior is not None and prior != item:
                raise ValueError("raw object descriptor conflict")
            objects[identity] = item
            if not whole and current is None and legacy:
                survivors = tuple(
                    f"{iid}/{ev['id']}/"
                    for ev in g.input_manifest["source"]["evidence"]
                    if ev["id"] not in removed
                )
                if obj["key"].startswith(survivors):
                    keep.add(identity)
    # A foreign SQL reference defeats deletion even when a local descriptor claims ownership.
    removable = set(objects) - keep
    shared_objects = False
    for g in s.scalars(select(EventGeneration).where(EventGeneration.investigation_id != iid)):
        if any((x["bucket"], x["key"]) in removable for x in g.raw_objects):
            shared_objects = True
    for f in s.scalars(select(EvidenceFile).join(Evidence).where(Evidence.investigation_id != iid)):
        bucket = "saw-evidence-extracted" if f.parent_file_id else "saw-evidence-original"
        if (bucket, f.object_key) in removable:
            shared_objects = True
    return {
        "generations": entries,
        "shared_objects": shared_objects,
        "head": (_entry(current) if current else None),
        "kept_objects": [list(x) for x in sorted(keep)],
        "objects": [objects[x] for x in sorted(removable)],
        "events": count,
    }


def abandon_writers(s, op):
    iid = op.investigation_id
    if iid is None:
        return
    s.execute(
        update(EventGeneration)
        .where(EventGeneration.investigation_id == iid, EventGeneration.status.in_(("allocated", "ready")))
        .values(status="abandoned", abandoned_at=utcnow(), reason="authorized_deletion")
    )
    s.execute(delete(WriterReservation).where(WriterReservation.investigation_id == iid))
    closure = deepcopy(op.plan.get("generation_closure", {}))
    closure["generations"] = [
        _entry(g)
        for g in s.scalars(
            select(EventGeneration)
            .where(EventGeneration.investigation_id == iid)
            .order_by(EventGeneration.id)
        )
    ]
    op.plan = {**op.plan, "generation_closure": closure}


@contextmanager
def receipt_lock(objects, did):
    if not isinstance(objects, LocalFSObjectStore):
        raise TypeError("cleanup requires local object storage")
    # Stable hashed lock name is internal and carries no authorization token or payload.
    name = hashlib.sha256(did.encode()).hexdigest() + ".lock"
    path = safe_path(objects.root / ".retention-locks" / name)
    if os.name == "nt":
        import ctypes

        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) not in (3, 6):
            raise ValueError("cleanup requires local fixed storage")
    elif str(path).startswith("//"):
        raise ValueError("cleanup requires local storage")
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_path(path)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        stream = os.fdopen(fd, "r+b")
    except OSError:
        raise HTTPException(409, "삭제 잠금 파일을 사용할 수 없습니다.") from None
    acquired = False
    try:
        safe_path(path)
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise ValueError("unsafe cleanup lock")
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise HTTPException(409, "이 삭제 작업이 이미 실행 중입니다.") from None
        acquired = True
        yield
    finally:
        if acquired:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _check(s, did, token, principal, *, iid=None):
    from saw.core.application import data_deletion as deletion

    fresh_admin(s, principal)
    op = s.get(DataDeletion, did, populate_existing=True)
    if (
        op is None
        or op.state == "COMPLETED"
        or op.plan.get("invocation") != {"token": token, "actor_id": principal.user_id}
        or (iid is not None and iid != op.investigation_id)
    ):
        raise ValueError("cleanup ownership changed")
    if op.investigation_id:
        inv = s.get(Investigation, op.investigation_id, populate_existing=True)
        if inv is None or (inv.settings or {}).get("data_deletion") != did:
            raise ValueError("cleanup barrier changed")
        if deletion._count(
            s, Evidence, Evidence.id.in_(op.plan["evidence_ids"]), Evidence.legal_hold.is_(True)
        ):
            raise ValueError("legal hold changed")
        if deletion._count(
            s, Job, Job.investigation_id == op.investigation_id, Job.state.notin_(deletion.TERMINAL)
        ):
            raise ValueError("active job changed")
        if s.scalar(
            select(UploadSession.id)
            .join(Evidence)
            .where(Evidence.investigation_id == op.investigation_id, UploadSession.status == "open")
            .limit(1)
        ):
            raise ValueError("open upload changed")
        expected = op.plan.get("generation_closure", {})
        head = s.get(InvestigationHead, op.investigation_id)
        old = expected.get("head")
        if (head.generation_id if head else None, head.revision if head else 0) != (
            old["generation_id"] if old else None,
            old["revision"] if old else 0,
        ):
            raise ValueError("cleanup source head changed")
        entries = expected.get("generations", []) + op.plan.get("cleanup_generations", [])
        actual = list(
            s.scalars(select(EventGeneration).where(EventGeneration.investigation_id == op.investigation_id))
        )
        if {g.id for g in actual} != {g["generation_id"] for g in entries}:
            raise ValueError("cleanup generation closure changed")
        by_id = {g.id: g for g in actual}
        if any(_entry(by_id[e["generation_id"]]) != e for e in entries):
            raise ValueError("cleanup generation metadata changed")
    return op


def _filter_generation(s, c, op, check, principal):
    """Persist allocation before copy; a crashed unfinished attempt is never resumed in place."""
    old = op.plan.get("generation_closure", {}).get("head")
    if op.target_type != "evidence" or old is None:
        return
    if op.plan.get("cleanup_generation"):
        return
    parent = s.get(EventGeneration, old["generation_id"])
    removed = set(op.plan["evidence_ids"])
    inp = deepcopy(parent.input_manifest)
    inp["source"]["evidence"] = [e for e in inp["source"]["evidence"] if e["id"] not in removed]
    # The parent input predates its publication. Overlay its immutable prepared results
    # before filtering so the new source describes the published surviving files.
    results = {(r["evidence_id"], r["file_id"]): r for r in parent.file_results}
    replacements = {(r["evidence_id"], r["file_id"]): r for r in parent.input_manifest["replacements"]}
    for evidence in inp["source"]["evidence"]:
        for source in evidence["files"]:
            identity = (evidence["id"], source["id"])
            result = results.get(identity)
            if result is None:
                continue
            for key in (
                "parser_id",
                "parser_version",
                "parse_status",
                "events_parsed",
                "events_failed",
                "error_samples",
                "message",
                "first_ts",
                "last_ts",
                "parser_confidence",
            ):
                if key in result:
                    source[key] = deepcopy(result[key])
            source["parser"] = deepcopy(replacements[identity]["parser"])
    inp["replacements"] = []
    inp["job_kind"] = "ingest"
    inp["requester_id"] = op.plan["invocation"]["actor_id"]
    inp["data_epoch"] = (s.get(Investigation, op.investigation_id).settings or {}).get("data_epoch", 0)
    files = [deepcopy(f) for f in parent.output_manifest["files"] if f["evidence_id"] not in removed]
    for f in files:
        f["replacement"] = False
        f["raw_objects"] = [{**x, "retained": True} for x in f["raw_objects"]]
    raw = {(x["bucket"], x["key"]): x for f in files for x in f["raw_objects"]}
    keep = {tuple(x) for x in op.plan["generation_closure"]["kept_objects"]}
    for obj in parent.raw_objects:
        if (obj["bucket"], obj["key"]) in keep:
            raw[(obj["bucket"], obj["key"])] = {**obj, "retained": True}
    gid = new_id()
    attempt = len(op.plan.get("cleanup_generations", [])) + 1
    g = EventGeneration(
        id=gid,
        investigation_id=op.investigation_id,
        job_id=op.id,
        attempt=attempt,
        purpose="cleanup",
        requester_id=op.plan["invocation"]["actor_id"],
        parent_id=parent.id,
        parent_revision=old["revision"],
        data_epoch=inp["data_epoch"],
        revision=0,
        input_manifest=inp,
        input_sha256=life._hash(inp),
        raw_objects=list(raw.values()),
        storage_targets=list(c.generations.plan_targets(op.investigation_id, gid)),
        status="allocated",
    )
    s.add(g)
    s.flush()
    op.plan = {**op.plan, "cleanup_generations": [*op.plan.get("cleanup_generations", []), _entry(g)]}
    s.commit()
    ref = life._ref(g)
    owner = {"job_id": op.id, "attempt": attempt, "input_sha256": g.input_sha256, "check": check}
    c.generations.create_target(ref, **owner)
    writer = c.generations.begin_write(ref, **owner)
    from saw.event_generations.reads import maintenance_scope

    with maintenance_scope(lambda iid: check(iid), purpose="authorized-deletion"):
        view = c.generations.open_view(op.investigation_id, ref=_ref(op.investigation_id, old))
        try:
            writer.index(
                e for e in view.iterate(op.investigation_id, []) if e.get("evidence_id") not in removed
            )
        finally:
            view.close()
    writer.seal()
    output = writer.verify(expected_files=files, check=check)
    check()
    from saw.core.application.data_deletion import lock_investigation

    lock_investigation(s, op.investigation_id, allow_deleting=True)
    _check(s, op.id, op.plan["invocation"]["token"], principal)
    life._validate_ready(g, output, [])
    g.output_manifest, g.output_sha256, g.status, g.ready_at = (
        output,
        output["output_sha256"],
        "ready",
        utcnow(),
    )
    s.flush()
    entries = [e if e["generation_id"] != gid else _entry(g) for e in op.plan["cleanup_generations"]]
    op.plan = {**op.plan, "cleanup_generations": entries, "cleanup_generation": gid}
    s.commit()


def finish_generations(s, op):
    iid = op.investigation_id
    if iid is None:
        return
    ids = select(EventGeneration.id).where(EventGeneration.investigation_id == iid)
    s.execute(delete(AnalysisRunGeneration).where(AnalysisRunGeneration.generation_id.in_(ids)))
    s.execute(delete(WriterReservation).where(WriterReservation.investigation_id == iid))
    survivor = op.plan.get("cleanup_generation")
    if survivor:
        g = s.get(EventGeneration, survivor)
        life._validate_ready(g, g.output_manifest, [])
        head = s.get(InvestigationHead, iid)
        head.generation_id, head.revision = g.id, g.parent_revision + 1
        g.status, g.revision, g.published_at = "published", head.revision, utcnow()
        s.flush()
        s.execute(
            delete(EventGeneration).where(
                EventGeneration.investigation_id == iid, EventGeneration.id != survivor
            )
        )
    else:
        s.execute(delete(InvestigationHead).where(InvestigationHead.investigation_id == iid))
        s.execute(delete(EventGeneration).where(EventGeneration.investigation_id == iid))


def _remove_events(c, op, check):
    """Recheck exact absence after object cleanup as well as before it."""
    cleanup = op.plan.get("cleanup_generation")
    for entry in op.plan.get("generation_closure", {}).get("generations", []) + op.plan.get(
        "cleanup_generations", []
    ):
        if entry["generation_id"] == cleanup:
            continue
        owner = {
            "format": "saw-event-generation/1",
            "investigation_id": op.investigation_id,
            "generation_id": entry["generation_id"],
            "job_id": entry["job_id"],
            "attempt": entry["attempt"],
            "input_sha256": entry["input_sha256"],
        }
        remove_target(c.generations, _ref(op.investigation_id, entry), owner=owner, check=check)
    check()
    es = legacy_store(c)
    if op.investigation_id:
        if op.target_type == "investigation":
            es.delete_by_investigation(op.investigation_id)
            if es.count(op.investigation_id):
                raise ValueError("remaining legacy events")
        else:
            from saw.core.schemas.query import Filter

            for eid in op.plan["evidence_ids"]:
                check()
                es.delete_by_evidence(op.investigation_id, eid)
                if es.count(op.investigation_id, [Filter(field="evidence_id", value=eid)]):
                    raise ValueError("remaining legacy events")
    check()


def _verify_cleanup(s, c, op, check):
    gid = op.plan.get("cleanup_generation")
    if gid is None:
        return
    g = s.get(EventGeneration, gid)
    ref, files, expected = life._ref(g), deepcopy(g.output_manifest["files"]), deepcopy(g.output_manifest)
    s.commit()
    manifest = c.generations.verify(ref, expected_files=files, check=check)
    if manifest != expected:
        raise GenerationUnavailable("cleanup verification receipt changed")


def resume(s, c, did, principal, *, retry_request=True):
    from saw.core.application import data_deletion as deletion

    fresh_admin(s, principal)
    s.commit()
    with receipt_lock(c.objects, did):
        op = s.get(DataDeletion, did, populate_existing=True)
        if op is None:
            raise NotFound("deletion receipt not found")
        if op.state != "COMPLETED" and op.investigation_id:
            deletion.lock_investigation(s, op.investigation_id, allow_deleting=True)
        if retry_request:
            audit.record(
                s,
                "data.delete_retry_requested",
                actor_id=principal.user_id,
                actor_name=principal.username,
                target_type=op.target_type,
                target_id=op.target_id,
                investigation_id=op.investigation_id,
                detail={"receipt_id": did, "previous_state": op.state, "previous_step": op.step},
            )
        if op.state == "COMPLETED":
            s.commit()
            return op
        token = new_id()
        op.plan = {**op.plan, "invocation": {"token": token, "actor_id": principal.user_id}}
        s.commit()

        def check(iid=None):
            with c.session_factory() as fresh:
                _check(fresh, did, token, principal, iid=iid)

        phase = op.step
        try:
            check()
            _filter_generation(s, c, op, check, principal)
            s.commit()
            _verify_cleanup(s, c, op, check)
            # Always repeat exact deletion/absence verification, even after a saved checkpoint.
            _remove_events(c, op, check)
            op.step = phase = "events_removed"
            s.commit()
            for obj in op.plan["objects"]:
                check()
                safe_path(c.objects.safe_delete_path(obj["bucket"], obj["key"]))
                c.objects.delete(obj["bucket"], obj["key"])
                if c.objects.exists(obj["bucket"], obj["key"]):
                    raise ValueError("remaining object")
                check()
            _remove_events(c, op, check)
            for obj in op.plan["objects"]:
                check()
                safe_path(c.objects.safe_delete_path(obj["bucket"], obj["key"]))
                if c.objects.exists(obj["bucket"], obj["key"]):
                    raise ValueError("object recreated during cleanup")
            op.step = phase = "objects_removed"
            s.commit()
            check()
            if op.plan.get("cleanup_generation"):
                entry = next(
                    e
                    for e in op.plan["cleanup_generations"]
                    if e["generation_id"] == op.plan["cleanup_generation"]
                )
                c.generations._readable(_ref(op.investigation_id, entry))
            if op.investigation_id:
                deletion.lock_investigation(s, op.investigation_id, allow_deleting=True)
            _check(s, did, token, principal)
            finish_generations(s, op)
            deletion._finish_relational(s, op)
            op.state, op.step, op.error_code, op.updated_at = "COMPLETED", "completed", "", utcnow()
            audit.record(
                s,
                "data.delete_completed",
                actor_id=op.actor_id,
                actor_name=op.actor_name,
                target_type=op.target_type,
                target_id=op.target_id,
                investigation_id=op.investigation_id,
                detail={"receipt_id": did, "counts": op.plan["counts"], "retained": deletion.RETAINED},
            )
            s.commit()
        except Exception:
            s.rollback()
            op = s.get(DataDeletion, did, populate_existing=True)
            if op.plan.get("invocation", {}).get("token") != token:
                raise
            if op.state == "COMPLETED":
                return op
            op.state, op.step, op.error_code, op.updated_at = "FAILED", phase, f"{phase}_failed", utcnow()
            audit.record(
                s,
                "data.delete_failed",
                actor_id=op.actor_id,
                actor_name=op.actor_name,
                target_type=op.target_type,
                target_id=op.target_id,
                investigation_id=op.investigation_id,
                outcome="failure",
                detail={"receipt_id": did, "error_code": op.error_code},
            )
            s.commit()
        return op
