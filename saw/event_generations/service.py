"""Caller-owned SQL transactions. No physical event/raw I/O or implicit commits here."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime
from typing import NotRequired, TypedDict

from sqlalchemy import select

from saw.core.application import provenance
from saw.core.application.data_deletion import epoch, lock_investigation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.security.authz import InvestigationAccess, can
from saw.event_generations.models import (
    AnalysisRunGeneration,
    EventGeneration,
    InvestigationHead,
    WriterReservation,
)
from saw.parsers import library
from saw.parsers.registry import builtin_parsers
from saw.source_context.models import EvidenceContextSnapshot
from saw.source_context.service import snapshot_payload
from saw.storage.db import new_id, utcnow
from saw.storage.generations import (
    GenerationConflict,
    GenerationRef,
    GenerationUnavailable,
    GenerationVerificationError,
    canonical_event_bytes,
)
from saw.storage.models import Evidence, EvidenceFile, Investigation, InvestigationMember, Job, User

INPUT_FORMAT = "saw-generation-input/1"
ACTIVE = {"PARSING", "INDEXING", "ANALYZING"}
READABLE = {"published", "retained"}


class FileResult(TypedDict):
    evidence_id: str
    file_id: str
    parser_id: str | None
    parser_version: str | None
    parser_digest: str
    settings: dict
    started_at: str | None
    parse_status: str
    coverage: dict
    events_parsed: int
    events_failed: int
    first_ts: str | None
    last_ts: str | None
    error_samples: list
    message: str
    parser_confidence: NotRequired[float]


def _hash(value):
    return hashlib.sha256(canonical_event_bytes(value)).hexdigest()


def _fresh(s, model, key):
    return s.get(model, key, populate_existing=True)


def _inv(s, inv_id):
    inv = _fresh(s, Investigation, inv_id)
    if inv is None or (inv.settings or {}).get("data_deletion"):
        raise GenerationUnavailable("generation_source_unavailable")
    return inv


def _actor(s, uid, inv_id):
    user = _fresh(s, User, uid)
    if user is None or user.status != "active":
        raise Forbidden("generation_actor_unavailable")
    p = principal_of(user)
    member = _fresh(s, InvestigationMember, (inv_id, uid))
    if not can(p, "investigation.write", InvestigationAccess(member.access if member else None)):
        raise Forbidden("generation_write_denied")
    return p


def _parser(s, p, pid, *, use=True, evidence_kind=None):
    if not isinstance(pid, str) or not pid:
        raise GenerationConflict("generation_parser_unavailable")
    if pid.startswith("u:"):
        if "@" in pid:
            match = library.PINNED.fullmatch(pid)
            if not match:
                raise GenerationConflict("generation_parser_unavailable")
            q = select(library.ParserDefinition).where(
                library.ParserDefinition.slug == match[1], library.ParserDefinition.version == int(match[2])
            )
        else:
            q = (
                select(library.ParserDefinition)
                .where(library.ParserDefinition.slug == pid[2:], library.ParserDefinition.status == "active")
                .order_by(library.ParserDefinition.version.desc())
                .limit(1)
            )
        row = s.scalar(q.execution_options(populate_existing=True))
        if row is None:
            raise GenerationConflict("generation_parser_unavailable")
        exact = f"u:{row.slug}@{row.version}"
        if use:
            library.check_use(s, p, exact)
        try:
            spec = library.ParserSpec.model_validate(row.spec).model_dump()
        except ValueError:
            raise GenerationConflict("generation_parser_invalid") from None
        return {
            "id": exact,
            "version": str(row.version),
            "digest": library.spec_digest(spec),
            "spec": spec,
            "definition_id": row.id,
        }
    parser = next((x for x in builtin_parsers() if x.id == pid), None)
    if parser is None:
        if pid == "pcap" or (not use and pid.startswith("pcap(") and pid.endswith(")")):
            from saw.integrations.pcapkit import PRODUCER

            return {
                "id": pid,
                "version": PRODUCER.rpartition("/")[2],
                "digest": provenance.pcap_engine_digest(),
                "spec": None,
                "definition_id": None,
            }
        raise GenerationConflict("generation_parser_unavailable")
    concrete = None
    if evidence_kind == 'connector' and pid == 'json_lines':
        from saw.parsers.connector import ConnectorEnvelopeParser, connector_implementation_pin
        parser = ConnectorEnvelopeParser()
        concrete = connector_implementation_pin()
    digest = concrete['digest'] if concrete else provenance.parser_digest(parser)
    if not digest:
        raise GenerationConflict("generation_parser_unavailable")
    return {
        "id": parser.id,
        **({"implementation": concrete["implementation"]} if concrete else {}),
        "version": str(parser.version),
        "digest": digest,
        "spec": None,
        "definition_id": None,
    }


def _source(s, inv, p):
    evidence = []
    for ev in s.scalars(
        select(Evidence)
        .where(Evidence.investigation_id == inv.id)
        .order_by(Evidence.id)
        .execution_options(populate_existing=True)
    ):
        context = None
        if ev.context_snapshot_id:
            row = _fresh(s, EvidenceContextSnapshot, ev.context_snapshot_id)
            if row is None or row.evidence_id != ev.id or row.investigation_id != inv.id:
                raise GenerationConflict("generation_context_unavailable")
            context = {"id": row.id, "sha256": row.sha256, "snapshot": snapshot_payload(row)}
        files = []
        for f in s.scalars(
            select(EvidenceFile)
            .where(EvidenceFile.evidence_id == ev.id)
            .order_by(EvidenceFile.id)
            .execution_options(populate_existing=True)
        ):
            fields = {c.name: getattr(f, c.name) for c in EvidenceFile.__table__.columns}
            for k in ("first_ts", "last_ts"):
                fields[k] = fields[k].isoformat() if fields[k] else None
            fields["object_bucket"] = (
                "saw-evidence-original" if f.parent_file_id is None else "saw-evidence-extracted"
            )
            historical_pid = f.parser_id
            if (
                historical_pid
                and historical_pid.startswith("u:")
                and "@" not in historical_pid
                and f.parser_version
            ):
                historical_pid += "@" + str(f.parser_version)
            fields["parser"] = (
                _parser(s, p, historical_pid, use=False, evidence_kind=ev.kind)
                if f.parser_id and f.parser_id != "ioc_list"
                else None
            )
            files.append(fields)
        evidence.append(
            {
                "id": ev.id,
                "kind": ev.kind,
                "tz_assumed": ev.tz_assumed,
                "context_snapshot_id": ev.context_snapshot_id,
                "source_context": context,
                "files": files,
            }
        )
    settings = {k: v for k, v in (inv.settings or {}).items() if k not in {"data_epoch", "data_deletion"}}
    return {
        "investigation": {"org_unit": inv.org_unit, "org_unit_id": inv.org_unit_id, "settings": settings},
        "evidence": evidence,
    }


def capture_input(s, job):
    """Capture trusted row metadata after producer file preparation and before event I/O."""
    inv = _inv(s, job.investigation_id)
    p = _actor(s, job.requested_by, inv.id)
    source = _source(s, inv, p)
    request = (job.stages or {}).get("generation_request")
    if job.kind == "reprocess":
        if not isinstance(request, dict) or request.get("sha256") != _hash(request.get("input", {})):
            raise GenerationConflict("generation_request_invalid")
        expected = request["input"]
        replacements = deepcopy(expected["replacements"])
        for item in replacements:
            evidence_kind = next((e['kind'] for e in source['evidence'] if e['id'] == item['evidence_id']), None)
            if _parser(s, p, item["parser"]["id"], evidence_kind=evidence_kind) != item["parser"]:
                raise GenerationConflict("generation_parser_changed")
        current = {
            "format": INPUT_FORMAT,
            "job_kind": job.kind,
            "investigation_id": inv.id,
            "data_epoch": epoch(inv),
            "requester_id": p.user_id,
            "source": source,
            "replacements": replacements,
        }
        if "runtime_pins" in expected:
            current["runtime_pins"] = deepcopy(expected["runtime_pins"])
        if current != expected:
            raise GenerationConflict("generation_source_changed")
        return current
    if job.kind != "ingest" or not job.evidence_id:
        raise GenerationConflict("generation_job_kind_invalid")
    replacements = []
    head = _fresh(s, InvestigationHead, inv.id)
    parent = _fresh(s, EventGeneration, head.generation_id) if head else None
    preserved = {(f["evidence_id"], f["file_id"]) for f in (parent.output_manifest.get("files", []) if parent else [])
                 if f["unique_count"] > 0}
    for ev in source["evidence"]:
        if ev["id"] != job.evidence_id:
            continue
        parents = {f["parent_file_id"] for f in ev["files"] if f["parent_file_id"]}
        for f in ev["files"]:
            # Normal ingest only prepares new/empty leaves. Replacing published data requires explicit reprocess.
            if (ev["id"], f["id"]) in preserved or (parent is None and f["events_parsed"] > 0):
                continue
            if f["id"] not in parents and f["parser_id"] != "ioc_list":
                replacements.append(
                    {
                        "evidence_id": ev["id"],
                        "file_id": f["id"],
                        "parser": _parser(s, p, f["parser_id"], evidence_kind=ev["kind"]) if f["parser_id"] else None,
                        "source_context": deepcopy(ev["source_context"]),
                    }
                )
    if not any(e["id"] == job.evidence_id for e in source["evidence"]):
        raise GenerationConflict("generation_evidence_mismatch")
    return {
        "format": INPUT_FORMAT,
        "job_kind": job.kind,
        "investigation_id": inv.id,
        "data_epoch": epoch(inv),
        "requester_id": p.user_id,
        "source": source,
        "replacements": replacements,
        **({"runtime_pins": deepcopy(job.stages["runtime_pins"])} if (job.stages or {}).get("runtime_pins") is not None else {}),
    }


def request_reprocess(s, p, evidence_id, file_id, parser_id, *, runtime_pins=None):
    ev = _fresh(s, Evidence, evidence_id)
    if ev is None:
        raise NotFound("generation_evidence_missing")
    inv = lock_investigation(s, ev.investigation_id)
    p = _actor(s, p.user_id, inv.id)
    f = _fresh(s, EvidenceFile, file_id)
    if f is None or f.evidence_id != ev.id:
        raise NotFound("generation_file_mismatch")
    parser = _parser(s, p, parser_id, evidence_kind=ev.kind)
    source = _source(s, inv, p)
    context = next(x["source_context"] for x in source["evidence"] if x["id"] == ev.id)
    manifest = {
        "format": INPUT_FORMAT,
        "job_kind": "reprocess",
        "investigation_id": inv.id,
        "data_epoch": epoch(inv),
        "requester_id": p.user_id,
        "source": source,
        "replacements": [
            {"evidence_id": ev.id, "file_id": f.id, "parser": parser, "source_context": context}
        ],
    }
    if runtime_pins is not None:
        if not isinstance(runtime_pins, dict) or runtime_pins.get("format") != "saw-pcap-runtime/1":
            raise GenerationConflict("generation_runtime_pins_invalid")
        canonical_event_bytes(runtime_pins)
        manifest["runtime_pins"] = deepcopy(runtime_pins)
    job = Job(
        investigation_id=inv.id,
        evidence_id=ev.id,
        kind="reprocess",
        state="QUEUED",
        requested_by=p.user_id,
        stages={
            "generation_request": {"input": manifest, "sha256": _hash(manifest)},
            "_queue_task": "reprocess.run",
            "requested": {"by": p.user_id, "name": p.username},
        },
    )
    s.add(job)
    s.flush()
    return job


def _ref(g):
    return GenerationRef(
        g.investigation_id,
        g.id,
        g.revision if g.status in READABLE else g.parent_revision,
        g.output_sha256,
        tuple(g.storage_targets),
        False,
    )


def _generation(s, ref):
    g = _fresh(s, EventGeneration, ref.generation_id)
    if (
        g is None
        or g.investigation_id != ref.investigation_id
        or tuple(g.storage_targets) != ref.storage_targets
    ):
        raise GenerationUnavailable("generation_reference_unavailable")
    return g


def resolve(s, investigation_id, *, generation_id=None):
    _inv(s, investigation_id)
    head = _fresh(s, InvestigationHead, investigation_id)
    if generation_id is None:
        if head is None:
            return None
        generation_id = head.generation_id
    g = _fresh(s, EventGeneration, generation_id)
    if (
        g is None
        or g.investigation_id != investigation_id
        or g.status not in READABLE
        or not g.storage_targets
        or not _sha(g.output_sha256)
        or not g.output_manifest
        or g.output_manifest.get("output_sha256") != g.output_sha256
    ):
        raise GenerationUnavailable("generation_reference_unavailable")
    try:
        _validate_ready(g, g.output_manifest, g.file_results)
        if _hash(g.input_manifest) != g.input_sha256:
            raise GenerationVerificationError("generation_input_corrupt")
    except (GenerationVerificationError, KeyError, TypeError, ValueError):
        raise GenerationUnavailable("generation_reference_unavailable") from None
    if head and head.generation_id == g.id and head.revision != g.revision:
        raise GenerationUnavailable("generation_head_corrupt")
    return _ref(g)


def _job(s, job_id, attempt):
    job = _fresh(s, Job, job_id)
    if job is None or job.attempt != attempt or job.state not in ACTIVE or job.cancel_requested:
        raise GenerationConflict("generation_lease_invalid")
    return job


def allocate(s, job, *, attempt, store, input_manifest=None, baseline=False):
    lock_investigation(s, job.investigation_id)
    job = _job(s, job.id, attempt)
    manifest = capture_input(s, job)
    if input_manifest is not None and input_manifest != manifest:
        raise GenerationConflict("generation_input_mismatch")
    purpose = "baseline" if baseline else "replacement"
    head = resolve(s, job.investigation_id)
    if baseline and head is not None:
        raise GenerationConflict("generation_baseline_has_head")
    reservation = _fresh(s, WriterReservation, job.investigation_id)
    previous = s.scalar(
        select(EventGeneration)
        .where(
            EventGeneration.job_id == job.id,
            EventGeneration.attempt == attempt,
            EventGeneration.purpose == purpose,
        )
        .execution_options(populate_existing=True)
    )
    if previous:
        if previous.status != "allocated" or previous.input_manifest != manifest:
            raise GenerationConflict("generation_attempt_not_writable")
        check_writer(s, _ref(previous), job_id=job.id, attempt=attempt)
        return _ref(previous)
    if reservation is not None:
        raise GenerationConflict("generation_writer_reserved")
    # Fence all old-style active ingestion writers before initial legacy transition.
    other = s.scalar(
        select(Job.id)
        .where(
            Job.investigation_id == job.investigation_id,
            Job.id != job.id,
            Job.kind.in_(("ingest", "reprocess")),
            Job.state.in_(ACTIVE),
        )
        .limit(1)
    )
    if other:
        raise GenerationConflict("generation_writer_active")
    gid = new_id()
    targets = tuple(store.plan_targets(job.investigation_id, gid))
    if not targets or not all(isinstance(x, str) and x for x in targets) or len(set(targets)) != len(targets):
        raise GenerationConflict("generation_target_plan_invalid")
    request_hash = ((job.stages or {}).get("generation_request") or {}).get("sha256", "")
    g = EventGeneration(
        id=gid,
        investigation_id=job.investigation_id,
        job_id=job.id,
        attempt=attempt,
        purpose=purpose,
        requester_id=job.requested_by,
        parent_id=head.generation_id if head else None,
        parent_revision=head.head_revision if head else 0,
        data_epoch=manifest["data_epoch"],
        input_manifest=deepcopy(manifest),
        input_sha256=_hash(manifest),
        request_sha256=request_hash,
        storage_targets=list(targets),
        raw_objects=_initial_objects(s, manifest, head),
        status="allocated",
    )
    s.add(g)
    s.flush()
    s.add(
        WriterReservation(
            investigation_id=g.investigation_id, generation_id=g.id, job_id=g.job_id, attempt=attempt
        )
    )
    key = "generation_baseline" if baseline else "generation"
    job.stages = {**(job.stages or {}), key: {"id": gid, "attempt": attempt, "published": False}}
    s.flush()
    return _ref(g)


def _input_objects(manifest):
    out = []
    for ev in manifest["source"]["evidence"]:
        for f in ev["files"]:
            if f["object_key"] and _sha(f["sha256"]):
                out.append(
                    {
                        "bucket": f["object_bucket"],
                        "key": f["object_key"],
                        "byte_length": f["size"],
                        "sha256": f["sha256"],
                        "owner_generation_id": None,
                        "owner_attempt": None,
                        "retained": True,
                    }
                )
    return out


def _initial_objects(s, manifest, head):
    objects = {(x["bucket"], x["key"]): x for x in _input_objects(manifest)}
    if head:
        parent = _fresh(s, EventGeneration, head.generation_id)
        for value in parent.raw_objects:
            obj = {**deepcopy(value), "retained": True}
            identity = (obj["bucket"], obj["key"])
            if identity in objects and objects[identity] != obj:
                raise GenerationConflict("generation_input_raw_conflict")
            objects[identity] = obj
    return list(objects.values())


def register_raw_objects(s, ref, objects, *, job_id, attempt):
    """Persist derived object ownership before physical creation; append only per attempt."""
    lock_investigation(s, ref.investigation_id)
    check_writer(s, ref, job_id=job_id, attempt=attempt)
    g = _generation(s, ref)
    if g.status != "allocated" or not isinstance(objects, list):
        raise GenerationConflict("generation_raw_registration_invalid")
    known = {(x["bucket"], x["key"]): deepcopy(x) for x in g.raw_objects}
    for obj in objects:
        required = {
            "bucket",
            "key",
            "byte_length",
            "sha256",
            "owner_generation_id",
            "owner_attempt",
            "retained",
        }
        if (
            not isinstance(obj, dict)
            or set(obj) != required
            or obj.get("retained") is not False
            or not isinstance(obj.get("bucket"), str)
            or not obj["bucket"]
            or not isinstance(obj.get("key"), str)
            or not obj["key"]
            or not _integer(obj.get("byte_length"))
            or not _sha(obj.get("sha256"))
            or (obj.get("owner_generation_id"), obj.get("owner_attempt")) != (g.id, g.attempt)
            or not obj["key"].startswith(f"generations/{g.id}/{g.attempt}/")
            or any(part in {"", "..", "."} for part in obj["key"].split("/"))
            or chr(92) in obj["key"]
        ):
            raise GenerationConflict("generation_raw_registration_invalid")
        identity = (obj["bucket"], obj["key"])
        if identity in known and known[identity] != obj:
            raise GenerationConflict("generation_raw_registration_conflict")
        known[identity] = deepcopy(obj)
    g.raw_objects = list(known.values())
    s.flush()


def legacy_transfer_owned(investigation_id, manifest, obj, source_file):
    """Exact content-addressed legacy transfer nominated by a captured PCAP file."""
    pcap_files = {(ev["id"], f["id"]) for ev in manifest["source"]["evidence"] for f in ev["files"]
                  if (f.get("parser_id") or "").startswith("pcap")}
    return (
        isinstance(source_file, tuple) and source_file in pcap_files
        and obj.get("bucket") == "saw-artifacts"
        and _sha(obj.get("sha256"))
        and obj.get("key") == f"{investigation_id}/extracted-files/{obj['sha256']}"
        and _integer(obj.get("byte_length"))
        and obj.get("retained") is True
        and obj.get("owner_generation_id") is None and obj.get("owner_attempt") is None
    )


def register_legacy_objects(s, ref, objects, *, job_id, attempt, source_file=None):
    """Record fingerprinted legacy PCAP logs or exact content-addressed transfers for a captured PCAP."""
    lock_investigation(s, ref.investigation_id)
    check_writer(s, ref, job_id=job_id, attempt=attempt)
    g = _generation(s, ref)
    if g.purpose != "baseline" or g.status != "allocated" or not isinstance(objects, list):
        raise GenerationConflict("generation_legacy_registration_invalid")
    prefixes = tuple(
        f"{g.investigation_id}/{ev['id']}/{f['id']}/"
        for ev in g.input_manifest["source"]["evidence"]
        for f in ev["files"]
        if (f.get("parser_id") or "").startswith("pcap")
    )
    known = {(x["bucket"], x["key"]): deepcopy(x) for x in g.raw_objects}
    required = {"bucket", "key", "byte_length", "sha256", "owner_generation_id", "owner_attempt", "retained"}
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or set(obj) != required
            or obj.get("retained") is not True
            or obj.get("bucket") != "saw-artifacts"
            or not isinstance(obj.get("key"), str)
            or not (obj["key"].startswith(prefixes) or
                    legacy_transfer_owned(g.investigation_id, g.input_manifest, obj, source_file))
            or any(part in {"", "..", "."} for part in obj["key"].split("/"))
            or chr(92) in obj["key"]
            or not _integer(obj.get("byte_length"))
            or not _sha(obj.get("sha256"))
            or obj.get("owner_generation_id") is not None
            or obj.get("owner_attempt") is not None
        ):
            raise GenerationConflict("generation_legacy_registration_invalid")
        identity = (obj["bucket"], obj["key"])
        if identity in known and known[identity] != obj:
            raise GenerationConflict("generation_legacy_registration_conflict")
        known[identity] = deepcopy(obj)
    g.raw_objects = list(known.values())
    s.flush()


def check_writer(s, ref, *, job_id, attempt):
    g = _generation(s, ref)
    if g.status not in {"allocated", "ready"} or g.job_id != job_id or g.attempt != attempt:
        raise GenerationConflict("generation_owner_invalid")
    job = _job(s, job_id, attempt)
    if job.investigation_id != g.investigation_id or job.requested_by != g.requester_id:
        raise GenerationConflict("generation_owner_invalid")
    inv = _inv(s, g.investigation_id)
    current = capture_input(s, job)
    if current != g.input_manifest or _hash(current) != g.input_sha256:
        raise GenerationConflict("generation_input_changed")
    if ((job.stages or {}).get("generation_request") or {}).get("sha256", "") != g.request_sha256:
        raise GenerationConflict("generation_request_changed")
    reservation = _fresh(s, WriterReservation, g.investigation_id)
    if reservation is None or (reservation.generation_id, reservation.job_id, reservation.attempt) != (
        g.id,
        job_id,
        attempt,
    ):
        raise GenerationConflict("generation_reservation_lost")
    head = resolve(s, g.investigation_id)
    if (head.generation_id if head else None, head.head_revision if head else 0, epoch(inv)) != (
        g.parent_id,
        g.parent_revision,
        g.data_epoch,
    ):
        raise GenerationConflict("generation_parent_changed")


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(x in "0123456789abcdef" for x in value)


def _integer(value):
    return type(value) is int and value >= 0


def _date(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise GenerationVerificationError("generation_result_timestamp_invalid")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise GenerationVerificationError("generation_result_timestamp_invalid") from None


def expected_source_closure(input_manifest, evidence_id, file_id, *, replacement=True):
    """Required CES identity/parser fields. Extra nested context constraints may be added."""
    evidence = next((e for e in input_manifest["source"]["evidence"] if e["id"] == evidence_id), None)
    source = next((f for f in (evidence or {}).get("files", []) if f["id"] == file_id), None)
    if source is None:
        raise GenerationVerificationError("generation_file_closure_invalid")
    replacement_spec = next(
        (
            x
            for x in input_manifest["replacements"]
            if x["evidence_id"] == evidence_id and x["file_id"] == file_id
        ),
        None,
    )
    parser = replacement_spec["parser"] if replacement and replacement_spec else source["parser"]
    closure = {
        "investigation_id": input_manifest["investigation_id"],
        "evidence_id": evidence_id,
        "source_file": source["display_name"],
    }
    if parser and parser["id"].startswith("pcap"):
        closure.pop("source_file")
    elif parser:
        closure["parser"] = parser["id"] if replacement and replacement_spec else source["parser_id"]
        closure["parser_version"] = (
            parser["version"] if replacement and replacement_spec else source["parser_version"]
        )
    return closure


def _validate_ready(g, manifest, results):
    fail = GenerationVerificationError
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != "saw-event-generation/1"
        or manifest.get("investigation_id") != g.investigation_id
        or manifest.get("generation_id") != g.id
        or manifest.get("storage_targets") != g.storage_targets
        or manifest.get("input_sha256") != g.input_sha256
        or manifest.get("complete") is not True
        or manifest.get("sealed") is not True
        or type(manifest.get("rejected")) is not int
        or manifest["rejected"] != 0
        or not _sha(manifest.get("output_sha256"))
        or not _integer(manifest.get("unique_count"))
    ):
        raise fail("generation_receipt_invalid")
    files = manifest.get("files")
    objects = manifest.get("raw_objects")
    if not isinstance(files, list) or not isinstance(objects, list):
        raise fail("generation_closure_invalid")
    known = {(ev["id"], f["id"]): f for ev in g.input_manifest["source"]["evidence"] for f in ev["files"]}
    replacements = {(r["evidence_id"], r["file_id"]): r for r in g.input_manifest["replacements"]}
    seen, raw = {}, {}
    allowed_raw = {(x["bucket"], x["key"]): x for x in g.raw_objects}
    for obj in objects:
        if (
            not isinstance(obj, dict)
            or not isinstance(obj.get("bucket"), str)
            or not obj["bucket"]
            or not isinstance(obj.get("key"), str)
            or not obj["key"]
            or not _integer(obj.get("byte_length"))
            or not _sha(obj.get("sha256"))
            or type(obj.get("retained")) is not bool
        ):
            raise fail("generation_raw_invalid")
        if not obj["retained"] and (obj.get("owner_generation_id"), obj.get("owner_attempt")) != (
            g.id,
            g.attempt,
        ):
            raise fail("generation_raw_owner_invalid")
        identity = (obj["bucket"], obj["key"])
        if allowed_raw.get(identity) != obj:
            raise fail("generation_raw_unregistered")
        if identity in raw and raw[identity] != obj:
            raise fail("generation_raw_duplicate")
        raw[identity] = obj
    for f in files:
        identity = (f.get("evidence_id"), f.get("file_id"))
        if (
            identity not in known
            or identity in seen
            or not _integer(f.get("unique_count"))
            or not _sha(f.get("events_sha256"))
        ):
            raise fail("generation_file_closure_invalid")
        if type(f.get("replacement")) is not bool or f["replacement"] != (
            identity in replacements
            and g.purpose != "baseline"
            and g.input_manifest["job_kind"] == "reprocess"
        ):
            raise fail("generation_replacement_invalid")
        if f["replacement"] and (
            f["unique_count"] == 0 or f.get("parse_status") not in {"done", "degraded", "partial"}
        ):
            raise fail("generation_replacement_empty")
        if not all(
            isinstance(f.get(k), dict) for k in ("coverage", "quality", "source_closure")
        ) or not isinstance(f.get("raw_objects"), list):
            raise fail("generation_file_metadata_invalid")
        if identity in replacements and g.purpose != "baseline":
            expected = expected_source_closure(g.input_manifest, *identity)
            if any(f["source_closure"].get(key) != value for key, value in expected.items()):
                raise fail("generation_source_closure_invalid")
        for obj in f["raw_objects"]:
            if raw.get((obj.get("bucket"), obj.get("key"))) != obj:
                raise fail("generation_raw_closure_mismatch")
        seen[identity] = f
    if sum(f["unique_count"] for f in files) != manifest["unique_count"]:
        raise fail("generation_count_mismatch")
    # All current event-bearing parent files and every replacement must be represented.
    required = {key for key, value in known.items() if value["events_parsed"] > 0}
    if g.purpose != "baseline":
        required |= set(replacements)
    if not required <= set(seen):
        raise fail("generation_file_missing")
    if not isinstance(results, list):
        raise fail("generation_results_invalid")
    checked = set()
    for result in results:
        keys = {
            "evidence_id",
            "file_id",
            "parser_id",
            "parser_version",
            "parser_digest",
            "settings",
            "started_at",
            "parse_status",
            "coverage",
            "events_parsed",
            "events_failed",
            "first_ts",
            "last_ts",
            "error_samples",
            "message",
        }
        if not isinstance(result, dict) or not keys <= result.keys():
            raise fail("generation_result_invalid")
        identity = (result["evidence_id"], result["file_id"])
        if identity not in replacements or identity in checked or identity not in seen:
            raise fail("generation_result_scope_invalid")
        parser = replacements[identity]["parser"]
        if parser is None:
            if (
                (result["parser_id"], result["parser_version"], result["parser_digest"]) != (None, None, "")
                or result["events_parsed"] != 0
                or result["parse_status"] not in {"waiting_input", "skipped", "failed"}
            ):
                raise fail("generation_result_parser_invalid")
        elif (result["parser_id"], str(result["parser_version"]), result["parser_digest"]) != (
            parser["id"],
            parser["version"],
            parser["digest"],
        ):
            raise fail("generation_result_parser_invalid")
        if (
            not _integer(result["events_parsed"])
            or not _integer(result["events_failed"])
            or result["events_parsed"] != seen[identity]["unique_count"]
            or result["parse_status"] != seen[identity]["parse_status"]
            or result["coverage"] != seen[identity]["coverage"]
            or not isinstance(result["settings"], dict)
            or not isinstance(result["error_samples"], list)
            or not isinstance(result["message"], str)
        ):
            raise fail("generation_result_mismatch")
        for key in ("started_at", "first_ts", "last_ts"):
            _date(result[key])
        checked.add(identity)
    if checked != (set() if g.purpose == "baseline" else set(replacements)):
        raise fail("generation_results_incomplete")
    canonical_event_bytes(manifest)
    canonical_event_bytes({"results": results})


def _validate_parent(s, g, manifest):
    if g.parent_id is None:
        return
    parent = _fresh(s, EventGeneration, g.parent_id)
    if parent is None or parent.status not in READABLE:
        raise GenerationVerificationError("generation_parent_unavailable")
    replaced = {(x["evidence_id"], x["file_id"]) for x in g.input_manifest["replacements"]}
    actual = {(x["evidence_id"], x["file_id"]): x for x in manifest["files"]}
    for previous in parent.output_manifest["files"]:
        identity = (previous["evidence_id"], previous["file_id"])
        if identity in replaced:
            continue
        expected = deepcopy(previous)
        expected["replacement"] = False
        expected["raw_objects"] = [{**x, "retained": True} for x in expected["raw_objects"]]
        if actual.get(identity) != expected:
            raise GenerationVerificationError("generation_parent_file_changed")


def mark_ready(s, ref, output_manifest, *, file_results: list[FileResult] | None = None):
    lock_investigation(s, ref.investigation_id)
    g = _generation(s, ref)
    check_writer(s, ref, job_id=g.job_id, attempt=g.attempt)
    results = file_results or []
    _validate_ready(g, output_manifest, results)
    _validate_parent(s, g, output_manifest)
    if g.status == "ready":
        if g.output_manifest != output_manifest or g.file_results != results:
            raise GenerationConflict("generation_ready_conflict")
        return
    g.output_manifest = deepcopy(output_manifest)
    g.output_sha256 = output_manifest["output_sha256"]
    # Keep the entire pre-created closure, including a derived artifact unused by final events.
    # This is the approved cleanup/backup closure, not merely the readable-event subset.
    g.file_results = deepcopy(results)
    g.status, g.ready_at = "ready", utcnow()
    s.flush()


def _published(s, g, job_id, attempt):
    if g.job_id != job_id or g.attempt != attempt:
        raise GenerationConflict("generation_owner_invalid")
    # Idempotent return refers to this historical generation, never reassigns current head.
    return resolve(s, g.investigation_id, generation_id=g.id)


def _publish_head(s, g, job):
    head = _fresh(s, InvestigationHead, g.investigation_id)
    if head:
        old = _fresh(s, EventGeneration, head.generation_id)
        old.status = "retained"
        head.generation_id, head.revision = g.id, g.parent_revision + 1
    else:
        s.add(InvestigationHead(investigation_id=g.investigation_id, generation_id=g.id, revision=1))
    g.revision, g.status, g.published_at = g.parent_revision + 1, "published", utcnow()
    reservation = _fresh(s, WriterReservation, g.investigation_id)
    s.delete(reservation)
    key = "generation_baseline" if g.purpose == "baseline" else "generation"
    job.stages = {
        **(job.stages or {}),
        key: {
            "id": g.id,
            "attempt": g.attempt,
            "published": True,
            "revision": g.revision,
            "output_sha256": g.output_sha256,
        },
    }
    s.flush()
    return _ref(g)


def publish(s, ref, *, job_id, attempt):
    lock_investigation(s, ref.investigation_id)
    g = _generation(s, ref)
    if g.status in READABLE:
        return _published(s, g, job_id, attempt)
    check_writer(s, ref, job_id=job_id, attempt=attempt)
    if g.status != "ready" or g.purpose != "replacement":
        raise GenerationConflict("generation_not_ready")
    _validate_ready(g, g.output_manifest, g.file_results)
    _validate_parent(s, g, g.output_manifest)
    job = _fresh(s, Job, job_id)
    touched = set()
    for result in g.file_results:
        f = _fresh(s, EvidenceFile, result["file_id"])
        for key in (
            "parser_id",
            "parser_version",
            "parse_status",
            "events_parsed",
            "events_failed",
            "error_samples",
            "message",
        ):
            setattr(f, key, deepcopy(result[key]))
        for key in ("first_ts", "last_ts"):
            setattr(f, key, _date(result[key]))
        f.parser_confidence = result.get("parser_confidence", f.parser_confidence)
        provenance.record_run(
            s,
            job=job,
            f=f,
            investigation_id=g.investigation_id,
            parser_id=result["parser_id"] or "",
            parser_version=result["parser_version"] or "",
            parser_fp=result["parser_digest"],
            settings=result["settings"],
            events=result["events_parsed"],
            failed=result["events_failed"],
            coverage=result["coverage"],
            status=result["parse_status"],
            started_at=_date(result["started_at"]),
        )
        touched.add(f.evidence_id)
    for evidence_id in touched:
        statuses = list(
            s.scalars(select(EvidenceFile.parse_status).where(EvidenceFile.evidence_id == evidence_id))
        )
        ev = _fresh(s, Evidence, evidence_id)
        ev.status = (
            "waiting_input"
            if all(x == "waiting_input" for x in statuses)
            else "failed"
            if all(x == "failed" for x in statuses)
            else "degraded"
            if any(x in {"failed", "degraded", "partial", "waiting_input"} for x in statuses)
            else "done"
        )
    inv = _fresh(s, Investigation, g.investigation_id)
    inv.settings = {**(inv.settings or {}), "data_epoch": g.data_epoch + 1}
    job.events_done = sum(r["events_parsed"] for r in g.file_results)
    return _publish_head(s, g, job)


def retain_baseline(s, ref, *, job_id, attempt):
    """Publish a verified legacy baseline without changing logical data or old history."""
    lock_investigation(s, ref.investigation_id)
    g = _generation(s, ref)
    if g.status in READABLE:
        return _published(s, g, job_id, attempt)
    check_writer(s, ref, job_id=job_id, attempt=attempt)
    if g.status != "ready" or g.purpose != "baseline" or g.parent_id is not None:
        raise GenerationConflict("generation_baseline_invalid")
    _validate_ready(g, g.output_manifest, [])
    job = _fresh(s, Job, job_id)
    return _publish_head(s, g, job)


def abandon(s, ref, *, job_id, attempt, reason):
    lock_investigation(s, ref.investigation_id, allow_deleting=True)
    g = _generation(s, ref)
    if g.job_id != job_id or g.attempt != attempt:
        raise GenerationConflict("generation_owner_invalid")
    if g.status in READABLE:
        return
    if g.status not in {"allocated", "ready", "abandoned"}:
        raise GenerationConflict("generation_state_invalid")
    g.status, g.abandoned_at = "abandoned", utcnow()
    g.reason = (
        reason if reason in {"cancelled", "stale", "recovery", "failed", "source_changed"} else "abandoned"
    )
    reservation = _fresh(s, WriterReservation, g.investigation_id)
    if reservation and (reservation.generation_id, reservation.job_id, reservation.attempt) == (
        g.id,
        job_id,
        attempt,
    ):
        s.delete(reservation)
    s.flush()


def recover(s, job):
    rows = list(
        s.scalars(
            select(EventGeneration)
            .where(EventGeneration.job_id == job.id)
            .order_by(EventGeneration.created_at.desc())
        )
    )
    published = None
    for g in rows:
        if g.status in {"allocated", "ready"}:
            abandon(s, _ref(g), job_id=g.job_id, attempt=g.attempt, reason="recovery")
        elif g.status in READABLE and g.purpose == "replacement" and published is None:
            published = g
    if published:
        resolve(s, job.investigation_id, generation_id=published.id)
        current = resolve(s, job.investigation_id)
        if current is None or current.generation_id != published.id:
            raise GenerationConflict("generation_published_superseded")
        return "analyze.run" if job.kind == "ingest" else "reprocess.run"
    return None


def retained_closure(s, investigation_id):
    rows = s.scalars(
        select(EventGeneration)
        .where(EventGeneration.investigation_id == investigation_id)
        .order_by(EventGeneration.created_at, EventGeneration.id)
    )
    return {
        "investigation_id": investigation_id,
        "generations": [
            {
                "generation_id": g.id,
                "job_id": g.job_id,
                "attempt": g.attempt,
                "status": g.status,
                "purpose": g.purpose,
                "storage_targets": deepcopy(g.storage_targets),
                "raw_objects": deepcopy(g.raw_objects),
                "output_sha256": g.output_sha256,
            }
            for g in rows
        ],
    }


def associate_analysis_run(s, run_id, generation_id):
    """Associate only an exact source/epoch match; never modify the historical payload/hash."""
    from saw.analysis_runs.models import AnalysisRun
    from saw.behavior.service import source_manifest

    run = _fresh(s, AnalysisRun, run_id)
    g = _fresh(s, EventGeneration, generation_id)
    if (
        run is None
        or g is None
        or g.purpose != "baseline"
        or g.status not in READABLE
        or run.investigation_id != g.investigation_id
    ):
        raise GenerationConflict("generation_history_mismatch")
    if (
        provenance.digest(run.input_manifest) != run.input_sha256
        or run.input_manifest.get("data_epoch") != g.data_epoch
    ):
        raise GenerationConflict("generation_history_mismatch")
    # Match the exact historical source projection at baseline time; source_jobs legitimately differ
    # because the reprocess request did not exist when the historical run was captured.
    current = source_manifest(s, g.investigation_id)
    if run.input_manifest.get("evidence") != current.get("evidence"):
        raise GenerationConflict("generation_history_mismatch")
    if (
        _source(s, _inv(s, g.investigation_id), _actor(s, g.requester_id, g.investigation_id))
        != g.input_manifest["source"]
    ):
        raise GenerationConflict("generation_history_mismatch")
    old = _fresh(s, AnalysisRunGeneration, run_id)
    if old:
        if old.generation_id != g.id or old.input_sha256 != run.input_sha256:
            raise GenerationConflict("generation_history_already_bound")
        return old
    row = AnalysisRunGeneration(
        run_id=run_id,
        generation_id=g.id,
        input_sha256=run.input_sha256,
        source_sha256=_hash(g.input_manifest["source"]),
    )
    s.add(row)
    s.flush()
    return row
