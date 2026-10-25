"""Synthetic, file-backed SQL lifecycle contracts; only physical planning is stubbed."""

import importlib.util
from copy import deepcopy
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from saw.analysis_runs.models import AnalysisRun
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.parsers.library import ParserDefinition
from saw.storage.db import Base, make_engine
from saw.storage.generations import GenerationConflict, GenerationUnavailable, GenerationVerificationError
from saw.storage.models import (
    Evidence,
    EvidenceFile,
    Investigation,
    InvestigationMember,
    Job,
    ProcessingRun,
    User,
)

GENERATION_ERRORS = (
    GenerationConflict,
    GenerationUnavailable,
    GenerationVerificationError,
    Forbidden,
    NotFound,
)


def test_lifecycle_is_available():
    assert importlib.util.find_spec("saw.event_generations") is not None, (
        "SQL generation lifecycle is missing"
    )


@pytest.fixture
def domain(tmp_path):
    from saw.event_generations import models
    from saw.event_generations import service as life

    engine = make_engine("sqlite:///" + str(tmp_path / "lifecycle.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as s:
        user = User(id="actor", username="synthetic", password_hash="unused", roles=["analyst"])
        s.add(user)
        s.flush()
        s.add(Investigation(id="inv", display_id="SYN-1", title="Synthetic", owner_id=user.id))
        s.flush()
        s.add(InvestigationMember(investigation_id="inv", user_id=user.id, access="owner"))
        s.add(Evidence(id="ev", investigation_id="inv", kind="log", uploaded_by=user.id, status="done"))
        s.flush()
        s.add(
            EvidenceFile(
                id="file",
                evidence_id="ev",
                display_name="synthetic.jsonl",
                object_key="raw/input",
                sha256="a" * 64,
                size=24,
                parser_id="json_lines",
                parser_version="1",
                parse_status="done",
                events_parsed=7,
            )
        )
        s.add(
            Job(
                id="old",
                investigation_id="inv",
                evidence_id="ev",
                kind="ingest",
                requested_by=user.id,
                state="COMPLETED",
                events_done=7,
                stages={"old": True},
            )
        )
    yield life, models, factory
    engine.dispose()


class PlanOnly:
    def plan_targets(self, investigation_id, generation_id):
        return ("synthetic-" + investigation_id + "-" + generation_id,)


def request(domain):
    life, _models, factory = domain
    with factory.begin() as s:
        # Resolve a real built-in ID from the registry, avoiding assumptions about its spelling.
        from saw.parsers.registry import builtin_parsers

        pid = builtin_parsers()[0].id
        f = s.get(EvidenceFile, "file")
        f.parser_id = pid
        f.parser_version = builtin_parsers()[0].version
        job = life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "file", pid)
        jid = job.id
    return jid


def allocated(domain, jid=None):
    life, _models, factory = domain
    jid = jid or request(domain)
    with factory.begin() as s:
        job = s.get(Job, jid)
        job.attempt += 1
        job.state = "PARSING"
        s.flush()
        ref = life.allocate(s, job, attempt=job.attempt, store=PlanOnly())
    return jid, ref


def receipt(domain, ref):
    life, models, factory = domain
    with factory() as s:
        gen = s.get(models.EventGeneration, ref.generation_id)
        parser = gen.input_manifest["replacements"][0]["parser"]
        raw = {
            "bucket": "saw-evidence-original",
            "key": "raw/input",
            "byte_length": 24,
            "sha256": "a" * 64,
            "owner_generation_id": None,
            "owner_attempt": None,
            "retained": True,
        }
        file = {
            "evidence_id": "ev",
            "file_id": "file",
            "replacement": True,
            "unique_count": 3,
            "events_sha256": "c" * 64,
            "source_closure": life.expected_source_closure(gen.input_manifest, "ev", "file"),
            "parse_status": "done",
            "quality": {},
            "coverage": {},
            "raw_objects": [raw],
        }
        manifest = {
            "format": "saw-event-generation/1",
            "investigation_id": "inv",
            "generation_id": gen.id,
            "storage_targets": list(ref.storage_targets),
            "input_sha256": gen.input_sha256,
            "unique_count": 3,
            "output_sha256": "b" * 64,
            "files": [file],
            "raw_objects": [raw],
            "rejected": 0,
            "sealed": True,
            "complete": True,
        }
        result = {
            "evidence_id": "ev",
            "file_id": "file",
            "parser_id": parser["id"] if parser else None,
            "parser_version": parser["version"] if parser else None,
            "parser_digest": parser["digest"] if parser else "",
            "settings": {"encoding": "utf-8"},
            "started_at": datetime.now(UTC).isoformat(),
            "parse_status": "done",
            "coverage": {},
            "events_parsed": 3,
            "events_failed": 0,
            "first_ts": None,
            "last_ts": None,
            "error_samples": [],
            "message": "",
        }
        return manifest, [result]


def ready(domain, jid=None):
    life, _models, factory = domain
    jid, ref = allocated(domain, jid)
    manifest, results = receipt(domain, ref)
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=results)
    return jid, ref


def test_request_does_not_mutate_existing_file_or_job(domain):
    _life, _models, factory = domain
    jid = request(domain)
    with factory() as s:
        assert s.get(EvidenceFile, "file").events_parsed == 7
        assert s.get(EvidenceFile, "file").parse_status == "done"
        assert s.get(Job, "old").stages == {"old": True}
        job = s.get(Job, jid)
        assert job.kind == "reprocess" and job.state == "QUEUED"
        assert job.stages["_queue_task"] == "reprocess.run"
        assert job.stages["generation_request"]["input"]["replacements"][0]["file_id"] == "file"


def test_staged_invisible_publish_is_atomic_and_idempotent(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        assert life.resolve(s, "inv") is None
        with pytest.raises(GENERATION_ERRORS):
            life.resolve(s, "inv", generation_id=ref.generation_id)
        published = life.publish(s, ref, job_id=jid, attempt=1)
        assert life.resolve(s, "inv") == published
        assert s.get(EvidenceFile, "file").events_parsed == 3
        assert s.get(Investigation, "inv").settings["data_epoch"] == 1
        assert s.scalar(select(ProcessingRun)).events == 3
        assert s.get(models.WriterReservation, "inv") is None
        assert life.publish(s, ref, job_id=jid, attempt=1) == published
    with factory() as s:
        assert life.resolve(s, "inv") == published
        assert len(list(s.scalars(select(ProcessingRun)))) == 1


def test_publish_rollback_keeps_old_current(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
        s.rollback()
    with factory() as s:
        assert life.resolve(s, "inv") is None
        assert s.get(EvidenceFile, "file").events_parsed == 7
        assert s.scalar(select(ProcessingRun)) is None
        assert s.get(models.EventGeneration, ref.generation_id).status == "ready"


@pytest.mark.parametrize(
    "mutation", ["attempt", "cancel", "actor", "membership", "source", "epoch", "request", "parser"]
)
def test_stale_writers_are_fenced(domain, mutation):
    life, _models, factory = domain
    jid, ref = allocated(domain)
    with factory.begin() as s:
        if mutation == "attempt":
            s.get(Job, jid).attempt = 2
        elif mutation == "cancel":
            s.get(Job, jid).cancel_requested = True
        elif mutation == "actor":
            s.get(User, "actor").status = "disabled"
        elif mutation == "membership":
            s.get(InvestigationMember, ("inv", "actor")).access = "viewer"
        elif mutation == "source":
            s.get(EvidenceFile, "file").sha256 = "d" * 64
        elif mutation == "epoch":
            s.get(Investigation, "inv").settings = {"data_epoch": 2}
        elif mutation == "request":
            from sqlalchemy import update

            s.execute(update(Job).where(Job.id == jid).values(stages={}))
        elif mutation == "parser":
            s.get(EvidenceFile, "file").parser_version = "changed"
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.check_writer(s, ref, job_id=jid, attempt=1)


def test_one_reservation_new_attempt_requires_abandon(domain):
    life, _models, factory = domain
    jid, ref = allocated(domain)
    with factory.begin() as s:
        assert life.allocate(s, s.get(Job, jid), attempt=1, store=PlanOnly()) == ref
    other = request(domain)
    with factory() as s:
        j = s.get(Job, other)
        j.attempt = 1
        j.state = "PARSING"
        s.flush()
        with pytest.raises(GENERATION_ERRORS):
            life.allocate(s, j, attempt=1, store=PlanOnly())
    with factory.begin() as s:
        life.abandon(s, ref, job_id=jid, attempt=1, reason="cancelled")
        s.get(Job, jid).attempt = 2
        s.flush()
        second = life.allocate(s, s.get(Job, jid), attempt=2, store=PlanOnly())
        assert second.generation_id != ref.generation_id
        assert second.storage_targets != ref.storage_targets
        assert len(life.retained_closure(s, "inv")["generations"]) == 2


@pytest.mark.parametrize(
    "bad", ["incomplete", "unsealed", "rejected", "input", "targets", "zero", "failed", "raw"]
)
def test_ready_rejects_invalid_receipts(domain, bad):
    life, _models, factory = domain
    _jid, ref = allocated(domain)
    manifest, results = receipt(domain, ref)
    if bad == "incomplete":
        manifest["complete"] = False
    elif bad == "unsealed":
        manifest["sealed"] = False
    elif bad == "rejected":
        manifest["rejected"] = 1
    elif bad == "input":
        manifest["input_sha256"] = "d" * 64
    elif bad == "targets":
        manifest["storage_targets"] = ["foreign"]
    elif bad == "zero":
        manifest["files"][0]["unique_count"] = 0
    elif bad == "failed":
        manifest["files"][0]["parse_status"] = "failed"
    elif bad == "raw":
        manifest["raw_objects"][0]["sha256"] = "wrong"
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.mark_ready(s, ref, manifest, file_results=results)


def test_recovery_abandons_ready_but_preserves_published(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        assert life.recover(s, s.get(Job, jid)) is None
        assert s.get(models.EventGeneration, ref.generation_id).status == "abandoned"
        assert life.resolve(s, "inv") is None
        assert life.retained_closure(s, "inv")["generations"][0]["raw_objects"]
    jid, ref = ready(domain, jid)
    with factory.begin() as s:
        pub = life.publish(s, ref, job_id=jid, attempt=2)
        assert life.recover(s, s.get(Job, jid)) == "reprocess.run"
        assert life.resolve(s, "inv") == pub


def test_missing_referenced_head_is_not_legacy(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
        from sqlalchemy import update

        s.execute(
            update(models.EventGeneration)
            .where(models.EventGeneration.id == ref.generation_id)
            .values(output_sha256="")
        )
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.resolve(s, "inv")


def test_unpinned_user_parser_is_exact_and_revoked_use_fails(domain):
    life, _models, factory = domain
    from saw.parsers.custom import ParserSpec

    with factory.begin() as s:
        s.add(
            ParserDefinition(
                id="parser",
                slug="synthetic",
                name="Synthetic",
                version=2,
                status="active",
                created_by="actor",
                spec=ParserSpec(format="json").model_dump(),
            )
        )
        f = s.get(EvidenceFile, "file")
        f.parser_id = None
        s.flush()
        job = life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "file", "u:synthetic")
        assert job.stages["generation_request"]["input"]["replacements"][0]["parser"]["id"] == "u:synthetic@2"
        jid = job.id
    jid, ref = allocated(domain, jid)
    with factory.begin() as s:
        s.get(ParserDefinition, "parser").status = "disabled"
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.check_writer(s, ref, job_id=jid, attempt=1)


def test_request_rejects_draft_of_other_author_and_wrong_file(domain):
    life, _models, factory = domain
    from saw.core.application.investigations import Forbidden, NotFound
    from saw.parsers.custom import ParserSpec

    with factory.begin() as s:
        s.add(
            ParserDefinition(
                slug="private",
                name="Private",
                version=1,
                status="draft",
                created_by="other",
                spec=ParserSpec(format="json").model_dump(),
            )
        )
    with factory() as s, pytest.raises(Forbidden):
        life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "file", "u:private@1")
    with factory() as s, pytest.raises(NotFound):
        life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "foreign", "u:private@1")


def test_staging_raw_closure_has_correct_bucket_and_rejects_unowned_retained_object(domain):
    life, _models, factory = domain
    _jid, ref = allocated(domain)
    with factory() as s:
        raw = life.retained_closure(s, "inv")["generations"][0]["raw_objects"][0]
        assert raw["bucket"] == "saw-evidence-original"
        assert raw["key"] == "raw/input"
    manifest, results = receipt(domain, ref)
    manifest["raw_objects"][0]["key"] = "foreign"
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.mark_ready(s, ref, manifest, file_results=results)


def test_derived_raw_must_be_registered_before_ready_and_survives_abandon(domain):
    life, _models, factory = domain
    jid, ref = allocated(domain)
    raw = {
        "bucket": "saw-evidence-extracted",
        "key": f"generations/{ref.generation_id}/1/synthetic",
        "byte_length": 4,
        "sha256": "d" * 64,
        "owner_generation_id": ref.generation_id,
        "owner_attempt": 1,
        "retained": False,
    }
    with factory.begin() as s:
        life.register_raw_objects(s, ref, [raw], job_id=jid, attempt=1)
    with factory.begin() as s:
        life.abandon(s, ref, job_id=jid, attempt=1, reason="failed")
        assert raw in life.retained_closure(s, "inv")["generations"][0]["raw_objects"]


def test_baseline_preserves_epoch_history_hash_and_allows_same_attempt_replacement(domain):
    life, _models, factory = domain
    jid = request(domain)
    with factory.begin() as s:
        from saw.behavior.service import source_manifest
        from saw.core.application.provenance import digest

        old = source_manifest(s, "inv")
        s.add(
            AnalysisRun(
                id="history",
                investigation_id="inv",
                version=1,
                status="done",
                input_manifest=old,
                input_sha256=digest(old),
                scope={},
            )
        )
        job = s.get(Job, jid)
        job.attempt = 1
        job.state = "PARSING"
        s.flush()
        baseline = life.allocate(s, job, attempt=1, store=PlanOnly(), baseline=True)
        old_hash = digest(old)
    manifest, _ = receipt(domain, baseline)
    manifest["files"][0].update(replacement=False, unique_count=7)
    manifest["unique_count"] = 7
    with factory.begin() as s:
        life.mark_ready(s, baseline, manifest, file_results=[])
        pub = life.retain_baseline(s, baseline, job_id=jid, attempt=1)
        life.associate_analysis_run(s, "history", baseline.generation_id)
        assert s.get(AnalysisRun, "history").input_sha256 == old_hash
        assert s.get(AnalysisRun, "history").input_manifest == old
        assert s.get(Investigation, "inv").settings.get("data_epoch", 0) == 0
        assert s.scalar(select(ProcessingRun)) is None
        assert s.get(EvidenceFile, "file").events_parsed == 7
        replacement = life.allocate(s, s.get(Job, jid), attempt=1, store=PlanOnly())
        assert replacement.generation_id != baseline.generation_id
        assert replacement.head_revision == pub.head_revision
    manifest, results = receipt(domain, replacement)
    with factory.begin() as s:
        life.mark_ready(s, replacement, manifest, file_results=results)
        latest = life.publish(s, replacement, job_id=jid, attempt=1)
        assert life.retain_baseline(s, baseline, job_id=jid, attempt=1) == pub
        assert life.resolve(s, "inv") == latest
        assert s.get(AnalysisRun, "history").input_sha256 == old_hash


def test_immutable_request_cannot_be_replaced_even_with_matching_digest(domain):
    life, _models, factory = domain
    jid = request(domain)
    with factory() as s, pytest.raises(ValueError, match="immutable"):
        job = s.get(Job, jid)
        changed = deepcopy(job.stages)
        changed["generation_request"]["input"]["source"]["evidence"][0]["files"][0]["sha256"] = "e" * 64
        changed["generation_request"]["sha256"] = life._hash(changed["generation_request"]["input"])
        job.stages = changed
        s.flush()


def test_published_generation_metadata_is_immutable(domain):
    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
    with factory() as s, pytest.raises(ValueError, match="immutable"):
        s.get(models.EventGeneration, ref.generation_id).storage_targets = ["other"]
        s.flush()


def test_two_sql_sessions_serialize_the_reservation(domain):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from saw.storage.generations import GenerationConflict

    life, models, factory = domain
    first = request(domain)
    second = request(domain)
    entered = Event()

    def competing_writer():
        entered.set()
        with factory.begin() as other:
            job = other.get(Job, second)
            job.attempt = 1
            job.state = "PARSING"
            other.flush()
            try:
                life.allocate(other, job, attempt=1, store=PlanOnly())
            except GenerationConflict as exc:
                return str(exc)
            return "unexpected_success"

    with ThreadPoolExecutor(max_workers=1) as pool:
        with factory.begin() as s:
            job = s.get(Job, first)
            job.attempt = 1
            job.state = "PARSING"
            s.flush()
            ref = life.allocate(s, job, attempt=1, store=PlanOnly())
            future = pool.submit(competing_writer)
            assert entered.wait(5)
        assert future.result(timeout=10) == "generation_writer_reserved"
    with factory() as s:
        assert s.get(models.WriterReservation, "inv").generation_id == ref.generation_id
        assert len(list(s.scalars(select(models.EventGeneration)))) == 1


def test_copied_source_change_and_parent_cas_are_fenced(domain):
    life, _models, factory = domain
    jid = request(domain)
    with factory.begin() as s:
        # Changes to a source unrelated to the replacement also stale the immutable request.
        s.add(
            EvidenceFile(
                id="copy",
                evidence_id="ev",
                display_name="copied",
                object_key="copy",
                sha256="c" * 64,
                size=4,
                parse_status="done",
                events_parsed=2,
            )
        )
    with factory() as s:
        job = s.get(Job, jid)
        job.attempt = 1
        job.state = "PARSING"
        s.flush()
        with pytest.raises(GENERATION_ERRORS, match="generation_source_changed"):
            life.allocate(s, job, attempt=1, store=PlanOnly())


def test_same_ready_receipt_is_idempotent_different_receipt_rejected(domain):
    life, models, factory = domain
    _jid, ref = ready(domain)
    with factory() as s:
        g = s.get(models.EventGeneration, ref.generation_id)
        manifest, results = deepcopy(g.output_manifest), deepcopy(g.file_results)
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=results)
    manifest["output_sha256"] = "e" * 64
    with factory() as s, pytest.raises(GENERATION_ERRORS, match="generation_ready_conflict"):
        life.mark_ready(s, ref, manifest, file_results=results)


def test_resolve_rejects_corrupt_manifest_closure(domain):
    from sqlalchemy import update

    life, models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
        s.execute(
            update(models.EventGeneration)
            .where(models.EventGeneration.id == ref.generation_id)
            .values(storage_targets=["substituted"])
        )
    with factory() as s, pytest.raises(GENERATION_ERRORS, match="generation_reference_unavailable"):
        life.resolve(s, "inv")


def test_registered_derived_object_cannot_reuse_abandoned_attempt_path(domain):
    life, _models, factory = domain
    jid, ref = allocated(domain)
    raw = {
        "bucket": "saw-evidence-extracted",
        "key": f"generations/{ref.generation_id}/1/shared-key",
        "byte_length": 4,
        "sha256": "d" * 64,
        "owner_generation_id": ref.generation_id,
        "owner_attempt": 1,
        "retained": False,
    }
    with factory.begin() as s:
        life.register_raw_objects(s, ref, [raw], job_id=jid, attempt=1)
        life.abandon(s, ref, job_id=jid, attempt=1, reason="failed")
    jid, new = allocated(domain, jid)
    raw.update(owner_generation_id=new.generation_id, owner_attempt=2)
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.register_raw_objects(s, new, [raw], job_id=jid, attempt=2)


def test_history_association_rejects_old_source_mismatch(domain):
    life, _models, factory = domain
    jid = request(domain)
    from saw.behavior.service import source_manifest
    from saw.core.application.provenance import digest

    with factory.begin() as s:
        old = source_manifest(s, "inv")
        old["evidence"][0]["files"][0]["sha256"] = "f" * 64
        s.add(
            AnalysisRun(
                id="wrong-history",
                investigation_id="inv",
                version=1,
                status="done",
                input_manifest=old,
                input_sha256=digest(old),
                scope={},
            )
        )
        job = s.get(Job, jid)
        job.attempt = 1
        job.state = "PARSING"
        s.flush()
        ref = life.allocate(s, job, attempt=1, store=PlanOnly(), baseline=True)
    manifest, _ = receipt(domain, ref)
    manifest["files"][0]["replacement"] = False
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=[])
        life.retain_baseline(s, ref, job_id=jid, attempt=1)
    with factory() as s, pytest.raises(GENERATION_ERRORS, match="generation_history_mismatch"):
        life.associate_analysis_run(s, "wrong-history", ref.generation_id)


def test_ready_rejects_unverified_parser_source_closure(domain):
    life, _models, factory = domain
    _jid, ref = allocated(domain)
    manifest, results = receipt(domain, ref)
    manifest["files"][0]["source_closure"] = {"parser": "foreign"}
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.mark_ready(s, ref, manifest, file_results=results)


def test_raw_registration_requires_generation_namespace(domain):
    life, _models, factory = domain
    jid, ref = allocated(domain)
    raw = {
        "bucket": "saw-evidence-extracted",
        "key": "arbitrary-global-path",
        "byte_length": 4,
        "sha256": "d" * 64,
        "owner_generation_id": ref.generation_id,
        "owner_attempt": 1,
        "retained": False,
    }
    with factory() as s, pytest.raises(GENERATION_ERRORS):
        life.register_raw_objects(s, ref, [raw], job_id=jid, attempt=1)


@pytest.mark.parametrize(
    "status,parser_assigned", [("failed", True), ("waiting_input", False), ("skipped", False)]
)
def test_initial_ingest_empty_results_remain_explicit(domain, status, parser_assigned):
    life, models, factory = domain
    from saw.parsers.registry import builtin_parsers

    with factory.begin() as s:
        f = s.get(EvidenceFile, "file")
        f.events_parsed = 0
        f.parse_status = "pending"
        f.parser_id = builtin_parsers()[0].id if parser_assigned else None
        f.parser_version = builtin_parsers()[0].version if parser_assigned else None
        job = Job(
            investigation_id="inv",
            evidence_id="ev",
            kind="ingest",
            requested_by="actor",
            state="PARSING",
            attempt=1,
        )
        s.add(job)
        s.flush()
        jid = job.id
        ref = life.allocate(s, job, attempt=1, store=PlanOnly())
        assert s.get(models.EventGeneration, ref.generation_id).input_manifest["replacements"], (
            "pending leaf result is omitted"
        )
    manifest, results = receipt(domain, ref)
    manifest["unique_count"] = 0
    manifest["files"][0].update(unique_count=0, replacement=False, parse_status=status)
    results[0].update(events_parsed=0, parse_status=status)
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=results)
        life.publish(s, ref, job_id=jid, attempt=1)
        assert s.get(EvidenceFile, "file").parse_status == status
        assert s.get(EvidenceFile, "file").events_parsed == 0
        assert s.scalar(select(ProcessingRun)).status == status
        assert life.recover(s, s.get(Job, jid)) == "analyze.run"


def test_pcap_request_pins_real_engine_and_accepts_historical_parser_label(domain):
    life, _models, factory = domain
    from saw.integrations.pcapkit import PRODUCER

    with factory.begin() as s:
        s.get(EvidenceFile, "file").parser_id = "pcap(builtin)"
        s.flush()
        job = life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "file", "pcap")
        spec = job.stages["generation_request"]["input"]["replacements"][0]["parser"]
        assert spec["version"] == PRODUCER.rpartition("/")[2]
        assert len(spec["digest"]) == 64


def test_read_resolution_and_retention_issue_no_writes(domain):
    from sqlalchemy import event

    life, _models, factory = domain
    jid, ref = ready(domain)
    with factory.begin() as s:
        life.publish(s, ref, job_id=jid, attempt=1)
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lstrip().split()[0].upper())

    engine = factory.kw["bind"]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        with factory() as s:
            life.resolve(s, "inv")
            life.resolve(s, "inv", generation_id=ref.generation_id)
            life.retained_closure(s, "inv")
        assert statements and set(statements) == {"SELECT"}
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def test_copied_parent_file_hash_cannot_change_and_rows_stay_unchanged(domain):
    life, models, factory = domain
    jid, parent = ready(domain)
    with factory.begin() as s:
        life.publish(s, parent, job_id=jid, attempt=1)
        s.get(Job, jid).state = "COMPLETED"
        original = deepcopy(s.get(models.EventGeneration, parent.generation_id).output_manifest)
        s.add(Evidence(id="ev2", investigation_id="inv", kind="log", uploaded_by="actor"))
        s.flush()
        s.add(
            EvidenceFile(
                id="new-file",
                evidence_id="ev2",
                display_name="empty",
                object_key="empty",
                sha256="e" * 64,
                size=0,
            )
        )
        job = Job(
            investigation_id="inv",
            evidence_id="ev2",
            kind="ingest",
            requested_by="actor",
            state="PARSING",
            attempt=1,
        )
        s.add(job)
        s.flush()
        new_id = job.id
        ref = life.allocate(s, job, attempt=1, store=PlanOnly())
        gen = s.get(models.EventGeneration, ref.generation_id)
        manifest = deepcopy(original)
        manifest.update(
            generation_id=ref.generation_id,
            storage_targets=list(ref.storage_targets),
            input_sha256=gen.input_sha256,
        )
        manifest["files"][0]["replacement"] = False
        manifest["files"].append(
            {
                "evidence_id": "ev2",
                "file_id": "new-file",
                "replacement": False,
                "unique_count": 0,
                "events_sha256": "e" * 64,
                "source_closure": life.expected_source_closure(gen.input_manifest, "ev2", "new-file"),
                "parse_status": "waiting_input",
                "quality": {},
                "coverage": {},
                "raw_objects": [],
            }
        )
        result = {
            "evidence_id": "ev2",
            "file_id": "new-file",
            "parser_id": None,
            "parser_version": None,
            "parser_digest": "",
            "settings": {},
            "started_at": None,
            "parse_status": "waiting_input",
            "coverage": {},
            "events_parsed": 0,
            "events_failed": 0,
            "first_ts": None,
            "last_ts": None,
            "error_samples": [],
            "message": "",
        }
    wrong = deepcopy(manifest)
    wrong["files"][0]["events_sha256"] = "f" * 64
    with factory() as s, pytest.raises(GENERATION_ERRORS, match="generation_parent_file_changed"):
        life.mark_ready(s, ref, wrong, file_results=[result])
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=[result])
        life.publish(s, ref, job_id=new_id, attempt=1)
        assert s.get(EvidenceFile, "file").events_parsed == 3
        assert len(list(s.scalars(select(ProcessingRun).where(ProcessingRun.file_id == "file")))) == 1
        assert s.get(EvidenceFile, "new-file").parse_status == "waiting_input"


def test_disabled_historical_unpinned_parser_can_be_replaced_by_builtin(domain):
    life, _models, factory = domain
    from saw.parsers.custom import ParserSpec
    from saw.parsers.registry import builtin_parsers

    with factory.begin() as s:
        s.add(
            ParserDefinition(
                slug="historical",
                name="Historical",
                version=2,
                status="disabled",
                created_by="actor",
                spec=ParserSpec(format="json").model_dump(),
            )
        )
        f = s.get(EvidenceFile, "file")
        f.parser_id = "u:historical"
        f.parser_version = "2"
        s.flush()
        job = life.request_reprocess(
            s, principal_of(s.get(User, "actor")), "ev", "file", builtin_parsers()[0].id
        )
        assert (
            job.stages["generation_request"]["input"]["source"]["evidence"][0]["files"][0]["parser"]["id"]
            == "u:historical@2"
        )


def test_recovery_of_superseded_publication_fails_without_moving_newer_head(domain):
    life, models, factory = domain
    jid, old = ready(domain)
    with factory.begin() as s:
        life.publish(s, old, job_id=jid, attempt=1)
        s.get(Job, jid).state = "COMPLETED"
    newer_id, newer = ready(domain)
    with factory.begin() as s:
        published = life.publish(s, newer, job_id=newer_id, attempt=1)
    with factory() as s, pytest.raises(GenerationConflict, match="generation_published_superseded"):
        life.recover(s, s.get(Job, jid))
    with factory() as s:
        assert life.resolve(s, "inv") == published
        assert s.get(models.EventGeneration, old.generation_id).status == "retained"


def test_legacy_pcap_objects_are_registered_only_for_captured_baseline_sources(domain):
    life, models, factory = domain
    assert hasattr(life, "register_legacy_objects"), "legacy PCAP closure registration is missing"
    with factory.begin() as s:
        s.get(EvidenceFile, "file").parser_id = "pcap(builtin)"
        s.flush()
        job = life.request_reprocess(s, principal_of(s.get(User, "actor")), "ev", "file", "pcap")
        job.attempt = 1
        job.state = "PARSING"
        s.flush()
        jid = job.id
        ref = life.allocate(s, job, attempt=1, store=PlanOnly(), baseline=True)
    raw = {
        "bucket": "saw-artifacts",
        "key": "inv/ev/file/builtin/conn.log",
        "byte_length": 24,
        "sha256": "d" * 64,
        "owner_generation_id": None,
        "owner_attempt": None,
        "retained": True,
    }
    with factory.begin() as s:
        life.register_legacy_objects(s, ref, [raw], job_id=jid, attempt=1)
        assert raw in life.retained_closure(s, "inv")["generations"][0]["raw_objects"]
    foreign = {**raw, "key": "foreign/ev/file/builtin/conn.log"}
    with factory() as s, pytest.raises(GenerationConflict):
        life.register_legacy_objects(s, ref, [foreign], job_id=jid, attempt=1)
    manifest, _ = receipt(domain, ref)
    manifest["files"][0].update(replacement=False, raw_objects=[raw])
    manifest["raw_objects"] = [raw]
    with factory.begin() as s:
        life.mark_ready(s, ref, manifest, file_results=[])
        life.retain_baseline(s, ref, job_id=jid, attempt=1)
        assert s.get(models.EventGeneration, ref.generation_id).status == "published"
