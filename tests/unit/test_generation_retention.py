"""Real file-backed SQL/event/object retention; all fixtures are synthetic."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from saw import container
from saw.core.application import data_deletion as deletion
from saw.core.application.identity import principal_of
from saw.event_generations import service as life
from saw.event_generations.models import EventGeneration, InvestigationHead
from saw.storage.db import Base, load_models, make_engine
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.generations import GenerationRef, event_stream_sha256
from saw.storage.models import Evidence, EvidenceFile, Investigation, InvestigationMember, User
from saw.storage.objectstore import LocalFSObjectStore


@pytest.fixture
def domain(tmp_path):
    load_models()
    engine = make_engine("sqlite:///" + str(tmp_path / "metadata.db"))
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    objects = LocalFSObjectStore(tmp_path / "objects")
    legacy = SQLiteEventStore(str(tmp_path / "legacy.db"))
    from saw.event_generations.reads import EventFacade, actor_scope

    facade = EventFacade(
        legacy,
        objects=objects,
        session_factory=factory,
        settings=SimpleNamespace(data_dir=tmp_path, session_idle_minutes=30),
    )
    store = facade.generations
    c = SimpleNamespace(
        events=facade, legacy_events=legacy, generations=store, objects=objects, session_factory=factory
    )
    with factory.begin() as s:
        admin = User(id="admin", username="admin", password_hash="unused", roles=["admin"])
        analyst = User(id="analyst", username="analyst", password_hash="unused", roles=["analyst"])
        s.add_all([admin, analyst])
        s.flush()
        for iid, eids in [("inv", ["remove", "keep"]), ("other", ["foreign"])]:
            s.add(
                Investigation(id=iid, display_id="SYN-" + iid, title="Private synthetic", owner_id="analyst")
            )
            s.flush()
            s.add(InvestigationMember(investigation_id=iid, user_id="analyst", access="owner"))
            for eid in eids:
                s.add(
                    Evidence(id=eid, investigation_id=iid, kind="log", uploaded_by="analyst", status="done")
                )
                s.flush()
                key = f"{iid}/{eid}/file-{eid}"
                size, sha = objects.put_bytes("saw-evidence-original", key, b"synthetic raw\n")
                s.add(
                    EvidenceFile(
                        id="file-" + eid,
                        evidence_id=eid,
                        display_name="private-" + eid,
                        object_key=key,
                        sha256=sha,
                        size=size,
                        events_parsed=1,
                        parse_status="done",
                    )
                )
        s.flush()
        principal = principal_of(admin)
    d = SimpleNamespace(c=c, factory=factory, principal=principal, tmp=tmp_path, refs={})
    for iid, gid, state in [
        ("inv", "old", "retained"),
        ("inv", "current", "published"),
        ("inv", "staged", "allocated"),
        ("other", "other-current", "published"),
    ]:
        _generation(d, iid, gid, state)
    with container.activate(c, factory), actor_scope("analyst"):
        yield d
    legacy.close() if hasattr(legacy, "close") else None
    engine.dispose()


def _generation(d, iid, gid, state, *, reprocessed=False):
    store, objects = d.c.generations, d.c.objects
    eids = ["remove", "keep"] if iid == "inv" else ["foreign"]
    raw, files, events, sources = [], [], [], []
    for eid in eids:
        with d.factory() as s:
            f = s.get(EvidenceFile, "file-" + eid)
            source = {
                name: getattr(f, name)
                for name in ["id", "display_name", "object_key", "sha256", "size", "events_parsed"]
            }
            source.update(parent_file_id=None, parser=None)
        # Every generation has unique derived bytes, including the abandoned/staged target.
        key = f"generations/{gid}/1/{eid}.raw"
        size, sha = objects.put_bytes("saw-artifacts", key, b"synthetic raw\n")
        obj = {
            "bucket": "saw-artifacts",
            "key": key,
            "byte_length": size,
            "sha256": sha,
            "owner_generation_id": gid,
            "owner_attempt": 1,
            "retained": False,
        }
        raw.append(obj)
        event = {
            "event_id": "event-" + eid,
            "investigation_id": iid,
            "evidence_id": eid,
            "file_id": "file-" + eid,
            "source_file": "private-" + eid,
            "parser": "fixture",
            "parser_version": "1",
            "timestamp": "2026-10-20T00:00:00Z",
            "raw_ref": {"object_key": "saw-artifacts/" + key, "offset": 0, "length": size},
        }
        events.append(event)
        files.append(
            {
                "evidence_id": eid,
                "file_id": "file-" + eid,
                "replacement": False,
                "unique_count": 1,
                "events_sha256": event_stream_sha256([event]),
                "source_closure": {"evidence_id": eid},
                "parse_status": "done",
                "quality": {"kept": True},
                "coverage": {"events": 1},
                "raw_objects": [obj],
            }
        )
        sources.append({"id": eid, "files": [source]})
    inp = {
        "format": "saw-generation-input/1",
        "job_kind": "ingest",
        "investigation_id": iid,
        "data_epoch": 0,
        "requester_id": "analyst",
        "source": {"investigation": {}, "evidence": sources},
        "replacements": [],
    }
    results = []
    if reprocessed:
        inp["job_kind"] = "reprocess"
        parser = {"id": "fixture", "version": "1", "digest": "a" * 64}
        inp["replacements"] = [{"evidence_id": "keep", "file_id": "file-keep", "parser": parser}]
        sources[1]["files"][0]["events_parsed"] = 9
        files[1]["replacement"] = True
        files[1]["source_closure"] = life.expected_source_closure(inp, "keep", "file-keep")
        results = [
            {
                "evidence_id": "keep",
                "file_id": "file-keep",
                "parser_id": "fixture",
                "parser_version": "1",
                "parser_digest": "a" * 64,
                "settings": {},
                "started_at": None,
                "parse_status": "done",
                "coverage": {"events": 1},
                "events_parsed": 1,
                "events_failed": 0,
                "first_ts": None,
                "last_ts": None,
                "error_samples": [],
                "message": "Immutable current result",
            }
        ]
    sha = life._hash(inp)
    ref = GenerationRef(iid, gid, 1, "", store.plan_targets(iid, gid), False)
    with d.factory.begin() as s:
        s.add(
            EventGeneration(
                id=gid,
                investigation_id=iid,
                job_id="job-" + gid,
                attempt=1,
                purpose=("replacement" if reprocessed else "baseline"),
                requester_id="analyst",
                data_epoch=0,
                input_manifest=inp,
                input_sha256=sha,
                storage_targets=list(ref.storage_targets),
                raw_objects=raw,
                status="allocated",
            )
        )
    store.create_target(ref, job_id="job-" + gid, attempt=1, input_sha256=sha, check=lambda: None)
    writer = store.begin_write(ref, job_id="job-" + gid, attempt=1, input_sha256=sha, check=lambda: None)
    writer.index(events)
    if state != "allocated":
        writer.seal()
        output = writer.verify(expected_files=files, check=lambda: None)
        with d.factory.begin() as s:
            g = s.get(EventGeneration, gid)
            g.file_results = results
            g.output_manifest = output
            g.output_sha256 = output["output_sha256"]
            g.status = state
            g.revision = 1
            if state == "published":
                s.add(InvestigationHead(investigation_id=iid, generation_id=gid, revision=1))
        ref = GenerationRef(iid, gid, 1, output["output_sha256"], ref.storage_targets, False)
    d.refs[gid] = ref


def run(d, kind="investigation", tid="inv"):
    with d.factory() as s:
        p = deletion.preview(s, kind, tid)
        assert not p["blockers"], p["blockers"]
        return deletion.start(
            s, d.principal, kind, tid, p["confirmation"], p["fingerprint"], "Synthetic retention cleanup"
        )


def retry(d, did):
    with d.factory() as s:
        return deletion.resume(s, did, requested_by=d.principal)


def test_whole_cleanup_removes_every_generation_and_only_owned_bytes(domain):
    d = domain
    result = run(d)
    assert result.state == "COMPLETED"
    assert not any(Path(d.refs[g].storage_targets[0]).exists() for g in ["old", "current", "staged"])
    assert Path(d.refs["other-current"].storage_targets[0]).is_file()
    assert not d.c.objects.exists("saw-artifacts", "generations/old/1/remove.raw")
    assert d.c.objects.exists("saw-artifacts", "generations/other-current/1/foreign.raw")
    with d.factory() as s:
        assert s.get(Investigation, "inv") is None
        assert s.get(Investigation, "other") is not None
        assert list(s.scalars(select(EventGeneration.id))) == ["other-current"]


def test_partial_cleanup_publishes_filtered_immutable_generation(domain):
    d = domain
    result = run(d, "evidence", "remove")
    assert result.state == "COMPLETED"
    with d.factory() as s:
        ref = life.resolve(s, "inv")
        assert ref.generation_id != "current"
        g = s.get(EventGeneration, ref.generation_id)
        assert g.purpose == "cleanup" and g.job_id == result.id
        assert [x["id"] for x in g.input_manifest["source"]["evidence"]] == ["keep"]
        assert g.output_manifest["files"][0]["quality"] == {"kept": True}
        assert s.get(Evidence, "remove") is None and s.get(Evidence, "keep") is not None
    view = d.c.generations.open_view("inv", ref=ref)
    try:
        assert [e["event_id"] for e in view.iterate("inv", [])] == ["event-keep"]
    finally:
        view.close()
    assert not any(Path(d.refs[g].storage_targets[0]).exists() for g in ["old", "current", "staged"])
    assert d.c.objects.exists("saw-artifacts", "generations/current/1/keep.raw")
    assert d.c.objects.exists("saw-evidence-original", "inv/keep/file-keep")
    assert not d.c.objects.exists("saw-artifacts", "generations/old/1/keep.raw")
    assert not d.c.objects.exists("saw-artifacts", "generations/current/1/remove.raw")


def test_preview_fingerprints_staged_generation_closure_without_leaking_paths(domain):
    d = domain
    with d.factory() as s:
        before = deletion.preview(s, "investigation", "inv")
    assert before["counts"]["events"] == 2
    assert "event-generations" not in str(before) and "private-" not in str(before)
    with d.factory.begin() as s:
        g = s.get(EventGeneration, "staged")
        g.raw_objects = [
            *g.raw_objects,
            {
                "bucket": "saw-artifacts",
                "key": "generations/staged/1/unused.raw",
                "byte_length": 0,
                "sha256": event_stream_sha256([]),
                "owner_generation_id": "staged",
                "owner_attempt": 1,
                "retained": False,
            },
        ]
    with d.factory() as s:
        after = deletion.preview(s, "investigation", "inv")
    assert before["fingerprint"] != after["fingerprint"]


def test_failed_copy_preserves_parent_and_retry_uses_new_owned_target(domain, monkeypatch):
    from saw.storage.generations import GenerationWriter

    d = domain
    original = GenerationWriter.index

    def fail(self, events):
        if self.owner["job_id"].startswith("job-"):
            return original(self, events)
        raise OSError("synthetic failed copy")

    monkeypatch.setattr(GenerationWriter, "index", fail)
    result = run(d, "evidence", "remove")
    assert result.state == "FAILED"
    assert all(Path(d.refs[g].storage_targets[0]).exists() for g in ["old", "current", "staged"])
    assert d.c.objects.exists("saw-evidence-original", "inv/remove/file-remove")
    with d.factory() as s:
        attempts = list(s.scalars(select(EventGeneration).where(EventGeneration.purpose == "cleanup")))
        assert len(attempts) == 1
        failed_id = attempts[0].id
        assert attempts[0].storage_targets == result.plan["cleanup_generations"][0]["storage_targets"]
    monkeypatch.setattr(GenerationWriter, "index", original)
    assert retry(d, result.id).state == "COMPLETED"
    with d.factory() as s:
        assert s.get(EventGeneration, failed_id) is None
        assert life.resolve(s, "inv").generation_id != failed_id


@pytest.mark.parametrize("failure", ["target", "object", "finalize", "ready"])
def test_crash_at_external_checkpoint_retries_exact_cleanup(domain, monkeypatch, failure):
    from saw.event_generations import retention

    d = domain
    if failure == "target":
        original = retention.remove_target

        def fail(*args, **kw):
            original(*args, **kw)
            raise OSError("crash after target")

        monkeypatch.setattr(retention, "remove_target", fail)
    elif failure == "object":
        original = d.c.objects.delete

        def fail(*args, **kw):
            original(*args, **kw)
            raise OSError("crash after object")

        monkeypatch.setattr(d.c.objects, "delete", fail)
    elif failure == "ready":
        original = retention._filter_generation

        def fail(*args, **kw):
            original(*args, **kw)
            raise OSError("crash after filtered ready")

        monkeypatch.setattr(retention, "_filter_generation", fail)
    else:
        original = deletion._finish_relational

        def fail(*args, **kw):
            original(*args, **kw)
            raise OSError("crash during SQL finalize")

        monkeypatch.setattr(deletion, "_finish_relational", fail)
    result = run(d, "evidence", "remove")
    assert result.state == "FAILED"
    with d.factory() as s:
        assert s.get(Investigation, "inv").settings["data_deletion"] == result.id
        assert s.get(Evidence, "remove") is not None
    monkeypatch.undo()
    result = retry(d, result.id)
    assert result.state == "COMPLETED"
    assert retry(d, result.id).state == "COMPLETED"
    with d.factory() as s:
        ref = life.resolve(s, "inv")
        assert (
            len(list(s.scalars(select(EventGeneration.id).where(EventGeneration.investigation_id == "inv"))))
            == 1
        )
    view = d.c.generations.open_view("inv", ref=ref)
    try:
        assert view.count("inv") == 1
    finally:
        view.close()
    assert d.c.objects.exists("saw-artifacts", "generations/current/1/keep.raw")
    assert not d.c.objects.exists("saw-artifacts", "generations/current/1/remove.raw")


def test_revoked_admin_cannot_continue_copy_or_retry(domain, monkeypatch):
    from fastapi import HTTPException

    d = domain
    original = d.c.generations.adapter.write

    def revoke(*args, **kwargs):
        original(*args, **kwargs)
        with d.factory.begin() as s:
            s.get(User, "admin").status = "disabled"

    monkeypatch.setattr(d.c.generations.adapter, "write", revoke)
    result = run(d, "evidence", "remove")
    assert result.state == "FAILED"
    assert Path(d.refs["current"].storage_targets[0]).exists()
    assert d.c.objects.exists("saw-artifacts", "generations/current/1/remove.raw")
    with pytest.raises(HTTPException) as error:
        retry(d, result.id)
    assert error.value.status_code == 403


def test_concurrent_retry_cannot_steal_live_receipt(domain, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from fastapi import HTTPException

    from saw.event_generations import retention

    d = domain
    original = d.c.objects.delete
    monkeypatch.setattr(d.c.objects, "delete", lambda *_: (_ for _ in ()).throw(OSError("pause")))
    result = run(d, "evidence", "remove")
    monkeypatch.setattr(d.c.objects, "delete", original)
    entered, release = Event(), Event()

    def held():
        with retention.receipt_lock(d.c.objects, result.id):
            entered.set()
            assert release.wait(10)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(held)
        assert entered.wait(5)
        try:
            with pytest.raises(HTTPException) as error:
                retry(d, result.id)
            assert error.value.status_code == 409
        finally:
            release.set()
        future.result()
    assert retry(d, result.id).state == "COMPLETED"


def test_missing_published_head_never_falls_back_to_legacy(domain):
    from saw.storage.generations import GenerationUnavailable

    d = domain
    with d.factory.begin() as s:
        s.delete(s.get(InvestigationHead, "inv"))
    with d.factory() as s, pytest.raises(GenerationUnavailable):
        deletion.preview(s, "investigation", "inv")


def test_staged_reservation_abandoned_before_any_external_deletion(domain, monkeypatch):
    from saw.event_generations import retention
    from saw.event_generations.models import WriterReservation

    d = domain
    with d.factory.begin() as s:
        s.add(
            WriterReservation(investigation_id="inv", generation_id="staged", job_id="job-staged", attempt=1)
        )
    original = retention.remove_target

    def inspect(*args, **kw):
        with d.factory() as s:
            assert s.get(WriterReservation, "inv") is None
            assert s.get(EventGeneration, "staged").status == "abandoned"
        return original(*args, **kw)

    monkeypatch.setattr(retention, "remove_target", inspect)
    assert run(d).state == "COMPLETED"


def test_unsafe_target_is_rejected_without_touching_unrelated_file(domain):
    from sqlalchemy import update

    from saw.storage.generations import GenerationUnavailable

    d = domain
    other = d.refs["other-current"].storage_targets[0]
    with d.factory.begin() as s:
        s.execute(
            update(EventGeneration).where(EventGeneration.id == "staged").values(storage_targets=[other])
        )
    with d.factory() as s, pytest.raises(GenerationUnavailable):
        deletion.preview(s, "investigation", "inv")
    assert Path(other).exists()


def test_hardlinked_target_and_raw_object_are_not_deleted(domain):
    import os

    d = domain
    original = Path(d.refs["staged"].storage_targets[0])
    linked = d.tmp / "external-link.sqlite3"
    os.link(original, linked)
    try:
        from fastapi import HTTPException

        with d.factory() as s, pytest.raises(HTTPException):
            deletion.preview(s, "investigation", "inv")
        assert original.exists() and linked.exists()
    finally:
        linked.unlink()


def test_preview_fingerprint_includes_generation_state(domain):
    d = domain
    with d.factory() as s:
        before = deletion.preview(s, "investigation", "inv")
    with d.factory.begin() as s:
        s.get(EventGeneration, "staged").status = "abandoned"
    with d.factory() as s:
        after = deletion.preview(s, "investigation", "inv")
    assert before["fingerprint"] != after["fingerprint"]


def test_partial_legacy_with_staging_keeps_surviving_original(domain):
    from sqlalchemy import delete

    d = domain
    with d.factory.begin() as s:
        s.delete(s.get(InvestigationHead, "inv"))
        s.flush()
        s.execute(delete(EventGeneration).where(EventGeneration.id.in_(["old", "current"])))
        g = s.get(EventGeneration, "staged")
        for eid in ["remove", "keep"]:
            f = s.get(EvidenceFile, "file-" + eid)
            obj = {
                "bucket": "saw-evidence-original",
                "key": f.object_key,
                "byte_length": f.size,
                "sha256": f.sha256,
                "owner_generation_id": None,
                "owner_attempt": None,
                "retained": True,
            }
            g.raw_objects = [*g.raw_objects, obj]
            d.c.legacy_events.index(
                [
                    {
                        "event_id": "legacy-" + eid,
                        "investigation_id": "inv",
                        "evidence_id": eid,
                        "raw_ref": {
                            "object_key": "saw-evidence-original/" + f.object_key,
                            "offset": 0,
                            "length": f.size,
                        },
                    }
                ]
            )
    for gid in ["old", "current"]:
        Path(d.refs[gid].storage_targets[0]).unlink()
    assert run(d, "evidence", "remove").state == "COMPLETED"
    assert d.c.objects.exists("saw-evidence-original", "inv/keep/file-keep")
    assert d.c.legacy_events.count("inv") == 1


def test_recreated_target_during_objects_is_not_certified_removed(domain, monkeypatch):
    d = domain
    path = Path(d.refs["old"].storage_targets[0])
    original = d.c.objects.delete

    def recreate(*args):
        original(*args)
        path.write_bytes(b"foreign unowned contents")

    monkeypatch.setattr(d.c.objects, "delete", recreate)
    result = run(d)
    assert result.state == "FAILED"
    with d.factory() as s:
        assert s.get(Investigation, "inv").settings["data_deletion"] == result.id


def test_sealed_generation_history_associations_are_deleted_in_fk_order(domain):
    from saw.analysis_runs.models import AnalysisRun
    from saw.event_generations.models import AnalysisRunGeneration

    d = domain
    with d.factory.begin() as s:
        s.add(
            AnalysisRun(
                id="history",
                investigation_id="inv",
                version=1,
                status="completed",
                input_manifest={"immutable": True},
                input_sha256="a" * 64,
            )
        )
        s.flush()
        s.add(
            AnalysisRunGeneration(
                run_id="history", generation_id="old", input_sha256="a" * 64, source_sha256="b" * 64
            )
        )
    assert run(d, "evidence", "remove").state == "COMPLETED"
    with d.factory() as s:
        assert s.get(AnalysisRun, "history") is None
        assert s.get(AnalysisRunGeneration, "history") is None


@pytest.mark.parametrize("boundary", ["ready", "target", "object"])
def test_uncaught_process_loss_leaves_durable_retry_receipt(domain, monkeypatch, boundary):
    from saw.event_generations import retention
    from saw.storage.models import DataDeletion

    d = domain
    subject, name = (
        (retention, "_filter_generation")
        if boundary == "ready"
        else ((retention, "remove_target") if boundary == "target" else (d.c.objects, "delete"))
    )
    original = getattr(subject, name)

    def crash(*args, **kw):
        original(*args, **kw)
        raise SystemExit("simulated process loss")

    monkeypatch.setattr(subject, name, crash)
    with pytest.raises(SystemExit):
        run(d, "evidence", "remove")
    with d.factory() as s:
        did = s.scalar(select(DataDeletion.id))
        assert s.get(Investigation, "inv").settings["data_deletion"] == did
    monkeypatch.undo()
    assert retry(d, did).state == "COMPLETED"


def test_missing_filtered_target_on_retry_never_deletes_parent(domain, monkeypatch):
    from saw.event_generations import retention

    d = domain
    original = retention.remove_target
    monkeypatch.setattr(
        retention, "remove_target", lambda *a, **kw: (_ for _ in ()).throw(OSError("stop before delete"))
    )
    result = run(d, "evidence", "remove")
    assert result.state == "FAILED"
    with d.factory() as s:
        g = s.get(EventGeneration, result.plan["cleanup_generation"])
        Path(g.storage_targets[0]).unlink()
    monkeypatch.setattr(retention, "remove_target", original)
    result = retry(d, result.id)
    assert result.state == "FAILED"
    assert all(Path(d.refs[g].storage_targets[0]).exists() for g in ["old", "current", "staged"])


def test_cleanup_source_uses_published_file_results_not_prior_input(domain):
    d = domain
    with d.factory.begin() as s:
        s.delete(s.get(InvestigationHead, "inv"))
        s.get(EventGeneration, "current").status = "retained"
    _generation(d, "inv", "latest", "published", reprocessed=True)
    assert run(d, "evidence", "remove").state == "COMPLETED"
    with d.factory() as s:
        ref = life.resolve(s, "inv")
        g = s.get(EventGeneration, ref.generation_id)
        f = g.input_manifest["source"]["evidence"][0]["files"][0]
        assert f["events_parsed"] == 1
        assert f["message"] == "Immutable current result"
        assert f["parser"]["id"] == "fixture"
        assert g.output_manifest["files"][0]["unique_count"] == 1


def test_lost_final_commit_ack_does_not_downgrade_completed_receipt(domain, monkeypatch):
    from sqlalchemy.orm import Session

    from saw.storage.models import DataDeletion

    d = domain
    original = Session.commit
    fired = False

    def lost_ack(s):
        nonlocal fired
        completed = any(
            isinstance(x, DataDeletion) and x.state == "COMPLETED" for x in s.identity_map.values()
        )
        original(s)
        if completed and not fired:
            fired = True
            raise OSError("commit acknowledgement lost")

    monkeypatch.setattr(Session, "commit", lost_ack)
    result = run(d)
    assert fired
    assert result.state == "COMPLETED"
    assert retry(d, result.id).state == "COMPLETED"


def test_hardlinked_original_blocks_preview(domain):
    import os

    d = domain
    original = d.c.objects.local_path("saw-evidence-original", "inv/remove/file-remove")
    linked = d.tmp / "original-link"
    os.link(original, linked)
    try:
        with d.factory() as s:
            preview = deletion.preview(s, "investigation", "inv")
        assert "unsafe_object" in preview["blockers"]
    finally:
        linked.unlink()


def test_junction_lock_path_is_rejected_without_touching_target(domain):
    import os

    from saw.event_generations.retention import receipt_lock

    d = domain
    alias = d.tmp / "junction-objects"
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(d.c.objects.root), str(alias))
    else:
        alias.symlink_to(d.c.objects.root, target_is_directory=True)
    try:
        linked_store = LocalFSObjectStore(alias)
        with pytest.raises(ValueError, match="reparse"), receipt_lock(linked_store, "receipt"):
            pytest.fail("unsafe lock admitted")
        assert not (d.c.objects.root / ".retention-locks").exists()
        assert d.c.objects.exists("saw-evidence-original", "inv/keep/file-keep")
    finally:
        alias.rmdir() if os.name == "nt" else alias.unlink()


@pytest.mark.parametrize(
    "mode", ["exact", "missing", "alias", "owner", "unacknowledged", "wildcard", "extra-target"]
)
def test_opensearch_exact_delete_protocol(mode):
    """Transport contract only; this does not claim native OpenSearch acceptance."""
    from copy import deepcopy

    from opensearchpy import NotFoundError

    from saw.event_generations.retention_targets import remove_target
    from saw.storage.generations import GenerationStore, GenerationUnavailable

    class Indices:
        def __init__(self):
            self.rows = {}
            self.deleted = []

        def get(self, *, index, **kw):
            assert kw == {"ignore_unavailable": False, "allow_no_indices": False, "expand_wildcards": "none"}
            if index not in self.rows:
                raise NotFoundError(404, "index_not_found_exception", {})
            found = {index: deepcopy(self.rows[index])}
            if mode == "extra-target":
                found["unrelated"] = {}
            return found

        def delete(self, *, index, **kw):
            assert kw == {"ignore_unavailable": False, "allow_no_indices": False, "expand_wildcards": "none"}
            assert index == target and "*" not in index and "," not in index
            self.deleted.append(index)
            self.rows.pop(index)
            return {"acknowledged": mode != "unacknowledged"}

    indices = Indices()
    backend = SimpleNamespace(client=SimpleNamespace(indices=indices), prefix="test", alias="test-events")
    store = GenerationStore(
        backend,
        resolve=lambda *_: None,
        check_read=lambda *_: None,
        open_raw=lambda *_: None,
        cursor_key=b"x" * 32,
    )
    target = store.plan_targets("inv", "generation")[0]
    owner = {
        "format": "saw-event-generation/1",
        "investigation_id": "inv",
        "generation_id": "generation",
        "job_id": "receipt",
        "attempt": 1,
        "input_sha256": "a" * 64,
    }
    metadata = {"owner": {**owner, "job_id": "foreign"} if mode == "owner" else owner, "sealed": False}
    state = {
        "aliases": {"unsafe": {}} if mode == "alias" else {},
        "settings": {"index": {"translog": {"durability": "request"}}},
        "mappings": {"_meta": {"saw_generation": metadata}},
    }
    indices.rows["unrelated"] = {"retained": True}
    if mode != "missing":
        indices.rows[target] = state
    ref = GenerationRef("inv", "generation", 0, "", (target + "*" if mode == "wildcard" else target,), False)
    if mode in {"exact", "missing"}:
        remove_target(store, ref, owner=owner, check=lambda: None)
        remove_target(store, ref, owner=owner, check=lambda: None)
        assert target not in indices.rows
    else:
        with pytest.raises(GenerationUnavailable):
            remove_target(store, ref, owner=owner, check=lambda: None)
        if mode != "unacknowledged":
            assert target in indices.rows and not indices.deleted
    assert indices.rows["unrelated"] == {"retained": True}


def test_network_mapped_root_is_not_admitted_for_cleanup(domain, monkeypatch):
    import ctypes
    import os

    from saw.event_generations.retention import receipt_lock

    if os.name != "nt":
        pytest.skip("Windows drive-type boundary")
    monkeypatch.setattr(ctypes.windll.kernel32, "GetDriveTypeW", lambda _: 4)
    with pytest.raises(ValueError, match="local"), receipt_lock(domain.c.objects, "receipt"):
        pytest.fail("network lock admitted")


def test_retained_original_descriptor_cannot_authorize_foreign_key(domain):
    from copy import deepcopy

    from fastapi import HTTPException
    from sqlalchemy import update

    d = domain
    key = "foreign-orphan/evidence/file"
    size, sha = d.c.objects.put_bytes("saw-evidence-original", key, b"unrelated bytes")
    with d.factory.begin() as s:
        g = s.get(EventGeneration, "old")
        inp = deepcopy(g.input_manifest)
        inp["source"]["evidence"][0]["files"][0]["object_key"] = key
        obj = {
            "bucket": "saw-evidence-original",
            "key": key,
            "byte_length": size,
            "sha256": sha,
            "owner_generation_id": None,
            "owner_attempt": None,
            "retained": True,
        }
        s.execute(
            update(EventGeneration)
            .where(EventGeneration.id == "old")
            .values(input_manifest=inp, input_sha256=life._hash(inp), raw_objects=[*g.raw_objects, obj])
        )
    with d.factory() as s, pytest.raises(HTTPException):
        deletion.preview(s, "investigation", "inv")
    assert d.c.objects.exists("saw-evidence-original", key)
