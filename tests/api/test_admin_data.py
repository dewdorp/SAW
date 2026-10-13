"""Administrator cleanup uses synthetic, isolated stores only."""
from sqlalchemy import select

from saw import container
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, Case, CaseRevision, Evidence, EvidenceFile, Investigation, Job, UploadSession
from tests.api.test_phase5_bulk import upload


def target(analyst, *, process=True):
    inv = analyst.post("/investigations", json={"title": "private synthetic title"}).json()
    ev = upload(analyst, inv["id"], "private-name.log", b'203.0.113.1 - - [05/Oct/2026:00:00:00 +0900] "GET / HTTP/1.1" 200 123 "-" "test"\n')
    if process:
        analyst.post(f"/evidence/{ev['evidence_id']}/process").raise_for_status()
    return inv, ev


def preview(admin, kind, tid):
    r = admin.post("/admin/data/deletion-preview", json={"target_type": kind, "target_id": tid})
    assert r.status_code == 200, r.text
    return r.json()


def execute(admin, p, **extra):
    return admin.post("/admin/data/deletions", json={"target_type": p["target_type"], "target_id": p["target_id"],
        "reason": "synthetic cleanup", "confirmation": p["confirmation"], "preview_fingerprint": p["fingerprint"], **extra})


def test_admin_metadata_does_not_grant_raw_read(analyst, admin):
    inv, ev = target(analyst)
    assert analyst.get("/admin/data").status_code == 403
    r = admin.get("/admin/data")
    assert r.status_code == 200
    assert "private synthetic title" not in r.text and "private-name.log" not in r.text
    assert "object_key" not in r.text
    assert admin.get(f"/investigations/{inv['id']}").status_code == 403
    assert admin.get(f"/evidence/{ev['evidence_id']}").status_code == 403


def test_bundle_deletion_removes_events_and_bytes_but_keeps_audit(analyst, admin):
    inv, ev = target(analyst)
    with session_scope() as s:
        files = list(s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev["evidence_id"])))
        paths = [container.get().objects.local_path("saw-evidence-original", f.object_key) for f in files]
        audits = list(s.scalars(select(AuditEvent.id)))
    p = preview(admin, "evidence", ev["evidence_id"])
    assert not p["blockers"] and p["counts"]["events"] == 1
    assert p["retained"]
    r = execute(admin, p)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "COMPLETED"
    assert not any(x.exists() for x in paths)
    assert container.get().events.count(inv["id"]) == 0
    with session_scope() as s:
        assert s.get(Evidence, ev["evidence_id"]) is None
        assert s.get(Investigation, inv["id"]) is not None
        assert set(audits).issubset(set(s.scalars(select(AuditEvent.id))))
    assert admin.get("/admin/audit/verify").json()["ok"] is True


def test_legal_hold_jobs_uploads_and_stale_confirmation(analyst, admin):
    inv, ev = target(analyst)
    p = preview(admin, "evidence", ev["evidence_id"])
    assert execute(admin, p, confirmation="wrong").status_code == 409
    with session_scope() as s:
        s.get(Evidence, ev["evidence_id"]).legal_hold = True
    assert "legal_hold" in preview(admin, "evidence", ev["evidence_id"])["blockers"]
    assert execute(admin, p).status_code == 409
    with session_scope() as s:
        s.get(Evidence, ev["evidence_id"]).legal_hold = False
        s.add(Job(investigation_id=inv["id"], kind="reanalyze", requested_by="synthetic", state="QUEUED"))
    assert "active_jobs" in preview(admin, "evidence", ev["evidence_id"])["blockers"]
    with session_scope() as s:
        for job in s.scalars(select(Job).where(Job.investigation_id == inv["id"])):
            job.state = "CANCELLED"
        s.add(UploadSession(user_id=s.get(Investigation, inv["id"]).owner_id, evidence_id=ev["evidence_id"],
                            filename="fixture.txt", declared_size=1, received_bytes=0, parts={}))
    assert "open_uploads" in preview(admin, "evidence", ev["evidence_id"])["blockers"]


def test_case_retains_snapshots_but_all_routes_reject(analyst, admin):
    c = analyst.post("/cases", json={"title": "synthetic case"}).json()
    p = preview(admin, "case", c["id"])
    assert execute(admin, p).json()["state"] == "COMPLETED"
    for suffix in ("", "/history", "/export"):
        assert analyst.get(f"/cases/{c['id']}{suffix}").status_code == 404
    assert analyst.patch(f"/cases/{c['id']}", json={"status": "open"}).status_code == 404
    assert not analyst.get("/cases").json()
    with session_scope() as s:
        assert s.get(Case, c["id"]).status == "deleted"
        assert s.scalar(select(CaseRevision).where(CaseRevision.case_id == c["id"])) is not None


def test_partial_object_failure_is_retryable_and_blocks_access(analyst, admin, monkeypatch):
    inv, ev = target(analyst)
    p = preview(admin, "investigation", inv["id"])
    store = container.get().objects
    original = store.delete
    def fail(*args):
        raise OSError("private path must not be reflected")
    monkeypatch.setattr(store, "delete", fail)
    r = execute(admin, p)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "FAILED" and "private path" not in r.text
    did = r.json()["id"]
    assert analyst.get(f"/investigations/{inv['id']}").status_code == 409
    assert analyst.post(f"/investigations/{inv['id']}/evidence", json={"kind": "auto"}).status_code == 409
    monkeypatch.setattr(store, "delete", original)
    retry = admin.post(f"/admin/data/deletions/{did}/retry")
    assert retry.status_code == 200 and retry.json()["state"] == "COMPLETED", retry.text
    assert analyst.get(f"/investigations/{inv['id']}").status_code == 404
    assert admin.post(f"/admin/data/deletions/{did}/retry").json()["state"] == "COMPLETED"


def test_shared_object_and_knowledge_reference_block(analyst, admin):
    from saw.knowledge.models import Experience
    inv, ev = target(analyst)
    other, other_ev = target(analyst)
    with session_scope() as s:
        f = s.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == ev["evidence_id"]))
        g = s.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == other_ev["evidence_id"]))
        g.object_key = f.object_key
    assert "shared_object" in preview(admin, "evidence", ev["evidence_id"])["blockers"]
    with session_scope() as s:
        s.add(Experience(display_id="EXP-test", analyst_id="synthetic", source_investigation_id=other["id"]))
    assert "knowledge_reference" in preview(admin, "investigation", other["id"])["blockers"]


def test_investigation_deletion_preserves_other_investigation_and_removes_notes(analyst, admin):
    from saw.storage.models import Note
    inv, ev = target(analyst)
    other, _ = target(analyst)
    with session_scope() as s:
        s.add(Note(investigation_id=inv["id"], author_id="synthetic", author_name="test", body_md="private synthetic note"))
    assert "analyst_records" in preview(admin, "evidence", ev["evidence_id"])["blockers"]
    p = preview(admin, "investigation", inv["id"])
    assert not p["blockers"] and p["counts"]["notes"] == 1
    assert execute(admin, p).json()["state"] == "COMPLETED"
    assert container.get().events.count(other["id"]) == 1
    assert analyst.get(f"/investigations/{other['id']}").status_code == 200
    with session_scope() as s:
        assert not list(s.scalars(select(Note).where(Note.investigation_id == inv["id"])))


def test_pcap_artifacts_are_removed_on_investigation_cleanup(analyst, admin):
    inv, ev = target(analyst)
    store = container.get().objects
    key = f"{inv['id']}/{ev['evidence_id']}/synthetic/builtin/conn.log"
    store.put_bytes("saw-artifacts", key, b"synthetic pcap connection")
    transferred = f"{inv['id']}/extracted-files/" + "a" * 64
    store.put_bytes("saw-artifacts", transferred, b"synthetic shared transfer")
    assert "shared_pcap_artifact" in preview(admin, "evidence", ev["evidence_id"])["blockers"]
    assert execute(admin, preview(admin, "investigation", inv["id"])).json()["state"] == "COMPLETED"
    assert not store.exists("saw-artifacts", key)
    assert not store.exists("saw-artifacts", transferred)


def test_llm_output_is_discarded_after_evidence_cleanup(analyst, admin, monkeypatch):
    from saw.llm import service
    from tests.api.test_ai_context_boundary import CapturingProvider
    inv, ev = target(analyst)
    class DeletingProvider(CapturingProvider):
        def generate(self, req):
            p = preview(admin, "evidence", ev["evidence_id"])
            assert execute(admin, p).json()["state"] == "COMPLETED"
            return super().generate(req)
    monkeypatch.setattr(service, "provider", lambda: DeletingProvider())
    result = analyst.post("/ai/actions", json={"investigation_id": inv["id"], "action": "ask"})
    assert result.status_code == 403, result.text
    with session_scope() as s:
        assert not list(s.scalars(select(service.LlmInteraction).where(service.LlmInteraction.investigation_id == inv["id"])))


def test_referenced_case_must_be_disposed_before_investigation(analyst, admin):
    inv, _ = target(analyst)
    case = analyst.post("/cases", json={"title": "synthetic related", "investigation_ids": [inv["id"]]}).json()
    assert "case_reference" in preview(admin, "investigation", inv["id"])["blockers"]
    assert execute(admin, preview(admin, "case", case["id"])).json()["state"] == "COMPLETED"
    assert execute(admin, preview(admin, "investigation", inv["id"])).json()["state"] == "COMPLETED"


def test_index_failure_keeps_original_until_retry(analyst, admin, monkeypatch):
    inv, ev = target(analyst)
    p = preview(admin, "investigation", inv["id"])
    es = container.get().events
    with session_scope() as s:
        f = s.scalar(select(EvidenceFile).where(EvidenceFile.evidence_id == ev["evidence_id"]))
        path = container.get().objects.local_path("saw-evidence-original", f.object_key)
    original = es.delete_by_investigation
    monkeypatch.setattr(es, "delete_by_investigation", lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic failure")))
    r = execute(admin, p).json()
    assert r["state"] == "FAILED" and r["step"] == "planned"
    assert path.exists() and es.count(inv["id"]) == 1
    monkeypatch.setattr(es, "delete_by_investigation", original)
    assert admin.post(f"/admin/data/deletions/{r['id']}/retry").json()["state"] == "COMPLETED"


def test_read_denial_is_preserved_during_failed_cleanup(analyst, admin, senior, monkeypatch):
    inv, _ = target(analyst)
    monkeypatch.setattr(container.get().events, "delete_by_investigation", lambda *_: (_ for _ in ()).throw(RuntimeError("fail")))
    assert execute(admin, preview(admin, "investigation", inv["id"])).json()["state"] == "FAILED"
    assert senior.get(f"/investigations/{inv['id']}").status_code == 403
    assert admin.get(f"/investigations/{inv['id']}").status_code == 403


def test_new_hold_before_retry_blocks_remaining_file_deletion(analyst, admin, monkeypatch):
    inv, ev = target(analyst)
    store = container.get().objects
    original = store.delete
    monkeypatch.setattr(store, "delete", lambda *_: (_ for _ in ()).throw(OSError("fail")))
    result = execute(admin, preview(admin, "evidence", ev["evidence_id"])).json()
    assert result["state"] == "FAILED"
    with session_scope() as s:
        s.get(Evidence, ev["evidence_id"]).legal_hold = True
    monkeypatch.setattr(store, "delete", original)
    result = admin.post(f"/admin/data/deletions/{result['id']}/retry").json()
    assert result["state"] == "FAILED"
    with session_scope() as s:
        assert s.get(Evidence, ev["evidence_id"]) is not None


def test_cancelled_worker_cannot_reenter_and_resurrect_deleted_data(analyst, admin):
    from saw.workers import pipeline
    from pytest import raises
    inv, ev = target(analyst, process=False)
    with session_scope() as s:
        job = s.scalar(select(Job).where(Job.evidence_id == ev["evidence_id"]))
        job.state = "CANCELLED"
        jid = job.id
    with raises(pipeline.StaleLease):
        pipeline.claim(jid)
    assert execute(admin, preview(admin, "investigation", inv["id"])).json()["state"] == "COMPLETED"
    with raises(pipeline.StaleLease):
        pipeline.claim(jid)


def test_new_write_prevents_stale_preview_from_deleting(analyst, admin):
    inv, _ = target(analyst)
    p = preview(admin, "investigation", inv["id"])
    more = upload(analyst, inv["id"], "more.txt", b"synthetic data")
    assert execute(admin, p).status_code == 409
    with session_scope() as s:
        assert s.get(Evidence, more["evidence_id"]) is not None


def test_compressed_bundle_cleanup_supports_existing_extracted_key_contract(analyst, admin):
    import gzip
    inv = analyst.post("/investigations", json={"title": "compressed synthetic"}).json()
    data = b'203.0.113.1 - - [05/Oct/2026:00:00:00 +0900] "GET / HTTP/1.1" 200 123 "-" "test"\n'
    ev = upload(analyst, inv["id"], "access.log.gz", gzip.compress(data))
    analyst.post(f"/evidence/{ev['evidence_id']}/process").raise_for_status()
    p = preview(admin, "evidence", ev["evidence_id"])
    assert not p["blockers"], p
    assert p["counts"]["files"] == 2
    assert execute(admin, p).json()["state"] == "COMPLETED"
    assert not container.get().objects.cleanup_keys("saw-evidence-extracted", inv["id"])


def test_case_reserved_states_are_admin_only(analyst):
    case = analyst.post("/cases", json={"title": "synthetic reserved state"}).json()
    for state in ("deleted", "deleting"):
        assert analyst.patch(f"/cases/{case['id']}", json={"status": state}).status_code == 403
    assert analyst.get(f"/cases/{case['id']}").status_code == 200


def test_sqlite_audit_and_investigation_lock_order_allows_two_writers(analyst, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import text
    from saw.core.application import audit
    from saw.core.application.data_deletion import lock_investigation
    from saw.storage.db import get_sessionmaker
    if get_sessionmaker().kw["bind"].dialect.name != "sqlite":
        import pytest
        pytest.skip("SQLite writer lock regression")
    inv = analyst.post("/investigations", json={"title": "synthetic concurrent audit"}).json()
    held, competitor = threading.Event(), threading.Event()
    original = audit._head
    def entered_head(s):
        if threading.current_thread().name.endswith("_1"):
            competitor.set()
        return original(s)
    monkeypatch.setattr(audit, "_head", entered_head)
    def owner():
        with session_scope() as s:
            s.execute(text("PRAGMA busy_timeout=1500"))
            lock_investigation(s, inv["id"])
            held.set()
            assert competitor.wait(3)
            audit.record(s, "synthetic.owner", target_id=inv["id"])
    def competing():
        assert held.wait(3)
        with session_scope() as s:
            s.execute(text("PRAGMA busy_timeout=1500"))
            audit.record(s, "synthetic.competitor", target_id=inv["id"])
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-order") as pool:
        a = pool.submit(owner)
        b = pool.submit(competing)
        a.result(timeout=5)
        b.result(timeout=5)
    with session_scope() as s:
        assert audit.verify(s, checkpoint=False)["ok"]


def test_claimed_worker_cannot_be_marked_terminal_before_it_stops(analyst, admin, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from saw.workers import pipeline
    inv, ev = target(analyst, process=False)
    with session_scope() as s:
        job = s.scalar(select(Job).where(Job.evidence_id == ev["evidence_id"]))
        job.state, jid = "QUEUED", job.id
    entered, release = threading.Event(), threading.Event()
    original = pipeline.claim
    def paused_claim(job_id):
        result = original(job_id)
        entered.set()
        assert release.wait(10)
        return result
    monkeypatch.setattr(pipeline, "claim", paused_claim)
    with ThreadPoolExecutor(max_workers=1) as pool:
        worker = pool.submit(pipeline.ingest_run, jid)
        try:
            assert entered.wait(5)
            result = analyst.post(f"/jobs/{jid}/cancel")
            assert result.status_code == 200
            assert result.json()["state"] == "PARSING"
            assert "active_jobs" in preview(admin, "investigation", inv["id"])["blockers"]
        finally:
            release.set()
        worker.result(timeout=10)
    assert execute(admin, preview(admin, "investigation", inv["id"])).json()["state"] == "COMPLETED"
    assert container.get().events.count(inv["id"]) == 0


def test_retry_rechecks_events_after_file_failure(analyst, admin, monkeypatch):
    inv, _ = target(analyst)
    es, store = container.get().events, container.get().objects
    event = next(es.iterate(inv["id"], []))
    original = store.delete
    monkeypatch.setattr(store, "delete", lambda *_: (_ for _ in ()).throw(OSError("synthetic")))
    result = execute(admin, preview(admin, "investigation", inv["id"])).json()
    assert result["state"] == "FAILED" and result["step"] == "events_removed"
    es.index([event])
    assert es.count(inv["id"]) == 1
    monkeypatch.setattr(store, "delete", original)
    assert admin.post(f"/admin/data/deletions/{result['id']}/retry").json()["state"] == "COMPLETED"
    assert es.count(inv["id"]) == 0


def test_cancel_refreshes_job_after_investigation_lock(analyst, monkeypatch):
    from saw.apps.api.routers import evidence as route
    from saw.workers import pipeline
    inv, ev = target(analyst, process=False)
    with session_scope() as s:
        job = s.scalar(select(Job).where(Job.evidence_id == ev["evidence_id"]))
        job.state, jid = "QUEUED", job.id
    original = route.require
    claimed = False
    def claim_before_lock(s, p, permission, investigation_id):
        nonlocal claimed
        if not claimed:
            claimed = True
            pipeline.claim(jid)
        return original(s, p, permission, investigation_id)
    monkeypatch.setattr(route, "require", claim_before_lock)
    from types import SimpleNamespace
    from saw.core.domain.enums import Role
    from saw.core.security.authz import Principal
    with session_scope() as s:
        ctx = SimpleNamespace(principal=Principal(s.get(Investigation, inv["id"]).owner_id,
                              "analyst1", frozenset({Role.ANALYST})))
        result = route.cancel_job(jid, ctx=ctx, s=s)
    assert result["state"] == "PARSING"
    assert result["cancel_requested"] is True


def test_retry_records_executing_admin_without_changing_requester(analyst, admin, app, monkeypatch):
    from tests.conftest import Api, make_user
    from saw.storage.models import DataDeletion, User
    inv, _ = target(analyst)
    store = container.get().objects
    original = store.delete
    monkeypatch.setattr(store, "delete", lambda *_: (_ for _ in ()).throw(OSError("synthetic")))
    result = execute(admin, preview(admin, "investigation", inv["id"])).json()
    assert result["state"] == "FAILED"
    make_user("cleanup-reviewer", ["admin"])
    reviewer = Api(app, "cleanup-reviewer")
    assert reviewer.post(f"/admin/data/deletions/{result['id']}/retry").json()["state"] == "FAILED"
    monkeypatch.setattr(store, "delete", original)
    assert reviewer.post(f"/admin/data/deletions/{result['id']}/retry").json()["state"] == "COMPLETED"
    assert reviewer.post(f"/admin/data/deletions/{result['id']}/retry").json()["state"] == "COMPLETED"
    with session_scope() as s:
        receipt = s.get(DataDeletion, result["id"])
        actor = s.scalar(select(User).where(User.username == "cleanup-reviewer"))
        events = list(s.scalars(select(AuditEvent).where(AuditEvent.action == "data.delete_retry_requested",
                                                     AuditEvent.target_id == inv["id"])))
        assert len(events) == 3
        assert all(e.actor_id == actor.id and e.actor_name == actor.username for e in events)
        assert all(e.detail["receipt_id"] == receipt.id for e in events)
        assert sorted(e.detail["previous_state"] for e in events) == ["COMPLETED", "FAILED", "FAILED"]
        assert receipt.actor_name == "admin1" and receipt.actor_id != actor.id
        from saw.core.application import audit
        assert audit.verify(s, checkpoint=False)["ok"]
