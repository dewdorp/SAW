"""Real composition, cancellation, startup and per-app request ownership."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from saw import container
from saw.config import Settings
from saw.storage import db
from saw.storage.models import Investigation, InvestigationMember, Job, User
from saw.workers.runner import TASKS, RunnerError


def settings_at(path):
    path.mkdir(parents=True, exist_ok=True)
    return Settings(_env_file=None, data_dir=path, database_url=f"sqlite:///{path / 'meta.db'}",
                    event_store_path=str(path / "events.db"), object_store_root=str(path / "objects"),
                    web_dist=str(path / "no-web"))


def seed(c):
    with db.session_scope() as s:
        user = User(username="synthetic", password_hash="unused", roles=["analyst"])
        s.add(user)
        s.flush()
        inv = Investigation(display_id="INV-SYNTHETIC", title="Synthetic", owner_id=user.id)
        s.add(inv)
        s.flush()
        s.add(InvestigationMember(investigation_id=inv.id, user_id=user.id, access="owner"))
        return user.id, inv.id


def add_job(uid, inv, **kw):
    with db.session_scope() as s:
        job = Job(investigation_id=inv, requested_by=uid, kind="reanalyze", **kw)
        s.add(job)
        s.flush()
        return job.id


@pytest.fixture(autouse=True)
def isolate_runtime(monkeypatch):
    previous = container._container
    # Test-owned containers only; do not carry a stopped runner into another test.
    monkeypatch.setattr(container, "_container", None)
    yield
    current = container._container
    if current is not None:
        close = getattr(current.runner, "close", None)
        if close:
            close(wait=True)
    container._container = previous


def test_committed_job_runs_after_build_without_submit(tmp_path, monkeypatch):
    config = settings_at(tmp_path / "first")
    first = container.build(config, synchronous_jobs=True)
    uid, inv = seed(first)
    job_id = add_job(uid, inv)
    observed = []

    def analyze(job_id):
        observed.append(container.get())
        with db.session_scope() as s:
            s.get(Job, job_id).state = "COMPLETED"

    monkeypatch.setitem(TASKS, "analyze.run", analyze)
    second = container.build(config)
    second.runner.wait_all(timeout=5)
    assert first.runner.status().state == "closed"
    assert observed == [second]
    with db.session_scope() as s:
        assert s.get(Job, job_id).state == "COMPLETED"


def test_old_runner_joins_before_replacing_global_database(tmp_path, monkeypatch):
    first_settings = settings_at(tmp_path / "first")
    seeded = container.build(first_settings, synchronous_jobs=True)
    uid, inv = seed(seeded)
    job_id = add_job(uid, inv)
    entered, finish = Event(), Event()
    seen = []

    def analyze(job_id):
        entered.set()
        assert finish.wait(5)
        seen.append((container.get(), db.get_sessionmaker()))
        with db.session_scope() as s:
            s.get(Job, job_id).state = "COMPLETED"

    monkeypatch.setitem(TASKS, "analyze.run", analyze)
    first = container.build(first_settings)
    assert entered.wait(5)
    old_factory = db.get_sessionmaker()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(container.build, settings_at(tmp_path / "second"))
        try:
            # A replacement is blocked in close, before init_db changes defaults.
            assert not pending.done()
            assert db.get_sessionmaker() is old_factory
        finally:
            finish.set()
        second = pending.result(30)
    assert seen == [(first, old_factory)]
    assert first.runner.status().state == "closed"
    assert second is not first
    with old_factory() as s:
        assert s.get(Job, job_id).state == "COMPLETED"


def test_old_app_requests_keep_their_captured_database(tmp_path):
    from saw.apps.api.main import create_app
    first_app = create_app(settings_at(tmp_path / "first"), synchronous_jobs=True)
    first = container.get()
    seed(first)

    @first_app.get("/probe")
    def probe():
        with db.session_scope() as s:
            return {"users": list(s.scalars(select(User.username)))}

    second_app = create_app(settings_at(tmp_path / "second"), synchronous_jobs=True)
    second = container.get()
    assert second is not first
    assert TestClient(first_app).get("/probe").json() == {"users": ["synthetic"]}
    assert TestClient(second_app).get("/api/v1/health").status_code == 200


def test_lifespan_closes_its_captured_runner_only(tmp_path):
    from saw.apps.api.main import create_app
    first_app = create_app(settings_at(tmp_path / "first"), synchronous_jobs=True)
    first = container.get()
    with TestClient(first_app):
        second_app = create_app(settings_at(tmp_path / "second"), synchronous_jobs=True)
        second = container.get()
        assert TestClient(second_app).get("/api/v1/health").status_code == 200
    assert first.runner.status().state == "closed"
    assert second.runner.status().state == "running"


def test_health_reports_safe_fatal_queue_status(tmp_path, monkeypatch):
    from saw.apps.api.main import create_app
    config = settings_at(tmp_path / "first")
    seeded = container.build(config, synchronous_jobs=True)
    uid, inv = seed(seeded)
    add_job(uid, inv)

    def analyze(job_id):
        raise RuntimeError("synthetic-secret-never-in-health")

    monkeypatch.setitem(TASKS, "analyze.run", analyze)
    app = create_app(config)
    c = container.get()
    with pytest.raises(RunnerError, match="task_unhandled_error"):
        c.runner.wait_all(timeout=5)
    response = TestClient(app).get("/api/v1/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["queue"]["fatal_code"] == "task_unhandled_error"
    assert "synthetic-secret" not in response.text
    assert uid not in response.text and inv not in response.text


def test_cancelled_queued_job_is_settled_without_payload(tmp_path, monkeypatch):
    config = settings_at(tmp_path / "first")
    first = container.build(config, synchronous_jobs=True)
    uid, inv = seed(first)
    job_id = add_job(uid, inv, cancel_requested=True)

    def analyze(job_id):
        pytest.fail("cancelled job entered payload")

    monkeypatch.setitem(TASKS, "analyze.run", analyze)
    second = container.build(config)
    second.runner.wait_all(timeout=5)
    with db.session_scope() as s:
        job = s.get(Job, job_id)
        assert job.state == "CANCELLED"
        assert job.finished_at is not None
        assert job.attempt == 0


def test_startup_fails_incomplete_golden_input_without_replay(tmp_path):
    config = settings_at(tmp_path / "first")
    first = container.build(config, synchronous_jobs=True)
    uid, inv = seed(first)
    with db.session_scope() as s:
        job = Job(investigation_id=inv, requested_by=uid, kind="golden_export",
                  stages={"input_state": "input_pending", "source_ids": [inv]})
        s.add(job)
        s.flush()
        job_id = job.id
    second = container.build(config)
    second.runner.wait_all(timeout=5)
    with db.session_scope() as s:
        job = s.get(Job, job_id)
        assert job.state == "FAILED"
        assert job.error["type"] == "InputIncomplete"


def test_queue_cursor_seed_is_idempotent_after_create_all(tmp_path):
    from saw.workers.queue_models import QueueCursor
    config = settings_at(tmp_path / "first")
    container.build(config, synchronous_jobs=True)
    with db.session_scope() as s:
        cursor = s.get(QueueCursor, "heavy")
        assert cursor is not None
        cursor.last_requester, cursor.revision = "synthetic-requester", 12
    container.build(config, synchronous_jobs=True)
    with db.session_scope() as s:
        cursor = s.get(QueueCursor, "heavy")
        assert (cursor.last_requester, cursor.revision) == ("synthetic-requester", 12)
