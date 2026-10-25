"""Durable admission tests use synthetic file-backed SQL and real worker threads."""
from __future__ import annotations

import json
import time
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Thread

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import sessionmaker

from saw.storage.db import make_engine
from saw.storage.models import Job
from saw.workers.runner import TASKS, InProcessRunner

ROUTES = {"ingest.run", "ingest.resume", "analyze.run", "behavior.run",
          "device_analysis.run", "report_export.run", "golden_export.run", "reprocess.run"}


@pytest.fixture
def queue(tmp_path, monkeypatch):
    from saw.workers.durable_queue import resolve_task
    from saw.workers.queue_models import QueueCursor
    engine = make_engine(f"sqlite:///{tmp_path / 'fair.db'}")
    Job.__table__.create(engine)
    QueueCursor.__table__.create(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as session:
        session.add(QueueCursor(id="heavy"))
    runners = []

    def payload(*, job_id):
        with factory.begin() as session:
            job = session.get(Job, job_id)
            job.state = "COMPLETED"
            job.attempt += 1

    for route in ROUTES:
        monkeypatch.setitem(TASKS, route, payload)

    def prepare(session, job, *, recovering):
        if job.cancel_requested:
            job.state = "CANCELLED"
            return None
        route = resolve_task(job)
        if route is not None:
            job.state = "QUEUED"
        return route

    def build(**kwargs):
        runner = InProcessRunner(workers=kwargs.pop("workers", 1), session_factory=factory,
                                 context_factory=kwargs.pop("context_factory", nullcontext),
                                 prepare_job=kwargs.pop("prepare_job", prepare),
                                 poll_interval=kwargs.pop("poll_interval", 0.02), **kwargs)
        runners.append(runner)
        return runner

    yield factory, build, engine
    for runner in runners:
        runner.close()
    engine.dispose()


def add(factory, *ids, kind="ingest", state="QUEUED", stages=None, cancel=False):
    with factory.begin() as session:
        for number, job_id in enumerate(ids):
            session.add(Job(id=job_id, investigation_id="synthetic", kind=kind, state=state,
                            requested_by=job_id[0], stages=stages or {}, cancel_requested=cancel,
                            created_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=number)))


def complete(factory, job_id):
    with factory.begin() as session:
        job = session.get(Job, job_id)
        job.state = "COMPLETED"
        job.attempt += 1


def test_three_requesters_round_robin_fifo_from_sql(queue, monkeypatch):
    factory, build, _ = queue
    # Equal timestamps deliberately make id the FIFO tie breaker.
    add(factory, *(f"A{i:04}" for i in range(1, 1001)), "B0001", "B0002", "B0003", "C0001", "C0002", "C0003")
    with factory.begin() as session:
        session.execute(update(Job).values(created_at=datetime(2026, 1, 1, tzinfo=UTC)))
    seen = []
    ninth = Event()
    release = Event()

    def payload(*, job_id):
        seen.append(job_id)
        if len(seen) == 9:
            ninth.set()
            assert release.wait(10)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build()
    try:
        runner.start()
        assert ninth.wait(10)
        assert seen == ["A0001", "B0001", "C0001", "A0002", "B0002", "C0002", "A0003", "B0003", "C0003"]
        from saw.workers.queue_models import QueueCursor
        with factory() as session:
            cursor = session.get(QueueCursor, "heavy")
            assert (cursor.last_requester, cursor.revision) == ("C", 9)
        runner.close(wait=False)
    finally:
        release.set()
        runner.close()


def test_cursor_survives_runner_recreation(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, "A1", "A2", "B1", "B2", "C1")
    reached = Event()
    release = Event()
    seen = []

    def payload(*, job_id):
        seen.append(job_id)
        if job_id == "B1":
            reached.set()
            assert release.wait(5)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    first = build()
    try:
        first.start()
        assert reached.wait(5)
        first.close(wait=False)
    finally:
        release.set()
        first.close()
    second = build()
    second.start()
    second.wait_all(5)
    assert seen == ["A1", "B1", "C1", "A2", "B2"]


@pytest.mark.parametrize("workers", [1, 2])
def test_hint_burst_does_not_allocate_backlog_futures(queue, monkeypatch, workers):
    factory, build, _ = queue
    add(factory, *(f"{('A', 'B', 'C')[i % 3]}{i:05}" for i in range(10000)))
    barrier = Barrier(workers + 1, timeout=10)
    release = Event()

    def payload(*, job_id):
        barrier.wait()
        assert release.wait(10)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build(workers=workers)
    try:
        runner.start()
        barrier.wait()
        for _ in range(1000):
            runner.submit("ingest.run", job_id="A00000")
        assert runner.status().active_count == workers
        assert len(runner.futures) <= workers
        assert len(runner._active_ids) <= workers
        runner.close(wait=False)
    finally:
        release.set()
        runner.close()
    assert len(runner.futures) == 0
    with factory() as session:
        assert len(list(session.scalars(select(Job.id).where(Job.state == "COMPLETED")))) == workers


def test_oldest_window_cannot_starve_other_requesters(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, *(f"A{i:04}" for i in range(1200)), "B1", "C1")
    seen = []
    reached = Event()
    release = Event()

    def payload(*, job_id):
        seen.append(job_id)
        if len(seen) == 3:
            reached.set()
            assert release.wait(5)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build(recovery_batch_size=16)
    try:
        runner.start()
        assert reached.wait(5)
        assert seen == ["A0000", "B1", "C1"]
        runner.close(wait=False)
    finally:
        release.set()
        runner.close()


@pytest.mark.parametrize("kind,route", [("ingest", "ingest.run"), ("ingest", "ingest.resume"),
    ("ingest", "analyze.run"), ("reanalyze", "analyze.run"), ("behavior", "behavior.run"),
    ("device_analysis", "device_analysis.run"), ("report_export", "report_export.run"),
    ("golden_export", "golden_export.run"), ("reprocess", "reprocess.run")])
def test_registry_routes_all_six_current_durable_kinds(queue, monkeypatch, kind, route):
    factory, build, _ = queue
    called = []
    stages = {"_queue_task": route, "input_state": "input_ready"}
    add(factory, "A1", kind=kind, stages=stages)

    def payload(*, job_id):
        called.append(route)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, route, payload)
    runner = build()
    runner.start()
    # A conflicting hint never overwrites persisted routing.
    runner.submit("ingest.run", job_id="A1")
    runner.wait_all(5)
    assert called == [route]


def test_waiting_uploading_terminal_and_pending_input_excluded(queue):
    factory, build, _ = queue
    for index, state in enumerate(("WAITING_INPUT", "UPLOADING", "COMPLETED", "FAILED", "CANCELLED")):
        add(factory, f"A{index}", state=state)
    add(factory, "B1", kind="unrecognized")
    runner = build()
    runner.start()
    # Pending producer is committed after recovery: polling must never orphan it.
    add(factory, "C1", kind="golden_export", stages={"input_state": "input_pending"})
    add(factory, "D1", kind="golden_export")
    runner.wait_all(5)
    from saw.workers.queue_models import QueueCursor
    with factory() as session:
        assert session.get(QueueCursor, "heavy").revision == 0
        assert session.get(Job, "C1").state == "QUEUED"
        assert session.get(Job, "C1").attempt == 0


def test_cancelled_queued_job_never_enters_payload(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, "A1", cancel=True)
    add(factory, "B1")
    runner = build()
    runner.start()
    runner.wait_all(5)
    with factory() as session:
        assert session.get(Job, "A1").state == "CANCELLED"
        assert session.get(Job, "A1").attempt == 0
        assert session.get(Job, "B1").state == "COMPLETED"


@pytest.mark.parametrize("batch_size", [64, 128])
def test_startup_recovery_is_bounded_and_persists_route(queue, monkeypatch, batch_size):
    factory, build, _engine = queue
    from saw.workers.durable_queue import resolve_task
    add(factory, *(f"A{i:03}" for i in range(130)), state="ANALYZING")
    recovered = []
    page_sizes = []
    release = Event()

    def prepare(session, job, *, recovering):
        if recovering:
            recovered.append(job.id)
            page_sizes.append(len(session.identity_map))
        route = resolve_task(job)
        job.state = "QUEUED"
        return route

    def payload(*, job_id):
        assert release.wait(10)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "analyze.run", payload)
    runner = build(prepare_job=prepare, recovery_batch_size=batch_size)
    try:
        runner.start()
        assert len(recovered) == 130
        assert max(page_sizes) <= 64
        with factory() as session:
            assert session.get(Job, "A129").stages["_queue_task"] == "analyze.run"
        runner.close(wait=False)
    finally:
        release.set()
        runner.close()
    # The legacy state was normalized, so the durable route is the only surviving hint.
    second = build()
    second.start()
    second.wait_all(10)
    with factory() as session:
        assert session.get(Job, "A129").state == "COMPLETED"


def test_duplicate_hints_cannot_double_claim(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, "A1")
    entered = Event()
    release = Event()

    def payload(*, job_id):
        entered.set()
        assert release.wait(5)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build(workers=3)
    try:
        runner.start()
        assert entered.wait(5)
        threads = [Thread(target=lambda: [runner.submit("ingest.run", job_id="A1") for _ in range(100)]) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert runner.status().active_count == 1
    finally:
        release.set()
    runner.wait_all(5)
    with factory() as session:
        assert session.get(Job, "A1").attempt == 1


def test_task_and_recovery_context_stay_on_original_app(queue, monkeypatch):
    factory, build, _ = queue
    bound = ContextVar("synthetic_app", default=None)
    lease = ContextVar("synthetic_lease", default=None)
    observations = []
    entered = Event()
    release = Event()

    @contextmanager
    def context():
        token = bound.set(factory)
        try:
            yield
        finally:
            bound.reset(token)

    def prepare(session, job, *, recovering):
        assert bound.get() is factory
        return "ingest.run"

    def payload(*, job_id):
        observations.append((bound.get(), lease.get()))
        lease.set("old invocation")
        if job_id == "A1":
            entered.set()
            assert release.wait(5)
        complete(bound.get(), job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    add(factory, "A1", "B1")
    runner = build(context_factory=context, prepare_job=prepare)
    try:
        runner.start()
        assert entered.wait(5)
        token = bound.set("replacement")
        release.set()
        runner.wait_all(5)
        assert bound.get() == "replacement"
        bound.reset(token)
        assert observations == [(factory, None), (factory, None)]
    finally:
        release.set()


def test_close_stops_admission_and_join_protects_replacement(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, "A1", "B1")
    entered = Event()
    release = Event()
    joined = Event()

    def payload(*, job_id):
        entered.set()
        assert release.wait(5)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build()
    try:
        runner.start()
        assert entered.wait(5)
        runner.close(wait=False)
        thread = Thread(target=lambda: (runner.close(), joined.set()))
        thread.start()
        assert not joined.wait(0.05)
        release.set()
        assert joined.wait(5)
        thread.join(5)
        with factory() as session:
            assert session.get(Job, "B1").state == "QUEUED"
        assert runner.status().state == "closed"
        assert not runner.futures
        with pytest.raises(RuntimeError):
            runner.submit("ingest.run", job_id="B1")
        with pytest.raises(RuntimeError):
            runner.start()
    finally:
        release.set()


def test_wait_all_observes_sql_and_uses_one_timeout(queue, monkeypatch):
    factory, build, _ = queue
    entered = Event()
    release = Event()
    self_wait = []
    runner = build(workers=2)

    def payload(*, job_id):
        try:
            runner.wait_all()
        except RuntimeError:
            self_wait.append(job_id)
        entered.set()
        assert release.wait(5)
        complete(factory, job_id)

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner.start()
    add(factory, "A1", "B1")
    try:
        assert entered.wait(5)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            runner.wait_all(0.1)
        assert time.monotonic() - started < 0.8
    finally:
        release.set()
    runner.wait_all(5)
    assert sorted(self_wait) == ["A1", "B1"]
    assert not runner.futures


def test_synchronous_exceptions_and_inline_child_preserved(monkeypatch):
    seen = []
    monkeypatch.setitem(TASKS, "synthetic", lambda value: seen.append(value))
    runner = InProcessRunner(synchronous=True)
    runner.submit("synthetic", value="inline")
    assert seen == ["inline"]
    assert runner.pool is None
    runner.wait_all()
    def broken():
        raise ValueError("synthetic")
    monkeypatch.setitem(TASKS, "broken", broken)
    with pytest.raises(ValueError, match="synthetic"):
        runner.submit("broken")
    runner.close()


@pytest.mark.parametrize("failure,code", [("startup", "startup_recovery_failed"),
    ("sql", "sql_refill_failed"), ("prepare", "prepare_contract_failed"),
    ("submit", "executor_submit_failed"), ("task", "task_unhandled_error"),
    ("incomplete", "task_incomplete_return")])
def test_fatal_status_is_bounded_safe_and_visible_to_root(queue, monkeypatch, failure, code):
    factory, build, engine = queue
    secret = "fake://token@host/private/path"
    triggered = Event()
    def broken(*args, **kwargs):
        triggered.set()
        raise RuntimeError(secret)
    def prepare(session, job, *, recovering):
        if failure == "startup" or (failure == "prepare" and not recovering):
            return broken()
        return "ingest.run"
    runner = build(prepare_job=prepare)
    if failure == "startup":
        add(factory, "A1")
        with pytest.raises(RuntimeError, match=code):
            runner.start()
    else:
        if failure == "task":
            monkeypatch.setitem(TASKS, "ingest.run", broken)
        if failure == "incomplete":
            monkeypatch.setitem(TASKS, "ingest.run", lambda **kwargs: triggered.set())
        runner.start()
        if failure == "submit":
            monkeypatch.setattr(runner.pool, "submit", broken)
        if failure == "sql":
            def fail_sql(*args):
                triggered.set()
                raise RuntimeError(secret)
            event.listen(engine, "before_cursor_execute", fail_sql)
            try:
                with pytest.raises(RuntimeError, match=code):
                    runner.wait_all(5)
            finally:
                event.remove(engine, "before_cursor_execute", fail_sql)
        else:
            add(factory, "A1", "B1")
            with pytest.raises(RuntimeError, match=code):
                runner.wait_all(5)
    status = runner.status()
    assert status.state == "failed"
    assert status.fatal_code == code
    assert status.active_count <= 1
    serialized = json.dumps(asdict(status))
    assert secret not in serialized
    assert set(asdict(status)) == {"state", "fatal_code", "active_count"}
    with pytest.raises(FrozenInstanceError):
        status.state = "running"
    runner.close()
    assert runner.status().fatal_code == code
    assert runner.status().active_count == 0
    assert not runner.futures


@pytest.mark.parametrize("kwargs", [{"workers": 0}, {"poll_interval": 0}, {"recovery_batch_size": 0}])
def test_invalid_limits_rejected(kwargs):
    with pytest.raises(ValueError):
        InProcessRunner(**kwargs)


def test_async_dependency_and_hint_validation(queue):
    with pytest.raises(ValueError):
        InProcessRunner()
    _, build, _ = queue
    runner = build()
    runner.start()
    with pytest.raises(KeyError):
        runner.submit("unknown", job_id="A1")
    for kwargs in ({}, {"job_id": "A1", "requester": "A"}, {"job_id": 1}):
        with pytest.raises(ValueError):
            runner.submit("ingest.run", **kwargs)


def test_wait_all_requires_scan_started_after_wait_request(queue, monkeypatch):
    factory, build, _ = queue
    from saw.workers import durable_queue
    original = durable_queue.choose_candidate
    selected_empty = Event()
    release_scan = Event()
    waiting = Event()
    entered = Event()
    release_task = Event()
    returned = Event()
    once = [True]

    def selection(session, active_ids=()):
        result = original(session, active_ids)
        if result is None and once[0]:
            once[0] = False
            selected_empty.set()
            assert release_scan.wait(5)
        return result

    def payload(*, job_id):
        entered.set()
        assert release_task.wait(5)
        complete(factory, job_id)

    monkeypatch.setattr(durable_queue, "choose_candidate", selection)
    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build()
    original_wait = runner._condition.wait
    def condition_wait(timeout=None):
        waiting.set()
        return original_wait(timeout)
    monkeypatch.setattr(runner._condition, "wait", condition_wait)
    runner.start()
    thread = Thread(target=lambda: (runner.wait_all(5), returned.set()))
    try:
        assert selected_empty.wait(5)
        thread.start()
        assert waiting.wait(5)
        add(factory, "A1")
        release_scan.set()
        assert entered.wait(5)
        assert not returned.is_set()
    finally:
        release_scan.set()
        release_task.set()
        thread.join(5)
    assert returned.is_set()


def test_status_never_waits_for_scheduler_lock(queue):
    _, build, _ = queue
    runner = build()
    observed = Event()
    with runner._condition:
        thread = Thread(target=lambda: (runner.status(), observed.set()))
        thread.start()
        immediate = observed.wait(0.2)
    thread.join(5)
    assert immediate


def test_preparation_can_delete_candidate_in_its_owned_transaction(queue):
    factory, build, _ = queue
    def prepare(session, job, *, recovering):
        if not recovering:
            session.delete(job)
            return None
        return "ingest.run"
    runner = build(prepare_job=prepare)
    runner.start()
    add(factory, "A1")
    runner.wait_all(5)
    with factory() as session:
        assert session.get(Job, "A1") is None


@pytest.mark.parametrize("mutation", ["cancel", "delete", "requester", "state"])
def test_revalidation_handles_candidate_race_before_payload(queue, monkeypatch, mutation):
    factory, build, _ = queue
    from saw.workers import durable_queue
    original = durable_queue.choose_candidate
    seen = []
    cleaned = []
    once = [True]
    def selection(session, active_ids=()):
        candidate = original(session, active_ids)
        if candidate is not None and candidate.job_id == "A1" and once[0]:
            once[0] = False
            with factory.begin() as writer:
                job = writer.get(Job, "A1")
                if mutation == "cancel":
                    job.cancel_requested = True
                elif mutation == "delete":
                    writer.delete(job)
                elif mutation == "requester":
                    job.requested_by = "C"
                else:
                    job.state = "WAITING_INPUT"
        return candidate
    def prepare(session, job, *, recovering):
        if job.cancel_requested:
            cleaned.append(job.id)
            job.state = "CANCELLED"
            return None
        return "ingest.run"
    def payload(*, job_id):
        seen.append(job_id)
        complete(factory, job_id)
    monkeypatch.setattr(durable_queue, "choose_candidate", selection)
    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build(prepare_job=prepare)
    runner.start()
    add(factory, "A1", "B1")
    runner.wait_all(5)
    assert seen == (["B1", "A1"] if mutation == "requester" else ["B1"])
    if mutation == "cancel":
        assert cleaned == ["A1"]
        with factory() as session:
            assert session.get(Job, "A1").state == "CANCELLED"
            assert session.get(Job, "A1").attempt == 0


@pytest.mark.parametrize("bad", ["none", "wrong_kind", "missing_registration", "cancel_unchanged"])
def test_bad_preparation_stops_without_redispatch(queue, monkeypatch, bad):
    factory, build, _ = queue
    called = []
    def prepare(session, job, *, recovering):
        if recovering:
            return "ingest.run"
        called.append(job.id)
        if bad in {"none", "cancel_unchanged"}:
            return None
        return "report_export.run" if bad == "wrong_kind" else "ingest.resume"
    if bad == "missing_registration":
        monkeypatch.delitem(TASKS, "ingest.resume")
    runner = build(prepare_job=prepare)
    runner.start()
    add(factory, "A1", "B1", cancel=bad == "cancel_unchanged")
    with pytest.raises(RuntimeError, match="prepare_contract_failed"):
        runner.wait_all(5)
    assert called == ["A1"]
    assert runner.status().active_count == 0
    with factory() as session:
        assert session.get(Job, "A1").attempt == 0
        assert session.get(Job, "A1").state == "QUEUED"


def test_live_cancellation_backlog_cannot_occupy_requester_window(queue, monkeypatch):
    factory, build, _ = queue
    from saw.workers.durable_queue import resolve_task
    cleaned = []
    def prepare(session, job, *, recovering):
        if job.cancel_requested:
            cleaned.append(job.id)
            job.state = "CANCELLED"
            return None
        return resolve_task(job)
    runner = build(prepare_job=prepare, recovery_batch_size=8)
    runner.start()
    add(factory, *(f"A{i:03}" for i in range(100)), cancel=True)
    add(factory, "B1", "C1")
    runner.wait_all(5)
    assert cleaned
    with factory() as session:
        assert session.get(Job, "B1").state == "COMPLETED"
        assert session.get(Job, "C1").state == "COMPLETED"
        assert all(attempt == 0 for attempt in session.scalars(select(Job.attempt).where(Job.requested_by == "A")))


def test_uncaught_task_or_submit_error_cannot_spin_or_leak(queue, monkeypatch):
    factory, build, _ = queue
    add(factory, "A1", "B1")
    calls = []
    def broken(*, job_id):
        calls.append(job_id)
        raise ValueError("synthetic crash")
    monkeypatch.setitem(TASKS, "ingest.run", broken)
    runner = build()
    runner.start()
    with pytest.raises(RuntimeError, match="task_unhandled_error"):
        runner.wait_all(5)
    runner.close()
    assert calls == ["A1"]
    assert not runner.futures
    classified = []
    def recover(session, job, *, recovering):
        assert recovering
        classified.append(job.id)
        job.state = "FAILED"
    replacement = build(prepare_job=recover)
    replacement.start()
    replacement.wait_all(5)
    assert classified == ["A1", "B1"]


def test_async_inline_child_and_owned_worker_close_guard(queue, monkeypatch):
    factory, build, _ = queue
    runner = build()
    seen = []
    def child(job_id):
        seen.append("child")
        complete(factory, job_id)
    def parent(*, job_id):
        with pytest.raises(RuntimeError, match="own slot"):
            runner.close()
        seen.append("parent")
        child(job_id)
    monkeypatch.setitem(TASKS, "ingest.run", parent)
    add(factory, "A1")
    runner.start()
    runner.wait_all(5)
    assert seen == ["parent", "child"]


def test_registry_is_captured_at_start(queue, monkeypatch):
    factory, build, _ = queue
    runner = build()
    runner.start()
    monkeypatch.setitem(TASKS, "ingest.run", lambda **kwargs: pytest.fail("changed registry escaped capture"))
    add(factory, "A1")
    runner.wait_all(5)
    with factory() as session:
        assert session.get(Job, "A1").state == "COMPLETED"


def test_actual_captured_context_nested_scope_and_lease_stay_on_app(queue, tmp_path, monkeypatch):
    # Uses the actual root ContextVar bindings, imported session_scope and pipeline lease.
    from saw import container
    from saw.config import Settings
    from saw.storage import db
    from saw.storage.db import session_scope
    from saw.workers.pipeline import _lease
    factory_a, build, _ = queue
    engine_b = make_engine(f"sqlite:///{tmp_path / 'app-b.db'}")
    Job.__table__.create(engine_b)
    factory_b = sessionmaker(engine_b, expire_on_commit=False)
    settings_a = Settings(data_dir=tmp_path / "a")
    settings_b = Settings(data_dir=tmp_path / "b")
    app_a = container.Container(settings_a, None, None, None)
    app_b = container.Container(settings_b, None, None, None)
    monkeypatch.setattr(container, "_container", app_a)
    monkeypatch.setattr(db, "_SessionLocal", factory_a)
    add(factory_a, "A1", "B1")
    add(factory_b, "A1", "B1")
    entered, release = Event(), Event()
    observed = []

    def check_owner():
        assert container.get() is app_a
        assert db.get_sessionmaker() is factory_a
        with session_scope() as session:
            assert session.bind is factory_a.kw["bind"]
        with container.activate(app_b, factory_b):
            assert container.get() is app_b
            assert db.get_sessionmaker() is factory_b
        assert container.get() is app_a
        assert db.get_sessionmaker() is factory_a

    def prepare(session, job, *, recovering):
        check_owner()
        return "ingest.run"

    def payload(*, job_id):
        observed.append(_lease.get())
        _lease.set((job_id, 999))
        if job_id == "A1":
            entered.set()
            assert release.wait(5)
        check_owner()
        with session_scope() as session:
            session.get(Job, job_id).state = "COMPLETED"

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = build(context_factory=lambda: container.activate(app_a, factory_a), prepare_job=prepare)
    app_a.runner = runner
    try:
        runner.start()
        assert entered.wait(5)
        monkeypatch.setattr(container, "_container", app_b)
        monkeypatch.setattr(db, "_SessionLocal", factory_b)
        release.set()
        runner.wait_all(5)
        assert observed == [None, None]
        with factory_b() as session:
            assert list(session.scalars(select(Job.state).order_by(Job.id))) == ["QUEUED", "QUEUED"]
        assert container.get() is app_b
        assert db.get_sessionmaker() is factory_b
    finally:
        release.set()
        runner.close()
        engine_b.dispose()


def test_queue_does_not_lock_job_before_domain_preparation(queue):
    from sqlalchemy.dialects import postgresql
    factory, build, engine = queue
    statements = []
    def capture(_connection, clause, _multiparams, _params, _options):
        if getattr(clause, "is_select", False):
            statements.append(str(clause.compile(dialect=postgresql.dialect())))
    runner = build()
    runner.start()
    event.listen(engine, "before_execute", capture)
    try:
        add(factory, "A1")
        runner.wait_all(5)
    finally:
        event.remove(engine, "before_execute", capture)
    assert statements
    # The captured domain callback must establish investigation/source lock order first.
    assert all("FOR UPDATE" not in sql for sql in statements)


def test_commit_without_submit_is_discovered_periodically(tmp_path, monkeypatch):
    from saw.workers.queue_models import QueueCursor
    engine = make_engine(f"sqlite:///{tmp_path / 'queue.db'}")
    Job.__table__.create(engine)
    QueueCursor.__table__.create(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory.begin() as session:
        session.add(QueueCursor(id="heavy"))
    done = Event()

    def payload(*, job_id):
        with factory.begin() as session:
            session.get(Job, job_id).state = "COMPLETED"
        done.set()

    def prepare(session, job, *, recovering):
        return "ingest.run"

    monkeypatch.setitem(TASKS, "ingest.run", payload)
    runner = InProcessRunner(workers=1, session_factory=factory,
                             context_factory=nullcontext, prepare_job=prepare,
                             poll_interval=0.02)
    try:
        runner.start()
        with factory.begin() as session:
            session.add(Job(id="A1", investigation_id="synthetic", kind="ingest", requested_by="A"))
        assert done.wait(5)
        runner.wait_all(5)
    finally:
        runner.close()
        engine.dispose()
