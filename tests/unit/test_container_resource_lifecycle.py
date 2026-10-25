"""Owned resource cleanup without invalidating retained app reads."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import event

from saw import container
from saw.storage import db
from tests.unit.test_container_queue_lifecycle import settings_at


@pytest.fixture
def owned(monkeypatch):
    made = []
    original = container.build
    previous = container._container
    monkeypatch.setattr(container, '_container', None)

    def build(*args, **kwargs):
        captured = original(*args, **kwargs)
        made.append(captured)
        return captured

    yield build
    for captured in reversed(made):
        container.close(captured)
    container._container = previous


def native_clients(monkeypatch, *, fail_ready=False):
    from saw.storage import objectstore, opensearch_store

    class Client:
        closed = 0

        def close(self):
            self.closed += 1

    shared = Client()

    class Events:
        def __init__(self, *args, ensure=True, **kwargs):
            self.client = shared
            if ensure:
                self._wait_ready()

        def _wait_ready(self):
            if fail_ready:
                raise RuntimeError('synthetic readiness failure')

        def ensure_template(self):
            pass

    monkeypatch.setattr(opensearch_store, 'OpenSearchEventStore', Events)
    monkeypatch.setattr(objectstore, 'S3ObjectStore', lambda *a: SimpleNamespace(s3=shared))
    from saw.event_generations import reads
    monkeypatch.setattr(reads, 'EventFacade', lambda *a, **kw: SimpleNamespace(generations=None))
    return shared


def test_close_drains_then_disposes_exact_engine_and_distinct_clients(tmp_path, monkeypatch, owned):
    client = native_clients(monkeypatch)
    config = settings_at(tmp_path / 'app').model_copy(update={'event_store': 'opensearch', 'object_store': 's3'})
    captured = owned(config, synchronous_jobs=True)
    engine = captured.session_factory.kw['bind']
    assert engine.pool.checkedin() > 0
    order = []
    stop = captured.runner.close

    def drain(*, wait):
        order.append('drain')
        assert engine.pool.checkedin() > 0
        stop(wait=wait)

    monkeypatch.setattr(captured.runner, 'close', drain)
    event.listen(engine, 'engine_disposed', lambda e: order.append('dispose'))
    unrelated = SimpleNamespace(dispose=lambda: pytest.fail('disposed unrelated global engine'))
    monkeypatch.setattr(db, '_engine', unrelated)
    container.close(captured)
    container.close(captured)
    assert order == ['drain', 'dispose']
    assert client.closed == 1  # Event and object adapter share one owned client.
    assert engine.pool.checkedin() == 0


def test_replacement_releases_idle_sql_but_keeps_retained_read_client(tmp_path, monkeypatch, owned):
    client = native_clients(monkeypatch)
    config = settings_at(tmp_path / 'first').model_copy(update={'event_store': 'opensearch'})
    first = owned(config, synchronous_jobs=True)
    engine = first.session_factory.kw['bind']
    second = owned(settings_at(tmp_path / 'second'), synchronous_jobs=True)
    assert first.runner.status().state == 'closed'
    assert engine.pool.checkedin() == 0
    assert client.closed == 0
    with first.session_factory() as session:
        assert session.connection().exec_driver_sql('SELECT 1').scalar() == 1
    container.close(first)
    assert client.closed == 1
    assert engine.pool.checkedin() == 0
    assert second.runner.status().state == 'running'


@pytest.mark.parametrize('failure', ['readiness', 'facade', 'start'])
def test_build_failure_releases_created_resources(tmp_path, monkeypatch, failure):
    client = native_clients(monkeypatch, fail_ready=failure == 'readiness')
    monkeypatch.setattr(container, '_container', None)
    engines = []
    original = container.init_db

    def initialize(*args, **kwargs):
        engine = original(*args, **kwargs)
        engines.append(engine)
        return engine

    monkeypatch.setattr(container, 'init_db', initialize)
    if failure == 'facade':
        from saw.event_generations import reads
        monkeypatch.setattr(reads, 'EventFacade', lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('synthetic facade')))
    if failure == 'start':
        monkeypatch.setattr(container.InProcessRunner, 'start', lambda self: (_ for _ in ()).throw(RuntimeError('synthetic start')))
    config = settings_at(tmp_path / 'app').model_copy(update={'event_store': 'opensearch', 'object_store': 's3'})
    with pytest.raises(RuntimeError, match='synthetic'):
        container.build(config, synchronous_jobs=True)
    assert engines[0].pool.checkedin() == 0
    assert client.closed == 1
    assert container._container is None


def test_native_settings_reset_disposes_temporary_engine(tmp_path, monkeypatch):
    from tests import conftest
    engine = db.make_engine(f"sqlite:///{tmp_path / 'reset.db'}")
    disposed = []
    event.listen(engine, 'engine_disposed', lambda e: disposed.append(e))
    monkeypatch.setattr(conftest, 'DATABASE_URL', 'synthetic-test-database')
    monkeypatch.setattr(db, 'make_engine', lambda url: engine)
    generator = conftest.settings.__wrapped__(tmp_path, monkeypatch)
    next(generator)
    assert disposed == [engine]
    assert engine.pool.checkedin() == 0
    with pytest.raises(StopIteration):
        next(generator)


def test_settings_finalizer_closes_only_all_containers_it_created(tmp_path, monkeypatch):
    from tests import conftest
    monkeypatch.setattr(container, '_container', None)
    generator = conftest.settings.__wrapped__(tmp_path, monkeypatch)
    config = next(generator)
    original = container.build.__wrapped__
    first = container.build(config, synchronous_jobs=True)
    second = container.build(settings_at(tmp_path / 'second'), synchronous_jobs=True)
    foreign = original(settings_at(tmp_path / 'foreign'), synchronous_jobs=True)
    try:
        with pytest.raises(StopIteration):
            next(generator)
        assert first._closed and second._closed
        assert foreign.runner.status().state == 'running'
        assert foreign.session_factory.kw['bind'].pool.checkedin() > 0
    finally:
        container.close(foreign)


@pytest.mark.parametrize("phase", ["schema", "queue_seed"])
def test_init_db_failure_disposes_only_new_engine_and_keeps_previous_bindings(tmp_path, monkeypatch, phase):
    old_engine = db.init_db(f"sqlite:///{tmp_path / 'old.db'}")
    old_factory = db.get_sessionmaker()
    created = db.make_engine(f"sqlite:///{tmp_path / 'failed.db'}")
    order = []
    event.listen(created, "engine_disposed", lambda e: order.append("dispose-new"))
    event.listen(old_engine, "engine_disposed", lambda e: order.append("dispose-old"))
    monkeypatch.setattr(db, "make_engine", lambda url: created)

    @event.listens_for(created, "before_cursor_execute")
    def fail(conn, cursor, statement, parameters, context, executemany):
        target = statement.startswith("CREATE TABLE") or statement.lstrip().startswith("CREATE TABLE")
        if phase == "queue_seed":
            target = statement.startswith("SELECT") and "an_job_queue_cursor" in statement
        if target:
            order.append("initialization-failed")
            raise RuntimeError("synthetic initialization failure")

    try:
        with pytest.raises(RuntimeError, match="synthetic initialization"):
            db.init_db("synthetic-new-db")
        assert order == ["initialization-failed", "dispose-new"]
        assert db._engine is old_engine
        assert db.get_sessionmaker() is old_factory
        assert created.pool.checkedin() == 0
        with old_factory() as session:
            assert session.connection().exec_driver_sql("SELECT 1").scalar() == 1
    finally:
        created.dispose()
        old_engine.dispose()
