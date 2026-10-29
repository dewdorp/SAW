"""Captured app dependencies remain isolated across replacement and worker reuse."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from saw import container
from saw.storage import db


@pytest.fixture
def runtime_pairs(tmp_path, monkeypatch):
    engines = []
    pairs = []
    for label in ("a", "b"):
        engine = create_engine(f"sqlite:///{tmp_path / (label + '.db')}")
        engines.append(engine)
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE context_probe (id TEXT PRIMARY KEY)"))
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        captured = container.Container(None, None, None, None)
        pairs.append((captured, factory))
    monkeypatch.setattr(container, "_container", pairs[1][0])
    monkeypatch.setattr(db, "_SessionLocal", pairs[1][1])
    yield pairs
    for engine in engines:
        engine.dispose()


def record(value):
    with db.session_scope() as session:
        session.execute(text("INSERT INTO context_probe VALUES (:value)"), {"value": value})


def recorded(factory):
    with factory() as session:
        return list(session.scalars(text("SELECT id FROM context_probe ORDER BY id")))


def test_captured_runtime_survives_global_replacement_and_worker_reuse(runtime_pairs, monkeypatch):
    (first, first_factory), (second, second_factory) = runtime_pairs
    entered, proceed = Event(), Event()

    def work():
        with container.activate(first, first_factory):
            entered.set()
            assert proceed.wait(5)
            assert container.get() is first
            assert db.get_sessionmaker() is first_factory
            record("first-worker")
        return container.get(), db.get_sessionmaker()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(work)
        try:
            if not entered.wait(5):
                future.result(timeout=1)
                pytest.fail("worker did not enter captured context")
            monkeypatch.setattr(container, "_container", second)
            monkeypatch.setattr(db, "_SessionLocal", second_factory)
        finally:
            proceed.set()
        assert future.result(timeout=5) == (second, second_factory)
        assert pool.submit(lambda: (container.get(), db.get_sessionmaker())).result(timeout=5) == (
            second, second_factory)
    assert recorded(first_factory) == ["first-worker"]
    assert recorded(second_factory) == []


def test_nested_activation_restores_both_dependencies_after_exception(runtime_pairs):
    (first, first_factory), (second, second_factory) = runtime_pairs
    with container.activate(first, first_factory):
        record("before")
        with pytest.raises(ValueError, match="synthetic"), container.activate(second, second_factory):
            assert container.get() is second
            record("nested")
            raise ValueError("synthetic")
        assert container.get() is first
        assert db.get_sessionmaker() is first_factory
        record("after")
    assert container.get() is second
    assert db.get_sessionmaker() is second_factory
    assert recorded(first_factory) == ["after", "before"]
    assert recorded(second_factory) == ["nested"]


def test_session_binding_resets_when_body_rolls_back(runtime_pairs):
    (_, first_factory), (_, second_factory) = runtime_pairs
    with (
        pytest.raises(RuntimeError, match="synthetic"),
        db.bind_sessionmaker(first_factory),
        db.session_scope() as session,
    ):
        session.execute(text("INSERT INTO context_probe VALUES ('rolled-back')"))
        raise RuntimeError("synthetic")
    assert db.get_sessionmaker() is second_factory
    assert recorded(first_factory) == []
