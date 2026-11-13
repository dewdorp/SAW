"""SQLAlchemy engine/session. PostgreSQL in production, SQLite locally (ENV-02)."""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None
_session_context: ContextVar[sessionmaker[Session] | None] = ContextVar("saw_sessionmaker", default=None)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 60})

        @event.listens_for(eng, "connect")
        def _pragma(conn, _rec):
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return eng
    return create_engine(url, pool_pre_ping=True)


def load_models() -> None:
    """Import every module that declares tables so Base.metadata is complete (create_all and Alembic)."""
    from saw.analysis_runs import models as _ar  # noqa: F401
    from saw.behavior import models as _bh  # noqa: F401
    from saw.connectors import registry as _cr  # noqa: F401
    from saw.content_packages import models as _cp  # noqa: F401
    from saw.detection import policy_models as _dp  # noqa: F401
    from saw.detection import service as _det  # noqa: F401
    from saw.detection import truth_models as _dt  # noqa: F401
    from saw.event_generations import models as _eg  # noqa: F401
    from saw.flows import models as _fl  # noqa: F401
    from saw.followups import models as _fu  # noqa: F401
    from saw.hunting import service as _hunt  # noqa: F401
    from saw.hunts import models as _hunts  # noqa: F401
    from saw.internal_kb import models as _ik  # noqa: F401
    from saw.knowledge import golden_governance_models as _gg  # noqa: F401
    from saw.knowledge import golden_models as _gm  # noqa: F401
    from saw.knowledge import models as _km  # noqa: F401
    from saw.knowledge import similar as _ks  # noqa: F401
    from saw.llm import model_packs as _lm  # noqa: F401
    from saw.llm import service as _llm  # noqa: F401
    from saw.parsers import library as _pl  # noqa: F401
    from saw.question_presets import models as _qp  # noqa: F401
    from saw.reports import models as _rp  # noqa: F401
    from saw.source_context import models as _sc  # noqa: F401
    from saw.storage import models  # noqa: F401
    from saw.workers import queue_models as _qm  # noqa: F401


def init_db(url: str, schema_mode: str = "create_all") -> Engine:
    """schema_mode: 'create_all' (dev/tests: build missing tables) or 'migrate' (production: Alembic upgrade head)."""
    global _engine, _SessionLocal
    load_models()
    engine = make_engine(url)
    try:
        if schema_mode == "migrate":
            from saw.storage.migrate import upgrade

            upgrade(engine)
        else:
            Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        from saw.workers.queue_models import QueueCursor
        with factory.begin() as session:
            if session.get(QueueCursor, "heavy") is None:
                session.add(QueueCursor(id="heavy"))
    except BaseException:
        engine.dispose()
        raise
    _engine, _SessionLocal = engine, factory
    return engine


@contextmanager
def bind_sessionmaker(factory: sessionmaker[Session]) -> Iterator[None]:
    """Bind one captured app database without changing another worker's defaults."""
    if factory is None:
        raise ValueError("captured session factory is required")
    token = _session_context.set(factory)
    try:
        yield
    finally:
        _session_context.reset(token)


def get_sessionmaker() -> sessionmaker[Session]:
    captured = _session_context.get()
    if captured is not None:
        return captured
    if _SessionLocal is None:
        raise RuntimeError("database not initialised")
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    s = get_sessionmaker()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
