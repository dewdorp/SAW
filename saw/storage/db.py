"""SQLAlchemy engine/session. PostgreSQL in production, SQLite locally (ENV-02)."""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
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


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 60})

        @event.listens_for(eng, "connect")
        def _pragma(conn, _rec):  # noqa: ANN001
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return eng
    return create_engine(url, pool_pre_ping=True)


def load_models() -> None:
    """Import every module that declares tables so Base.metadata is complete (create_all and Alembic)."""
    from saw.connectors import registry as _cr  # noqa: F401
    from saw.detection import service as _det  # noqa: F401
    from saw.hunting import service as _hunt  # noqa: F401
    from saw.knowledge import models as _km  # noqa: F401
    from saw.knowledge import similar as _ks  # noqa: F401
    from saw.llm import service as _llm  # noqa: F401
    from saw.llm import model_packs as _lm  # noqa: F401
    from saw.parsers import library as _pl  # noqa: F401
    from saw.storage import models  # noqa: F401


def init_db(url: str, schema_mode: str = "create_all") -> Engine:
    """schema_mode: 'create_all' (dev/tests: build missing tables) or 'migrate' (production: Alembic upgrade head)."""
    global _engine, _SessionLocal
    load_models()
    _engine = make_engine(url)
    if schema_mode == "migrate":
        from saw.storage.migrate import upgrade

        upgrade(_engine)
    else:
        Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
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
