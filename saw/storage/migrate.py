"""Schema migrations (Alembic) — adopted so upgrades can ALTER existing production databases (create_all cannot).

Script directory: saw/storage/migrations (ships with the app; no alembic.ini needed).
Databases created before migrations existed (create_all) are stamped at the baseline revision, then upgraded.
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

SCRIPTS = Path(__file__).with_name("migrations")
BASELINE = "0001"


def _config(engine: Engine) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPTS))
    cfg.attributes["engine"] = engine
    return cfg


def current(engine: Engine) -> str | None:
    with engine.connect() as c:
        return MigrationContext.configure(c).get_current_revision()


def head() -> str:
    return ScriptDirectory(str(SCRIPTS)).get_current_head()


def upgrade(engine: Engine, target: str = "head") -> str:
    cfg = _config(engine)
    if current(engine) is None:
        tables = set(inspect(engine).get_table_names())
        if "iam_user" in tables:  # legacy create_all database: schema equals the baseline
            command.stamp(cfg, BASELINE)
    command.upgrade(cfg, target)
    return current(engine) or ""


def revision(engine: Engine, message: str) -> None:  # developer helper: autogenerate a new migration
    command.revision(_config(engine), message=message, autogenerate=True)
