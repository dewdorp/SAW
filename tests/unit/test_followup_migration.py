"""Populated upgrades preserve old Check rows without inventing history."""
import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, select, func
from sqlalchemy.orm import Session

from saw.storage.db import make_engine
from saw.storage.migrate import upgrade
from saw.storage.models import User, Investigation, Check
from saw.followups.models import CheckRevision


def test_populated_upgrade_does_not_backdate_check_revisions_and_repairs_missing_index(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'followups.db').as_posix()}")
    upgrade(engine, "0018")
    with Session(engine) as s:
        user = User(username="synthetic", password_hash="", roles=["analyst"])
        s.add(user)
        s.flush()
        inv = Investigation(display_id="SYNTHETIC-001", title="Synthetic", owner_id=user.id)
        s.add(inv)
        s.flush()
        row = Check(investigation_id=inv.id, target_type="entity", target_key="ip:192.0.2.1",
                    questions=["success"], author_id=user.id, note="Original legacy note")
        s.add(row)
        s.commit()
        check_id = row.id
    upgrade(engine, "0019")
    with Session(engine) as s:
        assert s.get(Check, check_id).note == "Original legacy note"
        assert s.scalar(select(func.count()).select_from(CheckRevision)) == 0
    migration = importlib.import_module("saw.storage.migrations.versions.0019_followups")
    with engine.begin() as c:
        c.exec_driver_sql("DROP INDEX ix_inv_check_revision_check_id")
        with Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            migration.upgrade()
    assert "ix_inv_check_revision_check_id" in {x["name"] for x in inspect(engine).get_indexes("inv_check_revision")}
    engine.dispose()
