"""Context migration resumes safely over partial schemas without legacy relabeling."""
from sqlalchemy import inspect

from saw.storage.db import make_engine
from saw.storage.migrate import upgrade


def test_context_migration_preserves_legacy_and_retries_partial_schema(tmp_path):
    eng = make_engine(f"sqlite:///{(tmp_path / 'context.db').as_posix()}")
    upgrade(eng, "0014")
    with eng.begin() as c:
        c.exec_driver_sql("INSERT INTO iam_user (id, username, display_name, password_hash, roles, mfa_enabled, status, failed_count, created_at) VALUES ('synthetic-u', 'synthetic', '', '', '[]', 0, 'active', 0, CURRENT_TIMESTAMP)")
        c.exec_driver_sql("INSERT INTO inv_investigation (id, display_id, title, status, risk_level, risk_score, owner_id, close_detail, org_unit, settings, created_at) VALUES ('synthetic-i', 'INV-SYNTHETIC', 'Synthetic', 'open', 'info', 0, 'synthetic-u', '{}', 'Ambiguous legacy', '{}', CURRENT_TIMESTAMP)")
    upgrade(eng)
    assert "org_unit_id" in {x["name"] for x in inspect(eng).get_columns("inv_investigation")}
    assert "context_snapshot_id" in {x["name"] for x in inspect(eng).get_columns("ev_evidence")}
    with eng.connect() as c:
        assert c.exec_driver_sql("SELECT org_unit, org_unit_id FROM inv_investigation").one() == ("Ambiguous legacy", None)
    import importlib

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    migration = importlib.import_module("saw.storage.migrations.versions.0015_source_context")
    with eng.begin() as c:
        c.exec_driver_sql("DROP INDEX ix_sc_device_investigation_id")
        with Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            migration.upgrade()
    assert "ix_sc_device_investigation_id" in {x["name"] for x in inspect(eng).get_indexes("sc_device")}