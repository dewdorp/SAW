"""Migration preserves only exact current proven legacy heads; no draft resurrection."""
from datetime import UTC, datetime
import importlib
from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa
from saw.storage.db import make_engine
from saw.storage.migrate import upgrade

NOW = datetime.now(UTC)
LOGIC = "title: Synthetic\nlogsource: {category: webserver}\ndetection:\n  s: {sc-status: 403}\n  condition: s\n"


def seed_legacy(connection, ident, *, status="approved", complete=True, draft=False):
    meta = sa.MetaData()
    det = sa.Table("det_detection", meta, autoload_with=connection)
    ver = sa.Table("det_version", meta, autoload_with=connection)
    trial = sa.Table("det_test_run", meta, autoload_with=connection)
    connection.execute(det.insert().values(id=ident, display_id=ident, status="draft" if draft else status,
        current_version=2 if draft else 1, created_by="author", created_by_name="author", deployments=[],
        source={}, created_at=NOW, updated_at=NOW))
    def version(number):
        return dict(id=ident + "-" + str(number), detection_id=ident, version=number, title="Synthetic", description="",
            data_source="web", format="sigma", logic=LOGIC, threshold={}, exceptions=[], false_positive="",
            severity="low", confidence="medium", test_events=[], attack=[], created_by="author",
            reviewed_by="reviewer" if number == 1 else None, status_at_version="approved" if number == 1 else "draft", created_at=NOW)
    connection.execute(ver.insert().values(**version(1)))
    if draft:
        connection.execute(ver.insert().values(**version(2)))
    connection.execute(trial.insert().values(id=ident + "-test", detection_id=ident, version=1, scope={"investigations": []},
        result={"execution": "complete" if complete else "partial", "scanned": 3, "truncated": not complete},
        passed=True, ran_by="author", ran_at=NOW))


def test_governance_migration_is_conservative_and_idempotent(tmp_path):
    eng = make_engine(f"sqlite:///{(tmp_path / 'governance.db').as_posix()}")
    upgrade(eng, "0016")
    with eng.begin() as c:
        user = sa.Table("iam_user", sa.MetaData(), autoload_with=c)
        for ident, roles in (("author", ["analyst"]), ("reviewer", ["soc_manager"])):
            c.execute(user.insert().values(id=ident, username=ident, display_name="", password_hash="",
                roles=roles, mfa_enabled=False, status="active", failed_count=0, created_at=NOW))
        seed_legacy(c, "valid")
        seed_legacy(c, "partial", complete=False)
        seed_legacy(c, "draft", draft=True)
        seed_legacy(c, "retired", status="deprecated")
    upgrade(eng, "0017")
    migration = importlib.import_module("saw.storage.migrations.versions.0017_detection_governance")
    with eng.begin() as c:
        with Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            migration.upgrade()
        table = sa.Table("det_detection", sa.MetaData(), autoload_with=c)
        rows = {row["id"]: row for row in c.execute(sa.select(table)).mappings()}
        assert rows["valid"]["active_version_id"] == "valid-1"
        assert rows["valid"]["activation_revision"] == 1
        assert rows["partial"]["active_version_id"] is None
        assert rows["draft"]["draft_version_id"] == "draft-2"
        assert rows["draft"]["approved_version_id"] is None and rows["draft"]["active_version_id"] is None
        assert rows["retired"]["active_version_id"] is None
        assert c.exec_driver_sql("SELECT COUNT(*) FROM det_approval").scalar() == 1
        assert c.exec_driver_sql("SELECT COUNT(*) FROM det_activation").scalar() == 1
        assert c.exec_driver_sql("SELECT COUNT(*) FROM det_version WHERE length(payload_sha256)=64").scalar() == 5
    eng.dispose()
