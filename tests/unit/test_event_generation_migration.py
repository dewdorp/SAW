"""Additive 0023 upgrades preserve existing Jobs/history and requester rotation."""
import importlib

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from saw.analysis_runs.models import AnalysisRun
from saw.event_generations.models import generation_tables
from saw.storage.db import Base, load_models
from saw.storage.migrate import upgrade
from saw.storage.models import Investigation, Job, User
from saw.workers.queue_models import QueueCursor
from tests.unit import test_detector_version_migration as fixtures

isolated_engine = fixtures.isolated_engine


def test_0023_populated_upgrade_keeps_jobs_and_frozen_history(isolated_engine):
    engine = isolated_engine
    assert upgrade(engine, "0022") == "0022"
    with Session(engine) as session:
        session.add(User(id="author", username="synthetic", password_hash="", roles=["analyst"]))
        session.flush()
        session.add(Investigation(id="inv", display_id="INV-SYNTHETIC", title="Synthetic", owner_id="author"))
        session.flush()
        session.add(Job(id="job", investigation_id="inv", requested_by="author", kind="reanalyze",
                        state="QUEUED", stages={"exact": [1, "한글"]}))
        session.add(AnalysisRun(id="run", investigation_id="inv", version=1,
                                input_manifest={"schema": "retained", "raw": "한글"},
                                input_sha256="a" * 64))
        session.commit()
    queries = ("SELECT CAST(stages AS TEXT),state,attempt FROM an_job",
               "SELECT CAST(input_manifest AS TEXT),input_sha256 FROM an_analysis_run")
    with engine.connect() as conn:
        before = [list(conn.execute(text(query))) for query in queries]
    assert upgrade(engine, "0023") == "0023"
    assert upgrade(engine, "0023") == "0023"
    with engine.connect() as conn:
        assert [list(conn.execute(text(query))) for query in queries] == before
    with Session(engine) as session:
        assert session.get(QueueCursor, "heavy").revision == 0
    assert {table.name for table in generation_tables()} <= set(inspect(engine).get_table_names())
    assert next(index for index in inspect(engine).get_indexes("an_job")
                if index["name"] == "ix_an_job_queue_due")["column_names"] == [
                    "state", "requested_by", "created_at", "id"]


def test_0023_create_all_reentry_repairs_indexes_keeps_cursor(isolated_engine):
    engine = isolated_engine
    load_models()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(QueueCursor(id="heavy", last_requester="previous", revision=17))
        session.commit()
    migration = importlib.import_module("saw.storage.migrations.versions.0023_event_generations")
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP INDEX ix_an_job_queue_due")
        conn.exec_driver_sql("DROP INDEX ix_eg_generation_investigation_id")
        with Operations.context(MigrationContext.configure(conn)):
            migration.upgrade()
            migration.upgrade()
    with Session(engine) as session:
        cursor = session.get(QueueCursor, "heavy")
        assert (cursor.last_requester, cursor.revision) == ("previous", 17)
    assert "ix_an_job_queue_due" in {item["name"] for item in inspect(engine).get_indexes("an_job")}
    assert "ix_eg_generation_investigation_id" in {
        item["name"] for item in inspect(engine).get_indexes("eg_generation")}
