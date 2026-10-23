"""Exact detector provenance survives fresh schemas and populated 0021 upgrades."""
import importlib
import os
import uuid
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import Session

from saw.analysis_runs.models import AnalysisRun, DetectorExecution, FindingSnapshot
from saw.knowledge.golden_models import GoldenBlob, GoldenVersion
from saw.knowledge.models import Experience
from saw.storage.db import Base, load_models, make_engine
from saw.storage.migrate import upgrade
from saw.storage.models import Finding, FindingFeedback, Investigation, User

VERSIONS = ["firewall-observation/1", "synthetic-detector/" + "v" * 45]


@pytest.fixture(params=["sqlite", "postgresql"])
def isolated_engine(tmp_path, request):
    if request.param == "sqlite":
        engine = make_engine(f"sqlite:///{(tmp_path / 'detector-version.db').as_posix()}")
    else:
        # Only the explicitly supplied disposable test DB is used. Keep the generated
        # schema as evidence until its owner shuts down the disposable native fixture.
        value = os.environ.get("SAW_TEST_DATABASE_URL")
        if not value:
            pytest.skip("SAW_TEST_DATABASE_URL not set; actual PostgreSQL not exercised")
        url = sa.engine.make_url(value)
        assert url.get_backend_name() == "postgresql", "native case requires actual PostgreSQL"
        schema = "saw_detector_version_" + uuid.uuid4().hex
        bootstrap = make_engine(value)
        try:
            with bootstrap.begin() as connection:
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        finally:
            bootstrap.dispose()
        engine = sa.create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT current_schema()").scalar_one() == schema
    try:
        yield engine
    finally:
        engine.dispose()


def _finding(ident, version):
    return Finding(id=ident, display_id=ident, investigation_id="synthetic-inv",
                   detector_id="fw.observation", detector_version=version, title="Synthetic",
                   category="network.firewall.scan", risk_level="low", risk_score=1,
                   confidence="medium", dedup_key=ident)


def _version_column(engine):
    return next(column for column in sa.inspect(engine).get_columns("an_finding")
                if column["name"] == "detector_version")


def _history(connection):
    # CAST preserves the database's stored JSON representation, including v1 bytes.
    queries = {
        "finding": "SELECT * FROM an_finding ORDER BY id",
        "feedback": "SELECT * FROM an_finding_feedback ORDER BY id",
        "analysis": "SELECT CAST(input_manifest AS TEXT),input_sha256,CAST(summary AS TEXT) FROM an_analysis_run",
        "execution": "SELECT detector_version,CAST(effective_config AS TEXT),CAST(detail AS TEXT) FROM an_detector_execution",
        "snapshot": "SELECT CAST(payload AS TEXT),payload_sha256 FROM an_finding_snapshot",
        "golden": "SELECT CAST(input AS TEXT),CAST(answers AS TEXT),CAST(manifest AS TEXT),CAST(metadata_json AS TEXT),content_sha256 FROM kn_golden_version",
        "blob": "SELECT CAST(content AS TEXT),sha256 FROM kn_golden_blob",
    }
    return {name: connection.execute(sa.text(query)).all() for name, query in queries.items()}


def test_fresh_schema_preserves_complete_detector_versions(isolated_engine):
    load_models()
    Base.metadata.create_all(isolated_engine)
    with Session(isolated_engine) as session:
        session.add_all(_finding(f"fresh-{index}", version) for index, version in enumerate(VERSIONS))
        session.commit()
        assert list(session.scalars(sa.select(Finding.detector_version).order_by(Finding.id))) == VERSIONS
    # SQLite does not enforce VARCHAR lengths; check the declared storage contract too.
    assert _version_column(isolated_engine)["type"].length == 64


def test_0022_populated_0021_upgrade_twice_preserves_provenance_and_history(isolated_engine):
    assert upgrade(isolated_engine, "0021") == "0021"
    assert _version_column(isolated_engine)["type"].length == 16
    now = datetime(2026, 10, 23, tzinfo=UTC)
    with Session(isolated_engine) as session:
        session.add(User(id="synthetic-user", username="synthetic", password_hash="", roles=[]))
        session.flush()
        session.add(Investigation(id="synthetic-inv", display_id="INV-SYNTHETIC",
                                  title="Synthetic", owner_id="synthetic-user"))
        session.flush()
        session.add(_finding("legacy", "legacy/1"))
        session.add(AnalysisRun(id="synthetic-run", investigation_id="synthetic-inv", version=1,
                                input_manifest={"schema": "saw.analysis.v1"}, input_sha256="a" * 64))
        session.add(Experience(id="synthetic-exp", display_id="EXP-SYNTHETIC", analyst_id="synthetic-user"))
        session.flush()
        session.add(FindingFeedback(id="synthetic-feedback", finding_id="legacy", user_id="synthetic-user",
                                    verdict="confirmed", comment="Synthetic retained feedback"))
        session.add(DetectorExecution(id="synthetic-execution", run_id="synthetic-run", detector_id="fw.observation",
                                     detector_version=VERSIONS[0], status="complete", detail={"legacy": True}))
        session.add(FindingSnapshot(id="synthetic-snapshot", run_id="synthetic-run", finding_id="legacy",
                                   payload={"schema": "saw.finding.v1", "detector_version": "legacy/1"},
                                   payload_sha256="b" * 64))
        session.add(GoldenBlob(sha256="c" * 64, content={"legacy": True}, size_bytes=15))
        session.add(GoldenVersion(id="synthetic-golden", experience_id="synthetic-exp", experience_rev=1,
                                 version=1, source_investigation_id="synthetic-inv", methodology_version="legacy/1",
                                 as_of=now, input={"schema": "saw.golden.agent-input.v1"}, answers={"legacy": True},
                                 manifest=[], metadata_json={"title": "Synthetic"}, content_sha256="d" * 64,
                                 author_id="synthetic-user"))
        session.commit()
    with isolated_engine.connect() as connection:
        before = _history(connection)
    inspector = sa.inspect(isolated_engine)
    indexes = inspector.get_indexes("an_finding")
    unique = inspector.get_unique_constraints("an_finding")
    feedback_fk = inspector.get_foreign_keys("an_finding_feedback")
    assert upgrade(isolated_engine, "0022") == "0022"
    assert upgrade(isolated_engine, "0022") == "0022"
    migration = importlib.import_module("saw.storage.migrations.versions.0022_finding_detector_version")
    with isolated_engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            migration.upgrade()
        assert _history(connection) == before
        if connection.dialect.name == "sqlite":
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    inspector = sa.inspect(isolated_engine)
    assert inspector.get_indexes("an_finding") == indexes
    assert inspector.get_unique_constraints("an_finding") == unique
    assert inspector.get_foreign_keys("an_finding_feedback") == feedback_fk
    assert _version_column(isolated_engine)["nullable"] is False
    assert _version_column(isolated_engine)["type"].length == 64
    with Session(isolated_engine) as session:
        session.add_all(_finding(f"migrated-{index}", version) for index, version in enumerate(VERSIONS))
        session.commit()
        assert list(session.scalars(sa.select(Finding.detector_version)
                    .where(Finding.id.like("migrated-%")).order_by(Finding.id))) == VERSIONS
        with pytest.raises(sa.exc.IntegrityError):
            session.add(FindingFeedback(finding_id="missing", user_id="synthetic-user", verdict="confirmed"))
            session.commit()
        session.rollback()
        duplicate = _finding("duplicate", "legacy/1")
        duplicate.dedup_key = "legacy"
        with pytest.raises(sa.exc.IntegrityError):
            session.add(duplicate)
            session.commit()
        session.rollback()
