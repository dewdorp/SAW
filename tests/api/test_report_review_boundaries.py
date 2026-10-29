"""Report lease, frozen component closure and legacy migration boundaries."""
import importlib
from types import SimpleNamespace

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import select

from saw.core.application.investigations import Forbidden
from saw.core.application.provenance import canonical, digest
from saw.reports import export_jobs, service
from saw.reports.models import ReportSourceInvestigation, ReportVersion
from saw.storage.db import session_scope
from saw.storage.models import Investigation, Job
from tests.api.test_report_export_boundaries import queued
from tests.api.test_report_exports import finished


def test_preclaim_failure_cannot_overwrite_newer_worker_attempt(analyst, monkeypatch):
    job = queued(analyst, monkeypatch, key="independent-preclaim")
    original = export_jobs._actor
    fired = False
    def supersede_and_fail(s, uid):
        nonlocal fired
        if not fired:
            fired = True
            with session_scope() as other:
                live = other.get(Job, job["id"])
                live.attempt = 7
                live.state = "ANALYZING"
            raise Forbidden("synthetic old worker lost authorization")
        return original(s, uid)
    monkeypatch.setattr(export_jobs, "_actor", supersede_and_fail)
    export_jobs.run(job["id"])
    with session_scope() as s:
        saved = s.get(Job, job["id"])
        assert saved.attempt == 7 and saved.state == "ANALYZING"


def test_valid_bounded_multi_report_source_traversal_not_rejected_by_whole_graph_limit():
    source = "synthetic-source"
    payload = {"scope": {"query": {"filters": [], "time": None}},
               "context": {"guidance": {"input": {"facts": [], "unknowns": [], "queries": [], "limits": []}}},
               "evidence": [], "source_investigation_ids": [source]}
    content = {"schema_version": "saw.report.v2", "items": [
        {"checks": [{"payload": payload} for _ in range(1000)], "followups": [], "analysis": {}}
        for _ in range(5)]}
    assert len(canonical(content).encode()) < 16 * 1024 * 1024
    row = SimpleNamespace(investigation_id="anchor", source_investigation_ids=["anchor"], content=content)
    assert service.source_ids(row) == {"anchor", source}


def test_migration_backfill_includes_legacy_derived_content_sources(analyst):
    anchor, _ = finished(analyst)
    source, _ = finished(analyst)
    content = {"schema_version": "saw.report.v1", "analysis": {},
               "checks": [{"scope": {"source_investigation_ids": [source]}}]}
    with session_scope() as s:
        row = ReportVersion(investigation_id=anchor, version=1,
            created_by=s.get(Investigation, anchor).owner_id,
            source_investigation_ids=[anchor], content=content, content_sha256=digest(content))
        s.add(row)
        s.flush()
        ident, engine = row.id, s.get_bind()
    migration = importlib.import_module("saw.storage.migrations.versions.0020_report_source_ledgers")
    with engine.begin() as connection, Operations.context(MigrationContext.configure(connection)):
        migration.upgrade()
        migration.upgrade()
    with session_scope() as s:
        saved = s.get(ReportVersion, ident)
        assert canonical(saved.content) == canonical(content)
        assert saved.content_sha256 == digest(content)
        assert saved.source_investigation_ids == [anchor]
        assert set(s.scalars(select(ReportSourceInvestigation.investigation_id).where(
            ReportSourceInvestigation.report_id == ident))) == {anchor, source}


def test_report_capture_maps_followup_conflict_to_409_without_partial_save(analyst):
    from sqlalchemy import func

    from saw.followups.models import FollowUp
    from tests.api.test_followups import create
    from tests.api.test_report_exports import request_job, scope
    inv, run = finished(analyst)
    check = analyst.post(f"/investigations/{inv}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.88",
        "questions": ["impact"], "note": "Synthetic report conflict"}).json()
    item = create(analyst, f"/investigations/{inv}/follow-ups", check)
    with session_scope() as s:
        s.get(FollowUp, item["id"]).current_version_id = "missing-current"
    response = analyst.post(f"/investigations/{inv}/report-versions",
                            json={"analysis_run_id": run})
    assert response.status_code == 409, response.text
    response = request_job(analyst, scope((inv, run)), key="conflicted-followup")
    assert response.status_code == 409, response.text
    with session_scope() as s:
        assert s.scalar(select(func.count()).select_from(ReportVersion).where(
            ReportVersion.investigation_id == inv)) == 0
        assert s.scalar(select(func.count()).select_from(Job).where(
            Job.investigation_id == inv, Job.kind == "report_export")) == 0
