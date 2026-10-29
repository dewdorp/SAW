"""Synthetic evidence cleanup removes exports invalidated with their snapshots."""
from sqlalchemy import select

from saw import container
from saw.analysis_runs.models import AnalysisRun
from saw.reports.models import JobSourceInvestigation, ReportSourceInvestigation, ReportVersion
from saw.storage.db import session_scope
from saw.storage.models import Job
from tests.api.test_admin_data import execute, preview, target
from tests.api.test_report_exports import finished, request_job, scope


def test_evidence_cleanup_removes_own_report_jobs_and_retains_other_exports(analyst, admin):
    inv, evidence = target(analyst)
    with session_scope() as s:
        run_id = s.scalar(select(AnalysisRun.id).where(
            AnalysisRun.investigation_id == inv["id"]))
    job = request_job(analyst, scope((inv["id"], run_id))).json()
    other = request_job(analyst, scope(finished(analyst)), key="unrelated-export").json()
    assert job["state"] == other["state"] == "COMPLETED"
    report_id = job["stages"]["report_export"]["report_id"]
    store = container.get().objects
    assert store.cleanup_keys("saw-exports", "reports/" + job["id"])
    plan = preview(admin, "evidence", evidence["evidence_id"])
    assert not plan["blockers"], plan
    response = execute(admin, plan)
    assert response.status_code == 200 and response.json()["state"] == "COMPLETED"
    with session_scope() as s:
        assert s.get(ReportVersion, report_id) is None
        assert s.get(Job, job["id"]) is None
        assert s.scalar(select(JobSourceInvestigation).where(
            JobSourceInvestigation.job_id == job["id"])) is None
        assert s.scalar(select(ReportSourceInvestigation).where(
            ReportSourceInvestigation.report_id == report_id)) is None
        assert s.get(Job, other["id"]).state == "COMPLETED"
    assert not store.cleanup_keys("saw-exports", "reports/" + job["id"])
    assert analyst.get(f"/report-export-jobs/{other['id']}/download").status_code == 200
