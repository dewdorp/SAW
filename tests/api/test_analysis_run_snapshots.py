"""Immutable run provenance must survive reruns and isolate failed detectors."""
from sqlalchemy import select
from saw import container
from saw.core.application import analysis
from saw.detectors.base import FindingDraft
from saw.storage.db import session_scope
from tests.conftest import Api, make_user


class FixedDetector:
    id, version = "test.fixed", "1"
    data_sources = {"web"}

    def run(self, ctx):
        return [FindingDraft(self.id, self.version, "Possible unusual request", "web", "recon",
            0.5, "medium", [{"name": "requests", "observed": 1}], [], [], {}, None, None,
            "same-pattern", sample_event_ids=["synthetic-event"], total_events=1)]


class BrokenDetector:
    id, version = "test.broken", "1"
    data_sources = {"web"}

    def run(self, ctx):
        raise RuntimeError("synthetic detector error")


def setup_events(analyst):
    inv = analyst.post("/investigations", json={"title": "synthetic run"}).json()["id"]
    container.get().events.index([{"event_id": "synthetic-event", "investigation_id": inv,
        "data_source": "web", "timestamp": "2026-10-20T00:00:00Z", "src_ip": "192.0.2.1"}])
    return inv


def test_rerun_keeps_old_snapshot_and_stable_finding(analyst, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun, FindingSnapshot
    inv = setup_events(analyst)
    fixed = FixedDetector()
    monkeypatch.setattr(analysis, "all_detectors", lambda: [fixed])
    with session_scope() as s:
        first = analysis.run_detectors(s, inv)[0]
        first_id = first.id
    fixed.version = "2"
    with session_scope() as s:
        second = analysis.run_detectors(s, inv)[0]
        assert second.id == first_id
    with session_scope() as s:
        runs = list(s.scalars(select(AnalysisRun).where(AnalysisRun.investigation_id == inv).order_by(AnalysisRun.version)))
        assert len(runs) == 2 and all(r.status == "complete" for r in runs)
        snapshots = list(s.scalars(select(FindingSnapshot).where(FindingSnapshot.finding_id == first_id)
                                  .order_by(FindingSnapshot.created_at)))
        assert [r.payload["detector"]["version"] for r in snapshots] == ["1", "2"]
        assert snapshots[0].payload["metrics"][0]["observed"] == 1
        assert runs[0].input_manifest["data_epoch"] == 0


def test_failure_is_partial_and_has_no_false_zero_match_count(analyst, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun, DetectorExecution
    inv = setup_events(analyst)
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector(), BrokenDetector()])
    with session_scope() as s:
        analysis.run_detectors(s, inv)
    with session_scope() as s:
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.investigation_id == inv))
        assert run.status == "partial"
        failed = s.scalar(select(DetectorExecution).where(DetectorExecution.run_id == run.id,
                                                         DetectorExecution.detector_id == "test.broken"))
        assert failed.status == "failed" and failed.match_count is None
        assert failed.detail["error_type"] == "RuntimeError"
        assert failed.input_count == 1


def test_no_source_is_not_an_executed_zero(analyst, monkeypatch):
    from saw.analysis_runs.models import DetectorExecution
    inv = analyst.post("/investigations", json={"title": "empty"}).json()["id"]
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector()])
    with session_scope() as s:
        analysis.run_detectors(s, inv)
    with session_scope() as s:
        execution = s.scalar(select(DetectorExecution).where(DetectorExecution.detector_id == "test.fixed"))
        assert execution.status == "not_applicable"
        assert execution.match_count is None
        assert execution.detail["reason"] == "required_source_missing"


def test_saved_report_is_immutable_and_requires_source_acl(app, analyst, monkeypatch):
    inv = setup_events(analyst)
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector()])
    with session_scope() as s:
        analysis.run_detectors(s, inv)
    runs = analyst.get(f"/investigations/{inv}/analysis-runs")
    assert runs.status_code == 200
    run_id = runs.json()["runs"][0]["id"]
    saved = analyst.post(f"/investigations/{inv}/report-versions", json={"analysis_run_id": run_id})
    assert saved.status_code == 201, saved.text
    report = saved.json()
    analyst.patch(f"/investigations/{inv}", json={"title": "later title"})
    read = analyst.get(f"/investigations/{inv}/report-versions/{report['id']}")
    assert read.json()["content_sha256"] == report["content_sha256"]
    assert read.json()["content"]["investigation"]["title"] == "synthetic run"
    html = analyst.get(f"/investigations/{inv}/report-versions/{report['id']}/html")
    assert html.status_code == 200 and "synthetic run" in html.text
    make_user("unrelated-run-reader", ["analyst"])
    other = Api(app, "unrelated-run-reader")
    assert other.get(f"/investigations/{inv}/analysis-runs/{run_id}").status_code == 403
    assert other.get(f"/investigations/{inv}/report-versions/{report['id']}/html").status_code == 403


def test_pipeline_failure_seals_run_instead_of_leaving_running(analyst, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun
    from saw.storage.models import Job, Investigation
    from saw.workers.pipeline import analyze_run
    inv = setup_events(analyst)
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector()])
    def broken_patterns(s, inv_id):
        raise RuntimeError("synthetic stage failure")
    monkeypatch.setattr(analysis, "run_patterns", broken_patterns)
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze",
                  requested_by=s.get(Investigation, inv).owner_id, state="QUEUED")
        s.add(job)
        s.flush()
        job_id = job.id
    analyze_run(job_id)
    with session_scope() as s:
        assert s.get(Job, job_id).state == "FAILED"
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.job_id == job_id))
        assert run.status == "failed"
        assert run.finished_at is not None
        assert run.summary["error_type"] == "RuntimeError"


def test_saved_report_is_removed_by_approved_source_cleanup(analyst, admin, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun, FindingSnapshot
    from saw.reports.models import ReportVersion
    from tests.api.test_admin_data import preview, execute
    inv = setup_events(analyst)
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector()])
    with session_scope() as s:
        analysis.run_detectors(s, inv)
    run_id = analyst.get(f"/investigations/{inv}/analysis-runs").json()["runs"][0]["id"]
    report = analyst.post(f"/investigations/{inv}/report-versions",
                          json={"analysis_run_id": run_id})
    assert report.status_code == 201
    result = execute(admin, preview(admin, "investigation", inv))
    assert result.json()["state"] == "COMPLETED", result.text
    with session_scope() as s:
        assert s.get(AnalysisRun, run_id) is None
        assert s.get(ReportVersion, report.json()["id"]) is None
        assert s.scalar(select(FindingSnapshot).where(FindingSnapshot.run_id == run_id)) is None


def test_insufficient_semantics_never_becomes_complete_or_zero(analyst, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun, DetectorExecution
    inv = setup_events(analyst)
    class Unresolved(FixedDetector):
        def run(self, ctx):
            ctx.params.setdefault("execution_reports", {})[self.id] = {"status": "insufficient_data"}
            return []
    monkeypatch.setattr(analysis, "all_detectors", lambda: [Unresolved()])
    with session_scope() as s:
        analysis.run_detectors(s, inv)
    with session_scope() as s:
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.investigation_id == inv))
        execution = s.scalar(select(DetectorExecution).where(DetectorExecution.run_id == run.id,
                                                              DetectorExecution.detector_id == "test.fixed"))
        assert run.status == "partial"
        assert execution.status == "insufficient_data"
        assert execution.match_count is None


def test_requested_cancel_is_not_a_failed_detector_or_completed_run(analyst, monkeypatch):
    from saw.analysis_runs.models import AnalysisRun
    from saw.storage.models import Job, Investigation
    from saw.workers.pipeline import analyze_run, Cancelled
    inv = setup_events(analyst)
    class Cancelling(FixedDetector):
        def run(self, ctx):
            assert callable(ctx.params["cancelled"])
            raise Cancelled()
    monkeypatch.setattr(analysis, "all_detectors", lambda: [Cancelling()])
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze",
                  requested_by=s.get(Investigation, inv).owner_id, state="QUEUED")
        s.add(job); s.flush(); job_id = job.id
    analyze_run(job_id)
    with session_scope() as s:
        assert s.get(Job, job_id).state == "CANCELLED"
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.job_id == job_id))
        assert run.status == "cancelled"


def test_review_cancel_after_detectors_is_cancelled(analyst, monkeypatch):
    from tests.api.test_analysis_run_snapshots import setup_events, FixedDetector
    from saw.core.application import analysis
    from saw.storage.db import session_scope
    from saw.storage.models import Job, Investigation
    from saw.analysis_runs.models import AnalysisRun
    from saw.workers.pipeline import analyze_run
    inv = setup_events(analyst)
    monkeypatch.setattr(analysis, "all_detectors", lambda: [FixedDetector()])
    def cancel_during_patterns(s, inv_id):
        j = s.scalar(select(Job).where(Job.investigation_id == inv_id))
        j.cancel_requested = True
    monkeypatch.setattr(analysis,"run_patterns",cancel_during_patterns)
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze", requested_by=s.get(Investigation,inv).owner_id, state="QUEUED")
        s.add(job); s.flush(); job_id=job.id
    analyze_run(job_id)
    with session_scope() as s:
        job=s.get(Job,job_id)
        run=s.scalar(select(AnalysisRun).where(AnalysisRun.job_id==job_id))
        assert (job.state,run.status)==("CANCELLED","cancelled")
