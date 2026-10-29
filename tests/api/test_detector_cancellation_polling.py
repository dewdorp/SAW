"""Cancellation inside a hot callback window must never publish a completed run."""
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from saw.analysis_runs.models import AnalysisRun, FindingSnapshot
from saw.core.application import analysis
from saw.storage.db import session_scope
from saw.storage.models import Finding, Investigation, Job
from saw.workers import pipeline
from tests.api.test_analysis_run_snapshots import FixedDetector, setup_events


@pytest.mark.parametrize("mutation", ["cancel", "attempt"])
@pytest.mark.parametrize("phase", ["detector", "detector_failure", "final_publication"])
def test_change_inside_polling_window_cannot_publish(analyst, monkeypatch, mutation, phase):
    inv = setup_events(analyst)
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze",
                  requested_by=s.get(Investigation, inv).owner_id, state="QUEUED")
        s.add(job)
        s.flush()
        job_id = job.id
    # No clock advance: the second hot callback must stay inside its initial window.
    monkeypatch.setattr(analysis, "time", SimpleNamespace(monotonic=lambda: 10.0))
    armed = [False]
    observed = []

    def change(job):
        if mutation == "cancel":
            job.cancel_requested = True
        else:
            job.attempt += 1

    class MutatingDetector(FixedDetector):
        def run(self, ctx):
            observed.append(ctx.params["cancelled"]())
            if phase.startswith("detector"):
                with session_scope() as session:
                    change(session.get(Job, job_id))
                # Proves the mutation occurred inside the cached window.
                observed.append(ctx.params["cancelled"]())
            if phase == "detector_failure":
                raise RuntimeError("synthetic detector failure after cancellation")
            return super().run(ctx)

    monkeypatch.setattr(analysis, "all_detectors", lambda: [MutatingDetector()])
    if phase == "final_publication":
        from saw.core.application import data_deletion
        original_refresh = analysis.refresh_investigation
        original_lock = data_deletion.lock_investigation

        def refresh(session, inv_id):
            original_refresh(session, inv_id)
            armed[0] = True

        def lock(session, inv_id):
            result = original_lock(session, inv_id)
            if armed[0]:
                armed[0] = False
                change(session.get(Job, job_id))
                session.flush()
            return result

        monkeypatch.setattr(analysis, "refresh_investigation", refresh)
        monkeypatch.setattr(data_deletion, "lock_investigation", lock)
    pipeline.analyze_run(job_id)
    assert observed == ([False, False] if phase.startswith("detector") else [False])
    with session_scope() as s:
        job = s.get(Job, job_id)
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.job_id == job_id))
        assert job.state != "COMPLETED"
        assert run.status not in {"complete", "partial"}
        assert not (job.stages or {}).get("analyze", {}).get("done")
        if phase.startswith("detector"):
            assert s.scalar(select(Finding).where(Finding.investigation_id == inv)) is None
            assert s.scalar(select(FindingSnapshot).where(FindingSnapshot.run_id == run.id)) is None
        if mutation == "cancel":
            assert (job.state, run.status) == ("CANCELLED", "cancelled")


@pytest.mark.parametrize("mutation", ["cancel", "attempt"])
def test_next_detector_forces_fresh_check_inside_window(analyst, monkeypatch, mutation):
    inv = setup_events(analyst)
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze",
                  requested_by=s.get(Investigation, inv).owner_id, state="QUEUED")
        s.add(job)
        s.flush()
        job_id = job.id
    monkeypatch.setattr(analysis, "time", SimpleNamespace(monotonic=lambda: 10.0))
    entered = []

    class First(FixedDetector):
        def run(self, ctx):
            entered.append("first")
            return []

    class Second(FixedDetector):
        id = "test.second"

        def run(self, ctx):
            entered.append("second")
            return []

    original_capture = analysis.run_history.capture_findings

    def capture(session, run, findings):
        original_capture(session, run, findings)
        job = session.get(Job, job_id)
        if mutation == "cancel":
            job.cancel_requested = True
        else:
            job.attempt += 1

    monkeypatch.setattr(analysis, "all_detectors", lambda: [First(), Second()])
    monkeypatch.setattr(analysis.run_history, "capture_findings", capture)
    pipeline.analyze_run(job_id)
    assert entered == ["first"]
    with session_scope() as s:
        assert s.get(Job, job_id).state != "COMPLETED"
        run = s.scalar(select(AnalysisRun).where(AnalysisRun.job_id == job_id))
        assert run.status not in {"complete", "partial"}


def test_direct_pipeline_cancellation_reads_stay_fresh(analyst, monkeypatch):
    inv = setup_events(analyst)
    with session_scope() as s:
        job = Job(investigation_id=inv, kind="reanalyze",
                  requested_by=s.get(Investigation, inv).owner_id, state="QUEUED")
        s.add(job)
        s.flush()
        job_id = job.id
    monkeypatch.setattr(analysis, "time", SimpleNamespace(monotonic=lambda: 10.0))
    check = analysis._detector_cancellation(job_id)
    assert check() is False
    with session_scope() as s:
        s.get(Job, job_id).cancel_requested = True
    assert check() is False
    assert pipeline._cancelled(job_id) is True
    assert check(force=True) is True
