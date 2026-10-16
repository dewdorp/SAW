"""Job routing regression for immutable calculations."""
from sqlalchemy import select
from saw import container
from saw.storage.db import session_scope
from saw.storage.models import Job
from tests.api.test_guidance import make_case


def test_behavior_cancel_retry_and_completed_guard(analyst, monkeypatch):
    inv = make_case(analyst, 3)
    runner = container.get().runner
    dispatch = runner.submit
    queued = []
    monkeypatch.setattr(runner, "submit", lambda name, **kw: queued.append((name, kw)))
    job = analyst.post(f"/investigations/{inv['id']}/behavior", json={}).json()
    assert queued[-1][0] == "behavior.run"
    assert analyst.post(f"/jobs/{job['id']}/cancel").json()["state"] == "CANCELLED"
    monkeypatch.setattr(runner, "submit", dispatch)
    retried = analyst.post(f"/jobs/{job['id']}/retry")
    assert retried.status_code == 200, retried.text
    final = analyst.get(f"/jobs/{job['id']}").json()
    assert final["state"] == "COMPLETED", final
    assert analyst.post(f"/jobs/{job['id']}/retry").status_code == 409
    assert len(analyst.get(f"/investigations/{inv['id']}/behavior").json()["results"]) == 1


def test_restart_routes_behavior_to_calculator(analyst):
    inv = make_case(analyst, 3)
    with session_scope() as s:
        job = Job(investigation_id=inv["id"], kind="behavior", state="ANALYZING",
                  requested_by="synthetic", stages={"behavior_request": {"filters": []}})
        s.add(job)
        s.flush()
        jid = job.id
    class RecordingRunner:
        def __init__(self): self.calls = []
        def submit(self, name, **kw): self.calls.append((name, kw))
    recording = RecordingRunner()
    container._recover_orphaned_jobs(recording)
    assert ("behavior.run", {"job_id": jid}) in recording.calls
