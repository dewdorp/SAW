"""Job routing regression for immutable calculations."""
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


def test_restart_routes_behavior_to_calculator(analyst, monkeypatch):
    inv = make_case(analyst, 3)
    previous = container.get()
    # Commit a genuine request but simulate process loss before its wake hint runs.
    monkeypatch.setattr(previous.runner, "submit", lambda name, **kw: None)
    response = analyst.post(f"/investigations/{inv['id']}/behavior", json={})
    assert response.status_code == 202, response.text
    jid = response.json()["id"]
    with session_scope() as s:
        s.get(Job, jid).state = "ANALYZING"
    recovered = container.build(previous.settings)
    try:
        recovered.runner.wait_all(timeout=15)
        final = analyst.get(f"/jobs/{jid}").json()
        assert final["state"] == "COMPLETED", final
        with session_scope() as s:
            job = s.get(Job, jid)
            assert job.stages["_queue_task"] == "behavior.run"
            assert job.attempt == 1
        assert len(analyst.get(f"/investigations/{inv['id']}/behavior").json()["results"]) == 1
    finally:
        recovered.runner.close(wait=True)
