"""Finite independent A review: evidence stability at follow-up mutation publication."""
from saw import container
from saw.storage.db import utcnow
from tests.api.test_followups import create, setup


def event_for(inv_id):
    return {"event_id": "p3-review-event", "investigation_id": inv_id,
            "timestamp": utcnow().isoformat(), "data_source": "synthetic",
            "raw_event": "Original synthetic transaction"}


def test_verification_rejects_stale_retained_reply_evidence(analyst):
    inv, check, url = setup(analyst)
    event = event_for(inv["id"])
    container.get().events.index([event])
    task = create(analyst, url, check)
    endpoint = f"{url}/{task['id']}"
    refs = [{"investigation_id": inv["id"], "event_id": event["event_id"]}]
    replied = analyst.post(endpoint + "/reply", json={
        "expected_version_id": task["current"]["id"], "reason": "Synthetic reply",
        "note": "Original transaction", "evidence": refs})
    assert replied.status_code == 200, replied.text
    current = replied.json()["current"]
    container.get().events.index([{**event, "raw_event": "Changed synthetic transaction"}])
    response = analyst.post(endpoint + "/verify", json={"expected_version_id": current["id"],
        "reason": "Verify current transaction", "outcome": "confirmed", "basis": "Current source",
        "evidence": refs})
    assert response.status_code == 409, response.text
    assert analyst.get(endpoint).json()["current"]["id"] == current["id"]


def test_reply_rechecks_evidence_after_read_before_append(analyst, monkeypatch):
    inv, check, url = setup(analyst)
    event = event_for(inv["id"])
    store = container.get().events
    store.index([event])
    task = create(analyst, url, check)
    endpoint = f"{url}/{task['id']}"
    native_get = store.get
    altered = False
    def read_then_reprocess(*args, **kwargs):
        nonlocal altered
        value = native_get(*args, **kwargs)
        if not altered:
            altered = True
            store.index([{**event, "raw_event": "Changed during capture"}])
        return value
    monkeypatch.setattr(store, "get", read_then_reprocess)
    response = analyst.post(endpoint + "/reply", json={
        "expected_version_id": task["current"]["id"], "reason": "Synthetic reply",
        "note": "Validate stable content", "evidence": [{"investigation_id": inv["id"], "event_id": event["event_id"]}]})
    assert altered
    assert response.status_code == 409, response.text
    assert analyst.get(endpoint).json()["current"]["id"] == task["current"]["id"]


def test_fresh_reply_replaces_stale_refs_and_preserves_old_version(analyst):
    inv, check, url = setup(analyst)
    store = container.get().events
    event = event_for(inv["id"])
    store.index([event])
    task = create(analyst, url, check)
    endpoint = f"{url}/{task['id']}"
    refs = [{"investigation_id": inv["id"], "event_id": event["event_id"]}]
    first = analyst.post(endpoint + "/reply", json={
        "expected_version_id": task["current"]["id"], "reason": "Original reply",
        "note": "Original source", "evidence": refs}).json()["current"]
    store.index([{**event, "raw_event": "Fresh synthetic transaction"}])
    refreshed = analyst.post(endpoint + "/reply", json={"expected_version_id": first["id"],
        "reason": "Source changed", "note": "Fresh source checked explicitly", "evidence": refs})
    assert refreshed.status_code == 200, refreshed.text
    new_reply = refreshed.json()["current"]
    assert new_reply["payload"]["reply"]["evidence"][0]["sha256"] != first["payload"]["reply"]["evidence"][0]["sha256"]
    verified = analyst.post(endpoint + "/verify", json={"expected_version_id": new_reply["id"],
        "reason": "Check refreshed source", "outcome": "not_confirmed", "basis": "Fresh source",
        "evidence": refs})
    assert verified.status_code == 200, verified.text
    assert verified.json()["current"]["payload"]["status"] == "verified"
    old = analyst.get(endpoint + "/versions/" + first["id"])
    assert old.status_code == 200
    assert old.json()["version"]["payload"] == first["payload"]
