"""Real upload/process and retained-generation pattern routing, using only synthetic CSV."""
from copy import deepcopy

from saw import container
from saw.event_generations.reads import actor_scope
from tests.api.test_affiliate_firewall_flow import CSV
from tests.api.test_phase5_bulk import upload
from tests.unit.test_pattern_routing import verified_context


def test_verified_fw_patterns_excluded_but_mixed_unverified_csv_preserved(analyst, senior):
    org = senior.post("/source-context/org-units", json={"display_name": "Synthetic pattern routing"}).json()
    inv = analyst.post("/investigations", json={"title": "Synthetic patterns", "org_unit_id": org["id"]}).json()["id"]
    device = analyst.post(f"/source-context/investigations/{inv}/devices",
                          json={"display_name": "Synthetic FW"}).json()
    profile_payload = deepcopy(verified_context()["profile"])
    profile_payload.update(owner_org_unit_id=org["id"], network="test-lab")
    profile = analyst.post(f"/source-context/devices/{device['id']}/profiles", json=profile_payload)
    assert profile.status_code == 201, profile.text
    trusted = upload(analyst, inv, "synthetic-trusted.csv", CSV)
    attached = analyst.post(f"/source-context/evidence/{trusted['evidence_id']}/context", json={
        "device_profile_version_id": profile.json()["id"],
        "subject": {"org_unit_id": org["id"], "status": "verified", "basis": "synthetic fixture"},
        "collection": {"scope": "full", "loss": "known"}})
    assert attached.status_code == 201, attached.text
    result = analyst.post(f"/evidence/{trusted['evidence_id']}/process")
    assert result.status_code == 200, result.text
    job = analyst.get(f"/jobs/{result.json()['id']}").json()
    assert job["state"] == "COMPLETED", job
    response = analyst.get(f"/investigations/{inv}/patterns")
    assert response.status_code == 200, response.text
    assert response.json() == []
    with actor_scope(analyst.get("/auth/me").json()["id"]):
        before = list(container.get().events.iterate(inv, []))
    assert len(before) == 3
    assert all(row["raw_event"] and row["raw_ref"] for row in before)
    raw_refs = {row["event_id"]: row["raw_ref"] for row in before}

    unknown = upload(analyst, inv, "synthetic-unverified.csv", CSV)
    result = analyst.post(f"/evidence/{unknown['evidence_id']}/process")
    assert result.status_code == 200, result.text
    job = analyst.get(f"/jobs/{result.json()['id']}").json()
    assert job["state"] == "COMPLETED", job
    response = analyst.get(f"/investigations/{inv}/patterns")
    assert response.status_code == 200, response.text
    patterns = response.json()
    assert sum(pattern["count"] for pattern in patterns if "drain3" in pattern["tags"]) == 3
    with actor_scope(analyst.get("/auth/me").json()["id"]):
        after = list(container.get().events.iterate(inv, []))
    assert len(after) == 6
    assert {row["event_id"]: row["raw_ref"] for row in after if row["event_id"] in raw_refs} == raw_refs
    assert sum(row["ext"]["observation"]["context"]["resolved"] is False for row in after) == 3
