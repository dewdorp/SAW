"""Verified source time must drive scoped queries and observed calculations together."""
from saw import container
from saw.event_generations.reads import actor_scope
from tests.api.test_affiliate_firewall_flow import CSV
from tests.api.test_phase5_bulk import upload
from tests.api.test_source_context import org, investigation, device
from tests.api.test_scoped_device_analysis import submit, fw

def test_verified_profile_timezone_matches_actual_scoped_query(senior):
    organization = org(senior)
    inv = investigation(senior, organization["id"])["id"]
    dev = device(senior, inv)
    profile = senior.post(f"/source-context/devices/{dev['id']}/profiles", json={
        "functions": ["FW"], "network": "synthetic", "source_fields": {
            "timestamp": "timestamp", "record_kind": "record_type", "session_id": "session_id",
            "action": "action", "src_bytes": "sent_bytes", "dst_bytes": "received_bytes"},
        "record_kind_map": {"start": "session_start", "interim": "session_interim", "end": "session_end"},
        "action_verified": True, "action_map": {"allow": "allowed"}, "action_basis": "Synthetic schema",
        "measurement_profile": {"counter_semantics": "cumulative", "direction": "src_to_dst",
            "unit": "bytes", "verified": True, "basis": "Synthetic schema"},
        "time": {"role": "occurred", "timezone": "UTC", "precision": "second",
                 "verified": True, "basis": "Synthetic UTC schema"}})
    assert profile.status_code == 201
    # The evidence upload default is Asia/Seoul; an explicit verified profile says UTC.
    payload = CSV.replace(b"T00:", b" 09:").replace(b"Z,", b",")
    item = upload(senior, inv, "synthetic-time.csv", payload)
    attached = senior.post(f"/source-context/evidence/{item['evidence_id']}/context", json={
        "device_profile_version_id": profile.json()["id"], "subject": {
            "org_unit_id": organization["id"], "status": "verified", "basis": "Synthetic"}})
    assert attached.status_code == 201
    senior.post(f"/evidence/{item['evidence_id']}/process").raise_for_status()
    job, result = submit(senior, inv, time={"start": "2026-10-20T09:00:00Z", "end": "2026-10-20T09:03:00Z"})
    assert job["state"] == "COMPLETED"
    assert fw(result)["input_count"] == 3
    assert fw(result)["detail"]["sessions"][0]["src_to_dst_bytes"] == 300
    with actor_scope(senior.get("/auth/me").json()["id"]):
        rows = list(container.get().events.iterate(inv, []))
    assert all(r["timestamp"] == r["ext"]["observation"]["timestamp"] for r in rows)
    assert rows[0]["ext"]["observation"]["ces_timestamp"] == "2026-10-20T00:00:00.000Z"
