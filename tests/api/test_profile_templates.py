"""A confirmed device profile is reused in a new investigation as its own copy, within the same affiliate."""
import uuid


def _org(api):
    return api.post("/source-context/org-units", json={"display_name": f"T {uuid.uuid4().hex[:6]}"}).json()["id"]


def _inv(api, org, title):
    return api.post("/investigations", json={"title": title, "org_unit_id": org}).json()["id"]


PROFILE = {"functions": ["FW"], "network": "synthetic", "vendor": "Synthetic FW", "product": "Export",
           "source_fields": {"timestamp": "_time", "action": "action", "src_bytes": "sent_bytes", "dst_bytes": "rcvd_bytes",
                             "duration": "duration"},
           "action_map": {"allow": "allowed", "deny": "blocked"}, "action_verified": True, "action_basis": "vendor manual",
           "measurement_profile": {"counter_semantics": "total", "direction": "src_to_dst", "unit": "bytes",
                                   "duration_unit": "seconds", "verified": True, "basis": "vendor manual"},
           "time": {"role": "end", "timezone": "Asia/Seoul", "precision": "seconds", "verified": True, "basis": "vendor manual"}}


def test_template_is_copied_independently_and_never_crosses_affiliates(senior):
    org, other_org = _org(senior), _org(senior)
    first = _inv(senior, org, "first")
    device = senior.post(f"/source-context/investigations/{first}/devices", json={"display_name": "fw-01"}).json()
    original = senior.post(f"/source-context/devices/{device['id']}/profiles", json=PROFILE)
    assert original.status_code == 201, original.text
    second = _inv(senior, org, "second")
    templates = senior.get(f"/source-context/investigations/{second}/profile-templates").json()["items"]
    mine = next(t for t in templates if t["profile_version_id"] == original.json()["id"])
    assert mine["verified"] == {"time": True, "counters": True, "action": True} and mine["device_name"] == "fw-01"

    copied = senior.post(f"/source-context/investigations/{second}/devices/from-template",
                         json={"profile_version_id": mine["profile_version_id"], "display_name": "fw-01"})
    assert copied.status_code == 201, copied.text
    new = copied.json()
    assert new["profile_version_id"] != mine["profile_version_id"] and new["sha256"] == mine["sha256"]
    # The original changing later does not touch the copy.
    senior.post(f"/source-context/devices/{device['id']}/profiles", json={**PROFILE, "vendor": "Changed"})
    kept = senior.get(f"/source-context/devices/{new['device_id']}/profiles").json()
    assert len(kept) == 1 and kept[0]["sha256"] == mine["sha256"] and kept[0]["profile"]["vendor"] == "Synthetic FW"

    third = _inv(senior, other_org, "other affiliate")
    assert all(t["investigation_id"] != first for t in
               senior.get(f"/source-context/investigations/{third}/profile-templates").json()["items"])
    refused = senior.post(f"/source-context/investigations/{third}/devices/from-template",
                          json={"profile_version_id": mine["profile_version_id"]})
    assert refused.status_code == 400
