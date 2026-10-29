from saw import container
from saw.event_generations.reads import actor_scope


def seed(api):
    inv = api.post("/investigations", json={"title": "Synthetic comparison scope"}).json()["id"]
    rows = []
    for i in range(4):
        rows.append(dict(event_id=f"bd-{i}", investigation_id=inv, data_source="web",
            timestamp=f"2026-10-16T01:00:0{i}Z", src_ip="192.0.2.1",
            dst_ip="198.51.100.10" if i < 3 else "198.51.100.11",
            method="GET", uri=f"/api/item?id={i}&token=synthetic-secret-{i}",
            uri_template="/api/item?id=<NUM>&token=<STR>", url_path="/api/item",
            user_agent="SyntheticClient", status_code=200,
            raw_event=f"GET /api/item?id={i}&token=synthetic-secret-{i}"))
    container.get().events.index(rows)
    return inv


def test_diff_keeps_query_variations_and_masks_values(analyst):
    inv = seed(analyst)
    response = analyst.post(f"/investigations/{inv}/diff", json={"src_ip": "192.0.2.1"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert len(data["requests"]) == 4
    assert any(c["type"] == "PARAM_VALUE_CHANGE" for c in data["transitions"][0]["changes"])
    assert "synthetic-secret" not in response.text


def test_diff_intersects_saved_scope_and_explicit_ids(analyst):
    inv = seed(analyst)
    body = {"event_ids": ["bd-0", "bd-1", "bd-2", "bd-3"],
            "filters": [{"field": "dst_ip", "value": "198.51.100.10"}],
            "time": {"start": "2026-10-16T01:00:01Z", "end": "2026-10-16T01:00:02Z"},
            "ips": ["198.51.100.10"], "role": "either"}
    response = analyst.post(f"/investigations/{inv}/diff", json=body)
    assert response.status_code == 200, response.text
    assert len(response.json()["requests"]) == 2
    body["ips"] = ["203.0.113.9"]
    assert analyst.post(f"/investigations/{inv}/diff", json=body).status_code == 400


def test_diff_can_compare_destination_scope_without_explicit_ids(analyst):
    inv = seed(analyst)
    response = analyst.post(f"/investigations/{inv}/diff",
        json={"ips": ["198.51.100.10"], "role": "dst"})
    assert response.status_code == 200, response.text
    assert len(response.json()["requests"]) == 3

def test_behavior_diff_uses_saved_projection_after_reindex(analyst):
    inv = seed(analyst)
    job = analyst.post(f"/investigations/{inv}/behavior", json={"ips": ["192.0.2.1"]})
    assert job.status_code == 202
    saved = analyst.get(f"/investigations/{inv}/behavior").json()["results"][0]
    result = analyst.get(f"/investigations/{inv}/behavior/{saved['id']}").json()
    with actor_scope(analyst.get("/auth/me").json()["id"]):
        row = container.get().events.get(inv, "bd-1")
    row["uri"] = "/changed-after-snapshot"
    container.get().events.index([row])
    scope = result["result"]["scope"]
    body = {**scope, "behavior_result_id": result["id"], "result_sha256": result["result_sha256"],
            "event_ids": ["bd-0", "bd-1"]}
    response = analyst.post(f"/investigations/{inv}/diff", json=body)
    assert response.status_code == 200, response.text
    assert "/changed-after-snapshot" not in response.text
    assert any(c["type"] == "PARAM_VALUE_CHANGE" for c in response.json()["transitions"][0]["changes"])
    body["result_sha256"] = "0"*64
    assert analyst.post(f"/investigations/{inv}/diff", json=body).status_code == 400
