"""Uploading TXT/CSV with automatic detection (kind=auto): NDR meta export and a Korean CP949 firewall export."""
from __future__ import annotations

from saw.devtools.sample_data import scenario_kr_firewall_csv, scenario_ndr_meta_csv
from tests.api.test_phase5_bulk import upload


def _process(api, inv_id: str, name: str, data: bytes) -> dict:
    up = upload(api, inv_id, name, data, kind="auto")
    job = api.post(f"/evidence/{up['evidence_id']}/process").json()
    j = api.get(f"/jobs/{job['id']}").json()
    assert j["state"] == "COMPLETED", j
    return j


def test_ndr_meta_csv_auto_detected_paired_and_detected(analyst):
    inv = analyst.post("/investigations", json={"title": "NDR 로그"}).json()
    j = _process(analyst, inv["id"], "qsearch_meta_result.csv", scenario_ndr_meta_csv().encode("utf-8-sig"))
    f = j["files"][0]
    assert f["parser_id"] == "ndr_meta_csv" and f["status"] == "done", f
    ov = analyst.post(f"/investigations/{inv['id']}/overview", json={}).json()
    srcs = {b["key"]: b["count"] for b in ov["summary"]["data_sources"]}
    assert srcs["web"] == 906 and srcs["zeek_conn"] == 906
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {x["category"] for x in fs}
    assert "web.api_enumeration" in cats, cats  # 300-step ID walk from one cloud IP with 200 responses
    assert {"web.injection_like", "web.sensitive_file_probe"} & cats, cats
    # cookies never reach the event store: check the stored documents, not the (masked) API view
    from saw import container
    from saw.core.schemas.query import Filter

    stored = container.get().events.search(inv["id"], [Filter(field="data_source", value="web")], limit=50)["events"]
    assert stored and all("JSESSIONID=" not in str(e) for e in stored)
    assert stored[0]["ext"]["ndr"]["cookie_names"] == ["JSESSIONID", "WMONID"]


def test_korean_cp949_firewall_csv_auto_detected_as_network_flows(analyst):
    inv = analyst.post("/investigations", json={"title": "방화벽"}).json()
    j = _process(analyst, inv["id"], "firewall_kr.csv", scenario_kr_firewall_csv())
    assert j["files"][0]["parser_id"] == "csv" and j["files"][0]["status"] == "done"
    ov = analyst.post(f"/investigations/{inv['id']}/overview", json={}).json()
    assert ov["summary"]["data_sources"][0]["key"] == "connection"
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {x["category"] for x in fs}
    # Product names and Korean byte headings do not establish session/counter semantics.
    assert not ({"net.periodic", "net.large_outbound"} & cats)
    runs = analyst.get(f"/investigations/{inv['id']}/analysis-runs").json()["runs"]
    result = analyst.get(f"/investigations/{inv['id']}/analysis-runs/{runs[0]['id']}").json()
    fw = next(e for e in result["executions"] if e["detector_id"] == "fw.observation")
    assert fw["status"] == "insufficient_data" and fw["match_count"] is None
    assert fw["detail"]["counts"]["records"] == 449
    assert fw["detail"]["counts"]["unresolved_records"] == 449
