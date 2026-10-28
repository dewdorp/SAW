"""One affiliate + one period per investigation, and the same private IP never merges across affiliates."""
import csv
import io
import uuid

from saw.devtools.security_csv_samples import FW_COLUMNS
from tests.api.test_text_uploads import _process

SHARED_PRIVATE = "10.77.0.5"
SHARED_PUBLIC = "198.51.100.77"


def _org(api, name):
    r = api.post("/source-context/org-units", json={"display_name": f"{name} {uuid.uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    return r.json()


def _fw(src, dst, rows=6):
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(FW_COLUMNS)
    for i in range(rows):
        w.writerow([f"2026-10-01 10:{i:02d}:00", "가상 관계사", "192.0.2.1", "허용", src, 50000 + i, dst, 443, "TCP",
                    "SYN", 3, 100, 200, 3, 1, 2])
    return out.getvalue().encode("cp949")


def _investigation(api, org, **kw):
    r = api.post("/investigations", json={"title": f"isolation {org['display_name']}", "org_unit_id": org["id"],
                                         "period_start": "2026-10-01T00:00:00+09:00",
                                         "period_end": "2026-10-31T23:59:59+09:00", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_period_scope_is_stored_validated_and_editable(senior):
    org = _org(senior, "Period")
    inv = _investigation(senior, org)
    assert inv["period_start"].startswith("2026-09-30T15:00:00") or inv["period_start"].startswith("2026-10-01T00:00:00")
    assert inv["org_unit_id"] == org["id"]
    bad = senior.post("/investigations", json={"title": "x", "org_unit_id": org["id"],
                                               "period_start": "2026-10-31T00:00:00+09:00",
                                               "period_end": "2026-10-01T00:00:00+09:00"})
    assert bad.status_code == 400 and "before its start" in bad.text
    half = senior.post("/investigations", json={"title": "x", "period_start": "2026-10-01T00:00:00+09:00"})
    assert half.status_code == 400 and "both start and end" in half.text
    too_long = senior.post("/investigations", json={"title": "x", "period_start": "2025-01-01T00:00:00+09:00",
                                                    "period_end": "2026-10-01T00:00:00+09:00"})
    assert too_long.status_code == 400
    moved = senior.patch(f"/investigations/{inv['id']}", json={"period_start": "2026-09-01T00:00:00+09:00",
                                                             "period_end": "2026-11-30T23:59:59+09:00"})
    assert moved.status_code == 200 and moved.json()["period_end"].startswith("2026-11-30")


def test_private_address_history_is_separated_per_affiliate(senior):
    org_a, org_b = _org(senior, "Affiliate A"), _org(senior, "Affiliate B")
    inv_a, inv_b = _investigation(senior, org_a), _investigation(senior, org_b)
    _process(senior, inv_a["id"], "a.fw.csv", _fw(SHARED_PRIVATE, SHARED_PUBLIC))
    _process(senior, inv_b["id"], "b.fw.csv", _fw(SHARED_PRIVATE, SHARED_PUBLIC, rows=4))
    closed = senior.post(f"/investigations/{inv_b['id']}/close",
                         json={"verdict": "attack", "reason": "affiliate B only", "checks": []})
    assert closed.status_code == 200, closed.text

    item = senior.post("/analyze/ioc", json={"observables": [SHARED_PRIVATE]}).json()["items"][0]
    ctx = item["internal_context"]
    assert ctx["affiliate_scoped"] is True and ctx["affiliate_separated"] is True
    # Nothing from affiliate B is presented as history of the same host in affiliate A.
    assert ctx["previous_verdicts"] == [] and ctx["events_by_source"] == {}
    groups = {g["org_unit_id"]: g for g in ctx["by_affiliate"]}
    assert groups[org_a["id"]]["total_events"] == 6 and groups[org_b["id"]]["total_events"] == 4
    assert groups[org_a["id"]]["previous_verdicts"] == []
    assert [v["investigation_id"] for v in groups[org_b["id"]]["previous_verdicts"]] == [inv_b["id"]]

    scoped = senior.post("/analyze/ioc", json={"observables": [SHARED_PRIVATE], "org_unit_id": org_a["id"]})
    ctx = scoped.json()["items"][0]["internal_context"]
    assert ctx["affiliate_separated"] is False
    assert {i["investigation_id"] for i in ctx["investigations"]} == {inv_a["id"]}
    assert ctx["previous_verdicts"] == [] and ctx["total_events"] == 6

    public = senior.post("/analyze/ioc", json={"observables": [SHARED_PUBLIC]}).json()["items"][0]["internal_context"]
    # A public address is the same thing everywhere, so its history may be combined.
    assert public["affiliate_scoped"] is False and public["total_events"] == 10

    hunt = senior.post("/hunts", json={"hypothesis": "shared private host", "scope": "global"})
    assert hunt.status_code == 201, hunt.text
    query = {"filters": [{"field": "src_ip", "op": "is", "value": SHARED_PRIVATE}],
             "aggs": [{"type": "terms", "field": "src_ip", "size": 10}]}
    stepped = senior.post(f"/hunts/{hunt.json()['id']}/steps", json={"query": query, "rationale": "per affiliate"})
    assert stepped.status_code == 200, stepped.text
    buckets = stepped.json()["steps"][-1]["result"]["aggs"][0]["buckets"]
    assert sorted((b["key"], b["org_unit_id"], b["count"]) for b in buckets) == sorted(
        [(SHARED_PRIVATE, org_a["id"], 6), (SHARED_PRIVATE, org_b["id"], 4)])


def test_internal_asset_match_requires_the_registering_affiliate(senior):
    org_a, org_b = _org(senior, "Asset A"), _org(senior, "Asset B")
    r = senior.post("/assets", json={"asset_id": f"core-{uuid.uuid4().hex[:6]}", "service": "core banking",
                                              "criticality": "critical",
                                              "data": {"ip": [SHARED_PRIVATE], "org_unit_id": org_a["id"]}})
    assert r.status_code == 201, r.text
    assert senior.get("/assets/match", params={"ip": SHARED_PRIVATE}).json() is None
    assert senior.get("/assets/match", params={"ip": SHARED_PRIVATE, "org_unit_id": org_b["id"]}).json() is None
    hit = senior.get("/assets/match", params={"ip": SHARED_PRIVATE, "org_unit_id": org_a["id"]}).json()
    assert hit and hit["service"] == "core banking"
