"""Synthetic integration of configurable NDR policies and reanalysis cleanup."""
from copy import deepcopy

from saw import container
from saw.detectors import ndr_policy, scenarios
from tests.api.test_signature_detection import _run


def test_catalog_exposes_disabled_site_policies(analyst):
    data = analyst.get("/detection-catalog").json()
    assert len(data["network_rules"]) == 5
    assert not any(r["enabled"] for r in data["network_rules"])
    assert all("site" in r and "checks" in r for r in data["network_rules"])


def test_synthetic_connection_analysis_has_scoped_evidence(analyst, monkeypatch):
    cfg = deepcopy(ndr_policy.load())
    rule = next(r for r in cfg["rules"] if r["id"] == "internal_admin")
    rule["enabled"] = True
    monkeypatch.setattr(ndr_policy, "load", lambda: cfg)
    inv = analyst.post("/investigations", json={"title": "가상 내부 관리 접속"}).json()
    rows = [dict(e, investigation_id=inv["id"], evidence_id="synthetic") for e in rule["examples"][0]]
    container.get().events.index(rows)
    analyst.post(f"/investigations/{inv['id']}/reanalyze").raise_for_status()
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    d = next(f for f in fs if f["category"] == "ndr.internal_admin")
    assert d["evidence_refs"]["sample_event_ids"] == ["i1"]
    assert all(x["condition_met"] is False for x in d["attack"])
    query = analyst.post(f"/investigations/{inv['id']}/findings/{d['id']}/events", json={"limit": 50}).json()
    assert len(query["events"]) == 1
    other = analyst.post("/investigations", json={"title": "다른 가상 조사"}).json()
    assert analyst.get(f"/investigations/{other['id']}/findings").json() == []


def test_removed_signature_findings_cannot_recreate_a_flow_for_one_more_run(analyst, monkeypatch):
    from saw.detectors.signatures import SignatureMatch

    sc = scenarios.Scenario("cleanup", "가상 흐름", 0.8, (), "medium",
                            (scenarios.Step("웹셸", categories=("sig.webshell",)),
                             scenarios.Step("명령", categories=("sig.exec",))), "", ())
    monkeypatch.setattr(scenarios, "load", lambda: (sc,))
    inv, fs = _run(analyst, "가상 재분석")
    assert any(f["category"] == "scenario.cleanup" for f in fs)
    monkeypatch.setattr(SignatureMatch, "run", lambda self, ctx: [])
    analyst.post(f"/investigations/{inv['id']}/reanalyze").raise_for_status()
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    assert not any(f["category"] == "scenario.cleanup" for f in fs)
