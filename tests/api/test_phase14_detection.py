from __future__ import annotations

import pytest

from saw.detection.sigma_eval import SigmaError, compile_rule, evaluate, validate_with_pysigma
from saw.devtools.sample_data import gz_bytes, scenario_weblog
from tests.api.test_phase5_bulk import upload

RULE = """
title: Test rule
logsource: {category: webserver}
detection:
  sel_path:
    cs-uri-stem|startswith: /api/customer
  sel_ok:
    sc-status: 200
  filter_internal:
    c-ip|cidr: 10.0.0.0/8
  condition: 1 of sel_* and sel_ok and not filter_internal
tags: [attack.t1213]
level: high
"""


def test_sigma_evaluator_semantics():
    assert validate_with_pysigma(RULE) == []
    r = compile_rule(RULE)
    assert r.data_sources == ["web", "waf"]
    ev = {"url_path": "/api/customer", "status_code": 200, "src_ip": "43.201.1.1"}
    assert evaluate(r, ev)
    assert not evaluate(r, {**ev, "src_ip": "10.1.2.3"})  # not filter
    assert not evaluate(r, {**ev, "status_code": 403})
    r2 = compile_rule("title: x\nlogsource: {category: webserver}\ndetection:\n  s:\n    c-useragent|contains|all: [python, httpx]\n  condition: s\n")
    assert evaluate(r2, {"user_agent": "python-httpx/0.27"}) and not evaluate(r2, {"user_agent": "python-requests"})
    with pytest.raises(SigmaError):
        evaluate(compile_rule("title: x\ndetection:\n  s: {a: 1}\n  condition: s and (\n"), {})
    assert validate_with_pysigma("title: x\nnot sigma")  # invalid → problems reported


def _inv(api, title, verdict, **kw):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "a.log.gz", gz_bytes(scenario_weblog(**kw)))
    api.post(f"/evidence/{up['evidence_id']}/process")
    if verdict:
        api.post(f"/investigations/{inv['id']}/close", json={"verdict": verdict, "reason": "labelled for testing"})
    return inv


def test_detection_lifecycle(analyst, senior):
    atk = _inv(analyst, "attack", None, normal=300, enum_count=500)
    fs = analyst.get(f"/investigations/{atk['id']}/findings").json()
    enum = next(f for f in fs if f["category"] == "web.api_enumeration")
    analyst.post(f"/investigations/{atk['id']}/close", json={"verdict": "attack", "reason": "confirmed enumeration"})
    _inv(analyst, "benign", "normal", normal=400, enum_count=0, seed=21)
    d = analyst.post(f"/detections/from-finding/{enum['id']}").json()
    assert d["status"] == "draft" and d["format"] == "sigma" and d["current"]["threshold"]["count_gte"] == 300
    assert d["source"]["finding_id"] == enum["id"]
    # Legacy investigation replay remains useful but cannot authorize a new active version.
    assert senior.post(f"/detections/{d['id']}/approve").status_code == 409
    t = analyst.post(f"/detections/{d['id']}/test", json={}).json()
    res = t["result"]
    assert res["tp"] > 0 and res["fp"] == 0 and res["detects_confirmed_attacks"] is True and t["passed"]
    assert analyst.post(f"/detections/{d['id']}/approve").status_code == 403
    assert senior.post(f"/detections/{d['id']}/approve").status_code == 409
    assert analyst.get(f"/detections/{d['id']}").json()["pointers"]["active"] is None
    os_q = analyst.get(f"/detections/{d['id']}/export?fmt=opensearch").text
    assert "url_path:" in os_q and "status_code:200" in os_q and "cs-uri-stem" not in os_q  # pySigma + SAW CES field mapping
    assert analyst.get(f"/detections/{d['id']}/export?fmt=logpresso").status_code == 501  # ENV-11
    dep = senior.post(f"/detections/{d['id']}/deployed", json={"target": "SIEM rule set (manual)", "note": "CHG-123"})
    assert dep.status_code == 409
    # editing creates a new version and drops back to draft (re-test + re-approve needed)
    ed = analyst.patch(f"/detections/{d['id']}", json={"severity": "critical"}).json()
    assert ed["version"] == 2 and ed["status"] == "draft" and len(ed["versions"]) == 2
    cov = analyst.get("/coverage/attack").json()
    cell = next(c for c in cov["cells"] if c["technique_id"] == "T1110.001")
    assert cell["observed"] >= 1 and cell["state"] == "gap"  # brute force observed in a confirmed attack, no detection
    layer = analyst.get("/coverage/attack/navigator-layer").json()
    assert layer["versions"]["layer"] == "4.5"


def test_noisy_rule_shows_false_positives(analyst, senior):
    _inv(analyst, "benign", "normal", normal=500, enum_count=0, seed=3)
    noisy = "title: noisy\nlogsource: {category: webserver}\ndetection:\n  s:\n    sc-status: 200\n  condition: s\nlevel: low\n"
    d = analyst.post("/detections", json={"title": "noisy", "logic": noisy,
                                          "test_events": [{"expected": "match", "event": {"status_code": 200}},
                                                          {"expected": "no_match", "event": {"status_code": 404}}]}).json()
    r = analyst.post(f"/detections/{d['id']}/test", json={}).json()["result"]
    assert r["fp"] > 0 and r["fp_common"] and all(u["ok"] for u in r["unit_tests"])
    bad = analyst.post("/detections", json={"title": "bad", "logic": "title: x\nnot: sigma"})
    assert bad.status_code == 400


def test_component_map_uses_saw_data_source_names():
    """Regression: coverage showed 'no visibility' for exfiltration although zeek_conn data existed."""
    from saw.attack.catalog import COMPONENT_SOURCES
    from saw.parsers.network import zeek_record

    ds = zeek_record({"id.orig_h": "10.0.0.1", "id.resp_h": "1.2.3.4", "conn_state": "SF", "orig_bytes": 1})[0]
    assert ds in COMPONENT_SOURCES["Network Traffic: Network Traffic Flow"]


@pytest.mark.parametrize("verdict", ["attack", "attack_attempt", "compromise_confirmed"])
def test_new_attack_conclusions_count_as_attack_labels_in_the_legacy_replay(analyst, verdict):
    """ROOT-01: attack_attempt and compromise_confirmed were counted as unlabeled; only "attack" counted."""
    atk = _inv(analyst, f"attack-{verdict}", None, normal=300, enum_count=500)
    fs = analyst.get(f"/investigations/{atk['id']}/findings").json()
    enum = next(f for f in fs if f["category"] == "web.api_enumeration")
    analyst.post(f"/investigations/{atk['id']}/close", json={"verdict": verdict, "reason": "labelled for testing"})
    d = analyst.post(f"/detections/from-finding/{enum['id']}").json()
    res = analyst.post(f"/detections/{d['id']}/test", json={}).json()["result"]
    assert res["tp"] > 0 and res["detects_confirmed_attacks"] is True
    assert res["by_verdict"].get(verdict, 0) == res["tp"] and res["unlabeled"] == res["hits"] - res["tp"] - res["fp"]
    assert "조사 전체" in res["label_note"]
