from __future__ import annotations

import json
import yaml
from sqlalchemy import select

from saw.detection import service
from saw.detectors import signatures
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent
from tests.api.test_phase14_detection import RULE


def test_catalog_export_contains_effective_matching_logic_and_all_examples(analyst, senior):
    chosen = next(s for s in signatures.load_pack() if s.regex or s.needles)
    # Preserve a historical disabled flag; new direct mutations require governed policy.
    from saw.storage.models import SignatureSetting
    with session_scope() as s:
        s.add(SignatureSetting(sig_id=chosen.id, enabled=False, note="synthetic review reason", updated_by="legacy"))
    assert senior.put(f"/detection-catalog/signatures/{chosen.id}", json={"enabled": False, "note": "synthetic review reason"}).status_code == 409
    response = analyst.get("/detection-catalog/export?format=json")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    data = response.json()
    assert data["schema"] == "saw.detection-catalog.v1"
    assert data["scope"] == "all_shipped_rules"
    row = next(s for s in data["signatures"] if s["id"] == chosen.id)
    assert row["matching"]["match"] == list(chosen.needles)
    assert row["matching"]["all"] == list(chosen.all_needles)
    assert row["matching"]["regex"] == chosen.regex
    assert row["matching"]["regex_not"] == chosen.regex_not
    assert row["matching"]["method"] == list(chosen.methods)
    assert row["matching"]["where"] == chosen.where
    assert row["matching"]["success"] == chosen.success
    assert row["examples"] == list(chosen.examples) and row["benign"] == list(chosen.benign)
    assert row["enabled"] is False and row["note"] == "synthetic review reason"
    assert data["network_rules"] and data["scenarios"]
    assert all(d["implementation"] == "python" and d["version"] for d in data["detectors"])
    with session_scope() as s:
        assert s.execute(select(AuditEvent).where(AuditEvent.action == "detection.catalog_export")).scalars().first()


def test_catalog_yaml_is_equivalent_and_unknown_format_rejected(analyst):
    j = analyst.get("/detection-catalog/export?format=json").json()
    y = analyst.get("/detection-catalog/export?format=yaml")
    assert y.status_code == 200 and "yaml" in y.headers["content-type"]
    assert yaml.safe_load(y.text)["signatures"] == j["signatures"]
    assert analyst.get("/detection-catalog/export?format=html").status_code == 422


def test_custom_export_omits_test_data_and_preserves_current_conditions(analyst):
    d = analyst.post("/detections", json={"title": "synthetic export", "logic": RULE,
        "test_events": [{"expected": "match", "event": {"raw_event": "PRIVATE-TEST-PAYLOAD"}}],
        "threshold": {"count_gte": 2, "group_by": ["src_ip"], "timespan_sec": 60},
        "exceptions": [{"field": "src_ip", "op": "eq", "value": "192.0.2.9"}]}).json()
    response = analyst.get("/detections/export?format=json")
    assert response.status_code == 200
    data = response.json()
    assert data["schema"] == "saw.detection-rules.v1"
    row = next(x for x in data["rules"] if x["id"] == d["id"])
    assert row["logic"] == RULE and row["threshold"]["count_gte"] == 2
    assert row["exceptions"][0]["value"] == "192.0.2.9" and row["status"] == "draft"
    assert "PRIVATE-TEST-PAYLOAD" not in response.text
    assert not ({"test_events", "source", "test_runs"} & row.keys())
    native = analyst.get(f"/detections/{d['id']}/export?fmt=native")
    assert native.text == RULE and "attachment" in native.headers["content-disposition"]
    assert analyst.get(f"/detections/{d['id']}").json()["status"] == "draft"


def test_exports_require_authentication_and_custom_rule_read_permission(app, admin, analyst):
    from fastapi.testclient import TestClient
    client = TestClient(app)
    assert client.get("/api/v1/detection-catalog/export").status_code == 401
    assert client.get("/api/v1/detections/export").status_code == 401
    assert admin.get("/detections/export").status_code == 200  # the administrator can use every function


def test_export_over_limit_fails_without_partial_file(analyst, monkeypatch):
    from saw.detection import exporting
    monkeypatch.setattr(exporting, "MAX_EXPORT_BYTES", 10)
    response = analyst.get("/detection-catalog/export")
    assert response.status_code == 400
    assert "content-disposition" not in response.headers
