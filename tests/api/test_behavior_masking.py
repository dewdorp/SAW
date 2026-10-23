"""Sensitive serialized headers must not enter immutable exported snapshots."""
import json
import pytest
from saw import container
from saw.core.security.masking import mask_text
from tests.api.test_behavior import attachment, run
from tests.api.test_guidance import make_case
from tests.api.test_golden import approve


@pytest.mark.parametrize("value", [
    '{"Cookie": "session=SYNTHETIC_COOKIE_VALUE", "Authorization": "SYNTHETIC_AUTH_VALUE"}',
    '{"headers": {"cOoKiE": ["SYNTHETIC_COOKIE_VALUE", "SYNTHETIC_AUTH_VALUE"]}}',
    '{"Cookie": "prefix SYNTHETIC_COOKIE_VALUE trailing truncated',
    '{"Authorization": "prefix SYNTHETIC_AUTH_VALUE trailing truncated',
    '{"Cookie": {"nested": "SYNTHETIC_COOKIE_VALUE"}}',
])
def test_serialized_sensitive_headers_are_fully_masked(value):
    safe = mask_text(value).text
    assert "SYNTHETIC_COOKIE_VALUE" not in safe
    assert "SYNTHETIC_AUTH_VALUE" not in safe


def test_json_header_values_cannot_reach_behavior_report_or_golden_export(analyst, manager):
    inv = make_case(analyst, 1)
    es = container.get().events
    event = es.search(inv["id"], [], limit=1)["events"][0]
    event.update(raw_ref=None, raw_event=json.dumps({
        "Cookie": "session=SYNTHETIC_COOKIE_VALUE",
        "Authorization": "SYNTHETIC_AUTH_VALUE", "path": "/safe"}))
    es.index([event])
    result = run(analyst, inv)
    assert "SYNTHETIC_COOKIE_VALUE" not in json.dumps(result)
    assert "SYNTHETIC_AUTH_VALUE" not in json.dumps(result)
    assert analyst.post(f"/investigations/{inv['id']}/checks", json={
        "behavior": attachment(result), "note": "Synthetic review"}).status_code == 201
    closed = analyst.post(f"/investigations/{inv['id']}/close",
        json={"verdict": "unknown", "reason": "Synthetic", "save_experience": True}).json()
    eid = closed["experience_id"]
    prepared = analyst.post(f"/knowledge/golden/experience/{eid}/prepare",
        json={"expected_experience_rev": 1})
    assert prepared.status_code == 201, prepared.text
    from saw.knowledge.golden_models import GoldenBlob
    from saw.storage.db import session_scope
    with session_scope() as session:
        for sha in prepared.json()["input"]["evidence"]:
            content = json.dumps(session.get(GoldenBlob, sha).content)
            assert "SYNTHETIC_COOKIE_VALUE" not in content
            assert "SYNTHETIC_AUTH_VALUE" not in content
    analyst.post(f"/experiences/{eid}/submit")
    assert approve(manager, eid, prepared.json()).status_code == 200
    report = analyst.get(f"/investigations/{inv['id']}/behavior/{result['id']}/report")
    from tests.api.test_golden import frozen_input
    agent, blobs = frozen_input(prepared.json()["id"])
    for content in (report.text, json.dumps([agent, blobs])):
        assert "SYNTHETIC_COOKIE_VALUE" not in content
        assert "SYNTHETIC_AUTH_VALUE" not in content


def test_truncated_unicode_escaped_sensitive_key_is_masked():
    value = '{"' + chr(92) + 'u0043ookie": "SYNTHETIC_COOKIE_VALUE truncated'
    assert "SYNTHETIC_COOKIE_VALUE" not in mask_text(value).text


def test_masking_precedes_behavior_preview_truncation():
    from saw.behavior.calculator import calculate
    raw = json.dumps({"padding": "x" * 4020, "Cookie": {"secret_header": "SYNTHETIC_COOKIE_VALUE" * 30}})
    out = calculate([{"event_id": "synthetic", "timestamp": "2026-10-16T00:00:00Z",
                      "src_ip": "192.0.2.1", "hostname": "test", "method": "GET", "uri": "/",
                      "raw_event": raw}])
    assert "SYNTHETIC_COOKIE_VALUE" not in json.dumps(out)
