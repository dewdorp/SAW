from __future__ import annotations

from sqlalchemy import select

from saw.storage.db import session_scope


def test_connector_admin_secret_write_only(admin, analyst):
    assert analyst.get("/admin/connectors").status_code == 403
    r = admin.post("/admin/connectors", json={"name": "siem-mock", "kind": "mock_logpresso", "settings": {"seed": 11},
                                               "secret": "s3cr3t-token"}).json()
    assert r["has_secret"] is True and "secret" not in r and "s3cr3t" not in str(r)
    from saw.connectors.registry import ConnectorConfig

    with session_scope() as s:
        enc = s.execute(select(ConnectorConfig.secret_enc)).scalar_one()
    assert enc and "s3cr3t" not in enc  # encrypted at rest
    h = admin.post(f"/admin/connectors/{r['id']}/health").json()
    assert h["ok"] is True
    bad = admin.post("/admin/connectors", json={"name": "x", "kind": "mock_logpresso", "settings": {"url": "http://1.2.3.4"}})
    assert bad.status_code == 400  # https + internal allowlist only
    real = admin.post("/admin/connectors", json={"name": "real", "kind": "logpresso", "settings": {}}).json()
    assert admin.post(f"/admin/connectors/{real['id']}/health").json()["ok"] is False  # ENV-11: not invented


def test_connector_context_and_import(admin, analyst):
    c = admin.post("/admin/connectors", json={"name": "siem-mock", "kind": "mock_logpresso"}).json()
    ioc = analyst.post("/analyze/ioc", json={"observables": ["104.248.11.20"]}).json()["items"][0]
    ic = ioc["internal_context"]
    assert any(k.endswith("(SIEM)") for k in ic["events_by_source"]) and ic["connectors"][0]["note"].startswith("mock")
    inv = analyst.post("/investigations", json={"title": "from siem"}).json()
    r = analyst.post(f"/investigations/{inv['id']}/connector-import", json={
        "connector_id": c["id"], "filters": [{"field": "src_ip", "op": "is", "value": "104.248.11.20"}]}).json()
    assert r["imported"] > 0
    again = analyst.post(f"/investigations/{inv['id']}/connector-import", json={
        "connector_id": c["id"], "filters": [{"field": "src_ip", "op": "is", "value": "104.248.11.20"}]}).json()
    ov = analyst.post(f"/investigations/{inv['id']}/overview", json={}).json()
    assert ov["summary"]["events"] == r["imported"] == again["imported"]  # idempotent (deterministic ids)
    ev = analyst.get(f"/evidence/{r['evidence_id']}/custody").json()
    assert ev[0]["action"] == "import" and ev[0]["detail"]["connector"] == c["id"]
