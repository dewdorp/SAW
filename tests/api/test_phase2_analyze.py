from __future__ import annotations

from tests.api.test_phase1_foundation import Api  # noqa: F401
from tests.unit.test_analyzers import NGINX, REQ


def test_universal_endpoint(analyst):
    r = analyst.post("/analyze/universal", json={"input": REQ})
    assert r.status_code == 200, r.text
    j = r.json()
    ip = next(i for i in j["results"]["ioc"] if i["value"] == "43.201.12.7")
    assert "http" in j["results"] and "internal_context" in ip


def test_input_limit(analyst):
    r = analyst.post("/analyze/universal", json={"input": "a" * (5 * 1024 * 1024 + 1)})
    assert r.status_code == 413


def test_payload_http_diff_log_endpoints(analyst):
    assert analyst.post("/analyze/payload", json={"input": "%252e%252e%252f"}).json()["output"] == "../"
    j = analyst.post("/analyze/http", json={"request": REQ}).json()
    assert j["user_agent"]["class"] == "script"
    d = analyst.post("/analyze/diff", json={"requests": ["GET /a?id=1 HTTP/1.1\nHost: x\n",
                                                         "GET /a?id=2 HTTP/1.1\nHost: x\n"]}).json()
    assert d["transitions"][0]["changes"][0]["type"] == "PARAM_VALUE_CHANGE"
    lg = analyst.post("/analyze/log", json={"text": "\n".join(NGINX)}).json()
    assert lg["events"] == 3 and lg["suspicious"]
    assert analyst.post("/analyze/ioc/external", json={"observables": ["1.2.3.4"]}).status_code == 409


def test_viewer_cannot_analyze(app):
    from tests.conftest import Api, make_user

    make_user("view", ["viewer"])
    assert Api(app, "view").post("/analyze/universal", json={"input": "1.2.3.4"}).status_code == 403


def test_analyze_audited_without_content(analyst, manager):
    analyst.post("/analyze/universal", json={"input": "secret 900101-1234567"})
    rows = manager.get("/admin/audit?action=analyze.universal").json()
    assert rows and "sha256" in rows[0]["detail"] and "900101" not in str(rows[0]["detail"])
