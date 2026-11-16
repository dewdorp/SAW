"""Pasted web server logs: format, detector results and the synthetic cases that show them."""
import pytest

from saw.analyzers import weblog_cases
from saw.core.application.analyze import summarize_log
from saw.parsers.registry import parse_text

NCSA = {"nginx_combined", "apache_combined"}


@pytest.mark.parametrize("case", weblog_cases.CASES, ids=[c["id"] for c in weblog_cases.CASES])
def test_each_case_parses_fully_and_gives_exactly_the_stated_result(case):
    lg = parse_text(weblog_cases.build(case["id"]))
    assert lg["failed"] == 0
    assert lg["parser"] in NCSA if case["format"] == "ncsa_combined" else lg["parser"] == case["format"]
    out = summarize_log(lg, web_analysis=True)
    found = [f for f in out["web"]["findings"] if f["state"] == "found"]
    assert not [f for f in out["web"]["findings"] if f["state"] == "failed"]
    assert sorted({f["detector_id"] for f in found}) == sorted(case["expected"])
    for f in found:  # every result points at pasted lines and reads in Korean
        assert f["line_nos"] and f["title_ko"] != f["title"] and f["category_ko"] != f["category"]


def test_cases_are_deterministic_and_use_only_documentation_or_private_addresses():
    import ipaddress
    import re

    for case in weblog_cases.CASES:
        text = weblog_cases.build(case["id"])
        assert text == weblog_cases.build(case["id"])
        for ip in set(re.findall(r"(?<![/\w.])\d{1,3}(?:\.\d{1,3}){3}\b", text)):  # not a version like Chrome/130.0.0.0
            a = ipaddress.ip_address(ip)
            assert a.is_private, ip  # 10/8 and the TEST-NET ranges are both "private" to Python
        hosts = set(re.findall(r"\b[a-z][a-z0-9.-]*\.(?:com|net|org|kr|io|test)\b", text))
        assert all(h.endswith(".example.test") or h == "sqlmap.org" for h in hosts), hosts


def test_common_format_without_user_agent_is_not_called_an_automated_client():
    lg = parse_text(weblog_cases.build("WL05"))
    assert all(e.get("user_agent") is None for e in lg["events"])
    found = {f["detector_id"] for f in summarize_log(lg, web_analysis=True)["web"]["findings"]}
    assert "web.scripted_client" not in found


def test_account_count_is_not_shown_when_the_log_has_no_account_names():
    out = summarize_log(parse_text(weblog_cases.build("WL02")), web_analysis=True)
    f = next(x for x in out["web"]["findings"] if x["detector_id"] == "web.credential_attack")
    assert "계정" not in f["explanation"] and all(m["label"] != "계정" for m in f["metrics"])
    assert next(c for c in f["checks"] if c["label"] == "서로 다른 계정이 많음")["passed"] is None


def test_error_log_groups_modsecurity_rules():
    out = summarize_log(parse_text(weblog_cases.build("WL09")), web_analysis=True)
    labels = [g["label"] for g in out["web"]["errors"]]
    assert any("942100" in x for x in labels) and any("949110" in x for x in labels) and "Apache AH01630" in labels


def test_paste_api_runs_web_analysis_and_lists_cases(analyst):
    items = analyst.get("/analyze/log/web-cases").json()["items"]
    assert [c["id"] for c in items] == [c["id"] for c in weblog_cases.CASES]
    assert all("build" not in c and c["lines"] > 0 for c in items)
    text = analyst.get("/analyze/log/web-cases/WL03").json()["text"]
    r = analyst.post("/analyze/log", json={"text": text})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["parser"] == "iis_w3c" and j["format_ko"].startswith("IIS")
    assert [f["detector_id"] for f in j["web"]["findings"]] == ["web.injection_like"]
    assert analyst.get("/analyze/log/web-cases/NOPE").status_code == 404


def test_viewer_cannot_read_cases(app):
    from tests.conftest import Api, make_user

    make_user("weblog-viewer", ["viewer"])
    assert Api(app, "weblog-viewer").get("/analyze/log/web-cases").status_code == 403


def test_paste_never_writes_to_the_investigation_store(analyst, monkeypatch):
    from saw import container

    def refuse(*_a, **_k):
        raise AssertionError("pasted lines must not be indexed into the investigation store")

    monkeypatch.setattr(container.get().events, "index", refuse)
    r = analyst.post("/analyze/log", json={"text": weblog_cases.build("WL01")})
    assert r.status_code == 200, r.text
    assert len(r.json()["web"]["findings"]) == 3
