from __future__ import annotations

import base64
import gzip

from saw.analyzers.diff.request_diff import analyze_diff
from saw.analyzers.http.analyze import analyze_http
from saw.analyzers.ioc.analyze import analyze_observable
from saw.analyzers.ioc.observables import extract, refang
from saw.analyzers.log.normalize import parse_time, uri_template
from saw.analyzers.patterns import scan_value
from saw.analyzers.payload.transforms import apply_chain, auto_decode
from saw.analyzers.universal.detect import detect_all
from saw.parsers.registry import detect, parse_text

REQ = """GET /api/customer?id=123 HTTP/1.1
Host: service.example.com
User-Agent: python-httpx/0.27
X-Forwarded-For: 43.201.12.7
"""


def test_universal_http_request():
    r = detect_all(REQ)
    types = {d["type"] for d in r["detections"]}
    assert {"http_request", "ipv4", "host", "user_agent", "query_param"} <= types
    ip = next(d for d in r["detections"] if d["type"] == "ipv4")
    assert ip["value"] == "43.201.12.7" and ip["context"] == "X-Forwarded-For" and ip["scope"] == "external"
    rec = {x["analysis"]: x["auto"] for x in r["recommended"]}
    assert rec["http"] and rec["ioc"]
    # version strings like httpx/0.27 must not be IPs
    assert all(d.get("value") != "0.27" for d in r["detections"])


def test_universal_misc_types():
    jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    r = detect_all(f"token {jwt} and hxxp://evil[.]example[.]com/x and 44d88612fea8a8f36de82e1278abb02f")
    types = {d["type"] for d in r["detections"]}
    assert {"jwt", "url", "md5", "defanged_ioc"} <= types


def test_payload_double_url_decode_chain():
    ch = auto_decode("%252e%252e%252f")
    assert [s.op for s in ch.steps] == ["url_decode", "url_decode"] and ch.output == "../"
    assert scan_value(ch.output + "etc/passwd")


def test_payload_ps_and_gzip_base64():
    cmd = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()
    ch = auto_decode(f"powershell -enc {cmd}")
    assert "IEX" in ch.output and ch.steps[0].op == "ps_encoded"
    gz = base64.b64encode(gzip.compress(b"<script>alert(1)</script>")).decode()
    ch = auto_decode(gz)
    assert ch.output == "<script>alert(1)</script>" and [s.op for s in ch.steps] == ["base64", "gzip"]
    assert apply_chain("aGVsbG8gd29ybGQ=", ["base64"]).output == "hello world"


def test_pattern_detection_wording_and_evidence():
    hits = scan_value("' OR 1=1--")
    assert hits and hits[0].label == "Potential SQL Injection Pattern"
    assert any(e.kind == "tautology" for e in hits[0].evidence)
    assert not scan_value("hello world")
    assert not scan_value("select a product from the list")  # natural language
    assert scan_value("<svg/onload=alert(1)>")[0].pattern == "potential_xss"
    assert scan_value("http://169.254.169.254/latest/meta-data", "url")[0].confidence in ("medium", "high")
    assert scan_value("; cat /etc/passwd")
    assert scan_value("${jndi:ldap://x/a}")


def test_http_analyzer_with_response():
    req = ("POST /api/search HTTP/1.1\nHost: svc.example.com\nContent-Type: application/json\n"
           "Cookie: sid=abcdef123456\nContent-Length: 10\nTransfer-Encoding: chunked\n\n"
           '{"q":"%2527%20OR%201%3D1--","page":1}')
    resp = "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html\n\nYou have an error in your SQL syntax near"
    r = analyze_http(req, resp)
    assert r["method"] == "POST" and r["host"] == "svc.example.com"
    q = next(p for p in r["parameters"] if p["path"] == "$.q")
    assert q["decoded"] == "' OR 1=1--" and len(q["decode_chain"]) == 2
    sid = next(p for p in r["parameters"] if p["name"] == "sid")
    assert sid["masked"] and "abcdef" not in sid["value"]
    assert any(p["pattern"] == "potential_sql_injection" for p in r["patterns"])
    assert any(a["code"] == "cl_te_conflict" for a in r["anomalies"])
    assert r["response"]["error_signatures"][0]["kind"] == "sql_error"
    assert any(e["kind"] == "response_error_signature" for p in r["patterns"] for e in p["evidence"])


def test_http_curl_and_h2():
    r = analyze_http("curl 'https://a.example.com/x?y=1' -H 'User-Agent: sqlmap/1.7'")
    assert r["host"] == "a.example.com" and r["user_agent"]["class"] == "scanner"
    r = analyze_http(":method: GET\n:path: /p?a=1\n:authority: h2.example.com\n:scheme: https\n")
    assert r["path"] == "/p" and r["host"] == "h2.example.com"


def test_jwt_warnings():
    jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTAwfQ."
    r = analyze_http(f"GET / HTTP/1.1\nHost: x\nAuthorization: Bearer {jwt}\n")
    w = r["jwt"][0]["warnings"]
    assert any("alg=none" in x for x in w) and any("expired" in x for x in w)


def test_ioc_offline_and_extract():
    r = analyze_observable("43.201.12.7")
    assert r["scope"] == "external" and r["offline"]["cloud"] == "aws" and r["offline"]["source"] == "fixture"
    assert analyze_observable("10.0.0.1")["scope"] == "internal"
    assert analyze_observable("evil[.]example[.]co[.]kr")["registered_domain"] == "example.co.kr"
    assert refang("hxxps://a[.]b") == "https://a.b"
    vals = {o.value for o in extract("see config.php and www.example.com")}
    assert "www.example.com" in vals and "config.php" not in vals


def test_request_diff_bypass_point():
    reqs = [
        "GET /api/user?id=100 HTTP/1.1\nHost: x\n\nHTTP/1.1 403 Forbidden\n\ndenied",
        "GET /api/user?userId=100 HTTP/1.1\nHost: x\n\nHTTP/1.1 403 Forbidden\n\ndenied",
        'POST /api/user HTTP/1.1\nHost: x\nContent-Type: application/json\n\n{"id":100}\n\n'
        "HTTP/1.1 200 OK\n\n" + "x" * 1800,
    ]
    r = analyze_diff(reqs)
    t0 = {c["type"] for c in r["transitions"][0]["changes"]}
    assert "PARAM_RENAME" in t0
    t1 = {c["type"] for c in r["transitions"][1]["changes"]}
    assert "METHOD_SWITCH" in t1
    assert r["bypass_points"] == [{"from": 1, "to": 2, "reason": "403 → 200"}]
    assert r["strategy"]


def test_request_diff_split_single_blob():
    blob = "GET /a?id=1 HTTP/1.1\nHost: x\n\n###\nGET /a?id=2 HTTP/1.1\nHost: x\n"
    r = analyze_diff([blob])
    assert len(r["requests"]) == 2
    assert r["transitions"][0]["changes"][0]["detail"] == "+1"


def test_uri_template_and_time():
    _, t, params, names = uri_template("/api/customer/10001/orders?id=5&token=abc123def456ghi789jkl0&x=hello")
    assert t == "/api/customer/<NUM>/orders?id=<NUM>&token=<TOKEN>&x=<STR>"
    assert names == ["id", "path[3]", "token", "x"] and params["path[3]"] == "10001"
    ts, q = parse_time("05/Oct/2026:03:11:04 +0900")
    assert ts == "2026-10-04T18:11:04.000Z" and q == "exact"
    ts, q = parse_time("2026-10-05 03:11:04")
    assert ts == "2026-10-04T18:11:04.000Z" and q == "assumed_tz"


NGINX = [
    '43.201.12.7 - - [05/Oct/2026:03:11:04 +0900] "GET /api/customer?id=10001 HTTP/1.1" 200 1832 "-" "python-httpx/0.27"',
    '43.201.12.8 - - [05/Oct/2026:03:11:05 +0900] "GET /api/customer?id=10002 HTTP/1.1" 200 1840 "-" "python-httpx/0.27"',
    "10.1.1.1 - - [05/Oct/2026:03:11:06 +0900] \"GET /search?q=%27%20OR%201%3D1-- HTTP/1.1\" 500 12 \"-\" \"Mozilla/5.0\"",
]


def test_parser_detection_and_ces():
    d = detect(NGINX)
    assert d.parser_id in ("nginx_combined", "apache_combined") and d.confidence > 0.9
    r = parse_text("\n".join(NGINX))
    e = r["events"][0]
    assert e["uri_template"] == "/api/customer?id=<NUM>" and e["src_cloud"] == "aws" and e["ua_class"] == "script"
    assert e["raw_ref"]["line_no"] == 1 and e["timestamp"] == "2026-10-04T18:11:04.000Z"
    assert "pattern:sqli" in r["events"][2]["tags"]
    # deterministic event ids
    assert parse_text("\n".join(NGINX))["events"][0]["event_id"] == e["event_id"]


def test_other_parsers():
    iis = ("#Software: Microsoft IIS\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
           "c-ip cs(User-Agent) sc-status sc-bytes\n2026-10-05 03:11:04 10.0.0.5 GET /default.aspx id=1 443 - "
           "43.201.12.7 Mozilla/5.0+(Windows) 200 512")
    r = parse_text(iis)
    assert r["parser"] == "iis_w3c" and r["events"][0]["uri"] == "/default.aspx?id=1" and r["failed"] == 0
    cf = '{"ClientIP":"43.201.12.9","ClientRequestHost":"svc.example.com","ClientRequestMethod":"GET","ClientRequestURI":"/a?id=1","EdgeResponseStatus":200,"EdgeStartTimestamp":"2026-10-04T18:11:04Z","ClientRequestUserAgent":"curl/8","RayID":"8c1f"}'
    r = parse_text(cf + "\n" + cf)
    assert r["parser"] == "cloudflare_http" and r["events"][0]["src_ip"] == "43.201.12.9"
    assert r["events"][0]["ext"]["cloudflare"]["RayID"] == "8c1f"  # unknown fields preserved
    cef = "CEF:0|Vendor|WAF|1.0|942100|SQL Injection Attack|8|src=43.201.12.7 request=/search?q=1 act=blocked"
    r = parse_text(cef + "\n" + cef)
    assert r["parser"] == "waf_generic" and r["events"][0]["data_source"] == "waf"
    sl = "Oct  5 03:11:04 web01 sshd[123]: Failed password for invalid user admin from 43.201.12.7 port 5555 ssh2"
    r = parse_text(sl + "\n" + sl)
    assert r["parser"] == "syslog" and r["events"][0]["user"] == "admin" and r["events"][0]["event_type"] == "auth"
    csvt = "time,src_ip,method,url,status\n2026-10-05T03:00:00Z,1.2.3.4,GET,/a,200\n2026-10-05T03:00:01Z,1.2.3.5,GET,/b,404"
    r = parse_text(csvt)
    assert r["parser"] == "csv" and len(r["events"]) == 2 and r["failed"] == 0


def test_parser_detection_is_fast_on_quote_heavy_lines():
    """Regression: csv.Sniffer backtracked for minutes on quote-heavy web logs (ReDoS on untrusted input)."""
    import time

    lines = [f'43.201.10.{i % 40} - - [05/Oct/2026:02:00:{i % 60:02d} +0000] "GET /api/account/{50000 + i} '
             f'HTTP/1.1" 200 900 "-" "python-requests/2.32"' for i in range(200)]
    t = time.time()
    d = detect(lines)
    assert d.parser_id == "nginx_combined" and time.time() - t < 1.0


def test_attack_catalog_is_official_and_covers_all_mappings():
    """Adopted from the Codex comparison: full official catalog; every technique SAW maps must exist in it."""
    import re
    from pathlib import Path

    from saw.attack import catalog

    assert catalog.CATALOG_SOURCE["kind"] == "official-stix" and catalog.ATTACK_VERSION == "19.2"
    assert len(catalog.TECHNIQUES) > 600 and len(catalog.TACTICS) == 14 + 1
    used = set()
    for p in Path("saw").rglob("*.py"):
        used |= set(re.findall(r'"(T1\d{3}(?:\.\d{3})?)"', p.read_text(encoding="utf-8")))
    missing = sorted(t for t in used if t not in catalog.TECHNIQUES)
    assert not missing, f"techniques referenced in code but not active in ATT&CK {catalog.ATTACK_VERSION}: {missing}"
