"""PCAP ↔ other sources (NDR meta, web log) session links, and TLS server-certificate analysis."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from saw import container
from saw.core.schemas.query import Filter
from saw.devtools import pcap_writer as pw
from saw.devtools.sample_data import NDR_HEADER, make_cert, scenario_pcap_forensics, scenario_tls_certs
from saw.integrations.pcapkit import tls
from tests.api.test_phase5_bulk import upload

KST = timezone(timedelta(hours=9))


def _process(api, inv_id: str, name: str, data: bytes, kind: str) -> dict:
    up = upload(api, inv_id, name, data, kind=kind)
    j = api.get(f"/jobs/{api.post(f'/evidence/{up['evidence_id']}/process').json()['id']}").json()
    assert j["state"] == "COMPLETED", j
    return j


# ---------------------------------------------------------------------- TLS unit level
def test_certificate_chain_ja3s_and_name_matching():
    t0 = datetime(2026, 10, 3, tzinfo=timezone.utc)
    leaf, _ = make_cert("www.example.com", san=["www.example.com", "*.api.example.com"], not_before=t0)
    flight = pw.server_flight_tls12([leaf, leaf])
    chain = tls.parse_certificates(flight)
    assert len(chain) == 2 and chain[0] == leaf
    info = tls.cert_info(chain[0])
    assert info["subject_cn"] == "www.example.com" and info["self_signed"] is True and info["key_bits"] == 2048
    assert info["sha1"] == hashlib.sha1(leaf).hexdigest() and info["not_before"].startswith("2026-10-03")
    assert tls.name_matches("www.example.com", info) and tls.name_matches("v1.api.example.com", info)
    assert not tls.name_matches("evil.example.com", info) and not tls.name_matches("a.b.api.example.com", info)
    sh = tls.parse_server_hello(flight)
    assert tls.ja3s(sh) == hashlib.md5(b"771,49199,65281", usedforsecurity=False).hexdigest()
    assert tls.cert_info(b"\x30\x03garbage") is None and tls.parse_certificates(b"\x17\x03\x03\x00\x05hello") == []


def test_tls_certificate_findings_and_fingerprint_iocs(analyst):
    pcap = scenario_tls_certs()
    inv = analyst.post("/investigations", json={"title": "TLS"}).json()
    _process(analyst, inv["id"], "tls.pcap", pcap, "pcap")
    es = container.get().events
    bad = es.search(inv["id"], [Filter(field="dst_ip", value="45.77.12.34"), Filter(field="data_source", value="zeek_ssl")], limit=1)["events"][0]
    assert bad["cert_subject_cn"] == "localhost" and bad["ja3s"] and bad["ext"]["zeek"]["cert_name_match"] is False
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    tlsf = [f for f in fs if f["category"] == "pcap.tls_certificate"]
    assert len(tlsf) == 1, [f["title"] for f in fs]  # the CA-signed site and the internal service are not flagged
    f = tlsf[0]
    passed = {c["label"] for c in f["checks"] if c["passed"] is True}
    assert {"자체 서명 인증서", "요청한 서버 이름과 인증서 이름 불일치", "발급 3일 이내에 사용"} <= passed, passed
    assert any("약한 키" in c for c in passed) and "ip:45.77.12.34" in f["entities"]
    assert f["risk_level"] in ("medium", "high", "critical")
    certs = analyst.get(f"/investigations/{inv['id']}/forensics/certificates").json()
    assert certs["tls_sessions"] == 9 and certs["with_certificate"] == 9 and len(certs["certificates"]) == 3
    first = certs["certificates"][0]  # external + anomalous first
    assert first["dst_ip"] == "45.77.12.34" and first["self_signed"] and first["name_mismatch"] and first["key"] == "rsa-1024"
    internal = next(c for c in certs["certificates"] if c["dst_ip"] == "10.20.1.5")
    assert internal["external"] is False and internal["self_signed"] is True
    # the certificate fingerprint shared as an IOC is matched against TLS sessions
    inv2 = analyst.post("/investigations", json={"title": "TLS IOC"}).json()
    _process(analyst, inv2["id"], "iocs.txt", f"{bad['cert_sha1']}\n".encode(), "ioc_list")
    _process(analyst, inv2["id"], "tls.pcap", pcap, "pcap")
    titles = [x["title"] for x in analyst.get(f"/investigations/{inv2['id']}/findings").json()]
    assert f"IOC Match: hash {bad['cert_sha1']}" in titles, titles


# ---------------------------------------------------------------------- session links
def _ndr_row(ev: dict, path: str) -> str:
    t = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00")).astimezone(KST)
    head = (f"{t:%Y-%m-%d %H:%M},{ev['src_ip']},{ev['src_port']},{ev['dst_ip']},{ev['dst_port']},6,Web,HTTP,HTTP,US,KR,4,1,5,1,"
            f"meta,filtered=none,time={t:%Y-%m-%d %H:%M:%S}+0900,seq=1,num_of_meta=1,transaction_id=0,server_id=1,stream=1,"
            f"flow_rowid=900001,")
    req = head + f"type=http_request;method=request;hostname=x;method=GET;path={path};ua=curl" + "," * 19
    res = head + "type=http_response;method=response;ret_code=200;num_of_res=1" + "," * 19
    return f"{NDR_HEADER}\n{req}\n{res}\n"


def test_ndr_and_web_log_events_link_to_the_captured_session(analyst):
    inv = analyst.post("/investigations", json={"title": "links"}).json()
    _process(analyst, inv["id"], "incident.pcap", scenario_pcap_forensics(), "pcap")
    es = container.get().events
    http = next(e for e in es.search(inv["id"], [Filter(field="data_source", value="zeek_http")], limit=50)["events"]
                if e.get("method") == "GET" and e.get("url_path"))
    _process(analyst, inv["id"], "ndr.csv", _ndr_row(http, http["uri"]).encode(), "auto")
    t = datetime.fromisoformat(http["timestamp"].replace("Z", "+00:00")).astimezone(KST)
    weblog = (f'{http["src_ip"]} - - [{t:%d/%b/%Y:%H:%M:%S} +0900] "GET {http["uri"]} HTTP/1.1" 200 512 "-" "curl/8"\n')
    _process(analyst, inv["id"], "access.log", weblog.encode(), "web_log")

    ndr = es.search(inv["id"], [Filter(field="parser", value="ndr_meta_csv")], limit=1)["events"][0]
    r = analyst.get(f"/investigations/{inv['id']}/network/linked/{ndr['event_id']}").json()
    assert r["pcap_session"] is True
    rel = {(g["relation"], g["data_source"]) for g in r["groups"]}
    assert ("same_session", "zeek_http") in rel and ("same_session", "zeek_conn") in rel, rel
    assert ("same_request", "web") in rel, rel  # the access log has no ports: linked by client + path + time

    st = analyst.get(f"/investigations/{inv['id']}/forensics/sessions/{ndr['event_id']}/stream").json()
    assert st["packets"] > 0 and http["url_path"].split("/")[-1] in st["client_view"]["text"]
    pc = analyst.c.get(f"/api/v1/investigations/{inv['id']}/network/sessions/{ndr['event_id']}/pcap")
    assert pc.status_code == 200 and int(pc.headers["x-saw-packets"]) > 0

    web = es.search(inv["id"], [Filter(field="parser", value="nginx_combined")], limit=1)["events"][0]
    r2 = analyst.get(f"/investigations/{inv['id']}/network/linked/{web['event_id']}").json()
    assert {g["data_source"] for g in r2["groups"]} >= {"zeek_http"} and r2["pcap_session"] is False


def test_event_without_capture_explains_how_to_get_packets(analyst):
    inv = analyst.post("/investigations", json={"title": "no pcap"}).json()
    ev = {"timestamp": "2026-10-03T08:38:47Z", "src_ip": "198.51.100.7", "src_port": 50000, "dst_ip": "203.0.113.10",
          "dst_port": 8080}
    _process(analyst, inv["id"], "ndr.csv", _ndr_row(ev, "/a").encode(), "auto")
    e = container.get().events.search(inv["id"], [Filter(field="parser", value="ndr_meta_csv")], limit=1)["events"][0]
    r = analyst.get(f"/investigations/{inv['id']}/forensics/sessions/{e['event_id']}/stream")
    assert r.status_code == 409 and "PCAP" in r.json()["detail"]
    assert analyst.get(f"/investigations/{inv['id']}/network/linked/{e['event_id']}").json() == {"pcap_session": False, "groups": []}
