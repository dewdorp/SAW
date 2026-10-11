from __future__ import annotations

import io
import zipfile

from saw.devtools.sample_data import scenario_zeek
from tests.api.test_phase5_bulk import upload


def _zip(files: dict[str, list[str]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, lines in files.items():
            z.writestr(f"zeek/{name}", "\n".join(lines) + "\n")
    return buf.getvalue()


def test_network_logs_pipeline(analyst):
    inv = analyst.post("/investigations", json={"title": "PCAP 분석"}).json()
    up = upload(analyst, inv["id"], "zeek_output.zip", _zip(scenario_zeek()), kind="pcap")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    j = analyst.get(f"/jobs/{job['id']}").json()
    assert j["state"] == "COMPLETED", j
    parsers = {f["parser_id"] for f in j["files"] if f["parent_file_id"]}
    assert {"zeek_json", "suricata_eve"} <= parsers
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {f["category"] for f in fs}
    assert {"net.large_outbound", "net.periodic", "net.scan", "net.dns_anomaly", "net.tls_rarity", "net.long_conn",
            "net.unexpected_protocol", "net.ids_alerts"} <= cats, cats
    per = next(f for f in fs if f["category"] == "net.periodic")
    assert per["title"] == "Potential Periodic Communication"  # never "Confirmed C2"
    assert "43.201.88.10" in " ".join(per["entities"])
    ids = next(f for f in fs if f["category"] == "net.ids_alerts")
    assert ids["attack"][0]["source"] == "rule_metadata" and ids["attack"][0]["technique_id"] == "T1046"
    scan = next(f for f in fs if f["title"] == "Potential Port Scanning")
    assert scan["attack"][0]["technique_id"] == "T1046"  # internal source -> Network Service Discovery
    ov = analyst.get(f"/investigations/{inv['id']}/network/overview").json()
    assert ov["available"] and ov["summary"]["connections"] > 1500
    assert ov["top_destinations"][0]["ip"] == "185.220.100.5"
    assert any(e["flags"] for e in ov["story"])
    # uploaded Zeek logs carry no packets → session PCAP is refused honestly
    conn_ev = _first_event(inv["id"], "zeek_conn")
    assert analyst.get(f"/investigations/{inv['id']}/network/sessions/{conn_ev}/pcap").status_code == 409


def _first_event(inv_id: str, data_source: str, **eq) -> str:
    from saw import container
    from saw.core.schemas.query import Filter

    flt = [Filter(field="data_source", value=data_source)] + [Filter(field=k, value=v) for k, v in eq.items()]
    return container.get().events.search(inv_id, flt, limit=1)["events"][0]["event_id"]


def test_raw_pcap_builtin_analyzer_end_to_end(analyst):
    """ADR-0016: a real PCAP without Zeek (Windows server) → built-in analyzer → same detectors as Zeek logs."""
    from saw.devtools.sample_data import scenario_pcap
    from saw.integrations.pcapkit.reader import iter_packets

    inv = analyst.post("/investigations", json={"title": "raw pcap"}).json()
    up = upload(analyst, inv["id"], "capture.pcap", scenario_pcap(), kind="pcap")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    j = analyst.get(f"/jobs/{job['id']}").json()
    f = j["files"][0]
    assert j["state"] == "COMPLETED" and f["parser_id"] == "pcap(builtin)" and f["status"] == "done", f
    assert "Suricata 미설치" in f["message"] and f["events_parsed"] > 1000
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {x["category"] for x in fs}
    assert {"net.large_outbound", "net.periodic", "net.scan", "net.dns_anomaly", "net.tls_rarity", "net.long_conn",
            "net.unexpected_protocol"} <= cats, cats
    per = next(x for x in fs if x["category"] == "net.periodic")
    assert "43.201.88.10" in " ".join(per["entities"])
    ov = analyst.get(f"/investigations/{inv['id']}/network/overview").json()
    assert ov["available"] and ov["tools"]["builtin"].startswith("saw-pcapkit") and ov["tools"]["zeek"] is None
    # session PCAP download: an HTTP event resolves to its whole TCP connection
    ev = _first_event(inv["id"], "zeek_http", dst_ip="104.248.11.20")
    r = analyst.get(f"/investigations/{inv['id']}/network/sessions/{ev}/pcap")
    assert r.status_code == 200 and r.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert int(r.headers["x-saw-packets"]) == 8 and len(list(iter_packets(io.BytesIO(r.content)))) == 8  # 3-way, req, resp, FIN×2, ACK
    from sqlalchemy import select

    from saw.storage.db import session_scope
    from saw.storage.models import AuditEvent
    with session_scope() as s:  # packet download is evidence access → audited
        a = s.execute(select(AuditEvent).where(AuditEvent.action == "network.session_pcap")).scalars().one()
        assert a.target_id == ev and a.detail["packets"] == 8


def test_garbage_pcap_fails_honestly(analyst):
    inv = analyst.post("/investigations", json={"title": "empty pcap"}).json()
    pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16 + b"\x00" * 64
    up = upload(analyst, inv["id"], "capture.pcap", pcap, kind="pcap")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    f = analyst.get(f"/jobs/{job['id']}").json()["files"][0]
    assert f["type"] == "pcap" and f["status"] == "failed" and "decoded=0" in f["message"]


def test_unified_investigation_correlation(analyst):
    """Phase 7: web logs + network logs in one investigation -> cross-source correlations + unified timeline."""
    from saw.devtools.sample_data import gz_bytes, scenario_weblog

    inv = analyst.post("/investigations", json={"title": "unified"}).json()
    for name, data, kind in (("access.log.gz", gz_bytes(scenario_weblog(normal=300, enum_count=300)), "web_log"),
                             ("zeek.zip", _zip(scenario_zeek()), "pcap")):
        up = upload(analyst, inv["id"], name, data, kind=kind)
        analyst.post(f"/evidence/{up['evidence_id']}/process")
    cors = analyst.get(f"/investigations/{inv['id']}/correlations").json()
    assert any(c["kind"] == "same_ip_cross_source" for c in cors)
    c = next(c for c in cors if c["kind"] == "same_ip_cross_source")
    assert len({s["family"] for s in c["steps"]}) >= 2 and c["strength"] in ("strong", "weak")
    dens = analyst.post(f"/investigations/{inv['id']}/timeline/density", json={}).json()
    assert {"web", "zeek_conn"} <= {b["series"] for b in dens["buckets"]}
    r = analyst.patch(f"/investigations/{inv['id']}", json={"clock_skew": {"waf": -2.1}})
    assert r.json()["settings"]["clock_skew"]["waf"] == -2.1
    assert analyst.patch(f"/investigations/{inv['id']}", json={"clock_skew": {"waf": 999999}}).status_code == 400


def test_pcap_forensic_detectors_end_to_end(analyst):
    """Forensic scope (modelled on pcap-forensics-analyzer): every detector fires on its synthetic story, with
    response success signals, ATT&CK, analyst recommendations, and IOC matches from an uploaded IOC list."""
    import hashlib

    from saw.devtools.sample_data import PE_SAMPLE, scenario_pcap_forensics

    inv = analyst.post("/investigations", json={"title": "pcap forensics"}).json()
    iocs = f"# shared IOC list\n203[.]0[.]113[.]66\n{hashlib.sha256(PE_SAMPLE).hexdigest()}\n".encode()
    up = upload(analyst, inv["id"], "iocs.txt", iocs, kind="ioc_list")
    j = analyst.get(f"/jobs/{analyst.post(f'/evidence/{up[chr(101) + 'vidence_id']}/process').json()['id']}").json()
    assert j["files"][0]["parser_id"] == "ioc_list" and "IOC 2건" in j["files"][0]["message"], j["files"]
    up = upload(analyst, inv["id"], "incident.pcap", scenario_pcap_forensics(), kind="pcap")
    j = analyst.get(f"/jobs/{analyst.post(f'/evidence/{up[chr(101) + 'vidence_id']}/process').json()['id']}").json()
    assert j["state"] == "COMPLETED", j
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    by = {f["title"]: f for f in fs}
    titles = set(by)
    expected = {"Potential SQL Injection in Captured Traffic", "Potential Path Traversal / LFI in Captured Traffic",
                "Potential Web Shell Upload and Use", "Potential Masqueraded Executable Download",
                "Potential Exploit Kit Infection Chain", "Potential Brute Force (ftp) with Successful Login",
                "Potential Cleartext Credential Exposure", "Possible Weak or Default Password Accepted",
                "Potential ARP Spoofing (one IP, multiple MACs)", "Potential DGA Activity (NXDOMAIN burst)",
                "Possible Direct-IP HTTP Communication"}
    assert expected <= titles, sorted(titles)
    assert any(t.startswith("IOC Match: hash") for t in titles) and any(t.startswith("IOC Match: ip 203.0.113.66") for t in titles), sorted(titles)
    lfi = by["Potential Path Traversal / LFI in Captured Traffic"]
    assert lfi["risk_level"] in ("high", "critical") and any(c["passed"] and "passwd_file" in str(c["value"]) for c in lfi["checks"])
    shell = by["Potential Web Shell Upload and Use"]
    assert shell["attack"][0]["technique_id"] == "T1505.003" and shell["attack"][0]["confidence"] == "high"
    assert "확인·대응 권고" in by["Potential Masqueraded Executable Download"]["explanation_md"]
    brute = by["Potential Brute Force (ftp) with Successful Login"]
    assert next(m for m in brute["metrics"] if m["name"] == "failures")["observed"] == 6


def test_forensics_workspace_api(analyst):
    """Summary, extracted files (+inert download), credentials (no passwords), stream view, CSV and HTML report."""
    from saw.devtools.sample_data import PE_SAMPLE, scenario_pcap_forensics

    inv = analyst.post("/investigations", json={"title": "forensics api"}).json()
    up = upload(analyst, inv["id"], "incident.pcap", scenario_pcap_forensics(), kind="pcap")
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    base = f"/investigations/{inv['id']}/forensics"
    sm = analyst.get(base + "/summary").json()
    assert "verdict" in sm, sm
    assert sm["verdict"]["level"] == "high" and sm["captures"][0]["summary"]["files_extracted"] >= 5
    assert sm["counts"]["masquerade"] == 1 and sm["counts"]["auth"] == 8 and sm["severity"]["critical"] >= 1
    fl = analyst.get(base + "/files").json()
    exe = next(f for f in fl if f["masquerade"])
    assert exe["kind"] == "pe" and exe["filename"] == "invoice.jpg" and exe["risky"]
    r = analyst.get(base + f"/files/{exe['sha256']}/download")
    assert r.status_code == 200 and r.content == PE_SAMPLE
    assert r.headers["content-type"] == "application/octet-stream" and r.headers["content-disposition"].endswith('.infected"')
    assert analyst.get(base + "/files/" + "0" * 64 + "/download").status_code == 404
    cr = analyst.get(base + "/credentials").json()
    assert {c["outcome"] for c in cr} == {"failure", "success"} and "password" not in str([list(c) for c in cr]).replace("password_", "")
    http = _first_event(inv["id"], "zeek_http", dst_ip="10.20.1.15")
    st = analyst.get(base + f"/sessions/{http}/stream").json()
    assert st["client_view"]["mode"] == "text" and st["client_view"]["text"].startswith("GET /item")
    assert st["server_view"]["text"].startswith("HTTP/1.1 200")
    csv_ = analyst.get(base + "/export/files.csv")
    assert csv_.status_code == 200 and "invoice.jpg" in csv_.text and csv_.text.startswith("﻿timestamp")
    rep = analyst.get(base + "/report.html")
    assert rep.status_code == 200 and "PCAP 포렌식 분석 보고서" in rep.text and "<script" not in rep.text
    assert "Potential Web Shell Upload and Use" in rep.text
