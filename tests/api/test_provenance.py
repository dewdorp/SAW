"""Processing records: who processed which input with which parser/settings, visible per role, verifiable."""
from __future__ import annotations

import hashlib

from saw.core.application.provenance import pcap_engine_digest
from saw.devtools.sample_data import scenario_ndr_meta_csv, scenario_tls_certs
from saw.integrations.pcapkit import PRODUCER
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, ProcessingRun
from tests.api.test_parser_library import SAMPLE, SPEC
from tests.api.test_phase5_bulk import upload


def _process(api, inv_id: str, name: str, data: bytes, kind: str = "auto") -> dict:
    up = upload(api, inv_id, name, data, kind=kind)
    j = api.get(f"/jobs/{api.post(f'/evidence/{up['evidence_id']}/process').json()['id']}").json()
    assert j["state"] == "COMPLETED", j
    return {**up, "job": j}


def test_every_processing_leaves_a_verifiable_record(analyst):
    data = scenario_ndr_meta_csv(normal=20).encode("utf-8-sig")
    inv = analyst.post("/investigations", json={"title": "기록"}).json()
    _process(analyst, inv["id"], "ndr.csv", data)
    pcap_data = scenario_tls_certs()
    _process(analyst, inv["id"], "tls.pcap", pcap_data, "pcap")
    runs = analyst.get("/processing-runs").json()
    ndr = next(r for r in runs if r["parser_id"] == "ndr_meta_csv")
    assert ndr["actor"] == "analyst1" and ndr["input_sha256"] == hashlib.sha256(data).hexdigest()
    assert ndr["file_name"] == "ndr.csv" and ndr["investigation_title"] == "기록" and ndr["events"] > 0
    assert ndr["settings"]["pipeline"].startswith("saw.ingest/") and ndr["settings"]["encoding"] == "utf-8"
    assert len(ndr["parser_digest"]) == 64 and len(ndr["settings_digest"]) == 64 and len(ndr["run_digest"]) == 64
    pcap = next(r for r in runs if r["parser_id"] == "pcap")
    assert pcap["parser_version"] == PRODUCER.rpartition("/")[2]
    assert pcap["parser_digest"] == pcap_engine_digest()
    assert pcap["input_sha256"] == hashlib.sha256(pcap_data).hexdigest()
    assert pcap["coverage"]["packets"] > 0 and len(pcap["parser_digest"]) == 64
    v = analyst.get(f"/processing-runs/{ndr['id']}/verify").json()
    assert v["ok"] is True and v["audit_record_found"] is True
    # tampering with the stored record is detected against the hash-chained audit copy
    with session_scope() as s:
        s.get(ProcessingRun, ndr["id"]).events += 1
    v2 = analyst.get(f"/processing-runs/{ndr['id']}/verify").json()
    assert v2["ok"] is False and v2["recomputed_run_digest_ok"] is False
    with session_scope() as s:
        assert s.query(AuditEvent).filter_by(action="evidence.processed").count() >= 2


def test_roles_see_their_scope_and_the_consolidated_view_flags_inconsistent_settings(app, analyst, senior, manager, admin):
    inv = analyst.post("/investigations", json={"title": "사건 A — 고객사명"}).json()
    up = upload(analyst, inv["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    f = analyst.get(f"/jobs/{job['id']}").json()["files"][0]  # waits for a parser choice
    assert analyst.post(f"/evidence/{up['evidence_id']}/files/{f['id']}/parser", json={"parser_id": "csv"}).status_code == 200
    d = analyst.post("/parser-library", json={"name": "웹방화벽 X", "slug": "waf-x", "spec": {**SPEC, "detect": {}}}).json()
    # the same input re-processed with a personal draft parser by the author
    assert analyst.post(f"/evidence/{up['evidence_id']}/files/{f['id']}/parser", json={"parser_id": d["pinned_id"]}).status_code == 200
    inv_b = senior.post("/investigations", json={"title": "사건 B"}).json()
    _process(senior, inv_b["id"], "other.csv", scenario_ndr_meta_csv(normal=5).encode())

    mine = analyst.get("/processing-runs").json()
    assert {r["actor"] for r in mine} == {"analyst1"} and len(mine) == 2  # not senior's investigation
    assert analyst.get("/processing-runs?scope=all").status_code == 403

    allm = manager.get("/processing-runs?scope=all").json()
    assert {r["actor"] for r in allm} == {"analyst1", "senior1"} and allm[0]["investigation_title"]
    summ = manager.get("/processing-runs/summary").json()
    users = {u["actor"]: u for u in summ["by_user"]}
    assert users["analyst1"]["runs"] == 2 and users["analyst1"]["draft_runs"] == 1 and users["senior1"]["runs"] == 1
    warn = summ["warnings"]["same_input_different_settings"]
    assert len(warn) == 1 and warn[0]["settings_variants"] == 2 and warn[0]["input_sha256"] == hashlib.sha256(SAMPLE.encode()).hexdigest()
    assert summ["warnings"]["draft_parser_runs"][0]["parser_id"] == "u:waf-x@1"

    # the administrator audits processing without seeing case content (file names, titles)
    adm = admin.get("/processing-runs?scope=all").json()
    assert len(adm) == 3 and all(r["file_name"].startswith("(비공개)") for r in adm)
    assert all("investigation_title" not in r and "settings" not in r for r in adm)
    assert admin.get("/processing-runs/summary").json()["runs"] == 3
    assert admin.get(f"/processing-runs/{adm[0]['id']}/verify").json()["ok"] is True
