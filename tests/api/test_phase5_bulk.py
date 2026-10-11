from __future__ import annotations

import gzip
import hashlib
import io
import zipfile

from saw.devtools.sample_data import gz_bytes, scenario_waf_jsonl, scenario_weblog
from saw.workers.safe_extract import ExtractionError, extract


def upload(api, inv_id: str, name: str, data: bytes, kind: str = "web_log", part: int = 256 * 1024) -> dict:
    ev = api.post(f"/investigations/{inv_id}/evidence", json={"kind": kind, "title": name}).json()
    u = api.post("/uploads", json={"evidence_id": ev["id"], "filename": name, "size": len(data),
                                   "sha256": hashlib.sha256(data).hexdigest()}).json()
    for i in range(0, len(data), part):
        r = api.put(f"/uploads/{u['id']}/parts/{i // part + 1}", content=data[i:i + part])
        assert r.status_code == 200, r.text
    r = api.post(f"/uploads/{u['id']}/complete")
    assert r.status_code == 200, r.text
    return {"evidence_id": ev["id"], **r.json()}


def test_bulk_pipeline_end_to_end(analyst):
    inv = analyst.post("/investigations", json={"title": "API 대량조회"}).json()
    up = upload(analyst, inv["id"], "access.log.gz", gz_bytes(scenario_weblog()))
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    j = analyst.get(f"/jobs/{job['id']}").json()
    assert j["state"] == "COMPLETED", j
    assert j["files"][1]["parser_id"] == "nginx_combined" or any(f["parser_id"] == "nginx_combined" for f in j["files"])
    ov = analyst.post(f"/investigations/{inv['id']}/overview", json={}).json()
    assert ov["summary"]["events"] > 4000 and ov["summary"]["unique_ip"] > 100
    assert ov["charts"]["top_uri"]["buckets"][0]["key"] == "/api/customer?id=<NUM>"
    fs = analyst.get(f"/investigations/{inv['id']}/findings").json()
    cats = {f["category"] for f in fs}
    assert {"web.api_enumeration", "web.sensitive_file_probe", "web.discovery", "web.injection_like",
            "web.credential_attack", "web.request_mutation_success"} <= cats, cats
    enum = next(f for f in fs if f["category"] == "web.api_enumeration")
    assert enum["title"] == "Possible API Enumeration" and enum["risk_level"] in ("high", "critical", "medium")
    seq = next(m for m in enum["metrics"] if m["name"] == "sequential_ratio")["observed"]
    assert seq > 0.9
    assert any(c["label"] == "Multiple Cloud IP" and c["passed"] for c in enum["checks"])
    assert enum["attack"][0]["technique_id"] == "T1213" and enum["attack_unmapped_reason"]
    # drill-down: finding -> events -> event detail -> raw context
    evs = analyst.post(f"/investigations/{inv['id']}/findings/{enum['id']}/events", json={"limit": 5}).json()
    assert evs["total"] >= 1000 and len(evs["events"]) == 5
    eid = evs["events"][0]["event_id"]
    det = analyst.get(f"/investigations/{inv['id']}/events/{eid}").json()
    assert det["event"]["uri_template"] == "/api/customer?id=<NUM>"
    ctxl = analyst.get(f"/investigations/{inv['id']}/events/{eid}/context?lines=3").json()
    assert "/api/customer?id=" in ctxl["lines"][ctxl["target_index"]]
    # story / timeline / graph / patterns / parameters / attack
    st = analyst.get(f"/investigations/{inv['id']}/story").json()["story"]
    stages = [n["stage"] for n in st["graph"]["nodes"]]
    assert "DATA_ACCESS" in stages and "RECON" in stages
    tl = analyst.post(f"/investigations/{inv['id']}/timeline", json={"limit": 500,
                      "filters": [{"field": "uri_template", "op": "is", "value": "/api/customer?id=<NUM>"}]}).json()
    assert any(i["kind"] == "group" for i in tl["items"])
    g = analyst.get(f"/investigations/{inv['id']}/graph").json()
    assert any(n["type"] == "group" for n in g["nodes"])
    pats = analyst.get(f"/investigations/{inv['id']}/patterns").json()
    assert pats[0]["template"].endswith("/api/customer?id=<NUM>")
    ps = analyst.get(f"/investigations/{inv['id']}/parameters").json()
    assert ps[0]["param"] == "id" and ps[0]["profile"]["potential_behavior"] == "Sequential Enumeration"
    m = analyst.get(f"/investigations/{inv['id']}/attack/matrix").json()
    tids = {t["technique_id"] for c in m["columns"] for t in c["techniques"]}
    assert {"T1595.003", "T1110.004", "T1190"} & tids
    inf = analyst.get(f"/investigations/{inv['id']}/attack/inferred").json()
    assert inf["recommendations"] and inf["label"].startswith("Inferred")
    layer = analyst.get(f"/investigations/{inv['id']}/attack/navigator-layer").json()
    assert layer["versions"]["layer"] == "4.5" and layer["techniques"]
    # investigation summary updated
    i2 = analyst.get(f"/investigations/{inv['id']}").json()
    assert i2["risk_level"] in ("high", "critical") and i2["status"] == "in_progress"


def test_feedback_case_and_export(analyst):
    inv = analyst.post("/investigations", json={"title": "case flow"}).json()
    up = upload(analyst, inv["id"], "a.log", ("\n".join(scenario_weblog(normal=200, enum_count=400)) + "\n").encode())
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    f = analyst.get(f"/investigations/{inv['id']}/findings").json()[0]
    assert analyst.post(f"/investigations/{inv['id']}/findings/{f['id']}/feedback",
                        json={"verdict": "valid"}).json()["status"] == "valid"
    c = analyst.post("/cases", json={"title": "API 열거 사건", "investigation_ids": [inv["id"]]}).json()
    assert c["display_id"].startswith("CASE-")
    analyst.post(f"/cases/{c['id']}/items", json={"item_type": "finding", "ref_id": f["id"]})
    md = analyst.get(f"/cases/{c['id']}/export").text
    assert f["title"] in md and "Exported by analyst1" in md
    assert len(analyst.get(f"/cases/{c['id']}/history").json()) >= 1


def test_upload_rejects_bad_hash_and_size(analyst):
    inv = analyst.post("/investigations", json={"title": "x"}).json()
    ev = analyst.post(f"/investigations/{inv['id']}/evidence", json={"kind": "web_log"}).json()
    u = analyst.post("/uploads", json={"evidence_id": ev["id"], "filename": "../../etc/passwd", "size": 3,
                                       "sha256": "0" * 64}).json()
    assert analyst.put(f"/uploads/{u['id']}/parts/1", content=b"abcd").status_code == 400  # exceeds declared
    analyst.put(f"/uploads/{u['id']}/parts/1", content=b"abc")
    r = analyst.post(f"/uploads/{u['id']}/complete")
    assert r.status_code == 400 and "sha256" in r.text


def test_parser_waiting_input_then_override(analyst):
    inv = analyst.post("/investigations", json={"title": "x"}).json()
    data = b"\n".join(b"weird line %d with no structure" % i for i in range(50))
    up = upload(analyst, inv["id"], "weird.txt", data, kind="sec_log")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    j = analyst.get(f"/jobs/{job['id']}").json()
    assert j["state"] == "WAITING_INPUT"
    fid = next(f["id"] for f in j["files"] if f["status"] == "waiting_input")
    assert analyst.post(f"/evidence/{up['evidence_id']}/files/{fid}/parser", json={"parser_id": "syslog"}).status_code == 200
    j = analyst.get(f"/jobs/{job['id']}").json()
    assert j["state"] == "COMPLETED"
    assert j["files"][0]["status"] == "failed"  # honest: lines did not parse as syslog


def test_waf_jsonl_pipeline(analyst):
    inv = analyst.post("/investigations", json={"title": "waf"}).json()
    up = upload(analyst, inv["id"], "waf.jsonl", ("\n".join(scenario_waf_jsonl()) + "\n").encode(), kind="waf_log")
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    ov = analyst.post(f"/investigations/{inv['id']}/overview", json={}).json()
    assert ov["summary"]["data_sources"][0]["key"] == "waf"


def test_safe_extract_limits(tmp_path):
    bomb = tmp_path / "bomb.gz"
    bomb.write_bytes(gzip.compress(b"\0" * (30 * 1024 * 1024)))
    try:
        list(extract(bomb, "bomb.gz", tmp_path))
        raise AssertionError("expected ExtractionError")
    except ExtractionError as e:
        assert "archive bomb" in str(e)
    z = tmp_path / "slip.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", "x")
        zf.writestr("ok/access.log", "line")
    z.write_bytes(buf.getvalue())
    out = list(extract(z, "slip.zip", tmp_path))
    assert [o.display_name for o in out] == ["slip.zip:ok_access.log"]
    nested = tmp_path / "n.gz"
    data = b"x"
    for _ in range(5):
        data = gzip.compress(data)
    nested.write_bytes(data)
    try:
        list(extract(nested, "n.gz", tmp_path))
        raise AssertionError("expected depth error")
    except ExtractionError as e:
        assert "depth" in str(e)


def test_viewer_member_is_read_only(app, analyst):
    from tests.conftest import Api, make_user

    inv = analyst.post("/investigations", json={"title": "x"}).json()
    vid = make_user("v2", ["analyst"])
    analyst.post(f"/investigations/{inv['id']}/members", json={"user_id": vid, "access": "viewer"})
    v = Api(app, "v2")
    assert v.get(f"/investigations/{inv['id']}").status_code == 200
    assert v.post(f"/investigations/{inv['id']}/notes", json={"body_md": "x"}).status_code == 403
    assert v.post(f"/investigations/{inv['id']}/evidence", json={"kind": "web_log"}).status_code == 403


def test_process_is_idempotent_and_leases_are_exclusive(analyst):
    """Adopted from the Codex comparison: Idempotency-Key + active-job reuse, and stale workers stop writing."""
    import pytest

    from saw.storage.db import session_scope
    from saw.storage.models import Job
    from saw.workers import pipeline

    inv = analyst.post("/investigations", json={"title": "idem"}).json()
    up = upload(analyst, inv["id"], "a.log", b"1.2.3.4 - - [05/Oct/2026:02:30:00 +0900] \"GET / HTTP/1.1\" 200 1 \"-\" \"x\"\n")
    h = {"Idempotency-Key": "k-1"}
    j1 = analyst.post(f"/evidence/{up['evidence_id']}/process", headers=h).json()
    j2 = analyst.post(f"/evidence/{up['evidence_id']}/process", headers=h).json()
    assert j1["id"] == j2["id"]
    other = upload(analyst, inv["id"], "b.log", b"x\n")
    assert analyst.post(f"/evidence/{other['evidence_id']}/process", headers=h).status_code == 409
    # lease: a second claim supersedes the first worker
    pipeline.claim(j1["id"])
    with session_scope() as s:
        s.get(Job, j1["id"]).attempt += 1  # another worker took over
    with pytest.raises(pipeline.StaleLease):
        pipeline._job_update(j1["id"], current_item="late write")
    pipeline._lease.set(None)


def test_findings_carry_claim_types(analyst):
    """OBSERVED/DERIVED/INFERRED/VERDICT on every finding part (adopted from the Codex comparison)."""
    inv = analyst.post("/investigations", json={"title": "claims"}).json()
    up = upload(analyst, inv["id"], "access.log.gz", gz_bytes(scenario_weblog(normal=200, enum_count=300)))
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    f = analyst.get(f"/investigations/{inv['id']}/findings").json()[0]
    assert f["claim"] == "INFERRED" and f["evidence_refs"]["claim"] == "OBSERVED"
    assert all(m["claim"] == "DERIVED" for m in f["metrics"]) and all(a["claim"] == "INFERRED" for a in f["attack"])
    analyst.post(f"/investigations/{inv['id']}/findings/{f['id']}/feedback", json={"verdict": "valid", "comment": "ok"}).raise_for_status()
    d = analyst.get(f"/investigations/{inv['id']}/findings/{f['id']}").json()
    assert d["feedback"][0]["claim"] == "VERDICT"
