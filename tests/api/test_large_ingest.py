"""Large-file behaviour on small PCs: slim index + raw read-back, restart checkpoint, progress/ETA, projections."""
from __future__ import annotations

from saw.core.schemas.query import Filter
from saw.devtools.sample_data import scenario_kr_firewall_csv, scenario_ndr_meta_csv
from saw.storage.db import session_scope
from saw.storage.models import EvidenceFile, Job, User
from tests.api.test_generation_reprocessing import read_events
from tests.api.test_phase5_bulk import upload


def _web_event(inv_id: str) -> dict:
    return read_events().search(inv_id, [Filter(field="data_source", value="web")], limit=1)["events"][0]


def test_structured_events_are_stored_slim_and_raw_is_read_back_redacted(analyst):
    inv = analyst.post("/investigations", json={"title": "slim"}).json()
    up = upload(analyst, inv["id"], "ndr.csv", scenario_ndr_meta_csv(normal=30).encode("utf-8-sig"), kind="auto")
    j = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{j['id']}").json()["state"] == "COMPLETED"
    stored = _web_event(inv["id"])
    assert "raw_event" not in stored and stored["raw_ref"]["length"] > 0
    d = analyst.get(f"/investigations/{inv['id']}/events/{stored['event_id']}").json()["event"]
    assert d["raw_event"].startswith("2026-10-03") and "type=http_request" in d["raw_event"]
    assert "cookie=●●●●" in d["raw_event"] and "JSESSIONID=" not in d["raw_event"]


def test_cp949_raw_read_back_and_context(analyst):
    inv = analyst.post("/investigations", json={"title": "cp949"}).json()
    up = upload(analyst, inv["id"], "fw.csv", scenario_kr_firewall_csv(), kind="auto")
    j = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{j['id']}").json()["state"] == "COMPLETED"
    # last row of the file: the context window starts mid-file after Korean text (byte vs character offsets)
    e = read_events().search(inv["id"], [Filter(field="dst_port", value=8443)], limit=1)["events"][0]
    assert e["raw_ref"]["enc"] == "cp949"
    d = analyst.get(f"/investigations/{inv['id']}/events/{e['event_id']}").json()["event"]
    assert "업무망-인터넷" in d["raw_event"]
    ctx = analyst.get(f"/investigations/{inv['id']}/events/{e['event_id']}/context?lines=2").json()
    assert ctx["lines"][ctx["target_index"]].endswith("3400000000,5200,업무망-인터넷,허용")
    assert ctx["lines"][ctx["target_index"] - 1].startswith("2026-10-03 ")


def test_restart_checkpoint_replays_full_new_generation(analyst):
    """A fresh private generation must replay every event; an old acknowledged checkpoint cannot omit records."""
    from saw.workers.pipeline import ingest_run

    data = scenario_ndr_meta_csv(normal=200).encode("utf-8-sig")
    inv = analyst.post("/investigations", json={"title": "resume"}).json()
    up = upload(analyst, inv["id"], "ndr.csv", data, kind="auto")
    with session_scope() as s:
        uid = s.query(User).filter_by(username="analyst1").one().id
        job = Job(investigation_id=inv["id"], evidence_id=up["evidence_id"], kind="ingest", state="QUEUED",
                  requested_by=uid, stages={"parse": {"ckpt": {"file": up["file_id"], "emitted": 500}}})
        s.add(job)
        s.flush()
        jid = job.id
    ingest_run(jid)
    with session_scope() as s:
        j, f = s.get(Job, jid), s.get(EvidenceFile, up["file_id"])
        assert j.state == "COMPLETED", j.error
        total = f.events_parsed
    stored = read_events().count(inv["id"], [Filter(field="evidence_id", value=up["evidence_id"])])
    assert total > 1000 and stored == total


def test_progress_reports_bytes_pct_eta_and_checkpoint(analyst):
    import saw.workers.pipeline as pl

    seen: list[dict] = []
    orig = pl._job_update

    def spy(job_id, **kw):
        if "stage_parse" in kw:
            seen.append(dict(kw["stage_parse"]))
        return orig(job_id, **kw)

    pl._job_update, old_batch = spy, pl.BATCH
    pl.BATCH = 300
    try:
        inv = analyst.post("/investigations", json={"title": "eta"}).json()
        up = upload(analyst, inv["id"], "ndr.csv", scenario_ndr_meta_csv(normal=300).encode(), kind="auto")
        analyst.post(f"/evidence/{up['evidence_id']}/process")
    finally:
        pl._job_update, pl.BATCH = orig, old_batch
    mid = [x for x in seen if "eta_sec" in x]
    assert len(mid) >= 3
    assert all(0 < x["pct"] < 100 and x["eta_sec"] >= 0 and x["ckpt"]["emitted"] > 0 for x in mid)
    assert [x["pct"] for x in mid] == sorted(x["pct"] for x in mid)


def test_sqlite_projection_matches_full_documents(analyst):
    inv = analyst.post("/investigations", json={"title": "proj"}).json()
    up = upload(analyst, inv["id"], "ndr.csv", scenario_ndr_meta_csv(normal=20).encode(), kind="auto")
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    es = read_events()
    flt = [Filter(field="data_source", value="web")]
    fields = ["timestamp", "src_ip", "params", "status_code", "tags", "missing_field"]
    a = list(es.iterate(inv["id"], flt, fields=fields, batch=7))
    b = [{k: e.get(k) for k in fields} for e in es.iterate(inv["id"], flt, batch=7)]
    assert a == b and len(a) == 20 + 6 + 300


def test_checkpoint_that_no_longer_matches_reindexes_the_whole_file(analyst):
    """A checkpoint from another parser version or with a different boundary event must not skip anything."""
    from saw.workers.pipeline import ingest_run

    data = scenario_ndr_meta_csv(normal=200).encode("utf-8-sig")
    for ck in ({"emitted": 500, "last_event_id": "00000000-0000-0000-0000-000000000000",
                "parser": "ndr_meta_csv@1.0.0"}, {"emitted": 500, "parser": "ndr_meta_csv@0.9.0"}):
        inv = analyst.post("/investigations", json={"title": "resume-mismatch"}).json()
        up = upload(analyst, inv["id"], "ndr.csv", data, kind="auto")
        with session_scope() as s:
            uid = s.query(User).filter_by(username="analyst1").one().id
            j = Job(investigation_id=inv["id"], evidence_id=up["evidence_id"], kind="ingest", state="QUEUED",
                    requested_by=uid, stages={"parse": {"ckpt": {"file": up["file_id"], **ck}}})
            s.add(j)
            s.flush()
            jid = j.id
        ingest_run(jid)
        with session_scope() as s:
            assert s.get(Job, jid).state == "COMPLETED"
            total = s.get(EvidenceFile, up["file_id"]).events_parsed
        stored = read_events().count(inv["id"], [Filter(field="evidence_id", value=up["evidence_id"])])
        assert stored == total > 1000


def test_coverage_accounts_for_every_line(analyst):
    text = scenario_ndr_meta_csv(normal=50)
    inv = analyst.post("/investigations", json={"title": "coverage"}).json()
    up = upload(analyst, inv["id"], "ndr.csv", (text + "\n\nnot,a,valid,row\n").encode(), kind="auto")
    j = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    f = analyst.get(f"/jobs/{j['id']}").json()["files"][0]
    cov = f["coverage"]
    n = len(text.splitlines())
    assert cov["lines"] == n + 3 and cov["blank_lines"] == 2 and cov["failed_lines"] == 1  # text already ends with a newline

    assert cov["skipped_lines"] == 1 + text.count("type=http_response")  # header + responses folded into requests
    assert cov["events"] == f["events_parsed"] == n - 1 - text.count("type=http_response")
    assert cov["lines"] == sum(cov[k] for k in ("blank_lines", "skipped_lines", "failed_lines", "continuation_lines",
                                                 "events"))
