"""Findings of the 2026-10-09 comparison review about wrong-but-plausible results: records joined that do not belong
together, events counted as stored when the search engine refused them, values lost without notice."""
from __future__ import annotations

import base64
import gzip

import pytest

from saw import container
from saw.analyzers.payload.transforms import Incomplete, auto_decode, t_gzip
from saw.core.application.analyze import payload
from saw.core.schemas.query import Filter
from saw.detectors.base import DetectorContext
from saw.detectors.pcap_forensics import WebShellUpload
from saw.devtools.sample_data import NDR_HEADER, scenario_ndr_meta_csv
from saw.parsers.custom import DefinedParser, ParserSpec
from saw.parsers.ndr import NdrMetaCsvParser
from saw.parsers.registry import detect, parse_text
from saw.parsers.structured import CsvParser
from saw.storage.db import session_scope
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.models import EvidenceFile
from saw.storage.opensearch_store import IndexUnavailable, OpenSearchEventStore
from tests.api.test_phase5_bulk import upload
from tests.unit.test_text_ingest import _events


# ---------------------------------------------------------------- NDR: one flow number, different conversations
def _ndr(src: str, sport: int, server: str, stream: str, meta: str, flow: int = 77) -> str:
    return (f"2026-10-03 17:38,{src},{sport},203.0.113.10,8080,6,Web,HTTP,HTTP,KR,KR,4,1,5,1,meta,filtered=none,"
            f"time=2026-10-03 17:38:47+0900,seq=1,num_of_meta=1,transaction_id=0,server_id={server},stream={stream},"
            f"flow_rowid={flow},{meta}" + "," * 19)


REQ = "type=http_request;method=request;hostname=h.example.com;method=GET;path={};ua=x;xfwd=;cookie="
RESP = "type=http_response;method=response;ret_code={};num_of_res=1"


@pytest.mark.parametrize("other", [
    dict(src="198.51.100.7", sport=50000, server="2", stream="1"),   # another sensor reusing the number
    dict(src="198.51.100.99", sport=50000, server="1", stream="1"),  # another client
    dict(src="198.51.100.7", sport=50001, server="1", stream="1"),   # another connection of the same client
    dict(src="198.51.100.7", sport=50000, server="1", stream="2"),   # another stream
], ids=["server", "source", "port", "stream"])
def test_ndr_response_of_another_conversation_is_not_joined(other):
    text = "\n".join([NDR_HEADER, _ndr("198.51.100.7", 50000, "1", "1", REQ.format("/a")),
                      _ndr(meta=RESP.format(500), **other), ""])
    evs = _events(NdrMetaCsvParser(), text)
    web = next(e for e in evs if e["data_source"] == "web")
    assert "status_code" not in web                       # the request stays unanswered...
    orphan = next(e for e in evs if e["data_source"] == "ndr_http")
    assert orphan["status_code"] == 500                   # ...and the response is kept as its own event
    assert web["session_id"] != orphan["session_id"] or other["server"] == "1"


def test_ndr_same_conversation_still_pairs_also_when_the_response_lists_the_server_first():
    resp = _ndr("198.51.100.7", 50000, "1", "1", RESP.format(200)).split(",")
    resp[1], resp[2], resp[3], resp[4] = resp[3], resp[4], resp[1], resp[2]  # response row written server → client
    text = "\n".join([NDR_HEADER, _ndr("198.51.100.7", 50000, "1", "1", REQ.format("/a")), ",".join(resp), ""])
    evs = _events(NdrMetaCsvParser(), text)
    assert [e["data_source"] for e in evs] == ["web"] and evs[0]["status_code"] == 200
    assert evs[0]["session_id"] == "ndr-flow-1-77"


# ---------------------------------------------------------------- CSV: the same column name twice
CSV_DUP = ("time,src_ip,status,status,note\n2026-10-01 10:00:00,198.51.100.1,200,403,a\n"
           "2026-10-01 10:00:01,198.51.100.2,301,500,b\n")


def test_csv_repeated_column_keeps_both_values_and_says_so():
    p = CsvParser()
    evs = _events(p, CSV_DUP)
    assert [(e["status_code"], e["ext"]["csv"]["status_2"]) for e in evs] == [(200, "403"), (301, "500")]
    assert p.warnings and "status" in p.warnings[0]
    _events(p, "time,src_ip,status,note\n2026-10-01 10:00:00,198.51.100.1,200,a\n")
    assert p.warnings == []                                # per file, not sticky


def test_user_parser_repeated_column_keeps_both_values():
    p = DefinedParser("dup", 1, ParserSpec(format="delimited", delimiter=",", has_header=True), "dup")
    evs = _events(p, CSV_DUP)
    assert evs[0]["status_code"] == 200 and "403" in str(evs[0]["ext"]) and p.warnings


def test_ingest_reports_repeated_columns_on_the_file(analyst):
    inv = analyst.post("/investigations", json={"title": "dup"}).json()
    up = upload(analyst, inv["id"], "dup.csv", (CSV_DUP * 1).encode(), kind="auto")
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    with session_scope() as s:
        f = s.get(EvidenceFile, up["file_id"])
        assert f.parse_status == "done" and "같은 열 이름" in f.message and "status" in f.message


# ---------------------------------------------------------------- paste: no parser / records spanning lines
def test_unrecognised_text_is_not_given_to_an_arbitrary_parser():
    d = detect(["just some words", "and a few more of them"])
    assert d.parser_id == "" and d.confidence == 0 and d.candidates == []
    r = parse_text("just some words\nand a few more of them\n")
    assert r["parser"] is None and r["events"] == [] and r["failed"] == 2


def test_pasted_csv_with_line_breaks_inside_quotes_is_parsed_as_records():
    text = ('time,src_ip,uri,note\n2026-10-01 10:00:00,198.51.100.1,/a,"line one\nline two"\n'
            '2026-10-01 10:00:01,198.51.100.2,/b,"x\ny\nz"\n2026-10-01 10:00:02,198.51.100.3,/c,plain\n')
    r = parse_text(text)
    assert r["parser"] == "csv" and r["failed"] == 0
    assert [(e["uri"], e["raw_ref"]["line_no"]) for e in r["events"]] == [("/a", 2), ("/b", 4), ("/c", 7)]


def test_pasted_ndr_rows_pair_like_an_uploaded_file():
    r = parse_text(scenario_ndr_meta_csv(normal=5))
    web = [e for e in r["events"] if e["data_source"] == "web"]
    assert r["parser"] == "ndr_meta_csv" and web and all(e.get("status_code") for e in web)


# ---------------------------------------------------------------- cut-off compressed input
def test_cut_off_gzip_is_marked_incomplete():
    whole = gzip.compress(("GET /admin?cmd=whoami HTTP/1.1\r\n" * 400).encode())
    full = t_gzip(whole.decode("latin-1"))
    assert not isinstance(full, Incomplete)
    part = t_gzip(whole[: len(whole) // 2].decode("latin-1"))
    assert isinstance(part, Incomplete) and 0 < len(part) < len(full)
    with pytest.raises(ValueError):
        t_gzip(whole[:12].decode("latin-1"))               # header only: nothing to show
    ch = auto_decode(base64.b64encode(whole[: len(whole) // 2]).decode())
    assert ch.incomplete and ch.confidence == "low" and ch.steps[-1].note
    out = payload(base64.b64encode(whole[: len(whole) // 2]).decode())
    assert out["incomplete"] is True and out["steps"][-1]["note"]
    assert payload(base64.b64encode(whole).decode())["incomplete"] is False


# ---------------------------------------------------------------- events the search engine did not store
def test_refused_events_are_not_counted_as_stored(analyst, monkeypatch):
    store = container.get().events
    real = store.index

    def index(events):
        events = list(events)
        keep = [e for i, e in enumerate(events) if i % 7]   # the engine refuses every 7th document
        stored = real(keep)                                 # the real store resets its own report: set ours after it
        kept = {e["event_id"] for e in keep}
        store.last_errors = [{"event_id": e["event_id"], "reason": "mapper_parsing_exception"}
                             for e in events if e["event_id"] not in kept]
        return stored

    monkeypatch.setattr(store, "index", index, raising=False)
    monkeypatch.setattr(store, "last_errors", [], raising=False)
    inv = analyst.post("/investigations", json={"title": "refused"}).json()
    up = upload(analyst, inv["id"], "ndr.csv", scenario_ndr_meta_csv(normal=60).encode("utf-8-sig"), kind="auto")
    j = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{j['id']}").json()["state"] == "COMPLETED"
    searchable = store.count(inv["id"], [Filter(field="evidence_id", value=up["evidence_id"])])
    with session_scope() as s:
        f = s.get(EvidenceFile, up["file_id"])
        cov = next(x["coverage"] for x in f.error_samples if "coverage" in x)
        assert cov["rejected_events"] > 0 and f.events_parsed == searchable == cov["events"]
        assert f.events_failed == cov["failed_lines"] + cov["rejected_events"]
        assert "저장을 거부" in f.message
        assert any("저장을 거부" in (x.get("reason") or "") for x in f.error_samples)
        # every line of the file is still accounted for
        assert cov["lines"] == sum(cov[k] for k in ("blank_lines", "skipped_lines", "failed_lines", "continuation_lines",
                                                    "events", "rejected_events"))


def _bulk_result(monkeypatch, errors: list[dict], ok: int):
    from opensearchpy import helpers

    monkeypatch.setattr(helpers, "bulk", lambda *a, **k: (ok, errors))
    return OpenSearchEventStore("http://127.0.0.1:9", ensure=False, prefix="sawunit")


EV = [{"event_id": f"e{i}", "investigation_id": "i", "data_source": "web", "timestamp": "2026-10-01T00:00:00Z"}
      for i in range(3)]


def test_opensearch_overload_fails_the_batch_so_it_is_sent_again(monkeypatch):
    st = _bulk_result(monkeypatch, [{"index": {"_id": "e2", "status": 429, "error": {"type": "rejected_execution"}}}], 2)
    with pytest.raises(IndexUnavailable):
        st.index(EV)
    assert st.rejected == 0


def test_opensearch_permanent_rejection_is_reported_per_event(monkeypatch):
    st = _bulk_result(monkeypatch, [{"index": {"_id": "e2", "status": 400,
                                               "error": {"type": "mapper_parsing_exception", "reason": "secret value"}}}], 2)
    assert st.index(EV) == 2
    assert st.last_errors == [{"event_id": "e2", "reason": "mapper_parsing_exception"}]  # no document content


# ---------------------------------------------------------------- web shell: upload and "use"
def _http(i: int, ts: str, dst: str, uri: str, status: int | None, method: str = "GET") -> dict:
    return {"event_id": f"h{i}", "investigation_id": "inv", "data_source": "zeek_http", "timestamp": ts, "method": method,
            "src_ip": "198.51.100.7", "dst_ip": dst, "uri": uri, **({"status_code": status} if status else {})}


def _shell_findings(tmp_path, later: list[dict]):
    st = SQLiteEventStore(tmp_path / "ev.db")
    up = {"event_id": "f1", "investigation_id": "inv", "data_source": "zeek_files", "timestamp": "2026-10-01T10:00:00Z",
          "src_ip": "198.51.100.7", "dst_ip": "203.0.113.10",
          "ext": {"zeek": {"direction": "upload", "filename": "img.php", "kind": "php"}}}
    st.index([up] + later)
    return WebShellUpload().run(DetectorContext("inv", st))


def test_webshell_use_needs_the_same_server_and_exact_file_name(tmp_path):
    f = _shell_findings(tmp_path, [
        _http(1, "2026-10-01T10:01:00Z", "203.0.113.99", "/up/img.php", 200),         # same name on another server
        _http(2, "2026-10-01T10:02:00Z", "203.0.113.10", "/docs/myimg.php.txt", 200),  # name is only a substring
        _http(3, "2026-10-01T10:03:00Z", "203.0.113.10", "/up/img.php?c=id", 404),     # asked for, but not there
        _http(4, "2026-10-01T09:00:00Z", "203.0.113.10", "/up/img.php", 200),          # before the upload
    ])[0]
    assert f.title == "Potential Web Shell Upload" and f.success_signal is False


def test_webshell_use_is_reported_when_the_server_serves_the_uploaded_file(tmp_path):
    f = _shell_findings(tmp_path, [
        _http(1, "2026-10-01T10:03:00Z", "203.0.113.10", "/up/img.php?c=id", 404),
        _http(2, "2026-10-01T10:04:00Z", "203.0.113.10", "/upload/IMG.php?c=id", 200, "POST"),
    ])[0]
    assert f.title == "Potential Web Shell Upload and Use" and f.success_signal is True
    assert f.total_events == 2 and "거부된 요청" in str(f.checks)


# ---------------------------------------------------------------- login detector: volume alone is not an attack
def _login_log(rows: list[tuple[str, int, int]]) -> bytes:
    """rows: (source address, successful POST /login, refused POST /login)."""
    from datetime import datetime, timedelta

    from saw.devtools.sample_data import KST, _line

    t0 = datetime(2026, 10, 5, 9, 0, tzinfo=KST)
    out, n = [], 0
    for ip, ok, refused in rows:
        for status in [200] * ok + [401] * refused:
            n += 1
            out.append(_line(ip, t0 + timedelta(seconds=n), "POST", "/auth/login", status, 300, "Mozilla/5.0 (Linux; Android 14)"))
    out += [_line("198.51.100.200", t0 + timedelta(seconds=n + k), "GET", f"/page/{k}", 200, 900, "Mozilla/5.0") for k in range(50)]
    return ("\n".join(out) + "\n").encode()


def _login_findings(api, inv_id: str) -> dict[str, dict]:
    fs = [f for f in api.get(f"/investigations/{inv_id}/findings").json() if f["category"] == "web.credential_attack"]
    return {e.split(":", 1)[1]: f for f in fs for e in f["entities"] if e.startswith("ip:")}


def test_many_successful_logins_from_one_address_are_not_reported(analyst):
    """Regression (real NDR export): 95 "brute force" detections, every one with a 0 % failure rate - carrier and
    office addresses shared by many customers."""
    inv = analyst.post("/investigations", json={"title": "logins"}).json()
    up = upload(analyst, inv["id"], "access.log", _login_log([("203.0.113.10", 120, 0),    # busy shared address
                                                              ("203.0.113.20", 60, 3),     # a few typos
                                                              ("203.0.113.30", 5, 45)]))   # guessing
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    got = _login_findings(analyst, inv["id"])
    assert set(got) == {"203.0.113.30"}
    assert got["203.0.113.30"]["risk_level"] in ("high", "critical", "medium") and got["203.0.113.30"]["detector"]["version"] == "1.1.0"


def test_reanalysis_removes_detections_that_no_longer_hold_but_keeps_reviewed_ones(analyst):
    from saw.core.application import analysis
    from saw.storage.models import Finding

    inv = analyst.post("/investigations", json={"title": "stale"}).json()
    up = upload(analyst, inv["id"], "access.log", _login_log([("203.0.113.30", 5, 45), ("203.0.113.31", 4, 40)]))
    analyst.post(f"/evidence/{up['evidence_id']}/process")
    got = _login_findings(analyst, inv["id"])
    assert set(got) == {"203.0.113.30", "203.0.113.31"}
    reviewed = got["203.0.113.31"]
    analyst.post(f"/investigations/{inv['id']}/findings/{reviewed['id']}/feedback", json={"verdict": "valid"}).raise_for_status()
    # the evidence is replaced by one that no longer supports either detection (as after re-processing with another parser)
    container.get().events.delete_by_evidence(inv["id"], up["evidence_id"])
    with session_scope() as s:
        s.add(Finding(display_id="F-9000", investigation_id=inv["id"], detector_id="hunt.manual", detector_version="1.0.0",
                      title="Potential manual", category="hunt.result", risk_level="medium", risk_score=50, confidence="medium",
                      dedup_key="hunt:1"))
        analysis.run_detectors(s, inv["id"])
    left = {f["display_id"]: f for f in analyst.get(f"/investigations/{inv['id']}/findings").json()}
    assert reviewed["display_id"] in left                        # an analyst judged it: kept as a record
    assert got["203.0.113.30"]["display_id"] not in left         # untouched and unsupported: gone
    assert "F-9000" in left                                      # written by a person, not by a detector
    with session_scope() as s:
        assert analysis.next_finding_id(s) == "F-9001"           # numbers are never handed out twice
