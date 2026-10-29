"""Analyst-defined parsers: spec engine, wizard suggestions, preview, versioning, auto-detection, export/import."""
from __future__ import annotations

import time

import pytest

from saw.core.schemas.query import Filter
from saw.parsers.base import Failed, Parsed, Skip
from saw.parsers.custom import DefinedParser, ParserSpec, suggest
from tests.api.test_generation_reprocessing import read_events
from tests.api.test_phase5_bulk import upload

# a synthetic appliance export: Korean headers, '|' delimited, key=value details in one cell, compact timestamps
SAMPLE = "\n".join([
    "일시|공격자|피해자|포트|정책|상세",
    "20261003173847|198.51.100.7|203.0.113.10|8080|SQLi차단|method=GET;url=/login.do?id=1' or '1'='1;status=403;cookie=SID=s3cr3t",
    "20261003173850|198.51.100.7|203.0.113.10|8080|SQLi차단|method=GET;url=/search.do?q=<script>;status=403;cookie=SID=s3cr3t",
    "20261003173901|198.51.100.8|203.0.113.10|443|허용|method=POST;url=/api/customer?id=10001;status=200;cookie=",
] + [f"20261003174{i % 10}0{i % 6}|198.51.100.9|203.0.113.10|8080|허용|method=GET;url=/main.do;status=200;cookie="
     for i in range(30)]) + "\n"

SPEC = {
    "format": "delimited", "delimiter": "|", "has_header": True,
    "expand": [{"column": "상세", "pair_sep": ";", "kv_sep": "="}],
    "mapping": {"공격자": "src_ip", "피해자": "dst_ip", "포트": "dst_port"},
    "drop": ["cookie"], "time_format": "%Y%m%d%H%M%S", "timezone": "Asia/Seoul",
    "data_source": "waf", "event_type": "waf_event",
    "detect": {"header_contains": ["일시", "공격자", "상세"]},
}


def _parse(spec: dict, text: str) -> list:
    p = DefinedParser("t", 1, ParserSpec.model_validate(spec))
    return [p.parse_line(x) for x in text.splitlines() if x.strip()]


def test_spec_engine_expands_drops_maps_and_converts_time():
    res = _parse(SPEC, SAMPLE)
    assert isinstance(res[0], Skip)
    r = res[1]
    assert isinstance(r, Parsed)
    f, ext = r.fields, r.ext
    assert f["src_ip"] == "198.51.100.7" and f["dst_ip"] == "203.0.113.10" and f["dst_port"] == "8080"
    assert f["method"] == "GET" and f["uri"].startswith("/login.do") and f["status_code"] == "403"
    assert f["timestamp_raw"] == "2026-10-03T17:38:47+09:00" and f["data_source"] == "waf"
    assert "cookie" not in ext and "s3cr3t" not in str(r.fields) + str(ext)
    assert ext["정책"] == "SQLi차단" and r.redact is True


def test_regex_kv_json_formats_and_regex_timeout():
    rx = {"format": "regex", "pattern": r"^(?P<time>\S+ \S+) (?P<src_ip>\S+) -> (?P<dst_ip>\S+):(?P<dst_port>\d+)"}
    r = _parse(rx, "2026-10-03 17:38:47 10.1.1.5 -> 45.77.12.34:443")[0]
    assert r.fields["dst_ip"] == "45.77.12.34" and r.fields["timestamp_raw"] == "2026-10-03 17:38:47"
    kv = {"format": "kv", "pair_sep": "|", "kv_sep": ":", "mapping": {"sip": "src_ip"}}
    assert _parse(kv, "sip:10.0.0.1|act:deny|msg:a|b")[0].ext["msg"] == "a|b"
    js = {"format": "json", "mapping": {"client.addr": "src_ip"}}
    assert _parse(js, '{"client": {"addr": "10.0.0.9"}, "event": "x"}')[0].fields["src_ip"] == "10.0.0.9"
    evil = {"format": "regex", "pattern": r"^(?P<a>(x+x+)+)y$"}
    t = time.time()
    r = _parse(evil, "x" * 5000)[0]
    assert isinstance(r, Failed) and r.reason == "regex timeout" and time.time() - t < 2


def test_spec_validation_rejects_unsafe_or_broken_definitions():
    for bad in ({"format": "regex", "pattern": "no groups"}, {"format": "delimited", "has_header": False},
                {"format": "kv", "mapping": {"a": "not_a_field"}}, {"format": "kv", "data_source": "anything"},
                {"format": "kv", "timezone": "Mars/Base"}):
        with pytest.raises(ValueError):
            ParserSpec.model_validate(bad)


def test_suggest_builds_a_starting_spec_from_the_sample():
    s = suggest(SAMPLE.splitlines())
    spec = s["spec"]
    assert spec["format"] == "delimited" and spec["delimiter"] == "|" and spec["has_header"] is True
    assert spec["mapping"]["일시"] == "timestamp_raw"
    assert spec["expand"] == [{"column": "상세", "pair_sep": ";", "kv_sep": "="}]
    assert spec["detect"]["header_contains"]
    assert s["columns"][:3] == ["일시", "공격자", "피해자"]


def test_library_flow_draft_share_review_autodetect_export_import(analyst, senior):
    pv = analyst.post("/parser-library/preview", json={"spec": SPEC, "sample": SAMPLE}).json()
    assert pv["auto_detect"] is True and pv["coverage"]["events"] == 33 and pv["coverage"]["failed_lines"] == 0
    assert pv["rows"][0]["fields"]["src_ip"] == "198.51.100.7" and pv["rows"][0]["fields"]["status_code"] == 403
    v1 = analyst.post("/parser-library", json={"name": "웹방화벽 X", "slug": "waf-x", "spec": SPEC}).json()
    assert v1["status"] == "draft" and v1["pinned_id"] == "u:waf-x@1" and v1["version"] == 1
    # a draft is private: the author can pick it, others cannot see it, and it is never auto-detected
    assert any(p["id"] == "u:waf-x@1" for p in analyst.get("/parsers").json())
    assert not any(p.get("user") for p in senior.get("/parsers").json())
    assert senior.get("/parser-library").json()["parsers"] == []
    inv = analyst.post("/investigations", json={"title": "장비 로그"}).json()
    up = upload(analyst, inv["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    j = analyst.get(f"/jobs/{analyst.post(f'/evidence/{up['evidence_id']}/process').json()['id']}").json()
    assert j["files"][0]["parser_id"] != "u:waf-x"

    # share request -> the author cannot approve (4-eyes) -> another analyst approves -> auto-detected for everyone
    assert analyst.post("/parser-library/waf-x/versions/1/share").json()["status"] == "pending"
    assert analyst.post("/parser-library/waf-x/versions/1/review", json={"approve": True}).status_code == 403
    pending = senior.get("/parser-library").json()["parsers"][0]
    assert pending["status"] == "pending" and pending["can_review"] is True
    ok = senior.post("/parser-library/waf-x/versions/1/review", json={"approve": True, "note": "형식 확인"}).json()
    assert ok["status"] == "active" and ok["reviewed_by"] == "senior1"
    assert any(p["id"] == "u:waf-x" for p in senior.get("/parsers").json())

    inv2 = senior.post("/investigations", json={"title": "공용 파서"}).json()
    up2 = upload(senior, inv2["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    j2 = senior.get(f"/jobs/{senior.post(f'/evidence/{up2['evidence_id']}/process').json()['id']}").json()
    assert j2["state"] == "COMPLETED" and j2["files"][0]["parser_id"] == "u:waf-x@1", j2
    ev = read_events("senior1").search(inv2["id"], [Filter(field="data_source", value="waf")], limit=1)["events"][0]
    assert ev["parser"] == "u:waf-x@1" and ev["parser_version"] == "1" and ev["timestamp"] == "2026-10-03T08:38:47.000Z"
    fs = {f["category"] for f in senior.get(f"/investigations/{inv2['id']}/findings").json()}
    assert "web.injection_like" in fs, fs

    # a new version stays a draft until reviewed; the approved one keeps working meanwhile
    v2 = analyst.post("/parser-library", json={"name": "웹방화벽 X", "slug": "waf-x", "spec": {**SPEC, "mask": ["정책"]},
                                               "note": "정책명 가림"}).json()
    assert v2["version"] == 2 and v2["status"] == "draft"
    analyst.post("/parser-library/waf-x/versions/2/share")
    rej = senior.post("/parser-library/waf-x/versions/2/review", json={"approve": False, "note": "가림 범위 재검토"}).json()
    assert rej["status"] == "draft" and rej["review_note"] == "가림 범위 재검토"
    hist = analyst.get("/parser-library/waf-x").json()
    assert [(h["version"], h["status"]) for h in hist] == [(2, "draft"), (1, "active")]
    doc = senior.get("/parser-library/waf-x/export").json()
    assert doc["kind"] == "saw.parser-definition" and doc["version"] == 1 and len(doc["spec_digest"]) == 64
    imp = senior.post("/parser-library/import", json=doc).json()
    assert imp["version"] == 3 and imp["status"] == "draft" and "imported" in imp["note"]

    # turning the shared parser off affects everyone: approver permission
    assert analyst.post("/parser-library/waf-x/disable").status_code == 403
    assert senior.post("/parser-library/waf-x/disable").json()["status"] == "disabled"
    inv3 = analyst.post("/investigations", json={"title": "비활성"}).json()
    up3 = upload(analyst, inv3["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    j3 = analyst.post(f"/evidence/{up3['evidence_id']}/process").json()
    assert analyst.get(f"/jobs/{j3['id']}").json()["files"][0]["parser_id"] != "u:waf-x"


def test_reprocess_with_own_draft_and_file_sample(analyst, senior):
    inv = analyst.post("/investigations", json={"title": "재처리"}).json()
    no_detect = {**SPEC, "detect": {}}
    up = upload(analyst, inv["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    job = analyst.post(f"/evidence/{up['evidence_id']}/process").json()
    first = analyst.get(f"/jobs/{job['id']}").json()["files"][0]
    sample = analyst.get(f"/evidence/{up['evidence_id']}/files/{first['id']}/sample?lines=3").json()
    assert sample["lines"][0].startswith("일시|공격자") and "cookie=●●●●" in sample["lines"][1]
    d = analyst.post("/parser-library", json={"name": "수동 전용", "slug": "manual-x", "spec": no_detect}).json()
    r = analyst.post(f"/evidence/{up['evidence_id']}/files/{first['id']}/parser", json={"parser_id": d["pinned_id"]})
    assert r.status_code == 200, r.text
    f = analyst.get(f"/jobs/{job['id']}").json()["files"][0]
    assert f["parser_id"] == "u:manual-x@1" and f["status"] == "done" and f["events_parsed"] == 33
    # someone else's draft cannot be used
    inv2 = senior.post("/investigations", json={"title": "남의 초안"}).json()
    up2 = upload(senior, inv2["id"], "waf_x.txt", SAMPLE.encode("utf-8"), kind="auto")
    job2 = senior.post(f"/evidence/{up2['evidence_id']}/process").json()
    f2 = senior.get(f"/jobs/{job2['id']}").json()["files"][0]
    r2 = senior.post(f"/evidence/{up2['evidence_id']}/files/{f2['id']}/parser", json={"parser_id": "u:manual-x@1"})
    assert r2.status_code == 403


def test_viewer_cannot_save_parsers(app, analyst):
    from tests.conftest import Api, make_user

    make_user("viewer9", ["viewer"])
    v = Api(app, "viewer9")
    assert v.post("/parser-library", json={"name": "x", "spec": SPEC}).status_code == 403
