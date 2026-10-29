"""TXT/CSV ingest: NDR meta-search export, Korean/Excel CSV (CP949, BOM, padded rows), time formats, line reader."""
from __future__ import annotations

from saw.analyzers.log.normalize import parse_time
from saw.core.security.masking import mask_text
from saw.devtools.sample_data import NDR_HEADER, scenario_kr_firewall_csv, scenario_ndr_meta_csv
from saw.parsers.base import Parsed, RawLine, Skip
from saw.parsers.ndr import NdrMetaCsvParser, parse_meta
from saw.parsers.registry import detect, get_parser, iter_lines, sniff_encoding, to_ces
from saw.parsers.structured import CsvParser, infer_source


def _events(parser, text: str, encoding: str = "utf-8") -> list[dict]:
    raw = text.encode(encoding) if isinstance(text, str) else text
    lines = (rl for rl in iter_lines([raw[i:i + 4096] for i in range(0, len(raw), 4096)], encoding) if rl.text.strip())
    return [to_ces(parser, rl, r, investigation_id="i", evidence_id="e", file_id="f", source_file="s", object_key="k",
                   assumed_tz="Asia/Seoul") for rl, r in parser.parse(lines) if isinstance(r, Parsed)]


def test_meta_kv_keeps_semicolons_inside_values_and_takes_last_method():
    m = parse_meta("type=http_request;method=request;hostname=a.example.com;method=POST;path=/x.do;"
                   "content_type=application/x-www-form-urlencoded; charset=utf-8;accept_language=ko-KR,ko;q=0.9;"
                   "xfwd=;cookie=JSESSIONID=abc; WMONID=z; path=/")
    assert m["method"] == "POST" and m["path"] == "/x.do"
    assert m["content_type"] == "application/x-www-form-urlencoded; charset=utf-8"
    assert m["accept_language"] == "ko-KR,ko;q=0.9"
    assert m["cookie"] == "JSESSIONID=abc; WMONID=z; path=/"


def test_ndr_export_is_auto_detected_and_requests_pair_with_responses():
    text = scenario_ndr_meta_csv(normal=40)
    sample = text.splitlines()[:200]
    det = detect(sample)
    assert det.parser_id == "ndr_meta_csv" and det.confidence >= 0.95
    evs = _events(NdrMetaCsvParser(), "﻿" + text)
    web = [e for e in evs if e["data_source"] == "web"]
    conn = [e for e in evs if e["data_source"] == "zeek_conn"]
    n_req = text.count("type=http_request")
    assert len(web) == n_req and len(conn) == text.count("type=traffic")
    assert all(e.get("status_code") for e in web), "every request got its response status"
    sqli = next(e for e in web if e["uri"].startswith("/login.do"))
    assert sqli["method"] == "GET" and sqli["hostname"] == "mbank.example.com" and sqli["status_code"] == 404
    assert sqli["src_ip"] == "45.77.12.34" and sqli["dst_port"] == 8080 and sqli["timestamp_quality"] == "exact"
    assert "pattern:sqli" in sqli.get("tags", [])
    assert sqli["ua_class"] in ("scanner", "script")
    walk = [e for e in web if e["uri"].startswith("/api/customer")]
    assert walk[0]["uri_template"] == "/api/customer?id=<NUM>"
    c = conn[0]
    assert c["protocol"] == "tcp" and c["bytes_out"] == 700 and c["bytes_in"] > 0


def test_ndr_cookie_values_are_never_stored():
    evs = _events(NdrMetaCsvParser(), scenario_ndr_meta_csv(normal=5))
    req = next(e for e in evs if e["data_source"] == "web")
    assert req["ext"]["ndr"]["cookie_names"] == ["JSESSIONID", "WMONID"]
    assert req["raw_redacted"] is True and "JSESSIONID=" not in req["raw_event"] and "cookie=●●●●" in req["raw_event"]
    assert "JSESSIONID=" not in str(req)


def test_ndr_row_spilling_into_trailing_columns_and_unanswered_requests():
    head = NDR_HEADER
    base = ("2026-10-03 17:38,198.51.100.7,50000,203.0.113.10,8080,6,Web,HTTP,HTTP,KR,KR,4,1,5,1,meta,filtered=none,"
            "time=2026-10-03 17:38:47+0900,seq=1,num_of_meta=1,transaction_id=0,server_id=1,stream=1,flow_rowid=77,")
    req = base + "type=http_request;method=request;hostname=h.example.com;method=GET;path=/a;ua=x;accept_language=ko-KR,ko;q=0.9;xfwd=;cookie=" + "," * 18
    lone = base.replace("flow_rowid=77", "flow_rowid=78") + "type=http_response;method=response;ret_code=500;num_of_res=1" + "," * 19
    evs = _events(NdrMetaCsvParser(), f"{head}\n{req}\n{lone}\n")
    web = next(e for e in evs if e["data_source"] == "web")
    assert web["uri"] == "/a" and "status_code" not in web  # flushed at end of file without a response
    assert web["ext"]["ndr"]["accept_language"] == "ko-KR,ko;q=0.9"
    orphan = next(e for e in evs if e["data_source"] == "ndr_http")
    assert orphan["status_code"] == 500 and orphan["event_type"] == "http_response"


def test_korean_cp949_firewall_csv_maps_columns_and_becomes_network_flows():
    raw = scenario_kr_firewall_csv()
    assert sniff_encoding(raw[:65536]) == "cp949"
    lines = [rl.text for rl in iter_lines([raw], "cp949")][:200]
    det = detect(lines)
    assert det.parser_id == "csv" and det.confidence >= 0.8, det
    evs = _events(get_parser("csv"), raw, "cp949")
    assert len(evs) == 449 and all(e["data_source"] == "connection" for e in evs)
    e = evs[-1]
    assert e["src_ip"] == "10.10.5.20" and e["dst_ip"] == "45.77.12.34" and e["dst_port"] == 8443
    assert e["bytes_out"] == 3400000000 and e["timestamp_quality"] == "assumed_tz"
    assert e["ext"]["csv"]["정책명"] == "업무망-인터넷"


def test_generic_csv_tolerates_bom_padding_and_infers_web():
    text = ("﻿Source IP,Request URL,Method,HTTP Status,Event Time,,\n"
            "198.51.100.9,/login?id=1%27%20or%201=1--,GET,200,2026/10/03 17:38:47,,\n"
            "198.51.100.9,/a,GET,404,2026.10.03 오후 5:38:48\n")
    evs = _events(CsvParser(), text)
    assert [e["data_source"] for e in evs] == ["web", "web"]
    assert evs[0]["uri"].startswith("/login") and evs[0]["status_code"] == 200 and "pattern:sqli" in evs[0]["tags"]
    assert evs[1]["timestamp"] == "2026-10-03T08:38:48.000Z"
    assert infer_source(["src", "dst", "dport"]) == ("connection", "conn")
    assert infer_source(["시간", "메시지"]) == ("custom", "log")
    assert infer_source(["출발지 IP", "요청URL", "탐지명"]) == ("waf", "waf_event")


def test_local_time_formats():
    assert parse_time("2026/10/03 17:38:47") == ("2026-10-03T08:38:47.000Z", "assumed_tz")
    assert parse_time("2026.10.3. 오후 5:38:47")[0] == "2026-10-03T08:38:47.000Z"
    assert parse_time("2026-10-03 오전 12:05:00")[0] == "2026-10-02T15:05:00.000Z"
    assert parse_time("20261003173847")[0] == "2026-10-03T08:38:47.000Z"
    assert parse_time("2026/10/03 08:38:47Z") == ("2026-10-03T08:38:47.000Z", "exact")
    assert parse_time("2026-13-40 10:00:00") == (None, "invalid")


def test_line_reader_offsets_across_chunks_and_bom():
    data = "﻿a,b\r\nccc\n\ndd".encode()
    chunks = [data[i:i + 3] for i in range(0, len(data), 3)]
    got = list(iter_lines(chunks))
    assert [r.text for r in got] == ["a,b", "ccc", "", "dd"]
    assert [r.offset for r in got] == [0, 8, 12, 13] and [r.line_no for r in got] == [1, 2, 3, 4]
    assert sniff_encoding("한글".encode()) == "utf-8" and sniff_encoding(b"\xef\xbb\xbfx") == "utf-8"


def test_cookie_masking_in_display_text():
    assert mask_text("x;cookie=JSESSIONID=abc; WMONID=1,,").text == "x;cookie=●●●●[len=24],,"
    assert "sid=123" not in mask_text("GET / HTTP/1.1\nCookie: sid=123\n").text
    assert mask_text("cookie_consent banner").text == "cookie_consent banner"


def test_ndr_parse_line_still_works_for_paste():
    p = NdrMetaCsvParser()
    assert isinstance(p.parse_line(NDR_HEADER), Skip)
    line = scenario_ndr_meta_csv(normal=1).splitlines()[1]
    r = p.parse_line(line)
    assert isinstance(r, Parsed) and r.fields["uri"] and "status_code" not in r.fields
    assert isinstance(RawLine(line, 0, 1), RawLine)


def test_csv_records_with_line_breaks_inside_quotes():
    text = ('time,src_ip,url,status,message\n'
            '2026-10-03 09:00:00,198.51.100.1,/a,200,"first line\nsecond line\nthird line"\n'
            '2026-10-03 09:00:01,198.51.100.2,/b,404,plain\n')
    evs = _events(CsvParser(), text)
    assert [e["uri"] for e in evs] == ["/a", "/b"]
    assert evs[0]["ext"]["csv"]["message"] == "first line\nsecond line\nthird line"
    assert evs[0]["raw_ref"]["line_no"] == 2 and evs[1]["raw_ref"]["line_no"] == 5
    first = text.encode().index(b"2026-10-03 09:00:00")
    assert evs[0]["raw_ref"]["offset"] == first
    assert evs[0]["raw_ref"]["length"] == text.encode().index(b"\n2026-10-03 09:00:01") - first


def test_csv_unterminated_quote_fails_without_swallowing_the_file():
    from saw.parsers.structured import CSV_MAX_RECORD_LINES

    rows = ['time,src_ip,url', '2026-10-03 09:00:00,198.51.100.1,"/broken']
    rows += [f"2026-10-03 09:00:{i:02d},198.51.100.3,/x{i}" for i in range(CSV_MAX_RECORD_LINES + 5)]
    p = CsvParser()
    lines = [RawLine(t, i * 100, i + 1) for i, t in enumerate(rows)]
    out = list(p.parse(iter(lines)))
    assert out[1][1].reason == "unterminated quoted field"
    parsed = [r for _, r in out if isinstance(r, Parsed)]
    assert len(parsed) == CSV_MAX_RECORD_LINES + 5  # every ordinary row after the stray quote is still read
