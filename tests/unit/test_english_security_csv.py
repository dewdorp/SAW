"""English NDR HTTP and firewall exports keep their meaning: targets, request target, bytes and time."""
import csv
import io
import json

from saw.parsers.registry import parse_text

NDR = ["event_time", "_site", "app", "_schema", "protocol", "src_ip", "src_port", "src_country", "dest_ip", "dest_port",
       "dest_country", "_device_ip", "_device_name", "method", "host", "path", "query", "user_agent", "referer",
       "req_cookie", "uuid", "status", "sc_bytes", "cs_bytes"]
FW = ["_time", "_device_ip", "_device_name", "action", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
      "tcp_flag", "duration", "sent_bytes", "rcvd_bytes"]


def ndr_row(**kw):
    row = {"event_time": "2026-10-13T10:00:01+09:00", "_site": "site-a", "app": "HTTP", "_schema": "ndr-http-1",
           "protocol": "TCP", "src_ip": "198.51.100.23", "src_port": "51234", "src_country": "NL", "dest_ip": "10.20.1.10",
           "dest_port": "443", "dest_country": "KR", "_device_ip": "192.0.2.2", "_device_name": "ndr-01", "method": "GET",
           "host": "portal.example.test", "path": "/search", "query": "q=synthetic&lang=ko", "user_agent": "Mozilla/5.0",
           "referer": "https://portal.example.test/", "req_cookie": "sid=a1; theme=dark", "uuid": "u-0001",
           "status": "200", "sc_bytes": "5120", "cs_bytes": "420"}
    return {**row, **kw}


def fw_row(**kw):
    row = {"_time": "2026-10-13 10:00:02", "_device_ip": "192.0.2.1", "_device_name": "fw-01", "action": "allow",
           "src_ip": "10.20.5.11", "src_port": "50000", "dst_ip": "203.0.113.66", "dst_port": "443", "protocol": "TCP",
           "tcp_flag": "SA", "duration": "30", "sent_bytes": "1200", "rcvd_bytes": "64000"}
    return {**row, **kw}


def doc(headers, rows, delimiter=",", header_text=None):
    out = io.StringIO(newline="")
    w = csv.writer(out, delimiter=delimiter, lineterminator="\n")
    if header_text is None:
        w.writerow(headers)
    else:
        out.write(header_text + "\n")
    for r in rows:
        w.writerow([r.get(h.strip(), "") for h in headers])
    return out.getvalue()


def _warnings(parser_id, text):
    from saw.parsers.base import RawLine
    from saw.parsers.registry import get_parser

    parser = get_parser(parser_id)
    list(parser.parse(iter(RawLine(s, n * 100, n + 1) for n, s in enumerate(text.splitlines()))))
    return parser.warnings


def test_exact_ndr_header_maps_destination_request_target_and_byte_candidates():
    out = parse_text(doc(NDR, [ndr_row()]))
    assert out["parser"] == "en_ndr_http_csv" and out["failed"] == 0
    e = out["events"][0]
    assert (e["dst_ip"], e["dst_port"], e["src_port"]) == ("10.20.1.10", 443, 51234)
    assert e["data_source"] == "web" and e["method"] == "GET" and e["hostname"] == "portal.example.test"
    assert e["uri"] == "/search?q=synthetic&lang=ko" and e["url_path"] == "/search" and e["url_query"] == "q=synthetic&lang=ko"
    assert e.get("domain") is None, "an HTTP query is never a DNS domain"
    assert e["status_code"] == 200 and e["timestamp"] == "2026-10-13T01:00:01.000Z"
    assert (e["bytes_out"], e["bytes_in"]) == (420, 5120)  # request / response candidates
    assert any("cs_bytes" in w for w in _warnings("en_ndr_http_csv", doc(NDR, [ndr_row()])))
    raw = e["ext"]["security_csv"]
    assert raw["uuid"] == "u-0001" and e.get("session_id") is None  # an id of unknown scope is not a session
    assert raw["req_cookie_names"] == ["sid", "theme"] and "a1" not in json.dumps(e)  # cookie values stay in the file


def test_header_variants_order_spaces_bom_marker_and_delimiters():
    shuffled = list(reversed(NDR))
    spaced = [f" {h} " if i % 3 == 0 else h for i, h in enumerate(NDR)]
    for text in (doc(shuffled, [ndr_row()]),
                 "﻿" + doc(NDR, [ndr_row()]),
                 doc(spaced, [ndr_row()], header_text=",".join(spaced)),
                 doc(NDR, [ndr_row()], header_text="| # fields " + ",".join(NDR).replace("referer,req_cookie,uuid,status", "referer, req_cookie, uuid, status")),
                 doc(NDR, [ndr_row()], delimiter="\t")):
        out = parse_text(text)
        assert out["parser"] == "en_ndr_http_csv", out["candidates"]
        e = out["events"][0]
        assert e["timestamp"] == "2026-10-13T01:00:01.000Z" and e["dst_ip"] == "10.20.1.10" and e["url_query"] == "q=synthetic&lang=ko"
    # Text before the header that is not the field-list marker is not silently cut off.
    other = parse_text(doc(NDR, [ndr_row()], header_text="note " + ",".join(NDR)))
    assert other["parser"] != "en_ndr_http_csv" or other["events"][0].get("timestamp") is None


def test_request_target_edge_cases_and_isolated_bad_rows():
    rows = [ndr_row(query=""), ndr_row(path="/a?x=1", query="y=2"), ndr_row(path="/s", query="k=1&k=2&q=%27%20OR%201%3D1"),
            ndr_row(dest_port="70000"), ndr_row(src_ip="10.0.0.1")]
    text = doc(NDR, rows)
    lines = text.splitlines()
    lines.insert(4, "2026-10-13T10:00:01+09:00,only,three")  # a row with a known boundary but missing cells
    out = parse_text("\n".join(lines))
    assert out["parser"] == "en_ndr_http_csv" and out["failed"] == 1 and len(out["events"]) == 5
    a, b, c, d, e = out["events"]
    assert a["uri"] == "/search" and a.get("url_query") is None
    assert b["uri"] == "/a?x=1&y=2"
    assert c["params"]["k"] and "pattern:sqli" in (c.get("tags") or [])
    assert d.get("dst_port") is None and d["dst_ip"] == "10.20.1.10"  # the bad port is not used, the row is kept
    assert e["src_ip"] == "10.0.0.1"


def test_firewall_header_maps_action_ports_and_direction_candidates():
    out = parse_text(doc(FW, [fw_row(), fw_row(action="deny", rcvd_bytes="")]))
    assert out["parser"] == "en_fw_csv" and out["failed"] == 0
    first, second = out["events"]
    assert first["data_source"] == "connection" and first["enforcement_action"] == "allowed"
    assert (first["bytes_out"], first["bytes_in"]) == (1200, 64000)
    assert second["enforcement_action"] == "blocked" and second.get("bytes_in") is None
    raw = first["ext"]["security_csv"]
    assert raw["duration"] == "30" and raw["tcp_flag"] == "SA"  # unit and flag meaning stay unconfirmed, kept raw
    assert any("sent_bytes" in w for w in _warnings("en_fw_csv", doc(FW, [fw_row()])))


def test_jsonl_with_the_same_fields_and_dns_query_keeps_working():
    record = {k: ndr_row()[k] for k in NDR}
    out = parse_text(json.dumps(record) + "\n" + json.dumps(record))
    e = out["events"][0]
    assert e["data_source"] == "web" and e["dst_ip"] == "10.20.1.10" and e["url_query"] == "q=synthetic&lang=ko"
    assert e.get("domain") is None
    dns = {"ts": "2026-10-13T01:00:00Z", "src_ip": "10.20.5.11", "dst_ip": "10.20.0.53", "query": "portal.example.test", "qtype": "A"}
    dns_out = parse_text(json.dumps(dns) + "\n" + json.dumps(dns))
    assert dns_out["events"][0]["domain"] == "portal.example.test"
