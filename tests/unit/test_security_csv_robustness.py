"""Real-export quirks keep FW/NDR meaning and are reported, never silently downgraded or guessed."""
from __future__ import annotations

import pytest

from saw.parsers.registry import parse_text
from tests.unit.test_security_csv import FW, NDR, document, row


def parsed(text):
    out = parse_text(text)
    return out, out["events"]


def test_case_and_space_variants_keep_ndr_session_and_http_meaning():
    for variant in ("User-Agent", " User-agent "):
        headers = [variant if h == "User-agent" else h for h in NDR]
        out, events = parsed(document(headers, {**row(), variant: "synthetic-client"}))
        assert out["parser"] == "ko_ndr_csv"
        ev = events[0]
        assert (ev["data_source"], ev["session_id"], ev["method"], ev["status_code"]) == ("web", "synthetic-session", "GET", 200)
    headers = ["출발지 IP" if h == "출발지IP" else h for h in FW]
    out, events = parsed(document(headers, {**row(), "출발지 IP": "192.0.2.20"}))
    assert out["parser"] == "ko_fw_csv" and events[0]["src_ip"] == "192.0.2.20"


@pytest.mark.parametrize("delimiter", ["\t", ";"])
def test_tab_and_semicolon_exports_are_recognised(delimiter):
    text = document(NDR).replace(",", delimiter)
    out, events = parsed(text)
    assert out["parser"] == "ko_ndr_csv" and events[0]["uri"] == "/sample?q=1"


def test_missing_alert_name_column_is_named_and_the_rest_is_analysed():
    from saw.parsers.registry import get_parser

    parser = get_parser("ko_ndr_csv")
    headers = [h for h in NDR if h != "공격명"]
    text = document(headers)
    assert 0.95 < parser.detect(text.splitlines()) < 0.99
    out, events = parsed(text)
    assert out["parser"] == "ko_ndr_csv" and events[0]["method"] == "GET"
    assert "공격명" not in events[0]["ext"]["security_csv"]  # absent, not an invented empty value


def test_invalid_values_are_not_used_as_values_and_are_counted():
    from saw.parsers.registry import get_parser, iter_lines

    rows = [row(), row(출발지IP="999.10.20.30", 송신바이트="-100", 목적지포트="70000", 응답값="999"),
            row(송신바이트="1,200")]
    parser = get_parser("ko_ndr_csv")
    results = [r for _, r in parser.parse(iter_lines([document(NDR, *rows).encode()]))]
    fields = [r.fields for r in results if hasattr(r, "fields")]
    assert "src_ip" not in fields[1] and "bytes_out" not in fields[1] and "dst_port" not in fields[1]
    assert "status_code" not in fields[1]
    assert fields[2]["bytes_out"] == "1200"
    invalid = [r for r in results if hasattr(r, "ext")][1]
    assert invalid.ext["출발지IP"] == "999.10.20.30" and invalid.ext["송신바이트"] == "-100"  # original kept
    text = " ".join(parser.warnings)
    for word in ("포트", "바이트", "999.x.x.x", "응답 코드"):
        assert word in text


def test_opaque_destination_labels_remain_supported():
    out, events = parsed(document(NDR))
    assert events[0]["dst_ip"] == "opaque-destination"


def test_rows_with_wrong_column_count_name_the_missing_or_extra_cells():
    good = document(FW)
    short = good.rstrip("\r\n").rsplit(",", 1)[0]
    text = good + short.splitlines()[1] + "\r\n"
    out = parse_text(text)
    assert out["failed"] == 1 and len(out["events"]) == 1


def test_json_records_with_only_an_action_key_are_not_waf_events():
    # DDoS or web records carry "action" too; calling them WAF events would change their meaning silently.
    ddos = ('{"timestamp":"2026-10-14T14:00:00+09:00","source_type":"ddos","src_ip":"198.51.100.100",'
            '"dst_ip":"10.20.1.10","dst_port":443,"action":"detected","request_count":1200}')
    out = parse_text("\n".join([ddos] * 3))
    assert out["parser"] != "waf_json" and out["events"][0]["data_source"] != "waf"
    waf = ('{"timestamp":"2026-10-14T14:00:00Z","src_ip":"198.51.100.9","uri":"/a","action":"block",'
           '"rule_id":"942100","attack_type":"SQL Injection"}')
    assert parse_text("\n".join([waf] * 3))["parser"] == "waf_json"
