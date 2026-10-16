"""Producer-owned field coverage cannot be supplied through an uploaded ext object."""
from __future__ import annotations

import json
import pytest

from saw.analyzers.log.normalize import finalize
from saw.parsers.registry import parse_text


def observation(text, parser="json_lines"):
    ev = parse_text(text, parser_id=parser)["events"][0]
    assert "saw_observation" in ev.get("ext", {}), "producer field coverage is missing"
    return ev["ext"]["saw_observation"]


@pytest.mark.parametrize("value,expected", [("Browser", "present"), ("-", "recorded_empty"), ("", "recorded_empty"), (None, "not_collected")])
def test_json_observation_distinguishes_ua_value_empty_and_uncollected(value, expected):
    obs = observation(json.dumps({"time": "2026-10-16T00:00:00Z", "user_agent": value}))
    assert obs["user_agent"] == expected and obs["timestamp_precision"] == "seconds"


def test_missing_ua_and_forged_ext_cannot_claim_logged_empty():
    obs = observation(json.dumps({"time": "2026-10-16T00:00:00Z",
        "ext": {"saw_observation": {"user_agent": "recorded_empty", "timestamp_precision": "subseconds"}}}))
    assert obs["user_agent"] == "not_collected" and obs["timestamp_precision"] == "seconds"
    ev = finalize({"timestamp_raw": "2026-10-16T00:00:00Z", "ext": {"saw_observation": {"user_agent": "present"}}})
    assert ev["ext"]["saw_observation"]["user_agent"] == "not_collected"


@pytest.mark.parametrize("time,precision", [("2026-10-16T00:00:00.000Z", "subseconds"),
    ("2026-10-16T00:00:00Z", "seconds"), ("1792108800", "seconds"), ("1792108800000", "subseconds")])
def test_precision_is_recorded_before_timestamp_normalization(time, precision):
    assert observation(json.dumps({"time": time}))["timestamp_precision"] == precision


def test_common_combined_and_iis_ua_states():
    base = '192.0.2.1 - - [16/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 10'
    assert observation(base, "nginx_combined")["user_agent"] == "not_collected"
    assert observation(base + ' "-" "-"', "nginx_combined")["user_agent"] == "recorded_empty"
    iis = "#Fields: date time c-ip cs-method cs-uri-stem cs(User-Agent)\n2026-10-16 00:00:00 192.0.2.1 GET / -"
    assert observation(iis, "iis_w3c")["user_agent"] == "recorded_empty"


def test_csv_and_network_empty_ua_observation():
    assert observation("time,user_agent,uri\n2026-10-16T00:00:00Z,,/", "csv")["user_agent"] == "recorded_empty"
    zeek = json.dumps({"_path": "http", "ts": 1792108800, "id.orig_h": "192.0.2.1", "user_agent": "-", "uri": "/"})
    assert observation(zeek, "zeek_json")["user_agent"] == "recorded_empty"
    suricata = json.dumps({"event_type": "http", "timestamp": "2026-10-16T00:00:00Z", "http": {"http_user_agent": ""}})
    assert observation(suricata, "suricata_eve")["user_agent"] == "recorded_empty"

def test_custom_timestamp_format_keeps_explicit_zero_subsecond_precision():
    from saw.parsers.base import RawLine
    from saw.parsers.custom import DefinedParser, ParserSpec
    from saw.parsers.registry import to_ces
    parser = DefinedParser("synthetic", 1, ParserSpec(format="json", mapping={"t": "timestamp_raw"},
        time_format="%Y%m%d%H%M%S%f", timezone="UTC"))
    text = '{"t":"20261016000000000"}'
    result = parser.parse_line(text)
    ev = to_ces(parser, RawLine(text, 0, 1), result, investigation_id="i", evidence_id="e",
                file_id="f", source_file="s", object_key="k", assumed_tz="UTC")
    assert ev["ext"]["saw_observation"]["timestamp_precision"] == "subseconds"
