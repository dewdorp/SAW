"""Canonical and device time precision must reflect the actual selected field."""
import pytest

from tests.unit.test_connection_observation import context
from saw.parsers.base import Parsed, RawLine
from saw.parsers.registry import to_ces
from saw.parsers.structured import CsvParser
from saw.behavior.calculator import _row

def test_canonical_time_does_not_retain_other_field_precision():
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "observed_at"
    ctx["profile"]["time"].update(timezone="UTC", precision="minute")
    text = "timestamp,observed_at,src_ip,dst_ip,dst_port,uri,user_agent\n2026-10-20 09:00:59,2026-10-20 10:00,10.0.0.1,192.0.2.1,443,/synthetic,synthetic"
    parser = CsvParser()
    rows = [to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                   source_file="synthetic.csv", object_key="synthetic", assumed_tz="UTC", context_snapshot=ctx)
            for raw, result in parser.parse(iter(RawLine(s, n*100, n+1) for n,s in enumerate(text.splitlines())))
            if isinstance(result, Parsed)]
    row = rows[0]
    assert row["timestamp"] == "2026-10-20T10:00:00.000Z"
    assert _row(row).precision == "unknown", "minute-only mapped time must not inherit seconds from a different field"


@pytest.mark.parametrize("raw,declared,expected", [
    ("2026-10-20 10:00", "seconds", "unknown"),
    ("2026-10-20 10:00:00.123", "seconds", "seconds"),
    ("2026-10-20 10:00:00", "milliseconds", "seconds"),
    ("2026-10-20 10:00:00.123", "ms", "subseconds"),
    ("2026-10-20 10:00:00", "unknown", "unknown"),
    ("2026-10-20 10:00:00", "s", "seconds"),
])
def test_effective_precision_is_bounded_by_field_and_profile(raw, declared, expected):
    from saw.behavior.observation import bounded_timestamp_precision
    assert bounded_timestamp_precision(raw, declared) == expected


def test_fw_minute_only_field_cannot_make_seconds_scan_even_when_profile_claims_seconds():
    from tests.unit.test_connection_observation import events
    from saw.observation.firewall import analyze_firewall
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "observed_at"
    ctx["profile"]["time"].update(timezone="UTC", precision="seconds")
    rows = events([f"2026-10-20T00:00:0{i}Z,10.0.0.1,192.0.2.{i+1},443,S{i},session_end,deny,0,0,"
                   for i in range(6)])
    for row in rows:
        row["ext"]["csv"]["observed_at"] = "2026-10-20 10:00"
    result = analyze_firewall(rows, context_snapshot=ctx)
    assert result["counts"]["records"] == 6
    assert result["counts"]["deny_attempts"] == 6
    assert not result["candidates"]
