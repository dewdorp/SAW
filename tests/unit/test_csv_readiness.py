"""Readiness counts never invent semantics or expose source values."""
from copy import deepcopy

from saw.detectors.csv_readiness import inspect_events


def event(**changes):
    row = {"parser": "ko_ndr_csv", "timestamp": "2026-10-01T00:00:00+09:00",
           "timestamp_quality": "assumed_timezone", "src_ip": "192.0.2.1",
           "dst_ip": "익명-목적지-A", "method": "GET", "uri": "/status",
           "status_code": 200, "session_id": "SYNTHETIC-1",
           "ext": {"security_csv": {"csv_format": "ndr", "장비IP": "192.0.2.250", "공격명": "synthetic label"}}}
    row.update(changes)
    return row


def test_opaque_destinations_and_labels_do_not_prove_identity_or_truth():
    result = inspect_events(iter([event(), event(method=None, uri=None, status_code=None)]))
    row = result["formats"][0]
    assert result["schema"] == "csv-readiness/1"
    assert row["records"] == 2 and row["format"] == "ndr"
    assert row["fields"]["http_request"] == 1
    assert row["fields"]["http_response"] == 1
    assert row["fields"]["opaque_destination"] == 2
    assert row["fields"]["verified_context"] == 0
    assert row["fields"]["verified_counters"] == 0
    assert row["fields"]["reported_alert"] == 2
    assert "opaque_destination" in row["limitations"]
    assert "reported_alert_is_not_truth" in row["limitations"]
    assert not any(x in str(result) for x in ("192.0.2.250", "synthetic label", "익명-목적지-A", "/status"))


def test_multiple_devices_remain_separate_unverified_sources():
    rows = [event(), event()]
    rows[1]["ext"]["security_csv"]["장비IP"] = "192.0.2.251"
    result = inspect_events(iter(rows))["formats"][0]
    assert result["source_devices"] == 2
    assert "multiple_source_devices" in result["limitations"]


def test_trusted_parser_identity_and_missing_fields():
    rows = [event(parser="csv"), event(parser="ko_fw_csv", timestamp=None, src_ip=None,
                                       dst_ip=None, method=None, uri=None, session_id=None)]
    result = inspect_events(iter(rows))
    assert result["counts"]["records"] == 1
    row = result["formats"][0]
    assert row["format"] == "fw"
    assert row["fields"]["timestamp"] == 0
    assert row["fields"]["source_ip"] == 0
    assert row["fields"]["session_id"] == 0
    assert "missing_session_id" in row["limitations"]


def test_bounded_iteration_closes_and_reports_partial():
    closed = []
    def rows():
        try:
            for _ in range(4):
                yield event()
        finally:
            closed.append(True)
    result = inspect_events(rows(), max_records=2)
    assert result["status"] == "partial"
    assert result["counts"]["records"] == 2
    assert result["limits"]["coverage_complete"] is False
    assert closed == [True]


def test_cancellation_never_returns_complete():
    result = inspect_events(iter([event()]), cancelled=lambda: True)
    assert result["status"] == "cancelled"
    assert result["limits"]["coverage_complete"] is False


def test_empty_and_exact_limit_are_complete_not_a_detection_verdict():
    empty = inspect_events(iter([]))
    assert empty["status"] == "not_applicable" and empty["formats"] == []
    full = inspect_events(iter([event(), event()]), max_records=2)
    assert full["status"] == "complete" and full["limits"]["coverage_complete"] is True
    assert "verdict" not in full


def test_only_producer_observations_count_verified_semantics():
    row = event()
    row["ext"]["observation"] = {"producer": "saw", "version": "connection-observation/1",
        "context": {"resolved": True}, "counters": {
            "src_to_dst_bytes": {"state": "observed"}, "dst_to_src_bytes": {"state": "observed"}},
        "time_profile": {"verified": True}, "record_kind": "session_end"}
    result = inspect_events(iter([row]))["formats"][0]
    assert result["fields"]["verified_context"] == 1
    assert result["fields"]["verified_counters"] == 1
    assert result["fields"]["verified_time"] == 1
    assert result["fields"]["record_kind"] == 1
    bad = deepcopy(row)
    bad["ext"]["observation"]["producer"] = "uploaded"
    assert inspect_events(iter([bad]))["formats"][0]["fields"]["verified_context"] == 0


def test_empty_source_markers_are_not_observed_identifiers():
    row = event(session_id=" ")
    row["ext"]["security_csv"].update({"장비IP": "-", "공격명": "(empty)"})
    result = inspect_events(iter([row]))["formats"][0]
    assert result["source_devices"] == 0
    assert result["fields"]["session_id"] == result["fields"]["reported_alert"] == 0


def test_http_summaries_are_separate_from_full_request_line_not_wire_proof():
    full, summary = event(), event()
    full["ext"]["security_csv"]["요청헤더"] = "GET /status HTTP/1.1"
    summary["ext"]["security_csv"]["요청헤더"] = " GET /status "
    fields = inspect_events(iter([full, summary]))["formats"][0]["fields"]
    assert fields["http_request"] == 2
    assert fields["http_request_line"] == 1 and fields["http_request_summary"] == 1
