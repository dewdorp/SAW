"""Synthetic parser-to-observation and FW session semantics regressions."""
import importlib.util

import pytest

from saw.parsers.base import Parsed, RawLine
from saw.parsers.registry import to_ces
from saw.parsers.structured import CsvParser


def parsed_csv(text):
    parser = CsvParser()
    return [to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                   source_file="synthetic.csv", object_key="synthetic", assumed_tz="UTC")
            for raw, result in parser.parse(iter(RawLine(s, n * 100, n + 1)
                                                 for n, s in enumerate(text.splitlines())))
            if isinstance(result, Parsed)]


def api():
    assert importlib.util.find_spec("saw.observation") is not None, "common observation package missing"
    from saw.observation.connection import connection_observation
    from saw.observation.firewall import analyze_firewall
    return connection_observation, analyze_firewall


def context(mode="cumulative"):
    return {"schema_version": 1, "subject": {"org_unit_id": "A", "status": "verified"},
            "observer": {"device_id": "FW-1", "device_profile_version_id": "p1",
                         "network": "net", "virtual_domain": "root"},
            "profile": {"source_fields": {"record_kind": "kind", "session_id": "session_id",
                "start_time": "session_start", "action": "action", "src_bytes": "sent", "dst_bytes": "received"},
                "measurement_profile": {"counter_semantics": mode, "direction": "src_to_dst",
                    "unit": "bytes", "verified": True, "basis": "synthetic dictionary"},
                "time": {"verified": True, "role": "occurred", "precision": "seconds"}, "action_verified": True, "action_map": {"allow": "allowed", "deny": "blocked"}},
            "collection": {"scope": "full"}}

def events(rows):
    return parsed_csv("timestamp,src_ip,dst_ip,dst_port,session_id,kind,action,sent,received,session_start\n" +
                      "\n".join(rows))


def test_generic_connection_csv_preserves_source_and_ambiguous_byte_names():
    ev = parsed_csv("timestamp,src_ip,dst_ip,dst_port,orig_bytes,resp_bytes\n"
                    "2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,7,19")[0]
    assert ev["data_source"] == "connection", "generic CSV must not impersonate Zeek"
    assert ev["ext"]["csv"]["orig_bytes"] == "7"
    assert "bytes_in" not in ev and "bytes_out" not in ev
    observe, _ = api()
    obs = observe(ev)
    assert obs["counters"]["src_to_dst_bytes"]["state"] == "unknown_semantics"


def test_cumulative_sessions_keep_records_but_use_completed_values():
    _, analyze = api()
    evs = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{sent},{recv},2026-10-20T00:00:00Z"
                  for i, kind, sent, recv in [(0,"session_start",0,0),(1,"session_interim",100,900),(2,"session_end",300,1200)]])
    report = analyze(iter(evs), context_snapshot=context())
    assert report["counts"]["records"] == 3 and report["counts"]["sessions"] == 1
    session = report["sessions"][0]
    assert session["src_to_dst_bytes"] == 300 and session["dst_to_src_bytes"] == 1200
    assert session["record_count"] == 3 and len(session["event_refs"]) == 3
    assert not any(c["kind"] == "beacon" for c in report["candidates"])
    assert session["new_connection_observed"] is True


def test_observation_does_not_trust_uploaded_metadata_and_preserves_zero():
    observe, _ = api()
    ev = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,0,,2026-10-20T00:00:00Z"])[0]
    ev["ext"]["observation"] = {"producer": "saw", "counter_mode": "cumulative"}
    assert observe(ev)["context"]["resolved"] is False
    obs = observe(ev, context_snapshot=context())
    assert obs["counters"]["src_to_dst_bytes"]["value"] == 0
    assert obs["counters"]["src_to_dst_bytes"]["state"] == "observed"
    assert obs["counters"]["dst_to_src_bytes"]["state"] == "recorded_empty"


def test_unknown_devices_and_affiliates_do_not_merge_sessions():
    _, analyze = api()
    evs = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,10,20,"])
    report = analyze(iter(evs * 2))
    assert report["counts"]["sessions"] == 2
    assert report["counts"]["unresolved_records"] == 2
    assert report["status"] == "insufficient_data"


def test_delta_unknown_and_counter_reversal_are_distinct():
    _, analyze = api()
    rows = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{sent},1,2026-10-20T00:00:00Z"
                   for i, kind, sent in [(0,"session_start",0),(1,"session_interim",100),(2,"session_end",20)]])
    delta = analyze(iter(rows), context_snapshot=context("delta"))
    assert delta["sessions"][0]["src_to_dst_bytes"] == 120
    reset = analyze(iter(rows), context_snapshot=context())
    assert reset["sessions"][0]["src_to_dst_bytes"] is None
    assert reset["quality"]["counter_reset_or_reversal"] == 1
    unknown = analyze(iter(rows), context_snapshot=context("unknown"))
    assert unknown["sessions"][0]["src_to_dst_bytes"] is None


def test_deny_attempts_are_not_sessions_but_support_scan_and_later_allow():
    _, analyze = api()
    evs = events([f"2026-10-20T00:00:0{i}Z,10.0.0.1,192.0.2.{i + 1},{440 + i},S7,session_end,deny,0,0,"
                  for i in range(5)] +
                 ["2026-10-20T00:01:00Z,10.0.0.1,192.0.2.1,440,S8,session_end,allow,1,1,"])
    report = analyze(evs, context_snapshot=context())
    assert report["counts"]["deny_attempts"] == 5
    assert report["counts"]["sessions"] == 1
    assert {candidate["kind"] for candidate in report["candidates"]} == {"scan", "deny_to_allow"}
    assert report["sessions"][0]["established_connection"] is None


def test_missing_end_reused_id_and_context_boundaries():
    _, analyze = api()
    evs = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{sent},1,"
                  for i, kind, sent in [(0,"session_start",0),(1,"session_interim",5),
                                        (2,"session_start",0),(3,"session_end",7)]])
    report = analyze(evs, context_snapshot=context())
    assert report["counts"]["sessions"] == 2
    assert report["sessions"][0]["src_to_dst_bytes"] is None
    assert report["sessions"][1]["src_to_dst_bytes"] == 7
    observe, _ = api()
    a, b = context(), context()
    b["subject"]["org_unit_id"] = "B"
    for ev, ctx in zip(evs[:2], [a, b]):
        ev["ext"]["observation"] = observe(ev, context_snapshot=ctx)
    separated = analyze(evs[:2])
    assert separated["counts"]["sessions"] == 2


def test_periodicity_uses_only_verified_distinct_connection_starts():
    _, analyze = api()
    rows = []
    for minute in range(4):
        rows.extend([f"2026-10-20T00:0{minute}:00Z,10.0.0.1,192.0.2.1,443,S{minute},session_start,allow,0,0,",
                     f"2026-10-20T00:0{minute}:01Z,10.0.0.1,192.0.2.1,443,S{minute},session_end,allow,1,1,"])
    evs = events(rows)
    report = analyze(evs, context_snapshot=context())
    assert report["counts"]["new_connections"] == 4
    assert [c["kind"] for c in report["candidates"]] == ["beacon"]
    ctx = context()
    ctx["profile"]["time"]["verified"] = False
    report = analyze(evs, context_snapshot=ctx)
    assert report["counts"]["new_connections"] == 0
    assert report["candidates"] == []


def test_transfer_long_flow_and_output_caps_are_explicit():
    _, analyze = api()
    rows = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_start,allow,0,0,2026-10-20T00:00:00Z",
                   "2026-10-20T02:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,100000000,1,2026-10-20T00:00:00Z"])
    report = analyze(rows, context_snapshot=context(), max_results=1)
    assert report["counts"]["candidates"] == 2
    assert report["counts"]["omitted_candidates"] == 1
    assert report["limits"]["coverage_complete"] is True
    assert report["sessions"][0]["duration_seconds"] == 7200
    limited = analyze(iter(rows), context_snapshot=context(), max_records=1)
    assert limited["status"] == "partial"
    assert limited["limits"]["coverage_complete"] is False
    cancelled = analyze(iter(rows), cancelled=lambda: True)
    assert cancelled["status"] == "cancelled" and cancelled["counts"]["records"] == 0


def test_unverified_source_mapping_cannot_create_known_measurements():
    observe, _ = api()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
    ctx = context()
    ctx["profile"]["measurement_profile"]["verified"] = False
    assert observe(row, context_snapshot=ctx)["counters"]["src_to_dst_bytes"]["state"] == "unknown_semantics"


def test_true_zeek_preserves_orig_resp_direction():
    import json

    from saw.parsers.network import ZeekJsonParser
    parser = ZeekJsonParser()
    raw = RawLine(json.dumps({"ts": 1792454400, "id.orig_h": "10.0.0.1", "id.resp_h": "192.0.2.1",
                             "uid": "z1", "orig_bytes": 7, "resp_bytes": 19}), 0, 1)
    result = parser.parse_line(raw.text)
    ev = to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                source_file="synthetic.json", object_key="synthetic", assumed_tz="UTC")
    observe, _ = api()
    obs = observe(ev)
    assert ev["data_source"] == "zeek_conn" and ev["bytes_out"] == 7 and ev["bytes_in"] == 19
    assert obs["counters"]["src_to_dst_bytes"]["value"] == 7
    assert obs["counters"]["dst_to_src_bytes"]["value"] == 19


def test_analysis_order_does_not_change_completed_session():
    _, analyze = api()
    rows = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{sent},1,2026-10-20T00:00:00Z"
                   for i, kind, sent in [(0,"session_start",0),(1,"session_interim",100),(2,"session_end",200)]])
    assert analyze(rows, context_snapshot=context()) == analyze(list(reversed(rows)), context_snapshot=context())


def test_bounded_refs_do_not_hide_processed_record_count():
    _, analyze = api()
    rows = events([f"2026-10-20T00:00:{i:02d}Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{i},{i},2026-10-20T00:00:00Z"
                   for i, kind in [(0,"session_start")] + [(i,"session_interim") for i in range(1,30)] +
                   [(30,"session_end")]])
    report = analyze(rows, context_snapshot=context())
    assert report["counts"]["records"] == 31
    assert len(report["sessions"][0]["event_refs"]) == 20
    assert report["sessions"][0]["omitted_event_refs"] == 11


def test_invalid_time_cannot_create_verified_start_or_duration():
    _, analyze = api()
    rows = events(["invalid,10.0.0.1,192.0.2.1,443,S7,session_start,allow,0,0,",
                   "invalid,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])
    report = analyze(rows, context_snapshot=context())
    assert report["counts"]["new_connections"] == 0
    assert report["sessions"][0]["duration_seconds"] is None
    assert report["status"] == "partial"


def test_fractional_boolean_and_nonfinite_byte_counters_are_invalid():
    observe, _ = api()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
    for invalid in ("1.5", True, "nan", "-1"):
        row["ext"]["csv"]["sent"] = invalid
        assert observe(row, context_snapshot=context())["counters"]["src_to_dst_bytes"]["state"] == "invalid"


def test_raw_source_alias_mapping_and_reversed_direction_profile():
    observe, _ = api()
    row = parsed_csv("timestamp,src_ip,dst_ip,dst_port,sentbytes,receivedbytes\n"
                     "2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,15,7")[0]
    ctx = context()
    ctx["profile"]["source_fields"].update(src_bytes="sentbytes", dst_bytes="receivedbytes")
    assert observe(row, context_snapshot=ctx)["counters"]["src_to_dst_bytes"]["value"] == 15
    ctx["profile"]["measurement_profile"]["direction"] = "dst_to_src"
    assert observe(row, context_snapshot=ctx)["counters"]["src_to_dst_bytes"]["value"] == 7
    assert observe(row, context_snapshot=ctx)["counters"]["dst_to_src_bytes"]["value"] == 15


def test_analysis_does_not_mutate_events_or_reuse_mutable_context():
    from copy import deepcopy
    observe, analyze = api()
    ctx = context()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
    row["ext"]["observation"] = observe(row, context_snapshot=ctx)
    before = deepcopy(row)
    analyze([row])
    assert row == before
    ctx["collection"]["scope"] = "blocked_only"
    assert row["ext"]["observation"]["collection"]["scope"] == "full"


def test_scan_window_does_not_combine_distant_attempts():
    _, analyze = api()
    evs = events([f"2026-10-20T0{i}:00:00Z,10.0.0.1,192.0.2.{i+1},{440+i},S{i},session_end,deny,0,0,"
                  for i in range(5)])
    report = analyze(evs, context_snapshot=context())
    assert report["candidates"] == []
    assert report["policy"]["scan_window_seconds"] == 300


def test_cancel_during_disk_aggregation_is_reported():
    _, analyze = api()
    rows = events([f"2026-10-20T00:00:0{i}Z,10.0.0.1,192.0.2.{i+1},{440+i},S{i},session_end,deny,0,0,"
                   for i in range(5)])
    calls = 0
    def cancelled():
        nonlocal calls
        calls += 1
        return calls > 11
    report = analyze(rows, context_snapshot=context(), cancelled=cancelled)
    assert report["status"] == "cancelled"
    assert report["limits"]["coverage_complete"] is False


def test_missing_endpoints_and_unknown_action_are_quality_limits():
    _, analyze = api()
    rows = events(["2026-10-20T00:00:00Z,,192.0.2.1,443,S7,session_end,,15,1,"])
    report = analyze(rows, context_snapshot=context())
    assert report["status"] in {"partial", "insufficient_data"}
    assert report["quality"]["missing_endpoints"] == 1
    assert report["quality"]["unverified_action"] == 1


def test_invalid_thresholds_rejected_before_single_connection_division():
    import pytest
    _, analyze = api()
    for policy in ({"beacon_min_connections": 1}, {"scan_window_seconds": 0}, {"asymmetry_ratio": 0}):
        with pytest.raises(ValueError):
            analyze([], policy=policy)


def test_unknown_time_or_context_cannot_create_long_flow_or_transfer_candidates():
    _, analyze = api()
    rows = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_start,allow,0,0,2026-10-20T00:00:00Z",
                   "2026-10-20T02:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,100000000,1,2026-10-20T00:00:00Z"])
    ctx = context()
    ctx["profile"]["time"]["verified"] = False
    report = analyze(rows, context_snapshot=ctx)
    assert not any(c["kind"] == "long_flow" for c in report["candidates"])
    assert report["sessions"][0]["duration_seconds"] is None
    ctx = context()
    ctx["observer"]["device_id"] = None
    report = analyze(rows, context_snapshot=ctx)
    assert report["candidates"] == []
    assert all(s["src_to_dst_bytes"] is None for s in report["sessions"])


def test_unknown_precision_does_not_establish_periodic_start_times():
    _, analyze = api()
    ctx = context()
    ctx["profile"]["time"]["precision"] = "unknown"
    rows = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_start,allow,0,0,"])
    report = analyze(rows, context_snapshot=ctx)
    assert report["counts"]["new_connections"] == 0


def test_reused_id_generations_have_unique_session_keys():
    _, analyze = api()
    rows = events([f"2026-10-20T00:0{i}:00Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,0,0,"
                   for i, kind in [(0,"session_start"),(1,"session_end"),(2,"session_start"),(3,"session_end")]])
    report = analyze(rows, context_snapshot=context())
    assert len({session["session_key"] for session in report["sessions"]}) == 2


def test_packet_profile_keeps_packet_unit_and_cannot_impersonate_bytes():
    observe, analyze = api()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
    ctx = context()
    ctx["profile"]["source_fields"].update(src_packets="sent", dst_packets="received")
    ctx["profile"]["measurement_profile"]["unit"] = "packets"
    obs = observe(row, context_snapshot=ctx)
    assert obs["counters"]["src_to_dst_packets"]["value"] == 15
    assert obs["counters"]["src_to_dst_packets"]["unit"] == "packets"
    assert obs["counters"]["src_to_dst_bytes"]["state"] == "unknown_semantics"
    assert analyze([row], context_snapshot=ctx)["sessions"][0]["src_to_dst_bytes"] is None


def test_record_kind_requires_explicit_mapping_and_duration_unit_is_converted():
    observe, analyze = api()
    rows = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,start,allow,0,0,",
                   "2026-10-20T00:00:01Z,10.0.0.1,192.0.2.1,443,S7,end,allow,15,1,"])
    ctx = context()
    assert observe(rows[0], context_snapshot=ctx)["record_kind"] == "unknown"
    ctx["profile"]["record_kind_map"] = {"start": "session_start", "end": "session_end"}
    ctx["profile"]["source_fields"]["duration"] = "elapsed"
    ctx["profile"]["measurement_profile"]["duration_unit"] = "milliseconds"
    rows[1]["ext"]["csv"]["elapsed"] = "7200000"
    obs = observe(rows[1], context_snapshot=ctx)
    assert obs["duration_seconds"] == 7200
    assert analyze(rows, context_snapshot=ctx)["sessions"][0]["duration_seconds"] == 7200
    ctx["profile"]["measurement_profile"]["verified"] = False
    assert observe(rows[1], context_snapshot=ctx)["duration_seconds"] is None


def test_explicit_timestamp_mapping_uses_occurred_field_instead_of_collection_time():
    observe, _ = api()
    row = parsed_csv("timestamp,src_ip,dst_ip,dst_port,occurred_at\n"
                     "2026-10-20T12:00:00Z,10.0.0.1,192.0.2.1,443,2026-10-20T00:00:00Z")[0]
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "occurred_at"
    ctx["profile"]["time"]["timezone"] = "UTC"
    obs = observe(row, context_snapshot=ctx)
    assert obs["timestamp"] == "2026-10-20T00:00:00.000Z"
    assert row["timestamp"] == "2026-10-20T12:00:00.000Z"


def test_reference_caps_keep_the_terminal_counter_evidence():
    _, analyze = api()
    rows = events([f"2026-10-20T00:00:{i:02d}Z,10.0.0.1,192.0.2.1,443,S7,{kind},allow,{i},{i},2026-10-20T00:00:00Z"
                   for i, kind in [(0,"session_start")] + [(i,"session_interim") for i in range(1,30)] +
                   [(30,"session_end")]])
    report = analyze(rows, context_snapshot=context())
    assert report["sessions"][0]["event_refs"][-1]["event_id"] == rows[-1]["event_id"]


def test_beacon_references_represent_distinct_connection_starts():
    _, analyze = api()
    rows = []
    for minute in range(12):
        rows.extend([f"2026-10-20T00:{minute:02d}:00Z,10.0.0.1,192.0.2.1,443,S{minute},session_start,allow,0,0,",
                     f"2026-10-20T00:{minute:02d}:01Z,10.0.0.1,192.0.2.1,443,S{minute},session_end,allow,1,1,"])
    evs = events(rows)
    report = analyze(evs, context_snapshot=context())
    beacon = next(c for c in report["candidates"] if c["kind"] == "beacon")
    assert evs[-2]["event_id"] in {ref["event_id"] for ref in beacon["event_refs"]}


def test_mixed_row_affiliation_conflicts_remain_unresolved():
    observe, analyze = api()
    ctx = context()
    ctx["profile"]["source_fields"]["org_unit_id"] = "record_org"
    rows = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,100000000,1,"])
    row = rows[0]
    row["ext"]["csv"]["record_org"] = "B"
    obs = observe(row, context_snapshot=ctx)
    assert obs["context"]["resolved"] is False
    assert obs["context"]["org_unit_id"] is None
    assert obs["context"]["file_context"]["org_unit_id"] == "A"
    assert obs["context"]["row_attribution"]["org_unit_id"]["raw_value"] == "B"
    assert "conflicting_row_attribution" in obs["quality"]
    report = analyze(rows, context_snapshot=ctx)
    assert report["counts"]["unresolved_records"] == 1
    assert report["candidates"] == []
    assert report["sessions"][0]["src_to_dst_bytes"] is None


def test_row_hints_require_explicit_mapping_and_never_replace_file_context():
    observe, analyze = api()
    ctx = context()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
    row["ext"]["csv"]["org_unit_id"] = "A"
    assert observe(row, context_snapshot=ctx)["context"]["resolved"] is False
    ctx["profile"]["source_fields"]["org_unit_id"] = "org_unit_id"
    assert observe(row, context_snapshot=ctx)["context"]["resolved"] is True
    row["ext"]["csv"]["org_unit_id"] = "B"
    assert observe(row, context_snapshot=ctx)["context"]["resolved"] is False
    other = dict(row, ext={**row["ext"], "csv": {**row["ext"]["csv"], "org_unit_id": "A"}})
    report = analyze([row, other], context_snapshot=ctx)
    assert report["counts"]["sessions"] == 2
    assert report["counts"]["unresolved_records"] == 1


def test_conflicting_row_device_network_and_empty_declared_fields_are_isolated():
    observe, _ = api()
    for semantic, value in (("device_id", "FW-other"), ("network", "other-net"),
                            ("virtual_domain", "other-vdom"), ("device_profile_version_id", "other-profile")):
        row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,"])[0]
        ctx = context()
        ctx["profile"]["source_fields"][semantic] = "row_" + semantic
        row["ext"]["csv"]["row_" + semantic] = value
        obs = observe(row, context_snapshot=ctx)
        assert obs["context"]["resolved"] is False
        assert obs["context"]["row_attribution"][semantic]["raw_value"] == value
        row["ext"]["csv"]["row_" + semantic] = ""
        assert observe(row, context_snapshot=ctx)["context"]["resolved"] is False


def test_each_counter_requires_its_own_explicit_mapping():
    observe, analyze = api()
    row = events(["2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,100000000,1,"])[0]
    row["bytes_in"] = 987
    ctx = context()
    del ctx["profile"]["source_fields"]["dst_bytes"]
    obs = observe(row, context_snapshot=ctx)
    assert obs["counters"]["src_to_dst_bytes"]["value"] == 100000000
    assert obs["counters"]["dst_to_src_bytes"]["state"] == "unknown_semantics"
    assert obs["counters"]["dst_to_src_bytes"]["value"] is None
    assert obs["counters"]["dst_to_src_bytes"]["source_field"] == "bytes_in"
    assert obs["counters"]["dst_to_src_bytes"]["raw_value"] == 987
    assert analyze([row], context_snapshot=ctx)["candidates"] == []


def test_profile_timezone_reads_original_timestamp_through_actual_to_ces():
    parser = CsvParser()
    text = ("timestamp,src_ip,dst_ip,dst_port,session_id,kind,action,sent,received\n"
            "2026-10-20 09:00:00,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1")
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "timestamp"
    ctx["profile"]["time"]["timezone"] = "UTC"
    pairs = [(raw, result) for raw, result in parser.parse(iter(
        RawLine(line, n * 100, n + 1) for n, line in enumerate(text.splitlines()))) if isinstance(result, Parsed)]
    raw, result = pairs[0]
    row = to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                 source_file="synthetic.csv", object_key="synthetic", assumed_tz="Asia/Seoul",
                 context_snapshot=ctx)
    obs = row["ext"]["observation"]
    assert row["timestamp"] == "2026-10-20T09:00:00.000Z"
    assert row["timestamp_raw"] == "2026-10-20 09:00:00"
    assert obs["timestamp"] == "2026-10-20T09:00:00.000Z"
    assert obs["timestamp_raw"] == "2026-10-20 09:00:00"
    assert "timestamp_context_conflict" in obs["quality"]
    assert obs["ces_timestamp"] == "2026-10-20T00:00:00.000Z"
    assert obs["timestamp_basis"] == "verified_device_profile"
    assert obs["ces_timestamp_raw"] == row["timestamp_raw"]
    assert obs["ces_timestamp_quality"] == row["timestamp_quality"]


def test_explicit_time_alias_keeps_distinct_original_field():
    observe, _ = api()
    row = parsed_csv("timestamp,time,src_ip,dst_ip,dst_port\n"
                     "2026-10-20 09:00:00,2026-10-20 10:00:00,10.0.0.1,192.0.2.1,443")[0]
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "time"
    ctx["profile"]["time"]["timezone"] = "UTC"
    obs = observe(row, context_snapshot=ctx)
    assert obs["timestamp_raw"] == "2026-10-20 10:00:00"
    assert obs["timestamp"] == "2026-10-20T10:00:00.000Z"


def test_actual_mixed_csv_keeps_a_session_and_isolates_b_with_same_ip_and_session_id():
    observe, analyze = api()
    parser = CsvParser()
    ctx = context()
    ctx["profile"]["source_fields"]["org_unit_id"] = "record_org"
    ctx["profile"]["source_fields"]["timestamp"] = "timestamp"
    ctx["profile"]["time"]["timezone"] = "UTC"
    text = ("timestamp,src_ip,dst_ip,dst_port,session_id,kind,action,sent,received,record_org\n"
            "2026-10-20T00:00:00Z,10.0.0.1,192.0.2.1,443,S7,session_start,allow,0,0,A\n"
            "2026-10-20T00:01:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,100000000,1,B\n"
            "2026-10-20T00:02:00Z,10.0.0.1,192.0.2.1,443,S7,session_end,allow,15,1,A")
    rows = [to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                   source_file="synthetic.csv", object_key="synthetic", assumed_tz="UTC", context_snapshot=ctx)
            for raw, result in parser.parse(iter(RawLine(s, n*100, n+1) for n, s in enumerate(text.splitlines())))
            if isinstance(result, Parsed)]
    report = analyze(iter(rows))
    assert report["counts"]["unresolved_records"] == 1
    assert report["counts"]["sessions"] == 2
    a = next(session for session in report["sessions"] if session["context"]["org_unit_id"] == "A")
    assert a["record_count"] == 2 and a["src_to_dst_bytes"] == 15
    assert report["candidates"] == []
    assert rows[1]["ext"]["csv"]["record_org"] == "B"
    assert rows[1]["ext"]["observation"]["context"]["resolved"] is False
    assert observe(rows[1], context_snapshot=ctx)["context"]["resolved"] is False


@pytest.mark.parametrize("mode", ["unverified", "collected", "conflicting_context", "invalid", "unmapped"])
def test_unverified_or_non_occurrence_profile_does_not_rewrite_indexed_time(mode):
    parser = CsvParser()
    ctx = context()
    ctx["profile"]["source_fields"]["timestamp"] = "time"
    ctx["profile"]["time"]["timezone"] = "UTC"
    if mode == "unverified":
        ctx["profile"]["time"]["verified"] = False
    elif mode == "collected":
        ctx["profile"]["time"]["role"] = "collected"
    elif mode == "conflicting_context":
        ctx["profile"]["source_fields"]["org_unit_id"] = "row_org"
    elif mode == "unmapped":
        del ctx["profile"]["source_fields"]["timestamp"]
    mapped_time = "invalid-time" if mode == "invalid" else "2026-10-20 10:00:00"
    text = ("timestamp,time,src_ip,dst_ip,dst_port,row_org\n"
            f"2026-10-20 09:00:00,{mapped_time},10.0.0.1,192.0.2.1,443,B")
    rows = [to_ces(parser, raw, result, investigation_id="i", evidence_id="e", file_id="f",
                   source_file="synthetic.csv", object_key="synthetic", assumed_tz="Asia/Seoul",
                   context_snapshot=ctx)
            for raw, result in parser.parse(iter(RawLine(s, n*100, n+1) for n, s in enumerate(text.splitlines())))
            if isinstance(result, Parsed)]
    row = rows[0]
    assert row["timestamp"] == "2026-10-20T00:00:00.000Z"
    assert row["timestamp_raw"] == "2026-10-20 09:00:00"
    assert row["ext"]["observation"]["timestamp_basis"] == "parser_or_upload_default"
