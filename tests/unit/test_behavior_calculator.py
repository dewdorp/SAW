"""Synthetic behavior measurements: reference thresholds do not imply malicious intent."""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest

START = datetime(2026, 10, 16, tzinfo=timezone.utc)


def calculate(events, profile=None, **kwargs):
    try:
        module = importlib.import_module("saw.behavior.calculator")
    except ModuleNotFoundError:
        pytest.fail("the pure behavior calculator has not been implemented")
    return module.calculate(events, profile, **kwargs)


def event(i=0, seconds=0, **fields):
    return {"event_id": f"e{i}", "timestamp": (START + timedelta(seconds=seconds)).isoformat(),
            "src_ip": "192.0.2.1", "hostname": "app.test", "dst_port": 443, "method": "GET",
            "uri": "/index", "status_code": 200, "user_agent": "Browser/1", "data_source": "web",
            "source_file": "web.log", **fields}


def metric(result, metric_id):
    return next(m for m in result["metrics"] if m["id"] == metric_id)


@pytest.mark.parametrize("count,expected", [(29, "insufficient_data"), (30, "threshold_met")])
def test_reference_request_threshold_is_inclusive(count, expected):
    out = calculate([event(i, i / 10) for i in range(count)])
    m = metric(out, "requests_10s")
    assert m["value"] == count and m["result"] == expected
    assert m["reference_threshold"] == m["applied_threshold"] == 30
    assert out["methodology"]["definitions_version"] == "saw-web-behavior/1.0"


def test_half_open_sliding_window_excludes_exact_end_and_finds_unaligned_burst():
    rows = [event(0, 0)] + [event(i + 1, 9.9) for i in range(30)] + [event(99, 19.9)]
    m = metric(calculate(rows), "requests_10s")
    assert m["value"] == 31
    assert m["window"]["start"] == "2026-10-16T00:00:00.000000Z"
    separate = metric(calculate([event(0, 0), event(1, 10)]), "requests_10s")
    assert separate["value"] == 1


def test_different_sources_and_services_never_combine_threshold():
    rows = [event(i, src_ip=f"192.0.2.{i // 20 + 1}") for i in range(40)]
    assert metric(calculate(rows), "requests_10s")["value"] == 20
    rows = [event(i, hostname=f"app{i // 20}.test") for i in range(40)]
    assert metric(calculate(rows), "requests_10s")["value"] == 20


def test_paths_preserve_case_encoding_and_repeats_keep_query():
    rows = [event(i, uri=f"/Path?q={i}") for i in range(30)]
    rows += [event(40, uri="/path"), event(41, uri="/%50ath")]
    out = calculate(rows)
    assert metric(out, "paths_60s")["value"] == 3
    assert metric(out, "repeats_60s")["value"] == 1


def test_reference_excludes_options_and_static_only_from_three_metrics_cookie_never_excludes():
    rows = [event(i, uri="/x.css?q=dynamic", status_code=404) for i in range(15)]
    rows += [event(20 + i, method="OPTIONS", status_code=404, user_agent="OptionUA") for i in range(15)]
    rows += [event(40 + i, ext={"cookie": "synthetic-session"}) for i in range(30)]
    out = calculate(rows)
    for name in ("requests_10s", "paths_60s", "repeats_60s"):
        assert metric(out, name)["excluded_count"] == 30
        assert metric(out, name)["eligible_count"] == 30
    assert metric(out, "requests_10s")["value"] == 30
    assert metric(out, "status404_60s")["value"] == 30
    assert metric(out, "ua_600s")["value"] == 2


def test_ua_threshold_requires_404_in_the_same_actor_service_and_window():
    rows = [event(0, user_agent="a", status_code=404), event(1, 1, user_agent="b")]
    assert metric(calculate(rows), "ua_600s")["result"] == "insufficient_data"
    rows.append(event(2, 599, status_code=404))
    assert metric(calculate(rows), "ua_600s")["result"] == "threshold_met"
    rows[-1] = event(2, 600, status_code=404)
    assert metric(calculate(rows), "ua_600s")["result"] != "threshold_met"


def test_ua_search_finds_a_qualifying_window_even_when_larger_ua_window_does_not_qualify():
    rows = [event(i, i, user_agent=str(i)) for i in range(4)]
    rows += [event(8, 1000, user_agent="a", status_code=404), event(9, 1001, user_agent="b", status_code=404)]
    m = metric(calculate(rows), "ua_600s")
    assert m["result"] == "threshold_met"
    assert m["value"] == 4 and m["window"]["start"].startswith("2026-10-16T00:00:00")
    assert m["qualifying_window"]["value"] == 2
    assert m["qualifying_window"]["status404"] == 2


def test_missing_required_fields_are_null_partial_subset_has_denominator():
    row = event()
    for key in ("status_code", "user_agent", "uri", "method"):
        row.pop(key)
    out = calculate([row])
    for name in ("requests_10s", "paths_60s", "status404_60s", "repeats_60s", "ua_600s"):
        m = metric(out, name)
        assert m["value"] is None and m["data_state"] == "not_collected"
    assert out["summary"]["status_codes"] is None
    assert out["summary"]["unique_paths"] is None
    assert out["quality"]["user_agent"]["unknown"] == 1
    partial = metric(calculate([row, event(1)]), "status404_60s")
    assert partial["value"] == 0 and partial["data_state"] == "partial" and partial["eligible_count"] == 1


def test_timestamp_precision_comes_only_from_producer_and_ties_have_no_order():
    rows = [event(0), event(1)]
    rows[0]["ext"] = {"saw_observation": {"user_agent": "present", "timestamp_precision": "seconds"}}
    out = calculate(rows)
    assert out["quality"]["timestamp_precision"] == {"seconds": 1, "subseconds": 0, "unknown": 1}
    assert out["quality"]["timestamp_ties"] == 2
    assert "순서" in " ".join(out["limits"])


def test_dedup_is_opt_in_requires_complete_identity_distinct_source_and_retains_refs():
    a = event(0, request_id="r1", source_file="sensor-a")
    b = event(1, request_id="r1", source_file="sensor-b")
    assert calculate([a, b])["summary"]["count"] == 2
    out = calculate([a, b], {"deduplicate_request_id": True})
    assert out["summary"]["count"] == 1 and out["execution"]["deduplicated"] == 1
    assert {"e0", "e1"} <= set(metric(out, "requests_10s")["evidence_ids"])
    for changed in ({"uri": "/different"}, {"src_ip": "192.0.2.2"}, {"source_file": "sensor-a"},
                    {"timestamp": event(seconds=1)["timestamp"]}, {"method": "POST"}):
        assert calculate([a, {**b, **changed}], {"deduplicate_request_id": True})["summary"]["count"] == 2
    assert calculate([event(0), event(1)], {"deduplicate_request_id": True})["summary"]["count"] == 2


def test_source_without_actor_or_service_is_not_invented():
    a, b = event(0), event(1)
    a.pop("src_ip")
    b.pop("hostname")
    b.pop("dst_port")
    m = metric(calculate([a, b]), "requests_10s")
    assert m["value"] is None and m["window"] is None


def test_bounded_stream_stops_early_and_never_claims_whole_range():
    visited = []
    def stream():
        for i in range(1000):
            visited.append(i)
            yield event(i, i)
    out = calculate(stream(), max_events=12)
    assert len(visited) <= 13 and out["execution"]["processed"] == 12
    assert out["execution"]["truncated"] is True and out["execution"]["reason"] == "max_events"
    assert metric(out, "requests_10s")["result"] == "insufficient_data"
    assert all(m["data_state"] != "available" for m in out["metrics"])


def test_time_budget_and_cancel_stop_processing(monkeypatch):
    out = calculate([event()], max_seconds=0)
    assert out["execution"]["truncated"] and out["execution"]["reason"] == "max_seconds"
    with pytest.raises(RuntimeError, match="cancel"):
        calculate([event()], check_cancel=lambda: True)


def test_timeline_is_bounded_separate_from_peak_and_sparse_gaps_are_not_outages():
    rows = [event(i, i * 86400) for i in range(450)]
    out = calculate(rows)
    assert 0 < len(out["timeline"]["buckets"]) <= 400
    assert out["timeline"]["timezone"] == "UTC"
    assert out["timeline"]["annotations"][0]["metric_id"] == "requests_10s"
    assert "연속" in out["timeline"]["coverage_label"]


def test_waf_scope_and_indicator_cases_a_b_c_d():
    a = calculate([event(i, status_code=404, uri=f"/probe/{i}", data_source="waf") for i in range(35)])
    assert "WAF" in a["methodology"]["source_basis"]
    assert all(i["state"] != "observed" for i in a["indicators"] if i["category"] == "tool_string")
    b = calculate([event(0, user_agent="norma/0.4", enforcement_action="allowed")])
    found = next(i for i in b["indicators"] if i["id"] == "norma_ua")
    assert found["state"] == "observed" and found["verification"] == "conditional_code_derived"
    assert b["summary"]["actions"] == {"allowed": 1}
    c = calculate([event(i, ext={"approved_assessment": True}) for i in range(35)])
    assert metric(c, "requests_10s")["result"] == "threshold_met"
    assert "공격" in " ".join(c["limits"])
    drow = event(0)
    drow.pop("user_agent")
    drow["ext"] = {"saw_observation": {"user_agent": "not_collected", "timestamp_precision": "seconds"}}
    d = calculate([drow, {**drow, "event_id": "late", "timestamp": event(seconds=3600)["timestamp"]}])
    assert d["quality"]["user_agent"]["not_collected"] == 2
    assert metric(d, "ua_600s")["value"] is None


def test_custom_profile_is_local_validated_and_does_not_mutate_input():
    profile = {"thresholds": {"requests_10s": 2}, "exclude_methods": []}
    out = calculate([event(0), event(1)], profile)
    assert profile == {"thresholds": {"requests_10s": 2}, "exclude_methods": []}
    assert out["profile"]["id"] == "saw-local-v1"
    assert metric(out, "requests_10s")["applied_threshold"] == 2
    for bad in ({"thresholds": {"requests_10s": 0}}, {"unknown": 3}, {"deduplicate_request_id": "yes"}):
        with pytest.raises(ValueError):
            calculate([], bad)

def test_default_profile_roundtrip_retains_reference_identity():
    from saw.behavior.definitions import resolve_profile
    default = resolve_profile()
    assert resolve_profile(default) == default


def test_dedup_pairs_repeated_ids_by_source_occurrence_without_dropping_same_sensor_rows():
    rows = [event(i, request_id="collision", source_file=source)
            for i, source in enumerate(["a", "a", "b", "b"])]
    out = calculate(rows, {"deduplicate_request_id": True})
    assert out["summary"]["count"] == 2 and out["execution"]["deduplicated"] == 2
    assert set(metric(out, "requests_10s")["evidence_ids"]) == {"e0", "e1", "e2", "e3"}


def test_saved_evidence_preserves_source_file_and_hashes_full_raw_not_preview():
    import hashlib
    raw = "a" * 5000
    out = calculate([event(0, file_id="source-file-id", raw_event=raw)])
    ev = out["evidence_events"][0]
    assert ev["file_id"] == "source-file-id"
    assert ev["raw_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert len(ev["raw_event"]) == 4096 and ev["raw_truncated"] is True


@pytest.mark.parametrize("metric_id,count,extra", [
    ("paths_60s", 30, {}), ("status404_60s", 15, {"status_code": 404}),
    ("repeats_60s", 20, {})])
def test_each_reference_threshold_and_exact_window_boundary(metric_id, count, extra):
    rows = [event(i, 0, uri=f"/x/{i}" if metric_id == "paths_60s" else "/x", **extra) for i in range(count)]
    assert metric(calculate(rows), metric_id)["result"] == "threshold_met"
    assert metric(calculate(rows[:-1]), metric_id)["result"] != "threshold_met"
    last = {**rows[-1], "timestamp": event(seconds=60)["timestamp"]}
    assert metric(calculate(rows[:-1] + [last]), metric_id)["value"] == count - 1


def test_unknown_source_precision_and_ua_never_inferred_from_normalized_milliseconds():
    out = calculate([event()])
    assert out["quality"]["timestamp_precision"]["unknown"] == 1


def test_excluded_all_rows_is_zero_measured_not_missing_collection():
    out = calculate([event(i, uri="/asset.css") for i in range(40)])
    for key in ("requests_10s", "paths_60s", "repeats_60s"):
        assert metric(out, key)["value"] == 0
        assert metric(out, key)["data_state"] == "available"
        assert metric(out, key)["excluded_count"] == 40


def test_web_counts_do_not_count_non_http_connection_records():
    row = event(0, data_source="zeek_conn", event_type="conn")
    for key in ("method", "uri", "status_code", "user_agent"):
        row.pop(key)
    out = calculate([row])
    assert metric(out, "requests_10s")["value"] is None


def test_peak_evidence_for_repeat_is_actual_repeating_key():
    rows = [event(i, uri=f"/noise/{i}") for i in range(16)]
    rows += [event(100 + i, uri="/repeat") for i in range(20)]
    out = calculate(rows)
    ids = metric(out, "repeats_60s")["evidence_ids"]
    assert ids and all(int(eid[1:]) >= 100 for eid in ids)

def test_existing_normalized_rules_are_evidence_not_recomputed_verdicts():
    rows = [event(0, tags=["sig:tool.sqlmap", "pattern:sqli"]), event(1, tags=["sig:rce.log4shell"])]
    out = calculate(rows)
    scanner = next(i for i in out["indicators"] if i["id"] == "existing_scanner_tool")
    payload = next(i for i in out["indicators"] if i["id"] == "existing_payload")
    assert scanner["state"] == "observed" and scanner["rule_ids"] == ["tool.sqlmap"]
    assert payload["count"] == 2 and set(payload["rule_ids"]) == {"pattern:sqli", "rce.log4shell"}
    assert scanner["evidence_ids"] == ["e0"]


def test_raw_encoding_and_ua_empty_quality_survive_capture():
    row = event(0, raw_ref={"enc": "cp949", "object_key": "synthetic", "offset": 5, "length": 7, "line_no": 1})
    out = calculate([row])
    assert out["evidence_events"][0]["raw_ref"]["enc"] == "cp949"

def test_exclusion_does_not_invent_source_coverage():
    row = event(0, uri="/asset.css")
    row.pop("src_ip")
    m = metric(calculate([row]), "requests_10s")
    assert m["value"] is None and m["data_state"] == "not_collected"


def test_near_end_peak_has_incomplete_window_despite_long_overall_range():
    out = calculate([event(0, 0), event(1, 1000), event(2, 1001)])
    m = metric(out, "requests_10s")
    assert m["value"] == 2 and m["partial_window"] is True
    assert m["result"] == "insufficient_data"


def test_partition_and_memory_limits_are_explicit(monkeypatch):
    import saw.behavior.calculator as mod
    monkeypatch.setattr(mod, "MAX_PARTITIONS", 2)
    out = calculate([event(i, hostname=f"app{i}.test") for i in range(3)])
    assert out["execution"]["reason"] == "max_partitions" and out["execution"]["processed"] == 2
    monkeypatch.setattr(mod, "MAX_INPUT_BYTES", 1000)
    out = calculate([event(i, user_agent="x" * 500) for i in range(3)])
    assert out["execution"]["reason"] == "max_input_bytes" and out["execution"]["truncated"]


def test_exact_ua_window_boundary_with_recorded_empty_value_is_not_an_extra_agent():
    a = event(0, user_agent="a", status_code=404)
    b = event(1, 599, user_agent=None, status_code=404,
              ext={"saw_observation": {"user_agent": "recorded_empty", "timestamp_precision": "seconds"}})
    c = event(2, 600, user_agent="b", status_code=404)
    m = metric(calculate([a,b,c]), "ua_600s")
    assert m["value"] == 1 and m["result"] != "threshold_met"


def test_cancellation_callback_exception_is_not_swallowed():
    class Cancelled(Exception):
        pass
    def cancel():
        raise Cancelled("requested")
    with pytest.raises(Cancelled):
        calculate([event()], check_cancel=cancel)

@pytest.mark.parametrize("host_a,port_a,host_b,port_b", [
    ("2001:db8::1", 443, "2001:db8::1:443", None),
    ("app.test", 443, "app.test:443", None),
    ("[app.test]", 443, "[app.test]:443", None),
])
def test_service_identity_never_confuses_host_text_with_port(host_a, port_a, host_b, port_b):
    rows = [event(i, i / 100, hostname=None, dst_ip=host_a, dst_port=port_a) for i in range(20)]
    rows += [event(20 + i, i / 100, hostname=None, dst_ip=host_b, dst_port=port_b) for i in range(20)]
    result = calculate(rows)
    assert metric(result, "requests_10s")["value"] == 20
    assert len(result["summary"]["services"]) == 2

def test_followup_questions_have_complete_versioned_review_contract():
    result = calculate([event(0)])
    assert result["methodology"]["definitions_version"] == "saw-web-behavior/1.0"
    assert result["methodology"]["question_version"] == "saw-web-behavior-questions/1.0"
    assert {q["id"] for q in result["followups"]} == {"authorization", "origin_outcome", "collection"}
    for question in result["followups"]:
        for name in ("question_version", "question", "condition", "label", "if_unresolved"):
            assert isinstance(question[name], str) and question[name].strip()
        for name in ("needed_data", "allowed_actions", "resolution_criteria", "forbidden_claims", "items"):
            assert question[name] and all(isinstance(value, str) and value.strip() for value in question[name])


def test_tool_string_followup_is_conditional_and_never_runs_active_queries(monkeypatch):
    import socket
    import subprocess
    import urllib.request
    def forbidden(*args, **kwargs):
        raise AssertionError("behavior followups must not execute active queries")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    result = calculate([event(0, user_agent="norma/0.4 https://synthetic.invalid/model")])
    question = next(q for q in result["followups"] if q["id"] == "tool_identity")
    assert question["question_version"] == result["methodology"]["question_version"]
    assert question["indicator_ids"] == ["norma_ua"]
    assert question["evidence_ids"] == ["e0"]
    assert "미확인" in question["if_unresolved"]
    assert any("AI" in claim for claim in question["forbidden_claims"])
    egress = next(i for i in result["indicators"] if i["id"] == "llm_egress")
    assert egress["state"] == "unavailable" and egress["count"] is None
    assert metric(result, "requests_10s")["value"] == 1
