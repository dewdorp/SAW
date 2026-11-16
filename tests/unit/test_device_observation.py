"""Synthetic device observations: producer trust, units, scope and real calculations."""
import importlib.util
import json
from copy import deepcopy

import pytest

from saw.parsers.base import Parsed, RawLine
from saw.parsers.registry import to_ces
from saw.parsers.structured import JsonLinesParser


def api():
    assert importlib.util.find_spec("saw.detection.specs"), "DetectorSpec missing"
    assert importlib.util.find_spec("saw.observation.device"), "device producer/calculator missing"
    from saw.detection.specs import get_spec, validate_values
    from saw.observation.device import analyze_device, device_observation
    return get_spec, validate_values, analyze_device, device_observation


def profile(device, kind, **semantics):
    return {"schema_version": 1, "subject": {"org_unit_id": "A", "status": "verified"},
            "observer": {"device_id": "dev1", "device_profile_version_id": "p1", "network": "net1",
                         "virtual_domain": "root", "functions": [device], "observation_point": "edge1"},
            "profile": {"functions": [device], "source_fields": {
                "timestamp": "timestamp", "record_kind": "kind", "request_id": "request_id",
                "signature_id": "signature_id", "action": "action", "origin_status": "origin_status",
                "edge_status": "edge_status", "mode": "mode", "interval_start": "begin",
                "interval_end": "end", "rate": "rate", "target": "target", "attack_type": "attack_type",
                "mitigation": "mitigation", "tls_version": "tls_version",
                "session_id": "session_id", "src_bytes": "sent", "dst_bytes": "received"},
                "record_kind_map": {"start": "session_start", "interim": "session_interim", "end": "session_end",
                                    "request": "request", "hit": "rule_hit", "alert": "alert",
                                    "interval": "interval_summary", "flow": "flow", "dns": "dns", "http": "http", "tls": "tls"},
                "action_verified": True, "action_basis": "synthetic action", "action_map": {"allow": "allowed", "detect": "detected",
                                                       "drop": "blocked", "reset": "reset"},
                "time": {"verified": True, "role": "occurred", "timezone": "UTC", "precision": "seconds"},
                "measurement_profile": {"verified": True, "counter_semantics": "cumulative",
                                        "direction": "src_to_dst", "unit": "bytes"},
                "device_semantics": {"verified": True, "basis": "synthetic field dictionary", "record_kind": kind,
                    "mode": "mirror", "packet_available": False, "rate_unit": "bps", "rate_statistic": "mean",
                    "sampling_ratio": 1.0, "sampling_version": "synthetic/1", **semantics}},
            "collection": {"scope": "full", "loss": "known"}}


def rows(context, entries):
    _, _, _, observe = api()
    parser = JsonLinesParser()
    events = []
    for index, values in enumerate(entries):
        raw = RawLine(json.dumps({"timestamp": "2026-10-20T00:00:00Z", "src_ip": "10.0.0.1",
                                   "dst_ip": "192.0.2.1", "dst_port": 443, **values}), index * 100, index + 1)
        parsed = parser.parse_line(raw.text)
        assert isinstance(parsed, Parsed)
        event = to_ces(parser, raw, parsed, investigation_id="i", evidence_id="e", file_id="f",
                       source_file="synthetic.json", object_key="synthetic", assumed_tz="UTC",
                       context_snapshot=context)
        event["ext"]["device_observation"] = observe(event, context_snapshot=context)
        events.append(event)
    return events


def test_specs_validate_actual_fw_defaults_and_reject_untyped_values():
    spec, validate, _, _ = api()
    from saw.observation.firewall import DEFAULT_POLICY
    fw = spec("fw.observation")
    assert {key: fw["defaults"][key] for key in DEFAULT_POLICY} == DEFAULT_POLICY
    assert fw["window"]["parameter"] == "scan_window_seconds"
    for detector in ("waf", "ips", "ddos", "ndr"):
        item = spec(detector + ".observation")
        assert validate(item, {}) == item["defaults"]
        assert item["prerequisites"] and item["examples"] and item["benign_examples"] and item["follow_up"]
        with pytest.raises(ValueError):
            validate(item, {"window_seconds": True})
        with pytest.raises(ValueError):
            validate(item, {"window_seconds": 0})
        with pytest.raises(ValueError):
            validate(item, {"undeclared": 3})
    fw["defaults"]["scan_min_ports"] = 900
    assert spec("fw.observation")["defaults"]["scan_min_ports"] == 5


def test_waf_request_and_rule_hit_counts_ua_and_edge_origin_are_separate():
    _, _, analyze, _ = api()
    context = profile("WAF", "rule_hit")
    events = rows(context, [{"kind": "hit", "request_id": "R1", "signature_id": str(i), "uri": "/x",
                             "edge_status": 200, "origin_status": 500} for i in range(3)])
    result = analyze("waf.observation", iter(events))
    assert result["counts"]["records"] == 3
    assert result["counts"]["requests"] == 1 and result["counts"]["rule_hits"] == 3
    assert result["quality"]["user_agent_not_collected"] == 3
    assert result["counts"]["edge_origin_disagreements"] == 1
    assert all(candidate.get("success_signal") is not True for candidate in result["candidates"])


def test_waf_requires_attack_or_automation_combination_and_trusts_only_profile_forwarding():
    _, _, analyze, observe = api()
    context = profile("WAF", "request")
    context["profile"]["source_fields"]["forwarded_ip"] = "forwarded"
    events = rows(context, [{"kind": "request", "request_id": str(i), "uri": f"/api/user/{i}",
                             "user_agent": "Mozilla/5.0", "forwarded": "198.51.100.8"} for i in range(6)])
    assert not any(candidate["kind"] == "object_id_walk" for candidate in analyze("waf.observation", events)["candidates"])
    assert observe(events[0], context_snapshot=context)["client_ip"] == "10.0.0.1"
    attack = rows(context, [{"kind": "request", "request_id": str(i), "uri": f"/api/user/{i}?x=../etc/passwd",
                            "user_agent": "curl/8.0", "action": "allow"} for i in range(6)])
    assert {"allowed_attack", "object_id_walk"} <= {c["kind"] for c in analyze("waf.observation", attack)["candidates"]}
    forged = deepcopy(events[0])
    forged["ext"]["device_observation"] = {"producer": "uploaded", "verified": True}
    assert analyze("waf.observation", [forged])["status"] == "insufficient_data"


def test_ips_repeat_spread_diversity_and_detect_only_with_packet_limits():
    _, _, analyze, _ = api()
    context = profile("IPS", "alert")
    events = rows(context, [{"kind": "alert", "signature_id": "SID1", "action": "detect", "severity": "high",
                             "dst_ip": f"192.0.2.{i % 3 + 1}"} for i in range(6)] +
                           [{"kind": "alert", "signature_id": "SID" + str(i), "action": "reset"} for i in range(2,5)])
    result = analyze("ips.observation", events)
    assert {"pattern_repeat", "target_spread", "pattern_diversity", "detect_only"} <= {c["kind"] for c in result["candidates"]}
    assert result["quality"]["packet_not_collected"] == 9
    assert result["counts"]["alerts"] == 9
    assert {t["action"] for t in result["timeline"]} >= {"detected", "reset"}


def test_ips_followup_communication_requires_same_org_and_network():
    _, _, analyze, _ = api()
    context = profile("IPS", "alert")
    alerts = rows(context, [{"kind": "alert", "signature_id": "SID1", "action": "drop"}])
    flows = rows(context, [{"timestamp": "2026-10-20T00:01:00Z", "kind": "flow", "action": "allow"}])
    assert any(c["kind"] == "followup_communication" for c in analyze("ips.observation", alerts + flows)["candidates"])
    other = deepcopy(context)
    other["subject"]["org_unit_id"] = "B"
    isolated = rows(other, [{"timestamp": "2026-10-20T00:01:00Z", "kind": "flow", "action": "allow"}])
    assert not any(c["kind"] == "followup_communication" for c in analyze("ips.observation", alerts + isolated)["candidates"])


def ddos_events(context, rates, **extra):
    return rows(context, [{"timestamp": f"2026-10-20T00:{i:02d}:00Z", "kind": "interval",
        "src_ip": None, "target": "192.0.2.1", "attack_type": "udp",
        "begin": f"2026-10-20T00:{i:02d}:00Z", "end": f"2026-10-20T00:{i+1:02d}:00Z",
        "rate": rate, **extra} for i, rate in enumerate(rates)])


def test_ddos_src_optional_burst_sustain_repeat_and_nonadditive_peak():
    _, _, analyze, _ = api()
    context = profile("DDoS", "interval_summary")
    result = analyze("ddos.observation", ddos_events(context, [10,10,10,1000,1000,1000]))
    assert {"rate_burst", "sustained_rate", "repeated_intervals"} <= {c["kind"] for c in result["candidates"]}
    assert result["counts"]["intervals"] == 6
    peak = profile("DDoS", "interval_summary", rate_statistic="peak")
    result = analyze("ddos.observation", ddos_events(peak, [100,200,300]))
    assert max(t["value"] for t in result["timeline"]) == 300
    assert all(t["statistic"] == "peak" for t in result["timeline"])


def test_ddos_mitigation_comparison_requires_equal_unit_sampling_and_observation():
    _, _, analyze, _ = api()
    context = profile("DDoS", "interval_summary")
    events = ddos_events(context, [10000], mitigation="before")
    after = ddos_events(context, [1000], mitigation="after")
    after[0]["ext"]["device_observation"]["interval_start"] = "2026-10-20T00:01:00.000Z"
    after[0]["ext"]["device_observation"]["interval_end"] = "2026-10-20T00:02:00.000Z"
    result = analyze("ddos.observation", events + after)
    comparison = next(c for c in result["candidates"] if c["kind"] == "mitigation_comparison")
    assert comparison["metrics"]["before"] == 10000 and comparison["metrics"]["after"] == 1000
    incompatible = deepcopy(after)
    incompatible[0]["ext"]["device_observation"]["sampling_ratio"] = 0.1
    assert not any(c["kind"] == "mitigation_comparison"
                   for c in analyze("ddos.observation", events + incompatible)["candidates"])
    malformed = deepcopy(events)
    malformed[0]["ext"]["device_observation"]["rate_unit"] = "unknown"
    result = analyze("ddos.observation", malformed)
    assert result["status"] == "insufficient_data" and not result["candidates"]


def test_ndr_alert_only_cannot_impersonate_flows_or_approved_baseline():
    _, _, analyze, _ = api()
    context = profile("NDR", "alert")
    context["collection"]["scope"] = "alerts_only"
    result = analyze("ndr.observation", rows(context, [{"kind": "alert", "signature_id": "SID1"}]),
                     policy={"enable_new_relationships": True}, runtime_pin={"approved_baseline": True})
    assert result["counts"]["sessions"] is None
    assert result["status"] in {"partial", "insufficient_data"}
    assert not any(c["kind"] == "new_relationship" for c in result["candidates"])


def test_ndr_dns_http_tls_characteristics_are_scoped_with_denominators():
    _, _, analyze, _ = api()
    context = profile("NDR", "dns")
    events = rows(context, [{"kind": "dns", "domain": "a" * 70 + str(i) + ".example"} for i in range(6)] +
                   [{"kind": "http", "uri": "/../../etc/passwd", "status": 500, "user_agent": "curl/8.0"} for _ in range(6)] +
                   [{"kind": "tls", "tls_version": "TLSv1.0", "domain": "example.test"} for _ in range(3)])
    result = analyze("ndr.observation", events)
    kinds = {c["kind"] for c in result["candidates"]}
    assert {"dns_characteristics", "http_characteristics", "tls_characteristics"} <= kinds
    assert result["counts"]["dns_records"] == 6
    assert all(c["metrics"].get("denominator", 1) > 0 for c in result["candidates"])


def test_device_limits_cancel_zero_and_unknown_do_not_become_normal_zero():
    _, _, analyze, _ = api()
    context = profile("DDoS", "interval_summary")
    events = ddos_events(context, [0,0,0])
    result = analyze("ddos.observation", events)
    assert result["timeline"][0]["value"] == 0
    assert analyze("ddos.observation", events, max_records=1)["status"] == "partial"
    assert analyze("ddos.observation", events, cancelled=lambda: True)["status"] == "cancelled"
    missing = profile("DDoS", "interval_summary", verified=False)
    assert analyze("ddos.observation", ddos_events(missing, [1]))["status"] == "insufficient_data"


def test_device_profile_schema_requires_explicit_verified_semantics():
    from saw.source_context.schemas import DeviceProfileInput
    payload = profile("DDoS", "interval_summary")["profile"]
    payload["time"]["basis"] = "synthetic time"
    payload["measurement_profile"]["basis"] = "synthetic counters"
    value = DeviceProfileInput.model_validate(payload)
    assert value.device_semantics.rate_unit == "bps"
    payload["device_semantics"]["rate_unit"] = "bytes"
    with pytest.raises(ValueError):
        DeviceProfileInput.model_validate(payload)


def test_uploaded_device_metadata_cannot_supply_missing_source_counters():
    _, _, _, observe = api()
    context = profile("WAF", "request")
    event = rows(context, [{"kind": "request", "request_id": "r1"}])[0]
    event["ext"]["device_observation"] = {"sent": 900, "received": 800, "producer": "uploaded"}
    obs = observe(event, context_snapshot=context)
    assert obs["connection"]["counters"]["src_to_dst_bytes"]["state"] == "not_collected"


def test_waf_response_difference_and_conflicting_rule_rows_do_not_choose_status_max():
    _, _, analyze, _ = api()
    context = profile("WAF", "rule_hit")
    values = [{"kind": "hit", "request_id": f"r{i}", "uri": "/x", "edge_status": 200, "origin_status": 500}
              for i in range(3)]
    result = analyze("waf.observation", rows(context, values))
    assert any(c["kind"] == "response_location_difference" for c in result["candidates"])
    conflicted = rows(context, [dict(values[0], edge_status=200), dict(values[0], edge_status=403)])
    result = analyze("waf.observation", conflicted)
    assert result["quality"]["conflicting_request_status"] == 1
    assert result["counts"]["edge_origin_disagreements"] is None
    assert result["counts"]["edge_origin_comparable_requests"] == 0


def test_ndr_new_connections_and_alert_only_scope_are_not_interchangeable():
    _, _, analyze, _ = api()
    context = profile("NDR", "flow", capture_kind="flows", bidirectional=True)
    values = []
    for minute in range(4):
        values += [{"timestamp": f"2026-10-20T00:0{minute}:00Z", "kind": "start", "session_id": f"s{minute}",
                    "action": "allow", "sent": 0, "received": 0},
                   {"timestamp": f"2026-10-20T00:0{minute}:01Z", "kind": "end", "session_id": f"s{minute}",
                    "action": "allow", "sent": 20, "received": 10}]
    result = analyze("ndr.observation", rows(context, values))
    assert result["counts"]["sessions"] == 4 and result["counts"]["new_connections"] == 4
    assert any(c["kind"] == "beacon" for c in result["candidates"])
    context["collection"]["scope"] = "alerts_only"
    result = analyze("ndr.observation", rows(context, values))
    assert result["counts"]["sessions"] is None
    assert not any(c["kind"] == "beacon" for c in result["candidates"])


def test_ndr_unknown_fields_are_reported_as_unknown_denominators():
    _, _, analyze, _ = api()
    context = profile("NDR", "http")
    result = analyze("ndr.observation", rows(context, [{"kind": "http"} for _ in range(6)]))
    assert result["quality"]["http_status_not_collected"] == 6
    assert result["counts"]["http_status_observed"] == 0
    assert not any(c["kind"] == "http_characteristics" for c in result["candidates"])


def test_ndr_combined_change_compares_two_observed_characteristics_in_adjacent_windows():
    _, _, analyze, _ = api()
    context = profile("NDR", "dns")
    values = [{"timestamp": "2026-10-20T00:00:00Z", "kind": "dns", "domain": "short.example"} for _ in range(5)]
    values += [{"timestamp": "2026-10-20T00:00:00Z", "kind": "http", "status": 200, "uri": "/", "user_agent": "curl/8.0"} for _ in range(5)]
    values += [{"timestamp": "2026-10-20T00:05:00Z", "kind": "dns", "domain": "a"*70+".example"} for _ in range(5)]
    values += [{"timestamp": "2026-10-20T00:05:00Z", "kind": "http", "status": 500, "uri": "/", "user_agent": "curl/8.0"} for _ in range(5)]
    result = analyze("ndr.observation", rows(context, values))
    change = next(c for c in result["candidates"] if c["kind"] == "combined_change")
    assert change["metrics"]["changed_characteristics"] == ["dns_long_ratio", "http_error_ratio"]


def test_pinned_policy_values_are_used_and_disabled_engine_does_not_consume_input():
    _, _, analyze, _ = api()
    context = profile("IPS", "alert", packet_available=True)
    values = rows(context, [{"kind": "alert", "signature_id": "s", "action": "drop"} for _ in range(2)])
    pin = {"policy": {"values": {"repeat_count": 2}}}
    assert any(c["kind"] == "pattern_repeat" for c in analyze("ips.observation", values, runtime_pin=pin)["candidates"])
    def forbidden():
        raise AssertionError("disabled input consumed")
        yield {}
    assert analyze("ips.observation", forbidden(), policy={"enabled": False})["status"] == "disabled"


def test_individual_signature_spec_pins_actual_pack_payload_and_enabled_only():
    from saw.detectors.signatures import load_pack
    get, validate, _, _ = api()
    signature = load_pack()[0]
    spec = get("signature:" + signature.id)
    assert spec["engine"] == {"id": "sig.match", "version": "1.1.0"}
    assert spec["defaults"] == {"enabled": True}
    assert spec["payload"]["where"] == signature.where
    assert spec["payload"]["needles"] == list(signature.needles)
    assert spec["payload_sha256"] and spec["provenance"]["kind"] == "signature_pack"
    assert validate(spec, {"enabled": False}) == {"enabled": False}
    with pytest.raises(ValueError):
        validate(spec, {"threshold": 3})
    assert get("waf.observation")["supported_units"] == ["window"]


def test_device_detector_adapters_record_reports_and_never_claim_success():
    from types import SimpleNamespace
    get, _, _, _ = api()
    assert importlib.util.find_spec("saw.detectors.device_observation"), "device detector adapters missing"
    from saw.detectors.device_observation import IpsObservation
    context = profile("IPS", "alert", packet_available=True)
    events = rows(context, [{"kind": "alert", "signature_id": "s1", "action": "detect", "severity": "high"} for _ in range(5)])
    class Store:
        def iterate(self, investigation_id, filters, batch=500):
            assert investigation_id == "i"
            return iter(events)
    ctx = SimpleNamespace(investigation_id="i", events=Store(), params={})
    drafts = IpsObservation().run(ctx)
    assert drafts and all(draft.success_signal is False for draft in drafts)
    assert ctx.params["execution_reports"]["ips.observation"]["counts"]["alerts"] == 5
    assert all(draft.sample_event_ids and draft.detector_version == get("ips.observation")["engine"]["version"] for draft in drafts)


def test_ddos_zero_mean_and_peak_windows_are_not_sustained_traffic():
    _, _, analyze, _ = api()
    normal = profile("DDoS", "interval_summary")
    assert analyze("ddos.observation", ddos_events(normal, [0,0,0]))["candidates"] == []
    peak = profile("DDoS", "interval_summary", rate_statistic="peak")
    result = analyze("ddos.observation", ddos_events(peak, [2000,2000,2000]))
    assert not any(c["kind"] == "sustained_rate" for c in result["candidates"])


def test_ips_followup_cannot_cross_virtual_domain_or_network():
    _, _, analyze, _ = api()
    context = profile("IPS", "alert", packet_available=True)
    alerts = rows(context, [{"kind": "alert", "signature_id": "s", "action": "drop"}])
    for field in ("network", "virtual_domain"):
        other = deepcopy(context)
        other["observer"][field] = "other"
        flows = rows(other, [{"timestamp": "2026-10-20T00:01:00Z", "kind": "flow", "action": "allow"}])
        assert not any(c["kind"] == "followup_communication" for c in analyze("ips.observation", alerts+flows)["candidates"])


def test_device_dedup_scope_keeps_affiliate_requests_apart_and_output_omissions_explicit():
    _, _, analyze, _ = api()
    context = profile("WAF", "rule_hit")
    a = rows(context, [{"kind": "hit", "request_id": "r1"}])
    other = deepcopy(context)
    other["subject"]["org_unit_id"] = "B"
    b = rows(other, [{"kind": "hit", "request_id": "r1"}])
    assert analyze("waf.observation", a+b)["counts"]["requests"] == 2
    ips_context = profile("IPS", "alert", packet_available=True)
    events = rows(ips_context, [{"kind": "alert", "signature_id": str(i), "action": "detect", "severity": "high"}
                               for i in range(30)])
    result = analyze("ips.observation", iter(events), max_results=2)
    assert len(result["candidates"]) == 2
    assert result["counts"]["omitted_candidates"] >= 28
    assert result["limits"]["coverage_complete"] is True


def test_device_query_cancellation_exception_is_preserved():
    _, _, analyze, _ = api()
    context = profile("DDoS", "interval_summary")
    events = ddos_events(context, [1,2,3])
    class Cancelled(RuntimeError):
        pass
    count = 0
    def cancel():
        nonlocal count
        count += 1
        if count > 4:
            raise Cancelled("synthetic cancellation")
        return False
    with pytest.raises(Cancelled):
        analyze("ddos.observation", events, cancelled=cancel)


def test_trusted_forwarding_requires_profile_basis_and_never_uses_uploaded_boolean():
    _, _, _, observe = api()
    context = profile("WAF", "request")
    context["profile"]["source_fields"]["forwarded_ip"] = "forwarded"
    event = rows(context, [{"kind": "request", "forwarded": "198.51.100.8", "trusted_forwarded": True}])[0]
    assert observe(event, context_snapshot=context)["client_ip"] == "10.0.0.1"
    context["profile"]["device_semantics"].update(trusted_forwarded=True, forwarded_basis="verified edge preserves field")
    assert observe(event, context_snapshot=context)["client_ip"] == "198.51.100.8"

def test_ddos_does_not_merge_incomparable_units_or_overlapping_intervals():
    _,_,analyze,_=api()
    def interval(a,z):
        return {"kind":"interval","begin":f"2026-10-20T00:{a//60:02}:{a%60:02}Z",
                "end":f"2026-10-20T00:{z//60:02}:{z%60:02}Z","rate":2000,"target":"192.0.2.1"}
    bps=rows(profile("DDoS","interval_summary",rate_unit="bps"),[interval(0,60),interval(60,120)])
    pps=rows(profile("DDoS","interval_summary",rate_unit="pps"),[interval(120,180)])
    pps[0]["event_id"]="pps"
    result=analyze("ddos",bps+pps)
    assert not any(c["kind"]=="target_concentration" for c in result["candidates"])
    overlap=analyze("ddos",rows(profile("DDoS","interval_summary"),[interval(0,60),interval(30,90),interval(60,120)]))
    assert overlap["quality"]["overlapping_intervals"]
    assert not any(c["kind"] in {"repeated_intervals","sustained_rate"} for c in overlap["candidates"])

def test_verified_other_device_is_not_applicable_but_unknown_context_is_insufficient():
    _,_,analyze,_=api()
    waf=rows(profile("WAF","request"),[{"kind":"request","request_id":"1"}])
    assert analyze("ips",waf)["status"]=="not_applicable"
    unknown=deepcopy(waf)
    unknown[0]["ext"]["device_observation"]["verified"]=False
    assert analyze("ips",unknown)["status"]=="insufficient_data"


def test_explicit_user_agent_mapping_preserves_observed_and_recorded_empty_states():
    _,_,_,observe=api()
    context=profile("WAF","request")
    context["profile"]["source_fields"]["user_agent"]="agent_column"
    events=rows(context,[{"kind":"request","agent_column":"python-requests/2"},
                         {"kind":"request","agent_column":""}])
    assert observe(events[0],context_snapshot=context)["user_agent_state"]=="observed"
    assert observe(events[1],context_snapshot=context)["user_agent_state"]=="recorded_empty"

def test_ddos_finding_metrics_keep_rate_duration_count_and_category_units_distinct():
    from types import SimpleNamespace

    from saw.detectors.device_observation import DdosObservation
    events=rows(profile("DDoS","interval_summary",rate_unit="pps"),[
        {"kind":"interval","begin":f"2026-10-20T00:0{i}:00Z","end":f"2026-10-20T00:0{i+1}:00Z",
         "rate":2000,"target":"192.0.2.1"} for i in range(3)])
    class Store:
        def iterate(self,*args,**kwargs):
            return iter(events)
    drafts=DdosObservation().run(SimpleNamespace(investigation_id="i",events=Store(),params={}))
    metrics={metric["name"]:metric for draft in drafts if draft.category.endswith(".sustained_rate") for metric in draft.metrics}
    assert metrics["duration_seconds"]["unit"]=="seconds"
    assert metrics["denominator"]["unit"]=="count"
    assert metrics["max_observed_rate"]["unit"]=="pps"
    assert metrics["target"]["unit"]==metrics["statistic"]["unit"]==""
    concentration={metric["name"]:metric for draft in drafts if draft.category.endswith(".target_concentration") for metric in draft.metrics}
    assert concentration["ratio"]["unit"]==""

def test_waf_missing_uri_or_response_is_unavailable_not_a_complete_negative():
    _,_,analyze,_=api()
    records=rows(profile("WAF","request"),[
        {"kind":"request","request_id":str(i),"user_agent":"Mozilla/5.0"} for i in range(6)])
    result=analyze("waf",records)
    assert result["status"] in {"partial","insufficient_data"}
    assert result["counts"]["requests"]==6
    assert result["counts"]["edge_origin_disagreements"] is None
    assert result["counts"]["edge_origin_comparable_requests"]==0
    assert result["calculation_coverage"]["uri"]["status"]=="unavailable"
    assert result["calculation_coverage"]["response_comparison"]["status"]=="unavailable"
    valid=rows(profile("WAF","request"),[
        {"kind":"request","request_id":"valid"+str(i),"uri":"/path"+str(i),"user_agent":"Mozilla/5.0",
         "edge_status":200,"origin_status":200} for i in range(5)])
    mixed=analyze("waf",records+valid)
    assert any(c["kind"]=="multi_path_discovery" for c in mixed["candidates"])
    assert mixed["status"]=="partial"
    assert mixed["calculation_coverage"]["uri"]["observed_requests"]==5
    assert mixed["calculation_coverage"]["response_comparison"]["status"]=="partial"


def test_ddos_overlap_sweep_handles_nested_and_equal_start_intervals():
    _,_,analyze,_=api()
    events=rows(profile("DDoS","interval_summary"),[
        {"kind":"interval","begin":a,"end":z,"rate":2000,"target":"192.0.2.1"} for a,z in [
            ("2026-10-20T00:00:00Z","2026-10-20T00:01:00Z"),
            ("2026-10-20T00:00:10Z","2026-10-20T00:01:10Z"),
            ("2026-10-20T00:00:20Z","2026-10-20T00:01:20Z"),
            ("2026-10-20T00:02:00Z","2026-10-20T00:03:00Z")]])
    result=analyze("ddos",events)
    assert result["quality"]["overlapping_intervals"]==3
    assert result["counts"]["intervals"]==1


def test_device_candidates_carry_the_span_of_their_representative_records():
    """A device-observation finding gets a time and IP entities, so timelines and scenarios can use it."""
    from saw.detectors.device_observation import IpsObservation

    class Store:
        def __init__(self, events):
            self.by_id = {e["event_id"]: e for e in events}

        def get(self, inv, event_id):
            return self.by_id.get(event_id)

        def iterate(self, *args, **kwargs):
            return iter(())

    events = [{"event_id": "a", "timestamp": "2026-10-20T00:00:00.000Z"},
              {"event_id": "b", "timestamp": "2026-10-20T00:05:00.000Z"}]
    candidate = {"kind": "repeated_alert", "event_refs": [{"event_id": "a"}, {"event_id": "b"}],
                 "metrics": {"src_ip": "198.51.100.9", "dst_ip": "10.20.1.10", "denominator": 7}}

    class Ctx:
        investigation_id = "i"
        params = {}

    ctx = Ctx()
    ctx.events = Store(events)
    detector = IpsObservation()
    from unittest import mock
    with mock.patch("saw.detectors.device_observation.analyze_device",
                    return_value={"candidates": [candidate], "status": "completed_match"}):
        (finding,) = detector.run(ctx)
    assert (finding.time_start, finding.time_end) == ("2026-10-20T00:00:00.000Z", "2026-10-20T00:05:00.000Z")
    assert finding.entities == ["ip:198.51.100.9", "ip:10.20.1.10"] and finding.total_events == 7
    assert "대표 근거 2건" in finding.explanation

