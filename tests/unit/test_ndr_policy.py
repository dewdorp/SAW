"""Synthetic coverage for site-specific, disabled-by-default connection policies."""
from copy import deepcopy

import pytest

from saw.detectors.ndr_policy import evaluate, load


def event(**overrides):
    return {"event_id": "e1", "data_source": "zeek_conn", "timestamp": "2026-10-10T15:00:00Z",
            "src_ip": "10.2.0.5", "dst_ip": "198.51.100.8", "dst_port": 443,
            "bytes_out": 2 * 1024**3, "bytes_in": 100,
            "ext": {"ndr": {"dst_country": "US"}}, **overrides}


def policy(rule_id):
    cfg = deepcopy(load())
    for r in cfg["rules"]:
        r["enabled"] = r["id"] == rule_id
    cfg["site"]["baseline_note"] = "Approved synthetic service inventory 2026-10-11"
    return cfg


def test_shipped_rules_are_disabled_and_do_not_invent_baselines():
    cfg = load()
    assert len(cfg["rules"]) == 5
    assert not any(r["enabled"] for r in cfg["rules"])
    assert evaluate([event()], cfg) == []
    assert all(r["examples"] and r["benign"] and r["checks"] for r in cfg["rules"])


@pytest.mark.parametrize("rule_id", ["large_outbound", "unexpected_port", "foreign_destination",
                                     "off_hours_admin", "internal_admin"])
def test_each_yaml_rule_has_positive_and_negative_examples(rule_id):
    cfg = policy(rule_id)
    r = next(r for r in cfg["rules"] if r["id"] == rule_id)
    for case in r["examples"]:
        assert any(d.category == "ndr." + rule_id for d in evaluate(case, cfg))
    for case in r["benign"]:
        assert not any(d.category == "ndr." + rule_id for d in evaluate(case, cfg))


def test_volume_is_outbound_sum_for_source_in_one_configured_window():
    cfg = policy("large_outbound")
    r = next(r for r in cfg["rules"] if r["id"] == "large_outbound")
    r["min_bytes"] = 100
    rows = [event(event_id="a", bytes_out=60), event(event_id="b", bytes_out=60, dst_ip="203.0.113.8")]
    d, = evaluate(rows, cfg)
    assert d.total_events == 2
    assert any(m["name"] == "bytes_out" and m["observed"] == 120 for m in d.metrics)
    assert evaluate([event(bytes_out=1, bytes_in=10**9)], cfg) == []
    rows[1]["timestamp"] = "2026-10-10T17:00:00Z"
    assert evaluate(rows, cfg) == []


def test_unknown_country_or_time_is_not_assumed_foreign_or_after_hours():
    assert not any(d.category == "ndr.foreign_destination" for d in evaluate([event(ext={})], policy("foreign_destination")))
    assert not any(d.category == "ndr.foreign_destination" for d in evaluate([event(ext={"ndr": {"dst_country": "UNKNOWN"}})], policy("foreign_destination")))
    cfg = policy("off_hours_admin")
    for ts in (None, "bad", "2026-10-10T15:00:00"):
        assert not any(d.category == "ndr.off_hours_admin" for d in evaluate([event(timestamp=ts, dst_port=22)], cfg))


def test_configured_cidr_and_port_baseline_are_required():
    cfg = policy("unexpected_port")
    cfg["site"]["baseline_note"] = ""
    with pytest.raises(ValueError, match="baseline"):
        evaluate([event(dst_port=4444)], cfg)
    cfg["site"]["baseline_note"] = "Approved synthetic service inventory"
    cfg["site"]["internal_cidrs"] = []
    with pytest.raises(ValueError, match="internal_cidrs"):
        evaluate([event(dst_port=4444)], cfg)


def test_limits_are_visible_and_do_not_claim_complete_no_match():
    cfg = policy("large_outbound")
    cfg["limits"]["max_events"] = 1
    rows = [event(event_id="a", bytes_out=1), event(event_id="b", bytes_out=1)]
    d, = evaluate(rows, cfg)
    assert d.category == "ndr.coverage"
    assert any(c["passed"] is False for c in d.checks)
    assert "일부" in d.explanation
    assert d.success_signal is False


def test_evidence_is_sample_bounded_and_keeps_source_role():
    cfg = policy("large_outbound")
    cfg["limits"]["max_samples"] = 2
    ds = evaluate([event(event_id=str(i)) for i in range(4)], cfg)
    d, = ds
    assert len(d.sample_event_ids) == 2 and d.total_events == 4
    assert d.evidence_query["entity_roles"]["source"] == ["10.2.0.5"]
    assert d.evidence_query["sample_only"] is True
    assert d.attack[0].condition_met is False


def test_enabling_port_policy_requires_replacing_the_shipped_example_baseline():
    cfg = deepcopy(load())
    next(r for r in cfg["rules"] if r["id"] == "unexpected_port")["enabled"] = True
    with pytest.raises(ValueError, match="baseline"):
        evaluate([event(dst_port=4444)], cfg)
    cfg["site"]["baseline_note"] = "예시 기준입니다. 사용 전 승인된 서비스 목록과 기준일로 바꾸세요."
    with pytest.raises(ValueError, match="baseline"):
        evaluate([event(dst_port=4444)], cfg)


@pytest.mark.parametrize("kind,overrides,missing", [
    ("large_outbound", {"bytes_out": None}, "bytes_out"),
    ("large_outbound", {"bytes_out": True}, "bytes_out"),
    ("large_outbound", {"bytes_out": 1.5}, "bytes_out"),
    ("large_outbound", {"bytes_out": "invalid"}, "bytes_out"),
    ("large_outbound", {"bytes_out": -1}, "bytes_out"),
    ("unexpected_port", {"dst_port": None}, "dst_port"),
    ("unexpected_port", {"dst_port": True}, "dst_port"),
    ("unexpected_port", {"dst_port": 443.5}, "dst_port"),
    ("off_hours_admin", {"dst_port": None}, "dst_port"),
    ("internal_admin", {"dst_ip": "10.2.0.8", "dst_port": None}, "dst_port"),
    ("foreign_destination", {"ext": {}}, "dst_country"),
    ("foreign_destination", {"ext": {"ndr": {"dst_country": "QQ"}}}, "dst_country"),
    ("foreign_destination", {"ext": {"ndr": {"dst_country": "ZZ"}}}, "dst_country"),
    ("foreign_destination", {"ext": []}, "dst_country"),
])
def test_required_missing_or_invalid_inputs_are_visible_without_an_attack(kind, overrides, missing):
    ds = evaluate([event(**overrides)], policy(kind))
    assert not any(d.category == "ndr." + kind for d in ds)
    coverage, = [d for d in ds if d.category == "ndr.coverage"]
    assert any(m["name"] == "missing_" + missing and m["observed"] == 1 for m in coverage.metrics)
    assert coverage.success_signal is False


def test_missing_field_for_one_rule_does_not_hide_valid_evidence_for_another():
    cfg = policy("foreign_destination")
    next(r for r in cfg["rules"] if r["id"] == "large_outbound")["enabled"] = True
    ds = evaluate([event(ext={})], cfg)
    assert {d.category for d in ds} == {"ndr.large_outbound", "ndr.coverage"}
    assert any(c["passed"] is False for d in ds if d.category == "ndr.large_outbound" for c in d.checks)


def test_irrelevant_missing_values_and_real_zero_bytes_do_not_claim_incomplete_coverage():
    assert evaluate([event(dst_ip="10.2.0.8", ext={})], policy("foreign_destination")) == []
    assert evaluate([event(bytes_out=0)], policy("large_outbound")) == []
    ds = evaluate([event(dst_ip="10.2.0.8", dst_port=22, bytes_out=None, ext={})], policy("internal_admin"))
    assert [d.category for d in ds] == ["ndr.internal_admin"]
    assert any(m["name"] == "bytes_out" and m["approx"] is True for m in ds[0].metrics)


@pytest.mark.parametrize("section,key,value", [
    ("root", "version", True),
    ("root", "typo", 1),
    ("site", "home_countries", ["ZZ"]),
    ("site", "home_countries", ["QQ"]),
    ("site", "home_countries", "KR"),
    ("site", "allowed_ports", [True]),
    ("site", "admin_ports", "22"),
    ("site", "work_start_hour", True),
    ("site", "work_end_hour", 18.5),
    ("site", "work_days", [True]),
    ("site", "internal_cidrs", "10.0.0.0/8"),
    ("site", "timezone", "Not/AZone"),
    ("site", "baseline_note", 123),
    ("rule", "severity", True),
    ("rule", "severity", "high"),
    ("rule", "stage", "NOT_A_STAGE"),
    ("rule", "attack", "T1041"),
    ("rule", "checks", "not-a-list"),
    ("rule", "min_byte", 100),
    ("rule", "window_seconds", False),
])
def test_invalid_config_fails_with_a_validation_error(section, key, value):
    cfg = policy("off_hours_admin")
    target = cfg if section == "root" else (cfg["site"] if section == "site" else cfg["rules"][0])
    target[key] = value
    with pytest.raises(ValueError):
        evaluate([], cfg)


def test_missing_config_sections_are_validation_errors():
    cfg = policy("large_outbound")
    del cfg["limits"]["max_events"]
    with pytest.raises(ValueError):
        evaluate([], cfg)


def test_coverage_counts_towards_the_result_limit():
    cfg = policy("large_outbound")
    cfg["limits"]["max_findings"] = 1
    ds = evaluate([event(event_id="a"), event(event_id="b", src_ip="10.2.0.6")], cfg)
    assert len(ds) == 1 and ds[0].category == "ndr.coverage"


def test_group_limit_is_explicit_and_samples_remain_bounded():
    cfg = policy("large_outbound")
    cfg["limits"].update(max_groups=1, max_samples=1, max_findings=2)
    ds = evaluate([event(event_id="a"), event(event_id="b", src_ip="10.2.0.6")], cfg)
    assert {d.category for d in ds} == {"ndr.large_outbound", "ndr.coverage"}
    assert all(len(d.sample_event_ids) <= 1 for d in ds)


def test_oversized_evidence_identifier_is_skipped_with_coverage():
    ds = evaluate([event(event_id="x" * 300)], policy("large_outbound"))
    assert [d.category for d in ds] == ["ndr.coverage"]
    assert any(m["name"] == "missing_event_id" and m["observed"] == 1 for m in ds[0].metrics)


def test_many_bad_fields_count_an_incomplete_event_once():
    ds = evaluate([event(timestamp=None, src_ip=None, event_id=None)], policy("large_outbound"))
    coverage, = ds
    assert any(m["name"] == "skipped" and m["observed"] == 1 for m in coverage.metrics)
    assert {m["name"] for m in coverage.metrics} >= {"missing_timestamp", "missing_src_ip", "missing_event_id"}


def test_disabled_policies_do_not_consume_input():
    def rows():
        raise AssertionError("disabled policy must not read rows")
        yield
    assert evaluate(rows(), deepcopy(load())) == []


def test_unrepresentable_local_time_is_visible_instead_of_crashing():
    ds = evaluate([event(timestamp="9999-12-31T23:00:00Z", dst_port=22)], policy("off_hours_admin"))
    assert [d.category for d in ds] == ["ndr.coverage"]
    assert any(m["name"] == "missing_timestamp" for m in ds[0].metrics)


def test_decimal_strings_and_custom_internal_cidr_are_supported():
    cfg = policy("large_outbound")
    cfg["site"]["internal_cidrs"] = ["203.0.113.0/24"]
    ds = evaluate([event(src_ip="203.0.113.5", bytes_out=str(2 * 1024**3), dst_port="443")], cfg)
    assert [d.category for d in ds] == ["ndr.large_outbound"]
    assert evaluate([event()], cfg) == []


def test_exact_event_and_finding_limits_do_not_claim_truncation():
    cfg = policy("large_outbound")
    cfg["limits"].update(max_events=1, max_findings=1)
    ds = evaluate([event()], cfg)
    assert [d.category for d in ds] == ["ndr.large_outbound"]


def test_event_limit_consumes_only_one_lookahead_item():
    cfg = policy("large_outbound")
    cfg["limits"]["max_events"] = 2
    consumed = []
    def rows():
        for i in range(100):
            consumed.append(i)
            yield event(event_id=str(i), bytes_out=1)
    assert [d.category for d in evaluate(rows(), cfg)] == ["ndr.coverage"]
    assert consumed == [0, 1, 2]


def test_working_hours_do_not_require_a_port_for_the_off_hours_rule():
    assert evaluate([event(timestamp="2026-10-12T01:00:00Z", dst_port=None)], policy("off_hours_admin")) == []


def test_ip_numeric_coercion_does_not_create_an_internal_source():
    ds = evaluate([event(src_ip=167903237)], policy("large_outbound"))
    assert [d.category for d in ds] == ["ndr.coverage"]


def test_one_missing_port_counts_once_with_multiple_enabled_rules():
    cfg = policy("unexpected_port")
    next(r for r in cfg["rules"] if r["id"] == "off_hours_admin")["enabled"] = True
    ds = evaluate([event(dst_port=None)], cfg)
    coverage, = ds
    assert any(m["name"] == "missing_dst_port" and m["observed"] == 1 for m in coverage.metrics)
    assert any(m["name"] == "skipped" and m["observed"] == 1 for m in coverage.metrics)


def test_explicit_empty_configuration_does_not_fall_back_to_disabled_defaults():
    from types import SimpleNamespace
    from saw.detectors.ndr_policy import NdrPolicy

    with pytest.raises(ValueError):
        NdrPolicy().run(SimpleNamespace(params={"ndr_policy": {}}))
