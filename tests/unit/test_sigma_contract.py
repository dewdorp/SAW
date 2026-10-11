"""Local Sigma execution must retain its declared semantics and reject unsupported logic."""
from __future__ import annotations

import time

import pytest
import yaml

from saw.detection.service import _in_threshold
from saw.detection.sigma_eval import SigmaError, compile_rule, evaluate


def rule(selection, condition="s", **extra):
    return yaml.safe_dump({"title": "Synthetic", "logsource": {"category": "webserver"},
                           "detection": {"s": selection, "condition": condition}, **extra})


@pytest.mark.parametrize("selection", [
    {"cs-uri|base64": "test"}, {"cs-uri|contains|endswith": "test"}, {"cs-uri|all": []},
    {"cs-uri|exists": "true"}, {"cs-uri|cidr": "not-a-network"}, {"cs-uri|re": "("},
    {"unknown_field": "test"}, {"cs-uri": {"nested": "unsupported"}},
])
def test_unsupported_or_invalid_selection_is_rejected_before_execution(selection):
    with pytest.raises(SigmaError):
        compile_rule(rule(selection))


@pytest.mark.parametrize("condition", ["missing", "s and (", "all of missing*", "s trailing"])
def test_invalid_condition_is_rejected_at_compile_time(condition):
    with pytest.raises(SigmaError):
        compile_rule(rule({"cs-uri": "/"}, condition))


def test_timeframe_and_unknown_logsource_are_not_discarded():
    text = rule({"cs-uri": "/"})
    doc = yaml.safe_load(text)
    doc["detection"]["timeframe"] = "5m"
    with pytest.raises(SigmaError):
        compile_rule(yaml.safe_dump(doc))
    with pytest.raises(SigmaError):
        compile_rule(rule({"cs-uri": "/"}, logsource={"category": "unsupported_vendor"}))


def test_cased_and_escaped_wildcards_keep_literal_meaning():
    compiled = compile_rule(rule({"cs-uri|cased": r"/A\?\*"}))
    assert evaluate(compiled, {"uri": "/A?*"})
    assert not evaluate(compiled, {"uri": "/a?*"})
    assert not evaluate(compiled, {"uri": "/AXanything"})


@pytest.mark.parametrize("expected", [True, False])
def test_exists_uses_presence_instead_of_string_comparison(expected):
    compiled = compile_rule(rule({"cs-uri|exists": expected}))
    assert evaluate(compiled, {"uri": "/"}) is expected
    assert evaluate(compiled, {}) is not expected


def test_referrer_taxonomy_reads_nested_ndr_field():
    compiled = compile_rule(rule({"cs-referrer|contains": "synthetic.example"}))
    assert evaluate(compiled, {"ext": {"ndr": {"referer": "https://synthetic.example/"}}})


def test_path_and_query_can_be_read_from_uri_when_projection_is_missing():
    compiled = compile_rule(rule({"cs-uri-stem": "/x", "cs-uri-query": "n=1"}))
    assert evaluate(compiled, {"uri": "/x?n=1"})


def test_regex_work_is_bounded_instead_of_blocking_analysis():
    compiled = compile_rule(rule({"cs-uri|re": "(a|aa)+$"}))
    start = time.monotonic()
    with pytest.raises(SigmaError):
        evaluate(compiled, {"uri": "a" * 2000 + "!"})
    assert time.monotonic() - start < 1


def test_null_selection_never_matches_the_literal_text_none():
    compiled = compile_rule(rule({"cs-uri": None}))
    assert evaluate(compiled, {})
    assert not evaluate(compiled, {"uri": "None"})


def test_duplicate_yaml_selection_fields_are_rejected():
    text = "title: Synthetic\nlogsource: {category: webserver}\ndetection:\n  s:\n    cs-uri: /first\n    cs-uri: /second\n  condition: s\n"
    with pytest.raises(SigmaError):
        compile_rule(text)


def test_distinct_threshold_excludes_missing_values_and_keeps_real_window_members():
    hits = [
        {"event_id": "a", "timestamp": "2026-01-01T00:00:00Z", "src_ip": "192.0.2.1", "url_path": "/a"},
        {"event_id": "b", "timestamp": "2026-01-01T00:00:01Z", "src_ip": "192.0.2.1"},
        {"event_id": "c", "timestamp": "2026-01-01T00:00:02Z", "src_ip": "192.0.2.1", "url_path": "/b"},
        {"event_id": "d", "timestamp": "2026-01-01T00:00:10Z", "src_ip": "192.0.2.1", "url_path": "/c"},
    ]
    threshold = {"group_by": ["src_ip"], "timespan_sec": 2, "count_gte": 2, "distinct_field": "url_path"}
    assert _in_threshold(hits[:2], threshold) == []
    assert [e["event_id"] for e in _in_threshold(hits, threshold)] == ["a", "b", "c"]


def test_threshold_requires_known_time_and_group_values():
    hits = [{"event_id": "a"}, {"event_id": "b"}]
    with pytest.raises(SigmaError):
        _in_threshold(hits, {"group_by": ["src_ip"], "count_gte": 2})


@pytest.mark.parametrize("threshold", [{"count_gte": -1}, {"count_gte": 2, "timespan_sec": -1},
                                         {"count_gte": 2, "unsupported": True}])
def test_bad_threshold_cannot_silently_change_rule_meaning(threshold):
    with pytest.raises(SigmaError):
        _in_threshold([], threshold)


@pytest.mark.parametrize("modifier,actual", [("contains", "prefix/end\\suffix"), ("startswith", "/end\\suffix")])
def test_string_modifiers_do_not_change_a_trailing_literal_backslash(modifier, actual):
    compiled = compile_rule(rule({"cs-uri|" + modifier: "/end\\"}))
    assert evaluate(compiled, {"uri": actual})
    assert not evaluate(compiled, {"uri": actual.replace(chr(92), "*")})
