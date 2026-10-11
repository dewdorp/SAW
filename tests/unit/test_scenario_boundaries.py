"""Flows must preserve temporal and entity uncertainty."""
from dataclasses import replace

from saw.detectors import scenarios


def finding(fid, category, hour, entities=None, roles=None):
    return {"id": fid, "display_id": fid, "title": fid, "category": category, "stage": "DISCOVERY",
            "risk_level": "high", "success": False, "entities": entities or ["ip:10.0.0.1"],
            "entity_roles": roles or {}, "time_start": hour, "time_end": hour}


def example_scenario():
    return scenarios.Scenario("test", "가상 흐름 가능성", 0.8, (), "medium",
                              (scenarios.Step("첫 흔적", categories=("one",)),
                               scenarios.Step("다음 흔적", categories=("two",))), "추가 확인 필요", ())


def test_unrelated_days_are_not_joined(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    assert scenarios.match([finding("a", "one", "2026-10-01T00:00:00Z"),
                            finding("b", "two", "2026-10-10T00:01:00Z")]) == []


def test_invalid_or_naive_times_are_not_ordered_as_evidence(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    for invalid in ("invalid", "2026-10-10T00:00:00", None):
        assert scenarios.match([finding("a", "one", invalid),
                                finding("b", "two", "2026-10-10T00:01:00Z")]) == []


def test_later_valid_start_is_considered_after_expired_start(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    out = scenarios.match([finding("old", "one", "2026-10-01T00:00:00Z"),
                           finding("a", "one", "2026-10-10T00:00:00Z"),
                           finding("b", "two", "2026-10-10T00:01:00Z")])
    assert out[0].evidence_query["finding_ids"] == ["a", "b"]


def test_new_flows_require_same_source_role_and_strict_order(monkeypatch):
    sc = replace(example_scenario(), entity_role="source", strict_order=True)
    monkeypatch.setattr(scenarios, "load", lambda: (sc,))
    a = finding("a", "one", "2026-10-10T00:00:00Z", roles={"source": ["10.0.0.1"]})
    b = finding("b", "two", "2026-10-10T00:01:00Z", roles={"destination": ["10.0.0.1"]})
    assert scenarios.match([a, b]) == []
    b["entity_roles"] = {"source": ["10.0.0.1"]}
    assert len(scenarios.match([a, b])) == 1
    b["time_start"] = a["time_start"]
    assert scenarios.match([a, b]) == []


def test_flow_scope_exposes_bounded_time_and_does_not_assert_causation(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    d, = scenarios.match([finding("a", "one", "2026-10-10T00:00:00Z"),
                         finding("b", "two", "2026-10-10T00:01:00Z")])
    assert d.evidence_query["time"]["start"] and d.evidence_query["time"]["end"]
    assert "인과" in d.explanation


def test_new_yaml_flows_replay_positive_and_negative_cases():
    from datetime import datetime, timedelta, timezone
    import yaml

    doc = yaml.safe_load(scenarios.PACK.read_text(encoding="utf-8"))
    new = [s for s in doc["scenarios"] if s.get("entity_role") == "source"]
    assert len(new) == 3
    base = datetime(2026, 10, 11, tzinfo=timezone.utc)
    for sc in new:
        assert sc["examples"] and sc["benign"]
        for expected, cases in ((True, sc["examples"]), (False, sc["benign"])):
            for case in cases:
                rows = [finding(str(i), e["category"], (base + timedelta(seconds=e["offset"])).isoformat(),
                                entities=["ip:" + e["source"]], roles={"source": [e["source"]]})
                        for i, e in enumerate(case)]
                found = {d.category for d in scenarios.match(rows)}
                assert ("scenario." + sc["id"] in found) is expected, sc["id"]


def test_strict_flow_is_independent_of_same_timestamp_input_order(monkeypatch):
    from itertools import permutations

    sc = replace(example_scenario(), strict_order=True)
    monkeypatch.setattr(scenarios, "load", lambda: (sc,))
    a0 = finding("a0", "one", "2026-10-10T00:00:00Z")
    a60 = finding("a60", "one", "2026-10-10T00:01:00Z")
    b60 = finding("b60", "two", "2026-10-10T00:01:00Z")
    for rows in permutations([a0, a60, b60]):
        out = scenarios.match(list(rows))
        assert out and out[0].evidence_query["finding_ids"] == ["a0", "b60"]
