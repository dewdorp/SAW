"""Actual flow results and unavailable evidence have separate meanings."""
from dataclasses import replace

from saw.detectors import scenarios
from tests.unit.test_scenario_boundaries import example_scenario, finding


def test_report_pins_pack_and_actual_matches(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    rows = [finding("a", "one", "2026-10-01T00:00:00Z"),
            finding("b", "two", "2026-10-01T00:01:00Z")]
    drafts = scenarios.match(rows)
    report = scenarios.execution_report(rows, drafts)
    row = report["scenarios"][0]
    assert report["schema"] == "scenario-execution/1"
    assert len(report["pack_sha256"]) == 64
    assert row["status"] == "matched_candidate" and row["match_count"] == len(drafts) == 1
    assert [s["eligible_findings"] for s in row["steps"]] == [1, 1]
    assert report["counts"]["input_findings"] == 2
    # Authored guidance is surfaced per scenario so the result is actionable in-product.
    assert row["explain"] == "추가 확인 필요" and row["checks"] == []
    assert row["missing_steps"] == [] and row["next_step"] == scenarios.GUIDANCE["matched_candidate"]


def test_no_chain_differs_from_absent_steps(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (replace(example_scenario(), strict_order=True),))
    rows = [finding("a", "one", "2026-10-01T00:01:00Z"),
            finding("b", "two", "2026-10-01T00:00:00Z")]
    assert scenarios.match(rows) == []
    assert scenarios.execution_report(rows, [])["scenarios"][0]["status"] == "no_chain"
    report = scenarios.execution_report(rows[:1], [])
    row = report["scenarios"][0]
    assert row["status"] == "insufficient_evidence"
    assert row["steps"][1]["eligible_findings"] == 0
    assert row["missing_steps"] == [row["steps"][1]["name"]]
    assert row["next_step"] == scenarios.GUIDANCE["insufficient_evidence"]


def test_opaque_identity_and_invalid_time_cannot_join(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    rows = [finding("a", "one", "2026-10-01T00:00:00Z", entities=["ip:익명-A"]),
            finding("b", "two", "2026-10-01T00:01:00Z", entities=["ip:익명-A"])]
    assert scenarios.match(rows) == []
    report = scenarios.execution_report(rows, [])
    assert report["counts"]["eligible_findings"] == 0
    assert report["counts"]["excluded_findings"] == 2


def test_empty_report_does_not_call_missing_evidence_normal(monkeypatch):
    monkeypatch.setattr(scenarios, "load", lambda: (example_scenario(),))
    report = scenarios.execution_report([], [])
    assert report["scenarios"][0]["status"] == "insufficient_evidence"
    assert "true_negative" not in str(report)
