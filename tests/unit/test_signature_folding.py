"""Synthetic event-store regressions for stage-preserving signature folding."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from saw.detectors import scenarios, signatures as sg
from saw.detectors.base import DetectorContext
from saw.storage.eventstore import SQLiteEventStore

INV = "synthetic-folding"
SOURCE = "192.0.2.5"
BASE = datetime(2026, 10, 11, tzinfo=timezone.utc)


@pytest.fixture
def store():
    events = SQLiteEventStore(":memory:")
    yield events
    events._conn().close()


def add(events, sid, count=1, offset=0):
    events.index([
        {"event_id": f"{sid}-{i}", "investigation_id": INV, "data_source": "web",
         "timestamp": (BASE + timedelta(seconds=offset + i)).isoformat(), "src_ip": SOURCE,
         "tags": [sg.TAG + sid], "status_class": "4xx"}
        for i in range(count)
    ])


def run(events):
    return sg.SignatureMatch().run(DetectorContext(INV, events))


def metric(draft, name):
    return next(m["observed"] for m in draft.metrics if m["name"] == name)


def tags(draft):
    value = draft.evidence_query["filters"][0]["value"]
    return set(value if isinstance(value, list) else [value])


def mixed(events):
    add(events, "rce.f5_icontrol", 100)
    add(events, "rce.spring_cloud_function", offset=100)
    add(events, "rce.log4shell", offset=120)
    add(events, "rce.struts_ognl", offset=121)


def test_endpoint_probes_do_not_replace_exploitation_stage_or_evidence(store):
    mixed(store)
    drafts = run(store)

    assert len(drafts) == 2
    by_stage = {d.stage: d for d in drafts}
    assert set(by_stage) == {"DISCOVERY", "EXPLOITATION"}
    assert metric(by_stage["DISCOVERY"], "requests") == 101
    assert metric(by_stage["EXPLOITATION"], "requests") == 2
    assert tags(by_stage["DISCOVERY"]) == {"sig:rce.f5_icontrol", "sig:rce.spring_cloud_function"}
    assert tags(by_stage["EXPLOITATION"]) == {"sig:rce.log4shell", "sig:rce.struts_ognl"}
    assert {d.dedup_key for d in drafts} == {"sig-group:rce:DISCOVERY", "sig-group:rce:EXPLOITATION"}
    assert all(not d.success_signal for d in drafts)


def test_same_stage_group_keeps_existing_fold_and_dedup(store):
    add(store, "tool.sqlmap", 2)
    add(store, "tool.nikto", 3, offset=10)

    draft, = run(store)
    assert draft.category == "sig.tool"
    assert metric(draft, "requests") == 5
    assert metric(draft, "signatures") == 2
    assert tags(draft) == {"sig:tool.sqlmap", "sig:tool.nikto"}
    assert draft.dedup_key == "sig-group:tool"


def test_mixed_stage_group_key_is_stable_without_other_stage_events(store):
    add(store, "rce.log4shell")
    add(store, "rce.struts_ognl", offset=1)
    draft, = run(store)
    assert draft.stage == "EXPLOITATION"
    assert draft.dedup_key == "sig-group:rce:EXPLOITATION"


def test_exploitation_remains_available_to_stage_based_flow(store):
    mixed(store)
    execution = next(s for s in sg.load_pack() if s.group == "exec")
    add(store, execution.id, offset=180)
    findings = [
        {"id": d.dedup_key, "display_id": str(i), "title": d.title, "category": d.category,
         "stage": d.stage, "risk_level": d.risk()[1], "success": d.success_signal,
         "entities": d.entities, "time_start": d.time_start, "time_end": d.time_end}
        for i, d in enumerate(run(store))
    ]

    flows = {d.category: d for d in scenarios.match(findings)}
    assert "scenario.exec_after_exploit" in flows
    assert flows["scenario.exec_after_exploit"].evidence_query["finding_ids"][0] == "sig-group:rce:EXPLOITATION"
