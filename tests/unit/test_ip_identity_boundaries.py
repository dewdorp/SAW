"""Derived identity boundaries preserve opaque evidence without asserting an IP match."""
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from saw.analyzers.relation.build import build as relation_build
from saw.analyzers.story.build import build_story
from saw.core.application import correlation

INVALID = "SYNTHETIC-OPAQUE-DEST"
VALID = "192.0.2.40"
STAMP = datetime(2026, 10, 1, 10, tzinfo=UTC)


class Session:
    def __init__(self, findings=()):
        self.findings = list(findings)
        self.added = []

    def get(self, *args):
        return SimpleNamespace(settings={})

    def execute(self, *args):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.findings))

    def add(self, value):
        self.added.append(value)

    def flush(self):
        pass


class CrossSourceRows:
    def __init__(self, value, field="dst_ip"):
        self.value, self.field = value, field

    def group_by(self, inv, filters, fields, metrics, **kwargs):
        if fields[0] != self.field:
            return []
        return [{"key": {self.field: self.value, "data_source": source}, "count": count,
                 "first": STAMP.isoformat(), "last": STAMP.isoformat()}
                for source, count in (("connection", 12), ("web", 47))]


class RelationRows:
    def __init__(self, value, field="dst_ip"):
        self.value, self.field = value, field

    def group_by(self, inv, filters, fields, metrics, **kwargs):
        return [{"key": {"src_ip": "198.51.100.40", "dst_ip": "203.0.113.40", self.field: self.value}, "count": 1,
                 "first": STAMP.isoformat(), "last": STAMP.isoformat()}]


def finding(value, ident, stage):
    return {"id": ident, "display_id": ident, "title": "Potential synthetic observation",
            "stage": stage, "risk_level": "medium", "metrics": [],
            "entities": ["ip:" + value], "time_start": STAMP.isoformat(),
            "time_end": STAMP.isoformat(), "attack": []}


@pytest.mark.parametrize("value,valid", [(INVALID, False), (VALID, True), ("2001:db8::40", True)])
@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_cross_source_does_not_promote_opaque_text_to_ip(monkeypatch, value, valid, field):
    monkeypatch.setattr(correlation.container, "get", lambda: SimpleNamespace(events=CrossSourceRows(value, field)))
    result = correlation.run_correlation(Session(), "synthetic")
    matching = [c for c in result if c.kind == "same_ip_cross_source"]
    assert bool(matching) is valid
    if valid:
        assert matching[0].strength == "strong"


@pytest.mark.parametrize("value,valid", [(INVALID, False), (VALID, True), ("2001:db8::40", True)])
def test_finding_chain_requires_valid_ip_entity(monkeypatch, value, valid):
    field = "dst_ip"
    monkeypatch.setattr(correlation.container, "get", lambda: SimpleNamespace(events=CrossSourceRows(value, field)))
    rows = [SimpleNamespace(id="a", display_id="a", title="synthetic web", category="web.synthetic",
                            entities=["ip:" + value], time_start=STAMP),
            SimpleNamespace(id="b", display_id="b", title="synthetic network", category="net.synthetic",
                            entities=["ip:" + value], time_start=STAMP)]
    result = correlation.run_correlation(Session(rows), "synthetic")
    assert bool([c for c in result if c.kind == "finding_chain"]) is valid


@pytest.mark.parametrize("value,valid", [(INVALID, False), (VALID, True), ("2001:db8::40", True)])
def test_story_edge_does_not_use_invalid_ip_as_shared_identity(value, valid):
    inputs = [finding(value, "a", "RECON"), finding(value, "b", "EXECUTION")]
    graph = build_story(inputs)
    assert all(item["entities"] == ["ip:" + value] for item in inputs)
    reasons = [reason for edge in graph["edges"] for reason in edge["link_reason"]]
    assert ("ip:" + value in reasons) is valid
    if not valid:
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["confidence"] == "low"
        assert graph["edges"][0]["link_reason"] == ["time proximity (weak link)"]


@pytest.mark.parametrize("value,valid", [(INVALID, False), (VALID, True), ("2001:db8::40", True)])
def test_story_stage_does_not_merge_on_invalid_ip_identity(value, valid):
    graph = build_story([finding(value, "a", "RECON"), finding(value, "b", "RECON")])
    assert len(graph["nodes"]) == (1 if valid else 2)


@pytest.mark.parametrize("value,valid", [(INVALID, False), (VALID, True), ("2001:db8::40", True)])
@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_relation_graph_does_not_materialize_invalid_ip(value, valid, field):
    entities, edges = relation_build(RelationRows(value, field), "synthetic", ["zeek_conn"])
    assert ("ip:" + value in entities) is valid
    if valid:
        assert len(edges) == 1
