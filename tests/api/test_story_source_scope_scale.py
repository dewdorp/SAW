"""Attack story on a large investigation: the source ledger is collected per record, not as one walk.

A 100k-row upload produced enough findings that walking every finding dict as a single value exceeded the
20,000-node traversal bound (derived_source_scope_limit) even though no finding came near it on its own.
"""
from datetime import datetime, timedelta, timezone

import pytest

from saw.core.application import identity, investigations
from saw.core.application.analysis import run_story
from saw.core.application.investigations import Forbidden
from saw.detection.derived_access import combined_source_ids, source_ids
from saw.event_generations.reads import actor_scope
from saw.storage.db import session_scope
from saw.storage.models import Finding, User


def _finding(inv_id, n, sources):
    start = datetime(2026, 11, 1, tzinfo=timezone.utc) + timedelta(minutes=n)
    return Finding(display_id=f"F-{n:05d}", investigation_id=inv_id, detector_id="synthetic.scale", detector_version="1",
                   title=f"Synthetic scale finding {n}", category="network", stage="DISCOVERY", risk_level="medium",
                   risk_score=40.0, confidence="med", time_start=start, time_end=start + timedelta(seconds=30),
                   metrics=[{"name": f"m{i}", "observed": i, "unit": "count"} for i in range(10)],
                   entities=[f"ip:10.20.{n % 250}.{i}" for i in range(1, 11)],
                   evidence_refs={"source_investigation_ids": sources, "event_ids": [f"e-{n}-{i}" for i in range(5)]},
                   dedup_key=f"synthetic-scale-{n}")


def test_story_over_many_findings_keeps_every_source_without_hitting_the_walk_bound(analyst):
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        p = identity.principal_of(s.get(User, analyst.get("/auth/me").json()["id"]))
        inv = investigations.create(s, p, "Synthetic story scale")
        s.flush()
        rows = [_finding(inv.id, n, [inv.id]) for n in range(1000)]
        s.add_all(rows)
        s.flush()
        dicts = [{"metrics": r.metrics, "entities": r.entities, "evidence_refs": r.evidence_refs} for r in rows]
        with pytest.raises(Forbidden, match="derived_source_scope_limit"):
            source_ids(dicts)  # the old single walk over every finding
        story = run_story(s, inv.id)
        s.flush()
        assert story.graph["_source_investigation_ids"] == [inv.id]
        assert sum(len(n["finding_ids"]) for n in story.graph["nodes"]) == 1000


def test_similar_case_index_over_many_findings_keeps_the_source(analyst):
    from saw.knowledge import similar
    with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
        p = identity.principal_of(s.get(User, analyst.get("/auth/me").json()["id"]))
        inv = investigations.create(s, p, "Synthetic similar scale")
        s.flush()
        s.add_all([_finding(inv.id, n, [inv.id]) for n in range(1000)])
        s.flush()
        doc = similar.index_investigation(s, inv)
        assert doc is not None


def test_combined_sources_keep_the_per_record_and_aggregate_bounds():
    assert combined_source_ids([{"source_investigation_ids": ["a"]}, {"x": [{"_source_investigation_ids": ["b"]}]}]) == {"a", "b"}
    with pytest.raises(Forbidden, match="derived_source_scope_limit"):
        combined_source_ids([{"nested": [{} for _ in range(20001)]}])  # one pathological record still fails
    with pytest.raises(Forbidden, match="derived_source_scope_limit"):
        combined_source_ids([{"source_investigation_ids": [f"s{g}-{i}" for i in range(300)]} for g in range(2)])
    with pytest.raises(Forbidden, match="derived_source_scope_invalid"):
        combined_source_ids([{"source_investigation_ids": "not-a-list"}])
