"""Frozen report aggregation remains bounded without weakening each source record."""
from copy import deepcopy

import pytest

from saw.core.application.investigations import Forbidden
from saw.reports.source_scope import content_source_ids


def test_v1_and_v2_collect_every_frozen_component_and_unrecognized_metadata():
    item = {
        "source_investigation_ids": ["item"],
        "analysis": {
            "input_manifest": {"source_investigation_ids": ["manifest"]},
            "executions": [{"detail": {"source_investigation_ids": ["execution"]}}],
            "findings": [{"finding": {"evidence_refs": {"source_investigation_ids": ["finding"]}}}],
        },
        "checks": [{"payload": {"source_check_revision": {"_source_investigation_ids": ["citation"]}}}],
        "followups": [{"payload": {"reply": {"source_investigation_ids": ["reply"]}}}],
        "extra_metadata": {"source_investigation_ids": ["metadata"]},
    }
    expected = {"anchor", "item", "manifest", "execution", "finding", "citation", "reply", "metadata"}
    legacy = {"schema_version": "saw.report.v1", **item}
    modern = {"schema_version": "saw.report.v2", "items": [item]}
    before = deepcopy(modern)
    assert content_source_ids(legacy, base_sources={"anchor"}) == expected
    assert content_source_ids(modern, base_sources={"anchor"}) == expected
    assert modern == before


def test_aggregate_source_limit_is_distinct_from_individual_record_limit():
    checks = [{"source_investigation_ids": [f"source-{group}-{i}" for i in range(250)]}
              for group in range(4)]
    content = {"schema_version": "saw.report.v2", "items": [{"checks": checks}]}
    assert len(content_source_ids(content)) == 1000
    with pytest.raises(ValueError, match="report_source_limit"):
        content_source_ids(content, base_sources={"one-more-source"})
    content["items"][0]["checks"] = [{"source_investigation_ids": [str(i) for i in range(501)]}]
    with pytest.raises(Forbidden, match="derived_source_scope_limit"):
        content_source_ids(content)


def test_single_pathological_record_retains_original_traversal_bound():
    content = {"schema_version": "saw.report.v2",
               "items": [{"checks": [{"payload": {"nested": [{} for _ in range(20001)]}}]}]}
    with pytest.raises(Forbidden, match="derived_source_scope_limit"):
        content_source_ids(content)


@pytest.mark.parametrize("item", [{"checks": "invalid"}, {"analysis": []},
                                  {"checks": [{} for _ in range(2001)]}])
def test_invalid_or_excess_component_is_rejected_instead_of_omitted(item):
    with pytest.raises(ValueError, match="report_frozen_component"):
        content_source_ids({"schema_version": "saw.report.v2", "items": [item]})
