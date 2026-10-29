"""Bounded source closure for the frozen v1/v2 report schemas.

Each frozen record retains the existing derived-source validation limits. Report
aggregation has its own byte and total-source bounds, independent of record count.
"""
from saw.core.application.provenance import canonical
from saw.detection.derived_access import source_ids as derived_sources

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_SOURCES = 1000


def content_source_ids(content, *, base_sources=()):
    if len(canonical(content).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("report_snapshot_limit_split_selection")
    ids = set(base_sources)
    if any(not isinstance(value, str) for value in ids):
        raise ValueError("report_source_scope_invalid")

    def collect(value):
        ids.update(derived_sources(value))
        if len(ids) > MAX_SOURCES:
            raise ValueError("report_source_limit_split_selection")

    def records(value, key, *, maximum=None):
        rows = value.get(key, [])
        if not isinstance(rows, list):
            raise ValueError("report_frozen_component_invalid")  # noqa: TRY004 - public validation is a 400 response.
        if maximum is not None and len(rows) > maximum:
            raise ValueError("report_frozen_component_limit_split_selection")
        for row in rows:
            collect(row)
        return len(rows)

    def analysis(value):
        if not isinstance(value, dict):
            raise ValueError("report_frozen_component_invalid")  # noqa: TRY004 - public validation is a 400 response.
        collect({key: child for key, child in value.items()
                 if key not in {"executions", "findings"}})
        records(value, "executions")
        records(value, "findings")

    def item(value):
        if not isinstance(value, dict):
            raise ValueError("report_frozen_component_invalid")  # noqa: TRY004 - public validation is a 400 response.
        collect({key: child for key, child in value.items()
                 if key not in {"analysis", "checks", "followups"}})
        analysis(value.get("analysis", {}))
        records(value, "checks", maximum=2000)
        return records(value, "followups", maximum=100)

    collect({})
    if not isinstance(content, dict):
        raise ValueError("report_frozen_component_invalid")  # noqa: TRY004 - public validation is a 400 response.
    schema = content.get("schema_version")
    if schema == "saw.report.v2":
        collect({key: child for key, child in content.items() if key != "items"})
        items = content.get("items", [])
        if not isinstance(items, list) or len(items) > 20:
            raise ValueError("report_frozen_component_limit_split_selection")
        followups = 0
        for value in items:
            followups += item(value)
            if followups > 100:
                raise ValueError("report_followup_limit_select_fewer_investigations")
    elif schema == "saw.report.v1":
        item(content)
    else:
        # Unknown legacy shapes receive the original conservative traversal.
        collect(content)
    return ids
