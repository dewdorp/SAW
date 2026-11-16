"""A whole-group request target counts every record of the scope, not only the records a store could group."""
from types import SimpleNamespace

from saw.followups import service


class _DroppingStore:
    """Like an OpenSearch multi_terms group-by: records without a port are left out of the groups."""

    def group_by(self, inv, filters, fields, metrics, size=100, time=None):
        return [{"key": {"src_ip": "10.31.1.30", "dst_ip": "10.31.0.30", "dst_port": 443}, "count": 7}]

    def count(self, inv, filters=None, time=None):
        return 10


def test_records_missing_from_the_groups_make_the_target_incomplete(monkeypatch):
    monkeypatch.setattr(service.container, "get", lambda: SimpleNamespace(events=_DroppingStore()))
    item = {"filters": [{"field": "src_ip", "op": "is", "value": "10.31.1.30"}],
            "evidence_time": {"start": "2026-10-13T00:00:00+09:00", "end": "2026-10-14T00:00:00+09:00"}}
    whole = service._whole_targets("i1", item, {})
    assert whole["summary"]["records"] == 10
    assert whole["summary"]["unlisted_records"] == 3
    assert whole["summary"]["complete"] is False
