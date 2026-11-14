from __future__ import annotations

import io

import pytest

from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.core.security.authz import ALL_PERMISSIONS, InvestigationAccess, Principal, can
from saw.core.domain.enums import Role
from saw.core.security.masking import mask_text
from saw.core.security.sanitize import csv_safe, is_safe_member_path, sanitize_filename, visualize_controls
from saw.storage.eventstore import SQLiteEventStore
from saw.storage.objectstore import LocalFSObjectStore


def P(*roles):
    return Principal("u", "u", frozenset(roles))


def test_pdp_matrix():
    a = P(Role.ANALYST)
    assert can(a, "investigation.read", InvestigationAccess("viewer"))
    assert not can(a, "investigation.write", InvestigationAccess("viewer"))
    assert can(a, "investigation.write", InvestigationAccess("editor"))
    assert not can(a, "investigation.read", InvestigationAccess(None))
    assert can(P(Role.SOC_MANAGER), "investigation.read", InvestigationAccess(None))
    assert not can(a, "knowledge.approve")
    assert can(P(Role.SENIOR_ANALYST), "knowledge.approve")
    # The administrator and the SOC manager can use every function and open every investigation.
    assert can(P(Role.ADMIN), "investigation.read", InvestigationAccess(None))
    assert can(P(Role.ADMIN), "investigation.write", InvestigationAccess(None))
    for lead in (Role.ADMIN, Role.SOC_MANAGER):
        assert all(can(P(lead), permission) for permission in ALL_PERMISSIONS)
    assert not can(P(Role.VIEWER), "investigation.write", InvestigationAccess("owner"))


def test_masking():
    r = mask_text("rrn=900101-1234567 card 4111 1111 1111 1111 tel 010-1234-5678 a@b.com password=hunter2")
    assert "900101-1******" in r.text
    assert "4111-****-****-1111" in r.text
    assert "010-****-5678" in r.text and "a***@b.com" in r.text and "password=●●●●" in r.text
    assert "1234567" not in r.text
    # non-luhn digit runs are untouched
    assert mask_text("order 1234567890123").text == "order 1234567890123"


def test_sanitize():
    assert sanitize_filename("../../etc/passwd") == "_.._etc_passwd" or "/" not in sanitize_filename("../../etc/passwd")
    assert "\u202e" not in sanitize_filename("evil\u202egpj.exe")
    assert not is_safe_member_path("../x")
    assert not is_safe_member_path("/abs")
    assert not is_safe_member_path("C:/x")
    assert is_safe_member_path("logs/access.log")
    assert csv_safe("=cmd|'/c calc'!A1").startswith("'")
    assert csv_safe("normal") == "normal"
    assert "⟨RLO⟩" in visualize_controls("a\u202eb")


def test_objectstore_rejects_traversal(tmp_path):
    os_ = LocalFSObjectStore(tmp_path)
    with pytest.raises(ValueError):
        os_.put_stream("saw-exports", "../x", io.BytesIO(b"1"))
    n, h = os_.put_stream("saw-exports", "u/1.txt", io.BytesIO(b"hello"))
    assert n == 5 and len(h) == 64
    os_.append_part("saw-evidence-original", "a/b", 2, b"world")
    os_.append_part("saw-evidence-original", "a/b", 1, b"hello ")
    n, _ = os_.complete_parts("saw-evidence-original", "a/b", [1, 2])
    assert os_.read_range("saw-evidence-original", "a/b", 0, 11) == b"hello world"


def _ev(i, inv="inv1", **kw):
    d = {"event_id": f"e{i}", "investigation_id": inv, "timestamp": f"2026-10-05T03:{i // 60:02d}:{i % 60:02d}Z",
         "data_source": "web", "src_ip": f"10.0.0.{i % 3}", "status_code": 200 if i % 4 else 404,
         "uri_template": "/a?id=<NUM>", "bytes_out": i}
    d.update(kw)
    return d


def test_sqlite_eventstore_scoping_and_aggs(tmp_path):
    es = SQLiteEventStore(tmp_path / "e.db")
    es.index([_ev(i) for i in range(100)] + [_ev(i, inv="inv2") | {"event_id": f"x{i}"} for i in range(5)])
    assert es.count("inv1") == 100 and es.count("inv2") == 5
    with pytest.raises(ValueError):
        es.count("")
    t = es.aggregate("inv1", [], AggRequest(type="terms", field="src_ip", size=2))
    assert len(t["buckets"]) == 2 and t["other"] == 100 - sum(b["count"] for b in t["buckets"])
    assert es.aggregate("inv1", [Filter(field="status_code", op="is", value=404)], AggRequest(type="count"))["value"] == 25
    assert es.aggregate("inv1", [], AggRequest(type="cardinality", field="src_ip"))["value"] == 3
    h = es.aggregate("inv1", [], AggRequest(type="date_histogram", field="timestamp", interval_sec=60))
    assert sum(b["count"] for b in h["buckets"]) == 100
    g = es.group_by("inv1", [], ["src_ip", "status_code"], [GroupMetric(type="cardinality", field="bytes_out", name="u")])
    assert g[0]["count"] >= g[-1]["count"]
    # keyset pagination covers everything exactly once
    seen, cur = [], None
    while True:
        page = es.search("inv1", [], limit=30, cursor=cur)
        seen += [e["event_id"] for e in page["events"]]
        cur = page["next_cursor"]
        if not cur:
            break
    assert len(seen) == 100 and len(set(seen)) == 100
    assert es.delete_by_evidence("inv1", "nope") == 0
    # field names are validated -> no SQL/JSON-path injection
    with pytest.raises(ValueError):
        Filter(field="a') OR 1=1 --", value=1)
