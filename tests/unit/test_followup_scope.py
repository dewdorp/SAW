"""A reply explains an activity only for the affiliate, period and targets it actually covers."""
from datetime import UTC, datetime

from saw.followups.scope import compare, requested_scope

ASKED = {"target": {"org_unit_id": "aff-a", "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"], "dst_ports": [443]},
         "period": {"start": "2026-10-13T01:00:00+00:00", "end": "2026-10-13T01:05:18+00:00"}}


def scope(**kw):
    base = {"org_unit_id": "aff-a", "src_ips": ["198.51.100.23"], "dst_ips": ["10.20.1.10"], "dst_ports": [443],
            "start": "2026-10-13T00:59:00+00:00", "end": "2026-10-13T01:06:00+00:00"}
    return {**base, **kw}


def run(reply, events=()):
    return compare(requested_scope(ASKED, "aff-a", (None, None)), reply, list(events), "inv-1")


def test_matching_work_record_covers_the_whole_activity():
    out = run(scope())
    assert out["result"] == "matches" and out["uncovered"] == []


def test_other_period_or_affiliate_is_a_mismatch_not_an_explanation():
    assert run(scope(start="2026-10-20T00:00:00+00:00", end="2026-10-20T02:00:00+00:00"))["result"] == "mismatch"
    assert run(scope(org_unit_id="aff-b"))["result"] == "mismatch"
    assert run(scope(dst_ips=["10.20.9.9"]))["result"] == "mismatch"


def test_partial_cover_keeps_the_rest_as_an_open_question():
    out = run(scope(end="2026-10-13T01:02:00+00:00"))
    assert out["result"] == "partial" and any("일부만" in u for u in out["uncovered"])
    out = run(scope(src_ips=["198.51.100.23"], dst_ports=[]))
    assert out["result"] == "partial" and any("포트" in u for u in out["uncovered"])


def test_reply_without_any_scope_cannot_be_matched():
    out = run({})
    assert out["result"] == "not_stated"
    # Records attached as evidence show what was observed, not what the reply covers.
    inside = {"investigation_id": "inv-1", "timestamp": "2026-10-13T01:01:00Z"}
    assert run({}, [inside])["result"] == "not_stated"
    assert run(None, [inside])["result"] == "not_stated"


def test_evidence_from_another_investigation_or_outside_the_period_is_flagged():
    inside = {"investigation_id": "inv-1", "timestamp": "2026-10-13T01:01:00Z"}
    outside = {"investigation_id": "inv-1", "timestamp": "2026-10-14T01:01:00Z"}
    foreign = {"investigation_id": "inv-2", "timestamp": "2026-10-13T01:01:00Z"}
    assert run(scope(), [inside])["result"] == "matches"
    assert run(scope(), [inside, outside])["result"] == "partial"
    assert run(scope(), [outside])["result"] == "mismatch"
    assert run(scope(), [foreign])["result"] == "mismatch"


def test_investigation_scope_is_used_when_the_request_names_none():
    requested = requested_scope({}, "aff-a", ("2026-10-01T00:00:00+09:00", "2026-10-31T23:59:59+09:00"))
    assert requested["org_unit_id"] == "aff-a" and requested["start"] == datetime(2026, 9, 30, 15, tzinfo=UTC)
    assert compare(requested, {}, [], "inv")["result"] == "not_stated"
    assert compare(requested_scope({}, None, (None, None)), {}, [], "inv")["result"] == "no_request_scope"
    # Records from this investigation give no scope to compare when nothing was asked; another investigation's do.
    unscoped = requested_scope({}, None, (None, None))
    own = {"investigation_id": "inv", "timestamp": "2026-10-13T01:01:00Z"}
    assert compare(unscoped, {}, [own], "inv")["result"] == "no_request_scope"
    assert compare(unscoped, {}, [{**own, "investigation_id": "other"}], "inv")["result"] == "mismatch"
