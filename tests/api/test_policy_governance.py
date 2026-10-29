"""Synthetic policy lineage and value provenance tests."""
import pytest
from sqlalchemy import select
from saw.core.application.identity import principal_of
from saw.detection import governance as g
from saw.detection.policy_models import PolicyVersion
from saw.storage.db import session_scope
from saw.storage.models import User


def principal(s, name):
    return principal_of(s.scalar(select(User).where(User.username == name)))


def request(**kw):
    return {"detector_id": "fw.observation", "scope": {"kind": "group"}, "expected_draft_version_id": None,
            "changes": {"set": {"enabled": False, "deny_allow_window_seconds": 0}, "inherit": []},
            "reason": "Synthetic policy draft", **kw}


def test_draft_false_zero_and_explicit_empty_exclusions_are_preserved(analyst):
    with session_scope() as s:
        p = principal(s, "analyst1")
        b = g.draft_policy(s, p, request(exclusions={"mode": "set", "values": []}))
        v = s.get(PolicyVersion, b.draft_version_id)
        assert v.payload["overrides"] == {"enabled": False, "deny_allow_window_seconds": 0}
        assert v.payload["exclusions_override"] == []
        assert b.active_version_id is None and b.approved_version_id is None
        pin = g.pin_policy(s, p, b.id, v.id)
        assert pin["policy"]["values"]["enabled"] is False
        assert pin["policy"]["values"]["deny_allow_window_seconds"] == 0
        assert g.resolve_effective(s, "fw.observation", {"kind": "group"}, p=p)["values"]["enabled"] is True


def test_policy_edit_keeps_all_ancestor_contributors_and_inherit_clears_override(analyst, senior):
    with session_scope() as s:
        a, b = principal(s, "analyst1"), principal(s, "senior1")
        policy = g.draft_policy(s, a, request())
        v1 = s.get(PolicyVersion, policy.draft_version_id)
        policy = g.draft_policy(s, b, request(expected_draft_version_id=v1.id, base_version_id=v1.id,
                                changes={"set": {}, "inherit": ["enabled"]}, exclusions={"mode": "inherit"}))
        v2 = s.get(PolicyVersion, policy.draft_version_id)
        assert v2.contributor_ids == sorted([a.user_id, b.user_id])
        assert v2.payload["overrides"] == {"deny_allow_window_seconds": 0}
        assert v2.parent_version_id == v1.id and v2.payload["exclusions_override"] is None
        with pytest.raises(g.Forbidden):
            g.independent(s, a, g.contributors(v2))


def test_stale_policy_draft_and_unknown_values_fail_without_runtime_change(analyst):
    with session_scope() as s:
        p = principal(s, "analyst1")
        b = g.draft_policy(s, p, request())
        old = b.draft_version_id
        with pytest.raises(g.Conflict):
            g.draft_policy(s, p, request())
        with pytest.raises(ValueError):
            g.draft_policy(s, p, request(expected_draft_version_id=old, base_version_id=old,
                            changes={"set": {"enabled": "false"}, "inherit": []}))
        assert b.active_version_id is None


def test_policy_semantics_are_immutable(analyst):
    with pytest.raises(ValueError, match="immutable"):
        with session_scope() as s:
            b = g.draft_policy(s, principal(s, "analyst1"), request())
            v = s.get(PolicyVersion, b.draft_version_id)
            v.payload = {**v.payload, "overrides": {"enabled": True}}
            s.flush()


def test_policy_spec_hash_matches_the_published_specification(analyst):
    from saw.detection.specs import get_spec
    with session_scope() as s:
        b = g.draft_policy(s, principal(s, "analyst1"), request())
        version = s.get(PolicyVersion, b.draft_version_id)
        assert version.spec_sha256 == get_spec("fw.observation")["sha256"]
