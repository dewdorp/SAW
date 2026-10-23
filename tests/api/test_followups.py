"""Follow-up actions preserve exact evidence and require explicit verification."""
from sqlalchemy import select

from saw.storage.db import session_scope
from saw.storage.models import User
from saw.core.application.identity import principal_of
from tests.conftest import Api, make_user


def setup(api):
    inv = api.post("/investigations", json={"title": "Synthetic follow-up"}).json()
    check = api.post(f"/investigations/{inv['id']}/checks", json={
        "target_type": "entity", "target_key": "ip:198.51.100.8",
        "questions": ["success"], "note": "Application result not yet checked"}).json()
    return inv, check, f"/investigations/{inv['id']}/follow-ups"


def create(api, url, check, **extra):
    response = api.post(url, json={"check_id": check["id"], "check_revision_id": None,
        "question": "Was the request processed?", "reason": "HTTP response alone is insufficient",
        "needed_data": ["Application transaction log"], "items": ["Check transaction status"],
        "priority": "normal", "owner": {"org_unit_id": None, "department": None, "user_id": None},
        "due_at": None, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_nullable_assignment_and_due_have_exact_check_snapshot(analyst):
    inv, check, url = setup(analyst)
    got = create(analyst, url, check)
    current = got["current"]
    assert current["revision"] == 1 and current["action"] == "create"
    assert current["payload"]["status"] == "open" and not got["overdue"]
    assert current["payload"]["owner"] == {"org_unit_id": None, "department": None, "user_id": None}
    assert current["payload"]["check_ref"]["check_id"] == check["id"]
    assert current["payload"]["check_ref"]["revision_id"]
    assert analyst.get(url).json()["items"][0]["current"]["id"] == current["id"]
    assert analyst.get(f"{url}/{got['id']}/versions/{current['id']}").json()["version"]["payload"] == current["payload"]


def test_cas_edit_retains_old_version_and_explicit_null_clears(analyst):
    _, check, url = setup(analyst)
    got = create(analyst, url, check, due_at="2026-10-01T09:00:00+09:00")
    endpoint = f"{url}/{got['id']}"
    original = got["current"]
    changed = analyst.patch(endpoint, json={"expected_version_id": original["id"],
        "patch": {"due_at": None, "owner": {"org_unit_id": None, "user_id": None, "department": "Operations"}}})
    assert changed.status_code == 200, changed.text
    current = changed.json()["current"]
    assert current["revision"] == 2 and current["payload"]["due_at"] is None
    assert current["payload"]["question"] == original["payload"]["question"]
    assert current["payload"]["owner"]["department"] == "Operations"
    stale = analyst.patch(endpoint, json={"expected_version_id": original["id"], "patch": {"question": "Stale"}})
    assert stale.status_code == 409
    history = analyst.get(endpoint + "/versions").json()["versions"]
    assert len(history) == 2
    assert analyst.get(endpoint + "/versions/" + original["id"]).json()["version"]["payload"] == original["payload"]


def test_reply_is_not_verification_and_terminal_requires_reopen(analyst):
    _, check, url = setup(analyst)
    got = create(analyst, url, check)
    endpoint = f"{url}/{got['id']}"
    premature = analyst.post(endpoint + "/verify", json={"expected_version_id": got["current"]["id"],
        "reason": "Check", "outcome": "confirmed", "basis": "No reply", "evidence": []})
    assert premature.status_code == 400
    reply = analyst.post(endpoint + "/reply", json={"expected_version_id": got["current"]["id"],
        "reason": "Reply received", "note": "Need one more source", "evidence": []})
    assert reply.status_code == 200, reply.text
    v2 = reply.json()["current"]
    assert v2["payload"]["status"] == "replied" and v2["payload"]["verification"] is None
    closed = analyst.post(endpoint + "/close-with-limits", json={"expected_version_id": v2["id"], "reason": "Source unavailable"})
    assert closed.status_code == 200
    v3 = closed.json()["current"]
    assert v3["payload"]["status"] == "closed_with_limits" and v3["payload"]["verification"] is None
    assert analyst.patch(endpoint, json={"expected_version_id": v3["id"], "patch": {"question": "Changed"}}).status_code == 409
    reopened = analyst.post(endpoint + "/reopen", json={"expected_version_id": v3["id"], "reason": "Source recovered"})
    assert reopened.status_code == 200
    assert reopened.json()["current"]["payload"]["status"] == "replied"


def test_assignment_does_not_grant_access_and_fake_evidence_rejected(analyst, app):
    _, check, url = setup(analyst)
    outsider = make_user("followup-outsider", ["analyst"])
    response = analyst.post(url, json={"check_id": check["id"], "question": "Question", "reason": "Reason",
        "owner": {"user_id": outsider}})
    assert response.status_code == 403
    got = create(analyst, url, check)
    response = analyst.post(f"{url}/{got['id']}/reply", json={"expected_version_id": got["current"]["id"],
        "reason": "Test", "note": "Not a real reference", "evidence": [{"investigation_id": got["investigation_id"], "event_id": "missing"}]})
    assert response.status_code in {400, 404}
    assert analyst.get(f"{url}/{got['id']}").json()["current"]["revision"] == 1
    assert Api(app, "followup-outsider").get(url).status_code == 403


def test_check_revisions_preserve_cancelled_state_without_rewriting_previous(analyst):
    from saw.followups.check_revisions import capture_check, snapshot_checks, get_check_revision
    from saw.storage.models import Check
    inv, check, _ = setup(analyst)
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        first = capture_check(s, p, s.get(Check, check["id"]))
        first_id, first_sha = first.id, first.payload_sha256
        assert first.payload["state"] == "active"
    response = analyst.post(f"/investigations/{inv['id']}/checks/{check['id']}/cancel", json={"note": "Wrong target"})
    assert response.status_code == 200
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        old = get_check_revision(s, p, inv["id"], first_id)
        assert old.payload["state"] == "active" and old.payload_sha256 == first_sha
        latest = capture_check(s, p, s.get(Check, check["id"]))
        assert latest.revision == 2 and latest.payload["state"] == "cancelled"
        assert snapshot_checks(s, p, inv["id"])["checks"] == []


def test_scope_snapshot_never_silently_drops_broken_current_pointer(analyst):
    import pytest
    from saw.followups.models import FollowUp
    from saw.followups import service
    from saw.followups.check_revisions import Conflict
    inv, check, url = setup(analyst)
    got = create(analyst, url, check)
    with session_scope() as s:
        s.get(FollowUp, got["id"]).current_version_id = "missing-current"
    with session_scope() as s:
        p = principal_of(s.scalar(select(User).where(User.username == "analyst1")))
        with pytest.raises(Conflict, match="current_version"):
            service.snapshot_followups(s, p, inv["id"])
