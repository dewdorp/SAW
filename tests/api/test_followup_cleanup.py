"""Approved cleanup respects frozen follow-up references and Check snapshot FKs."""
from sqlalchemy import func, select

from saw import container
from saw.followups.models import CheckRevision, FollowUp, FollowUpVersion
from saw.storage.db import session_scope, utcnow
from tests.api.test_followups import setup, create
from tests.api.test_admin_data import preview, execute


def test_approved_investigation_cleanup_removes_own_followup_and_check_history(analyst, admin):
    inv, check, url = setup(analyst)
    create(analyst, url, check)
    plan = preview(admin, "investigation", inv["id"])
    assert not plan["blockers"], plan
    result = execute(admin, plan)
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "COMPLETED", result.text
    with session_scope() as s:
        for model in (FollowUp, FollowUpVersion, CheckRevision):
            assert s.scalar(select(func.count()).select_from(model)) == 0


def test_followup_evidence_from_other_investigation_prevents_source_deletion(analyst, admin):
    source = analyst.post("/investigations", json={"title": "Synthetic source"}).json()
    inv, check, url = setup(analyst)
    container.get().events.index([{"event_id": "source-for-followup", "investigation_id": source["id"],
        "timestamp": utcnow().isoformat(), "data_source": "synthetic", "raw_event": "confirmation"}])
    got = create(analyst, url, check)
    reply = analyst.post(f"{url}/{got['id']}/reply", json={"expected_version_id": got["current"]["id"],
        "reason": "Linked evidence", "note": "Checked source",
        "evidence": [{"investigation_id": source["id"], "event_id": "source-for-followup"}]})
    assert reply.status_code == 200, reply.text
    plan = preview(admin, "investigation", source["id"])
    assert "followup_reference" in plan["blockers"]
    assert execute(admin, plan).status_code == 409
