"""Historical rule tests must not publish samples after their source scope changes."""
from __future__ import annotations

import pytest
from sqlalchemy import delete, select

from saw import container
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound
from saw.event_generations.reads import actor_scope
from saw.detection import service
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, User
from tests.api.test_admin_data import execute, preview, target

RULE = "title: synthetic scope\nlogsource: {category: webserver}\ndetection:\n  s:\n    sc-status: 200\n  condition: s\nlevel: low\n"


@pytest.mark.parametrize("change", ["investigation", "evidence", "membership", "disabled", "rule_version"])
def test_historical_result_is_not_published_after_scope_changes(analyst, admin, monkeypatch, change):
    inv, ev = target(analyst)
    det = analyst.post("/detections", json={"title": "synthetic scope", "logic": RULE}).json()
    es = container.get().events
    original = es.iterate
    changed = []
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == "analyst1"))
        principal = principal_of(user)

    def changing_iteration(*args, **kwargs):
        rows = list(original(*args, **kwargs))
        if args[0] == inv["id"] and not changed:
            changed.append(True)
            if change in ("investigation", "evidence"):
                tid = inv["id"] if change == "investigation" else ev["evidence_id"]
                assert execute(admin, preview(admin, change, tid)).json()["state"] == "COMPLETED"
            elif change == "rule_version":
                result = analyst.patch(f"/detections/{det['id']}", json={"severity": "high"})
                assert result.status_code == 200
            else:
                with session_scope() as other:
                    if change == "membership":
                        other.execute(delete(InvestigationMember).where(InvestigationMember.investigation_id == inv["id"],
                                                                        InvestigationMember.user_id == principal.user_id))
                    else:
                        other.get(User, principal.user_id).status = "disabled"
        yield from rows

    monkeypatch.setattr(es, "iterate", changing_iteration)
    # Exercise the service without an unrelated SQLite login-session writer lock.
    # Native PostgreSQL uses independent per-user session rows and permits this interleaving too.
    expected_error = NotFound if change == "investigation" else ValueError if change == "rule_version" else Forbidden
    with pytest.raises(expected_error):
        with actor_scope(analyst.get("/auth/me").json()["id"]), session_scope() as s:
            service.run_test(s, principal, det["id"], [inv["id"]])
    assert changed
    with session_scope() as s:
        assert not list(s.scalars(select(service.TestRun).where(service.TestRun.detection_id == det["id"])))
        assert s.get(service.Detection, det["id"]).status == "draft"


@pytest.mark.parametrize("change", ["revoked", "expired", "mfa"])
def test_historical_api_discards_results_if_session_is_invalidated(analyst, monkeypatch, change):
    from datetime import timedelta
    from saw.storage.db import utcnow
    from saw.storage.models import UserSession

    inv, _ = target(analyst)
    det = analyst.post("/detections", json={"title": "synthetic session scope", "logic": RULE}).json()
    es = container.get().events
    original = es.iterate
    changed = []

    def invalidating_iteration(*args, **kwargs):
        rows = list(original(*args, **kwargs))
        if args[0] == inv["id"] and not changed:
            changed.append(True)
            with session_scope() as other:
                uid = other.scalar(select(User.id).where(User.username == "analyst1"))
                login = other.scalar(select(UserSession).where(UserSession.user_id == uid))
                if change == "revoked":
                    login.revoked_at = utcnow()
                elif change == "expired":
                    login.expires_at = utcnow() - timedelta(minutes=1)
                else:
                    login.mfa_passed = False
        yield from rows

    monkeypatch.setattr(es, "iterate", invalidating_iteration)
    result = analyst.post(f"/detections/{det['id']}/test", json={"investigation_ids": [inv["id"]]})
    assert result.status_code == 403, result.text
    assert changed
    with session_scope() as s:
        assert not list(s.scalars(select(service.TestRun).where(service.TestRun.detection_id == det["id"])))
        assert s.get(service.Detection, det["id"]).status == "draft"
