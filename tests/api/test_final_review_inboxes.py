"""Synthetic owning-investigation ACL regressions for global work inboxes."""
import pytest

from saw.storage.db import session_scope
from saw.storage.models import Investigation, InvestigationMember, User


@pytest.mark.parametrize("kind", ["ordinary", "returned", "support"])
@pytest.mark.parametrize("revocation", ["membership", "role", "deletion"])
def test_inboxes_require_current_owning_investigation_access(analyst, senior, kind, revocation):
    owner_id = analyst.get("/auth/me").json()["id"]
    senior_id = senior.get("/auth/me").json()["id"]
    # The returning requester is a member rather than the owner, so membership revocation is effective.
    caller = analyst if kind == "returned" else senior
    caller_id = owner_id if kind == "returned" else senior_id
    rows = []
    for label in ("hidden", "retained"):
        owner = senior if kind == "returned" else analyst
        inv = owner.post("/investigations", json={"title": label + " synthetic private title"}).json()
        if kind == "returned":
            with session_scope() as s:
                s.add(InvestigationMember(investigation_id=inv["id"], user_id=owner_id, access="editor"))
        base = f"/investigations/{inv['id']}"
        if kind == "support":
            response = analyst.post(base + "/support", json={"question": "Synthetic independent support question", "helper_id": senior_id})
        else:
            response = analyst.post(base + "/reviews", json={"conclusion": "Synthetic ordinary private conclusion", "reviewer_id": senior_id})
        assert response.status_code == 201, response.text
        row = response.json()
        if kind == "returned":
            response = senior.post(f"/reviews/{row['id']}/decide", json={"outcome": "changes_requested", "note": "Synthetic requested revision"})
            assert response.status_code == 200, response.text
        rows.append((inv, row))
    route = "/support/inbox" if kind == "support" else "/reviews/inbox"
    field = "items" if kind == "support" else ("returned" if kind == "returned" else "to_review")
    assert {r["id"] for r in caller.get(route).json()[field]} == {r["id"] for _, r in rows}
    with session_scope() as s:
        if revocation == "deletion":
            s.get(Investigation, rows[0][0]["id"]).settings = {"data_deletion": {"id": "synthetic-marker"}}
        elif revocation == "membership":
            s.delete(s.get(InvestigationMember, (rows[0][0]["id"], caller_id)))
        else:
            s.get(User, caller_id).roles = []
    payload = caller.get(route).json()
    assert set(payload) == ({"items"} if kind == "support" else {"to_review", "returned"})
    assert [r["id"] for r in payload[field]] == ([rows[1][1]["id"]] if revocation != "role" else [])
    assert rows[0][0]["id"] not in str(payload) and rows[0][1]["id"] not in str(payload)
    assert rows[0][0]["title"] not in str(payload)
