"""Actual artifact bytes and fresh authority are checked across slow I/O."""
from contextlib import contextmanager

import pytest
from sqlalchemy import delete, select, update

from saw import container
from saw.storage.db import session_scope, utcnow
from saw.storage.models import User, UserSession, InvestigationMember
from tests.api.test_golden_governance import adopted_candidate, release_request
from tests.api.test_golden_holdout_governance import approved_release


def test_independent_reviewer_can_decline_without_preview(analyst, manager, senior):
    inv, _, golden = adopted_candidate(analyst, manager)
    with session_scope() as s:
        uid = s.scalar(select(User.id).where(User.username == "senior1"))
    assert analyst.post(f"/investigations/{inv['id']}/members",
                        json={"user_id": uid, "access": "viewer"}).status_code == 200
    built = analyst.post("/knowledge/golden/releases",
                         json=release_request(analyst, golden)).json()
    url = f"/knowledge/golden/releases/{built['release_id']}/versions/{built['current_version_id']}"
    version = senior.get(url).json()["version"]
    response = senior.post(url + "/approve", json={
        "expected_current_version_id": version["id"],
        "expected_payload_sha256": version["payload_sha256"],
        "expected_artifact_sha256": version["artifact"]["sha256"],
        "expected_decision_id": None, "decision": "decline",
        "reason": "Synthetic release is unsuitable for the requested purpose",
        "confirmations": {"preview_reviewed": False, "redistribution_rights": False,
                          "recipient_and_purpose": False, "limits_accepted": False}})
    assert response.status_code == 200, response.text
    assert response.json()["approval"]["decision"] == "decline"
    assert analyst.get(url + "/download").status_code == 409


@pytest.mark.parametrize("change", ["disabled", "role", "session", "membership"])
def test_download_rechecks_actor_after_actual_object_read(analyst, manager, senior, monkeypatch, change):
    url, _ = approved_release(analyst, manager, senior, split="dev")
    objects = container.get().objects
    original = objects.open
    observed = []
    streams = []
    from saw.knowledge import golden_release_http
    spool = golden_release_http.tempfile.SpooledTemporaryFile
    def capture_spool(*args, **kwargs):
        stream = spool(*args, **kwargs)
        streams.append(stream)
        return stream
    monkeypatch.setattr(golden_release_http.tempfile, "SpooledTemporaryFile", capture_spool)
    @contextmanager
    def changed_after_read(bucket, key):
        with original(bucket, key) as stream:
            yield stream
        if "/artifact/" in key:
            with session_scope() as s:
                name = "senior1" if change == "membership" else "analyst1"
                user = s.scalar(select(User).where(User.username == name))
                if change == "disabled":
                    user.status = "disabled"
                elif change == "role":
                    user.roles = []
                elif change == "session":
                    s.execute(update(UserSession).where(UserSession.user_id == user.id).values(revoked_at=utcnow()))
                else:
                    s.execute(delete(InvestigationMember).where(InvestigationMember.user_id == user.id))
            observed.append(key)
    monkeypatch.setattr(objects, "open", changed_after_read)
    response = (senior if change == "membership" else analyst).get(url + "/download")
    assert streams and all(s.closed for s in streams)
    assert observed
    assert response.status_code == 403, response.text
    assert response.headers.get("content-type") != "application/zip"


def test_download_rechecks_reviewers_active_status_after_read(analyst, manager, senior, monkeypatch):
    url, _ = approved_release(analyst, manager, senior, split="dev")
    objects = container.get().objects
    original = objects.open
    @contextmanager
    def reviewer_disabled(bucket, key):
        with original(bucket, key) as stream:
            yield stream
        if "/artifact/" in key:
            with session_scope() as s:
                user = s.scalar(select(User).where(User.username == "senior1"))
                user.status = "disabled"
    monkeypatch.setattr(objects, "open", reviewer_disabled)
    response = analyst.get(url + "/download")
    assert response.status_code == 409, response.text
    assert response.headers.get("content-type") != "application/zip"


def test_download_rechecks_revocation_after_actual_read(analyst, manager, senior, monkeypatch):
    url, release = approved_release(analyst, manager, senior, split="dev")
    objects = container.get().objects
    original = objects.open
    @contextmanager
    def revoked_after_read(bucket, key):
        with original(bucket, key) as stream:
            yield stream
        if "/artifact/" in key:
            response = senior.post(url + "/revoke", json={
                "expected_decision_id": release["approval"]["id"], "reason": "Synthetic mid-read revocation"})
            assert response.status_code == 200, response.text
    monkeypatch.setattr(objects, "open", revoked_after_read)
    response = analyst.get(url + "/download")
    assert response.status_code == 409, response.text
    assert response.headers.get("content-type") != "application/zip"
