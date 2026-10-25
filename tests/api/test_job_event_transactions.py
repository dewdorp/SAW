"""Actual authenticated SSE requests must not retain a competing SQLite writer."""
import json

import pytest
from sqlalchemy import event, select

from saw import container
from saw.storage.db import session_scope
from saw.storage.models import InvestigationMember, Job, User, UserSession


def pending_job(analyst):
    inv = analyst.post("/investigations", json={"title": "Synthetic SSE"}).json()["id"]
    uid = analyst.get("/auth/me").json()["id"]
    with session_scope() as s:
        job = Job(investigation_id=inv, requested_by=uid, kind="ingest", state="QUEUED", stages={})
        s.add(job)
        s.flush()
        jid = job.id
    return inv, uid, jid


def short_sqlite_wait():
    engine = container.get().session_factory.kw["bind"]
    if engine.dialect.name != "sqlite":
        return lambda: None
    def configure(connection, record, proxy):
        connection.execute("PRAGMA busy_timeout=200")
    event.listen(engine, "checkout", configure)
    return lambda: event.remove(engine, "checkout", configure)


def progress_records(response):
    return [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines()
            if line.startswith("data: ") and line != "data: {}"]


def test_terminal_sse_commits_authentication_before_independent_reader(analyst):
    _, _, jid = pending_job(analyst)
    with session_scope() as s:
        s.get(Job, jid).state = "COMPLETED"
    cleanup = short_sqlite_wait()
    try:
        response = analyst.get(f"/jobs/{jid}/events")
    finally:
        cleanup()
    assert response.status_code == 200
    assert [row["state"] for row in progress_records(response)] == ["COMPLETED"]
    assert "event: end" in response.text


@pytest.mark.parametrize("revocation", ["membership", "user", "session"])
def test_progress_stream_rechecks_access_before_next_payload(analyst, monkeypatch, revocation):
    import saw.apps.api.routers.evidence as routes
    from saw.storage.db import utcnow
    inv, uid, jid = pending_job(analyst)
    calls = []
    async def revoke(_seconds):
        calls.append(True)
        assert len(calls) == 1, "a revoked stream must end at its next checkpoint"
        with session_scope() as s:
            if revocation == "membership":
                s.delete(s.get(InvestigationMember, (inv, uid)))
            elif revocation == "user":
                s.get(User, uid).status = "disabled"
            else:
                for row in s.scalars(select(UserSession).where(UserSession.user_id == uid)):
                    row.revoked_at = utcnow()
            s.get(Job, jid).current_item = "must never be sent after revocation"
    monkeypatch.setattr(routes.asyncio, "sleep", revoke)
    cleanup = short_sqlite_wait()
    try:
        response = analyst.get(f"/jobs/{jid}/events")
    finally:
        cleanup()
    assert response.status_code == 200
    assert len(progress_records(response)) == 1
    assert "must never be sent" not in response.text
    assert "event: end" in response.text and calls
