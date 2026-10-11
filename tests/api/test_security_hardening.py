"""Findings of the 2026-10-09 comparison review: MFA attempts/replay, 4-eyes on edited knowledge, secrets in HTTP
analysis output, and audit entries removed from the end of the chain."""
from __future__ import annotations

import json
import threading

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from saw.analyzers.http.analyze import analyze_http
from saw.core.application import audit, identity
from saw.core.security.masking import mask_text
from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, AuditHead, User
from tests.conftest import PASSWORD, Api, make_user

CANARY = "SYNTHETIC_CANARY_42"


def _login(app, username: str):
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    return c, r


def _secret(username: str) -> str:
    with session_scope() as s:
        return s.execute(select(User.mfa_secret).where(User.username == username)).scalar_one()


def _mfa(c: TestClient, csrf: str, code: str):
    return c.post("/api/v1/auth/mfa/verify", json={"code": code}, headers={"x-csrf-token": csrf})


def test_mfa_wrong_codes_lock_the_account(app, settings):
    make_user("m1", ["analyst"])
    c, r = _login(app, "m1")
    csrf = r.json()["csrf_token"]
    code = pyotp.TOTP(_secret("m1")).now()
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(settings.login_max_failures):
        assert _mfa(c, csrf, wrong).status_code == 401
    assert _mfa(c, csrf, code).status_code == 401          # the right code no longer helps: session revoked
    assert _login(app, "m1")[1].status_code == 401          # ...and the account is locked for a while
    with session_scope() as s:
        fails = s.execute(select(AuditEvent.detail).where(AuditEvent.action == "auth.mfa",
                                                          AuditEvent.outcome == "failure")).scalars().all()
    assert sum(1 for d in fails if d.get("reason") == "bad_code") == settings.login_max_failures
    assert any(d.get("locked") for d in fails)


def test_mfa_code_cannot_be_used_twice(app):
    make_user("m2", ["analyst"])
    c1, r1 = _login(app, "m2")
    code = pyotp.TOTP(_secret("m2")).now()
    assert _mfa(c1, r1.json()["csrf_token"], code).status_code == 200
    assert _mfa(c1, r1.json()["csrf_token"], code).status_code == 200  # same session, double submit: nothing to do
    c2, r2 = _login(app, "m2")                                           # someone who saw the code and the password
    again = _mfa(c2, r2.json()["csrf_token"], code)
    assert again.status_code == 401 and "already used" in again.text
    assert c2.get("/api/v1/auth/me").status_code == 401
    assert c1.get("/api/v1/auth/me").status_code == 200


def test_enrolled_account_needs_its_code_even_when_mfa_is_optional(app, settings):
    make_user("m3", ["analyst"])
    Api(app, "m3")  # enrols
    with session_scope() as s:
        r = identity.login(s, settings.model_copy(update={"mfa_required": False}), "m3", PASSWORD)
    assert r.state == "mfa_required"


def test_reviewer_who_edited_cannot_approve(app):
    for name, role in (("an", "analyst"), ("sr", "senior_analyst"), ("mg", "soc_manager")):
        make_user(name, [role])
    analyst, senior, manager = Api(app, "an"), Api(app, "sr"), Api(app, "mg")
    e = analyst.post("/experiences", json={"data": {"title": "t", "category": "attack", "reason": "r"}}).json()
    eid = e["id"]
    r = senior.patch(f"/experiences/{eid}", json={"data": {"reason": "rewritten by the reviewer"}})
    assert r.status_code == 200, r.text
    assert senior.post(f"/experiences/{eid}/submit").status_code == 200
    assert senior.post(f"/experiences/{eid}/approve", json={}).status_code == 403   # would be approving own text
    assert manager.post(f"/experiences/{eid}/approve", json={}).json()["status"] == "approved"
    # after the approval the count starts again: a later edit by the analyst can be approved by the senior
    assert analyst.patch(f"/experiences/{eid}", json={"data": {"reason": "v2"}}).status_code == 200
    assert analyst.post(f"/experiences/{eid}/submit").status_code == 200
    assert senior.post(f"/experiences/{eid}/approve", json={}).json()["status"] == "approved"


RESPONSE = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            + json.dumps({"ok": True, "password": CANARY, "session_token": CANARY, "nested": {"apiKey": CANARY}}))


@pytest.mark.parametrize("request_text", [
    "POST /login HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\n\r\n"
    + json.dumps({"user": "kim", "password": CANARY, "profile": {"access_token": CANARY}}),
    f"GET /cb?token={CANARY[:9]}%2542{CANARY[9:]}%2520x HTTP/1.1\r\nHost: a.test\r\n\r\n",
    f"GET /cb?next=token%253D{CANARY}%2526a%253D1 HTTP/1.1\r\nHost: a.test\r\n\r\n",
    f"POST /l HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=kim&passwd={CANARY}",
    f"GET /a?api_key={CANARY}&id=7 HTTP/1.1\r\nHost: a.test\r\n\r\n",
], ids=["json-body", "double-encoded-secret-param", "secret-inside-encoded-value", "form", "query"])
def test_http_analysis_output_has_no_secret_values(request_text):
    out = analyze_http(request_text, RESPONSE)
    assert CANARY not in json.dumps(out, ensure_ascii=False)
    assert out["parameters"]  # still analysed, only the values are hidden


def test_json_secret_masking_keeps_other_fields():
    r = mask_text('{"user":"kim","userPassword":"x y","count":3,"note":"reset token sent"}')
    assert r.text == '{"user":"kim","userPassword":"●●●●","count":3,"note":"reset token sent"}'
    assert r.kinds == ["secret_param"]


def _records(n: int) -> None:
    with session_scope() as s:
        for i in range(n):
            audit.record(s, "test.event", actor_name="t", detail={"i": i})


def test_audit_detects_removed_tail(app):
    _records(5)
    with session_scope() as s:
        assert audit.verify(s, checkpoint=False)["ok"]
        last = s.execute(select(AuditEvent.id).order_by(AuditEvent.id.desc()).limit(2)).scalars().all()
        s.execute(delete(AuditEvent).where(AuditEvent.id.in_(last)))
    with session_scope() as s:
        r = audit.verify(s)
        assert audit.verify_chain(s)[0] is False  # kept for callers that only need (ok, id)
    assert not r["ok"] and r["reason"] == "tail" and r["entries"] == r["expected_entries"] - 2


def test_audit_anchor_detects_tail_removed_together_with_the_head(app, settings):
    _records(4)
    with session_scope() as s:
        assert audit.verify(s)["ok"]                      # writes an anchor next to the data
    assert (settings.data_dir / audit.ANCHOR_FILE).is_file()
    with session_scope() as s:                            # someone with database access rewrites both tables
        rows = s.execute(select(AuditEvent).order_by(AuditEvent.id.desc())).scalars().all()
        s.delete(rows[0])
        h = s.get(AuditHead, 1)
        h.last_id, h.last_hash, h.entries = rows[1].id, rows[1].hash, h.entries - 1
    with session_scope() as s:
        r = audit.verify(s)
    assert not r["ok"] and r["reason"] == "anchor"


def test_audit_chain_survives_overlapping_transactions(app):
    """Entries written by requests that overlap in time must still form one chain (no two entries share a parent)."""
    start = threading.Barrier(6)
    errors: list[Exception] = []

    def work(k: int) -> None:
        try:
            start.wait(timeout=10)
            for i in range(5):
                with session_scope() as s:
                    audit.record(s, "test.overlap", actor_name=f"w{k}", detail={"i": i})
                    s.execute(select(User).limit(1)).all()  # keep the transaction open a little longer
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=work, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors
    with session_scope() as s:
        r = audit.verify(s, checkpoint=False)
    assert r["ok"] and r["entries"] >= 30, r
