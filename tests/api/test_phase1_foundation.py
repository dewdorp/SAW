from __future__ import annotations

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from saw.storage.db import session_scope
from saw.storage.models import AuditEvent, User
from tests.conftest import PASSWORD, Api, make_user


def test_health(app):
    r = TestClient(app).get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_login_requires_mfa_enrollment_then_ok(app):
    make_user("u1", ["analyst"])
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": "u1", "password": PASSWORD})
    assert r.json()["state"] == "mfa_enroll" and r.json()["provisioning_uri"].startswith("otpauth://")
    csrf = r.json()["csrf_token"]
    # MFA not yet passed -> protected endpoints refuse
    assert c.get("/api/v1/auth/me").status_code == 401
    bad = c.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers={"x-csrf-token": csrf})
    assert bad.status_code == 401
    with session_scope() as s:
        secret = s.execute(select(User.mfa_secret).where(User.username == "u1")).scalar_one()
    ok = c.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()}, headers={"x-csrf-token": csrf})
    assert ok.status_code == 200
    me = c.get("/api/v1/auth/me").json()
    assert me["username"] == "u1" and "analyze.run" in me["permissions"]
    # second login asks for code (already enrolled)
    r2 = TestClient(app).post("/api/v1/auth/login", json={"username": "u1", "password": PASSWORD})
    assert r2.json()["state"] == "mfa_required"


def test_lockout_after_failures(app):
    make_user("u2", ["analyst"])
    c = TestClient(app)
    for _ in range(5):
        assert c.post("/api/v1/auth/login", json={"username": "u2", "password": "wrong"}).status_code == 401
    r = c.post("/api/v1/auth/login", json={"username": "u2", "password": PASSWORD})
    assert r.status_code == 401 and "locked" in r.text


def test_csrf_required_on_unsafe(app, analyst: Api):
    r = analyst.c.post("/api/v1/investigations", json={"title": "x"})  # no header
    assert r.status_code == 403 and "CSRF" in r.text
    assert analyst.post("/investigations", json={"title": "x"}).status_code == 201


def test_investigation_acl_idor(app, analyst: Api):
    inv = analyst.post("/investigations", json={"title": "API 대량조회"}).json()
    assert inv["display_id"].startswith("INV-")
    make_user("other", ["analyst"])
    other = Api(app, "other")
    assert other.get(f"/investigations/{inv['id']}").status_code == 403
    assert all(i["id"] != inv["id"] for i in other.get("/investigations").json())
    make_user("mgr", ["soc_manager"])
    assert Api(app, "mgr").get(f"/investigations/{inv['id']}").status_code == 200


def test_viewer_cannot_create(app):
    make_user("v", ["viewer"])
    assert Api(app, "v").post("/investigations", json={"title": "x"}).status_code == 403


def test_admin_can_use_every_function(app, admin: Api):
    assert admin.post("/investigations", json={"title": "x"}).status_code == 201
    assert admin.get("/admin/users").status_code == 200


def test_close_requires_reason(app, analyst: Api):
    inv = analyst.post("/investigations", json={"title": "x"}).json()
    assert analyst.post(f"/investigations/{inv['id']}/close", json={"verdict": "attack", "reason": " "}).status_code == 400
    r = analyst.post(f"/investigations/{inv['id']}/close", json={"verdict": "attack", "reason": "확인됨"})
    assert r.status_code == 200 and r.json()["status"] == "closed"


def test_audit_chain_and_tamper_detection(app, analyst: Api, manager: Api):
    analyst.post("/investigations", json={"title": "x"})
    v = manager.get("/admin/audit/verify").json()
    assert v["ok"] is True
    with session_scope() as s:
        e = s.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars().first()
        e.detail = {"tampered": True}
    v = manager.get("/admin/audit/verify").json()
    assert v["ok"] is False and v["first_broken_id"] is not None


def test_weak_password_rejected(app, admin: Api):
    r = admin.post("/admin/users", json={"username": "w", "password": "short", "roles": ["analyst"]})
    assert r.status_code == 400


def test_admin_mfa_reset_forces_reenrollment(app, admin: Api):
    make_user("u3", ["analyst"])
    user = Api(app, "u3")  # enrolled + logged in
    uid = next(x["id"] for x in admin.get("/admin/users").json() if x["username"] == "u3")
    assert admin.post(f"/admin/users/{uid}/mfa-reset").json()["ok"]
    assert user.get("/auth/me").status_code == 401  # active sessions revoked
    r = TestClient(app).post("/api/v1/auth/login", json={"username": "u3", "password": PASSWORD})
    assert r.json()["state"] == "mfa_enroll" and r.json()["provisioning_uri"].startswith("otpauth://totp/SAW:u3")
    make_user("u4", ["analyst"])
    assert Api(app, "u4").post(f"/admin/users/{uid}/mfa-reset").status_code == 403  # analysts cannot reset


def test_db_commit_happens_before_response(app):
    """Regression: the login loop after MFA — verify returned 200 before mfa_passed was committed, so the
    browser's immediate /auth/me saw the old state. The commit must be visible as soon as the response arrives."""
    from saw.storage.models import UserSession

    make_user("u5", ["analyst"])
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"username": "u5", "password": PASSWORD})
    with session_scope() as s:
        secret = s.execute(select(User.mfa_secret).where(User.username == "u5")).scalar_one()
    ok = c.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()},
                headers={"x-csrf-token": r.json()["csrf_token"]})
    assert ok.status_code == 200
    with session_scope() as s:  # independent connection, read right after the response
        uid = s.execute(select(User.id).where(User.username == "u5")).scalar_one()
        rows = s.execute(select(UserSession.mfa_passed).where(UserSession.user_id == uid)).scalars().all()
        assert rows == [True]
    # every handler must commit before the response is sent (FastAPI's default yield scope exits after sending)
    import re
    from pathlib import Path

    import saw.apps.api as api_pkg
    bad = [str(f) for f in Path(api_pkg.__file__).parent.rglob("*.py")
           if re.search(r"Depends\(db\)", f.read_text(encoding="utf-8"))]
    assert not bad, bad


def test_password_change_and_admin_reset(app, admin: Api):
    make_user("u6", ["analyst"])
    user = Api(app, "u6")
    other = Api(app, "u6")  # second session
    assert user.post("/auth/password", json={"current_password": "wrong", "new_password": "N3w!Passw0rd-x"}).status_code == 400
    assert user.post("/auth/password", json={"current_password": PASSWORD, "new_password": "short"}).status_code == 400
    assert user.post("/auth/password", json={"current_password": PASSWORD, "new_password": "N3w!Passw0rd-x"}).json()["ok"]
    assert user.get("/auth/me").status_code == 200        # the session that changed it stays
    assert other.get("/auth/me").status_code == 401       # other sessions revoked
    old = TestClient(app).post("/api/v1/auth/login", json={"username": "u6", "password": PASSWORD})
    assert old.status_code == 401
    uid = next(x["id"] for x in admin.get("/admin/users").json() if x["username"] == "u6")
    assert admin.post(f"/admin/users/{uid}/password", json={"password": "Temp!0rary-Pass1"}).json()["ok"]
    assert user.get("/auth/me").status_code == 401
    r = TestClient(app).post("/api/v1/auth/login", json={"username": "u6", "password": "Temp!0rary-Pass1"})
    assert r.status_code == 200 and r.json()["state"] == "mfa_required"
    with session_scope() as s:
        acts = [a for (a,) in s.execute(select(AuditEvent.action).where(AuditEvent.action.like("auth.password%")))]
    assert acts.count("auth.password_change") == 2 and acts.count("auth.password_reset") == 1
