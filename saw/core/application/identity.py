"""Authentication use cases: password + TOTP MFA + server-side sessions (docs/12 §2)."""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pyotp
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.config import Settings
from saw.core.application import audit
from saw.core.domain.enums import Role
from saw.core.security.authz import Principal
from saw.core.security.passwords import hash_password, new_token, token_hash, verify_password
from saw.storage.db import utcnow
from saw.storage.models import User, UserSession


class AuthError(Exception):
    pass


@dataclass
class LoginResult:
    token: str
    csrf: str
    state: str  # ok | mfa_required | mfa_enroll
    provisioning_uri: str | None = None


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def create_user(s: Session, username: str, password: str, roles: list[Role | str], display_name: str = "",
                actor: Principal | None = None) -> User:
    if s.execute(select(User).where(User.username == username)).scalar_one_or_none():
        raise ValueError("username already exists")
    u = User(username=username, display_name=display_name or username, password_hash=hash_password(password),
             roles=[str(Role(r)) for r in roles])
    s.add(u)
    s.flush()
    audit.record(s, "user.create", actor_id=actor.user_id if actor else None,
                 actor_name=actor.username if actor else "system", target_type="user", target_id=u.id,
                 detail={"username": username, "roles": u.roles})
    return u


def login(s: Session, cfg: Settings, username: str, password: str, ip: str = "", ua: str = "") -> LoginResult:
    u = s.execute(select(User).where(User.username == username)).scalar_one_or_none()
    now = utcnow()
    if u is None:
        audit.record(s, "auth.login", actor_name=username, actor_ip=ip, outcome="failure",
                     detail={"reason": "unknown_user"})
        raise AuthError("invalid credentials")
    if u.status != "active":
        audit.record(s, "auth.login", actor_id=u.id, actor_name=username, actor_ip=ip, outcome="failure",
                     detail={"reason": "disabled"})
        raise AuthError("account disabled")
    locked = _aware(u.locked_until)
    if locked and locked > now:
        audit.record(s, "auth.login", actor_id=u.id, actor_name=username, actor_ip=ip, outcome="failure",
                     detail={"reason": "locked"})
        raise AuthError("account locked")
    if not verify_password(u.password_hash, password):
        u.failed_count += 1
        if u.failed_count >= cfg.login_max_failures:
            u.locked_until = now + timedelta(minutes=cfg.login_lock_minutes)
            u.failed_count = 0
        audit.record(s, "auth.login", actor_id=u.id, actor_name=username, actor_ip=ip, outcome="failure",
                     detail={"reason": "bad_password"})
        raise AuthError("invalid credentials")
    u.failed_count = 0
    token, csrf = new_token(), secrets.token_hex(16)
    state, uri = "ok", None
    if cfg.mfa_required or u.mfa_enabled:  # an enrolled account always needs its code, whatever the site default
        if u.mfa_enabled:
            state = "mfa_required"
        else:
            if not u.mfa_secret:
                u.mfa_secret = pyotp.random_base32()
            state = "mfa_enroll"
            uri = pyotp.TOTP(u.mfa_secret).provisioning_uri(name=u.username, issuer_name="SAW")
    sess = UserSession(token_hash=token_hash(token), user_id=u.id, csrf_token=csrf, mfa_passed=(state == "ok"),
                       expires_at=now + timedelta(hours=cfg.session_absolute_hours), ip=ip, user_agent=ua[:256])
    s.add(sess)
    if state == "ok":
        u.last_login_at = now
    audit.record(s, "auth.login", actor_id=u.id, actor_name=username, actor_ip=ip,
                 detail={"state": state})
    return LoginResult(token, csrf, state, uri)


def _totp_step(secret: str, code: str, now: datetime) -> int | None:
    """The time step the code belongs to (current step ±1), or None when it matches none of them."""
    totp = pyotp.TOTP(secret)
    code = code.strip()
    current = int(now.timestamp()) // totp.interval
    found = None
    for off in (0, -1, 1):  # no early exit: the comparison time must not tell which step matched
        if pyotp.utils.strings_equal(totp.at(now, counter_offset=off), code):
            found = current + off if found is None else found
    return found


def verify_mfa(s: Session, sess: UserSession, code: str, ip: str = "", cfg: Settings | None = None) -> None:
    """A code is accepted once: wrong codes count towards the account lock, and a code (or an older one) that was
    already accepted is refused, so a code seen over someone's shoulder cannot be replayed within its validity."""
    u = s.get(User, sess.user_id)
    assert u is not None
    if sess.mfa_passed:  # a repeated submit of the same form
        return
    cfg = cfg or Settings()
    now = utcnow()

    def fail(reason: str, message: str, count: bool = True) -> AuthError:
        detail: dict = {"reason": reason}
        if count:
            u.mfa_failed_count = (u.mfa_failed_count or 0) + 1
            if u.mfa_failed_count >= cfg.login_max_failures:
                u.locked_until = now + timedelta(minutes=cfg.login_lock_minutes)
                u.mfa_failed_count = 0
                sess.revoked_at = now  # the password step has to be repeated after the lock
                detail["locked"] = True
        audit.record(s, "auth.mfa", actor_id=u.id, actor_name=u.username, actor_ip=ip, outcome="failure", detail=detail)
        return AuthError(message)

    locked = _aware(u.locked_until)
    if locked and locked > now:
        sess.revoked_at = now
        raise fail("locked", "account locked", count=False)
    step = _totp_step(u.mfa_secret, code, now) if u.mfa_secret else None
    if step is None:
        raise fail("bad_code", "invalid MFA code")
    if u.mfa_last_step is not None and step <= u.mfa_last_step:
        raise fail("code_reused", "MFA code already used")
    u.mfa_last_step, u.mfa_failed_count = step, 0
    enrolled_now = not u.mfa_enabled
    u.mfa_enabled = True
    sess.mfa_passed = True
    u.last_login_at = now
    audit.record(s, "auth.mfa", actor_id=u.id, actor_name=u.username, actor_ip=ip,
                 detail={"enrolled": enrolled_now})


def resolve_session(s: Session, cfg: Settings, token: str | None) -> tuple[UserSession, User] | None:
    if not token:
        return None
    sess = s.execute(select(UserSession).where(UserSession.token_hash == token_hash(token))).scalar_one_or_none()
    if sess is None or sess.revoked_at is not None:
        return None
    now = utcnow()
    if _aware(sess.expires_at) < now:
        return None
    if _aware(sess.last_seen_at) + timedelta(minutes=cfg.session_idle_minutes) < now:
        sess.revoked_at = now
        return None
    sess.last_seen_at = now
    u = s.get(User, sess.user_id)
    if u is None or u.status != "active":
        return None
    return sess, u


def logout(s: Session, sess: UserSession, u: User) -> None:
    sess.revoked_at = utcnow()
    audit.record(s, "auth.logout", actor_id=u.id, actor_name=u.username)


def reset_mfa(s: Session, actor: Principal | None, user_id: str) -> User:
    """Admin action: clear the TOTP secret so the user re-enrolls (QR) at next login. Revokes active sessions."""
    u = s.get(User, user_id)
    if u is None:
        raise ValueError("user not found")
    u.mfa_secret, u.mfa_enabled = None, False
    u.mfa_last_step, u.mfa_failed_count = None, 0
    for sess in s.execute(select(UserSession).where(UserSession.user_id == u.id, UserSession.revoked_at.is_(None))).scalars():
        sess.revoked_at = utcnow()
    audit.record(s, "auth.mfa_reset", actor_id=actor.user_id if actor else None,
                 actor_name=actor.username if actor else "system(cli)", target_type="user", target_id=u.id,
                 detail={"username": u.username})
    return u


def _revoke_sessions(s: Session, user_id: str, keep: str | None = None) -> None:
    for sess in s.execute(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))).scalars():
        if sess.id != keep:
            sess.revoked_at = utcnow()


def change_password(s: Session, u: User, current: str, new: str, keep_session: str | None, ip: str = "") -> None:
    """Self-service change. Wrong current password counts like a failed login (audited); other sessions are revoked."""
    if not verify_password(u.password_hash, current):
        audit.record(s, "auth.password_change", actor_id=u.id, actor_name=u.username, actor_ip=ip, outcome="failure",
                     detail={"reason": "bad_current_password"})
        raise AuthError("current password is incorrect")
    if verify_password(u.password_hash, new):
        raise ValueError("new password must differ from the current one")
    u.password_hash = hash_password(new)  # validates strength
    _revoke_sessions(s, u.id, keep=keep_session)
    audit.record(s, "auth.password_change", actor_id=u.id, actor_name=u.username, actor_ip=ip)


def admin_set_password(s: Session, actor: Principal | None, user_id: str, new: str) -> User:
    """Admin/CLI: set a temporary password (e.g. forgotten password). All sessions of the user are revoked."""
    u = s.get(User, user_id)
    if u is None:
        raise ValueError("user not found")
    u.password_hash = hash_password(new)
    u.failed_count, u.locked_until = 0, None
    _revoke_sessions(s, u.id)
    audit.record(s, "auth.password_reset", actor_id=actor.user_id if actor else None,
                 actor_name=actor.username if actor else "system(cli)", target_type="user", target_id=u.id,
                 detail={"username": u.username})
    return u


def principal_of(u: User) -> Principal:
    return Principal(user_id=u.id, username=u.username, roles=frozenset(Role(r) for r in u.roles))
