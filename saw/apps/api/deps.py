"""FastAPI dependencies: DB session, principal (session cookie + MFA), CSRF (docs/11 §1)."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import identity
from saw.core.security.authz import Principal, has_permission
from saw.storage.db import get_sessionmaker
from saw.storage.models import User, UserSession

SESSION_COOKIE = "saw_session"
CSRF_COOKIE = "saw_csrf"
CSRF_HEADER = "x-csrf-token"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def db() -> Iterator[Session]:
    s = get_sessionmaker()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


@dataclass
class AuthContext:
    principal: Principal
    user: User
    session: UserSession
    ip: str


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _session(request: Request, s: Session) -> tuple[UserSession, User]:
    resolved = identity.resolve_session(s, container.get().settings, request.cookies.get(SESSION_COOKIE))
    if resolved is None:
        raise HTTPException(401, "authentication required")
    sess, _ = resolved
    if request.method in UNSAFE and request.headers.get(CSRF_HEADER) != sess.csrf_token:
        raise HTTPException(403, "CSRF token missing or invalid")
    return resolved


def pending_session(request: Request, s: Session = Depends(db, scope="function")) -> tuple[UserSession, User]:
    """Authenticated by password but MFA may still be pending."""
    return _session(request, s)


def auth(request: Request, s: Session = Depends(db, scope="function")) -> AuthContext:
    sess, u = _session(request, s)
    if not sess.mfa_passed:
        raise HTTPException(401, "MFA required")
    from saw.event_generations.reads import bind_request_actor

    bind_request_actor(u.id, sess.id)
    principal = identity.principal_of(u)
    s.info["principal"] = principal
    return AuthContext(principal, u, sess, client_ip(request))


def require_perm(permission: str):
    def dep(ctx: AuthContext = Depends(auth)) -> AuthContext:
        if not has_permission(ctx.principal, permission):
            raise HTTPException(403, f"missing permission {permission}")
        return ctx

    return dep
