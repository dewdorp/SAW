from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import CSRF_COOKIE, SESSION_COOKIE, AuthContext, auth, client_ip, db, pending_session
from saw.core.application import identity
from saw.core.security.authz import permissions_for
from saw.core.security.passwords import WeakPasswordError

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str
    password: str


class MfaIn(BaseModel):
    code: str


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


def _set_cookies(resp: Response, token: str, csrf: str) -> None:
    secure = container.get().settings.cookie_secure
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, secure=secure, samesite="strict", path="/")
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="strict", path="/")


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, s: Session = Depends(db, scope="function")):
    try:
        r = identity.login(s, container.get().settings, body.username, body.password, client_ip(request),
                           request.headers.get("user-agent", ""))
    except identity.AuthError as e:
        s.commit()  # persist failure counters + audit
        raise HTTPException(401, str(e)) from None
    _set_cookies(response, r.token, r.csrf)
    return {"state": r.state, "provisioning_uri": r.provisioning_uri, "csrf_token": r.csrf}


@router.post("/mfa/verify")
def mfa_verify(body: MfaIn, request: Request, pending=Depends(pending_session), s: Session = Depends(db, scope="function")):
    sess, _ = pending
    sess = s.merge(sess)
    try:
        identity.verify_mfa(s, sess, body.code, client_ip(request), container.get().settings)
    except identity.AuthError as e:
        s.commit()
        raise HTTPException(401, str(e)) from None
    return {"state": "ok"}


@router.post("/logout")
def logout(response: Response, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    identity.logout(s, s.merge(ctx.session), s.merge(ctx.user))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}


@router.post("/password")
def change_password(body: PasswordIn, request: Request, ctx: AuthContext = Depends(auth),
                    s: Session = Depends(db, scope="function")):
    try:
        identity.change_password(s, s.merge(ctx.user), body.current_password, body.new_password, ctx.session.id,
                                 client_ip(request))
    except identity.AuthError as e:
        s.commit()  # keep the failure audit
        raise HTTPException(400, str(e)) from None
    except (ValueError, WeakPasswordError) as e:
        raise HTTPException(400, str(e)) from None
    return {"ok": True}


@router.get("/me")
def me(ctx: AuthContext = Depends(auth)):
    return {
        "id": ctx.user.id, "username": ctx.user.username, "display_name": ctx.user.display_name,
        "roles": sorted(ctx.principal.roles), "permissions": permissions_for(ctx.principal.roles),
        "csrf_token": ctx.session.csrf_token,
    }
