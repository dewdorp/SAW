from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application import audit, identity
from saw.core.domain.enums import Role
from saw.core.security.passwords import WeakPasswordError
from saw.storage.models import AuditEvent, User

router = APIRouter(prefix="/admin", tags=["admin"])


class UserIn(BaseModel):
    username: str
    password: str
    roles: list[Role]
    display_name: str = ""


@router.get("/users")
def list_users(ctx: AuthContext = Depends(require_perm("admin.users")), s: Session = Depends(db, scope="function")):
    return [{"id": u.id, "username": u.username, "display_name": u.display_name, "roles": u.roles,
             "status": u.status, "mfa_enabled": u.mfa_enabled} for u in s.execute(select(User)).scalars()]


@router.post("/users", status_code=201)
def create_user(body: UserIn, ctx: AuthContext = Depends(require_perm("admin.users")), s: Session = Depends(db, scope="function")):
    try:
        u = identity.create_user(s, body.username, body.password, list(body.roles), body.display_name,
                                 ctx.principal)
    except (ValueError, WeakPasswordError) as e:
        raise HTTPException(400, str(e)) from None
    return {"id": u.id}


@router.post("/users/{user_id}/mfa-reset")
def mfa_reset(user_id: str, ctx: AuthContext = Depends(require_perm("admin.users")), s: Session = Depends(db, scope="function")):
    try:
        u = identity.reset_mfa(s, ctx.principal, user_id)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    return {"ok": True, "username": u.username}


class TempPasswordIn(BaseModel):
    password: str


@router.post("/users/{user_id}/password")
def set_password(user_id: str, body: TempPasswordIn, ctx: AuthContext = Depends(require_perm("admin.users")),
                 s: Session = Depends(db, scope="function")):
    try:
        u = identity.admin_set_password(s, ctx.principal, user_id, body.password)
    except WeakPasswordError as e:
        raise HTTPException(400, str(e)) from None
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    return {"ok": True, "username": u.username}


@router.get("/audit")
def list_audit(action: str | None = None, limit: int = Query(100, le=1000),
               ctx: AuthContext = Depends(require_perm("audit.read")), s: Session = Depends(db, scope="function")):
    q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if action:
        q = q.where(AuditEvent.action == action)
    rows = s.execute(q).scalars()
    return [{"id": e.id, "at": e.at, "actor": e.actor_name, "ip": e.actor_ip, "action": e.action,
             "target_type": e.target_type, "target_id": e.target_id, "investigation_id": e.investigation_id,
             "outcome": e.outcome, "detail": e.detail, "hash": e.hash} for e in rows]


@router.get("/audit/verify")
def verify_audit(ctx: AuthContext = Depends(require_perm("audit.read")), s: Session = Depends(db, scope="function")):
    return audit.verify(s)
