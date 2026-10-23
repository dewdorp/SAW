"""Analyst follow-up routes; mutations append exact revisions."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.followups import schemas, service
from saw.followups.check_revisions import Conflict

router = APIRouter(prefix="/investigations/{inv_id}/follow-ups", tags=["follow-ups"])


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Conflict as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("")
def list_(inv_id: str, status: str | None = None, priority: str | None = None,
          owner_user_id: str | None = None, before: str | None = None,
          limit: int = Query(default=50, ge=1, le=100),
          ctx: AuthContext = Depends(require_perm("investigation.read")),
          s: Session = Depends(db, scope="function")):
    return _call(service.list_for, s, ctx.principal, inv_id, status=status, priority=priority,
                 owner_user_id=owner_user_id, before=before, limit=limit)


@router.get("/choices")
def choices(inv_id: str, followup_id: str | None = None, check_id: str | None = None,
            q: str = Query(default="", max_length=64),
            ctx: AuthContext = Depends(require_perm("investigation.read")),
            s: Session = Depends(db, scope="function")):
    return _call(service.choices, s, ctx.principal, inv_id, followup_id=followup_id, check_id=check_id, q=q)


@router.post("", status_code=201)
def create(inv_id: str, body: schemas.CreateIn,
           ctx: AuthContext = Depends(require_perm("investigation.write")),
           s: Session = Depends(db, scope="function")):
    row = _call(service.create, s, ctx.principal, inv_id, body)
    return _call(service.to_dict, s, ctx.principal, row)


@router.get("/{ident}")
def get(inv_id: str, ident: str, ctx: AuthContext = Depends(require_perm("investigation.read")),
        s: Session = Depends(db, scope="function")):
    return _call(service.get, s, ctx.principal, inv_id, ident)


@router.patch("/{ident}")
def edit(inv_id: str, ident: str, body: schemas.PatchIn,
         ctx: AuthContext = Depends(require_perm("investigation.write")),
         s: Session = Depends(db, scope="function")):
    row = _call(service.mutate, s, ctx.principal, inv_id, ident, "edit", body)
    return _call(service.to_dict, s, ctx.principal, row)


@router.post("/{ident}/reply")
def reply(inv_id: str, ident: str, body: schemas.ReplyIn,
          ctx: AuthContext = Depends(require_perm("investigation.write")),
          s: Session = Depends(db, scope="function")):
    row = _call(service.mutate, s, ctx.principal, inv_id, ident, "reply", body)
    return _call(service.to_dict, s, ctx.principal, row)


@router.post("/{ident}/verify")
def verify(inv_id: str, ident: str, body: schemas.VerifyIn,
           ctx: AuthContext = Depends(require_perm("investigation.write")),
           s: Session = Depends(db, scope="function")):
    row = _call(service.mutate, s, ctx.principal, inv_id, ident, "verify", body)
    return _call(service.to_dict, s, ctx.principal, row)


def _action(action):
    def execute(inv_id: str, ident: str, body: schemas.ActionIn,
                ctx: AuthContext = Depends(require_perm("investigation.write")),
                s: Session = Depends(db, scope="function")):
        row = _call(service.mutate, s, ctx.principal, inv_id, ident, action, body)
        return _call(service.to_dict, s, ctx.principal, row)
    execute.__name__ = "followup_" + action
    return execute


for _path, _name in (("close-with-limits", "close_with_limits"), ("cancel", "cancel"), ("reopen", "reopen")):
    router.post("/{ident}/" + _path)(_action(_name))


@router.get("/{ident}/versions")
def versions(inv_id: str, ident: str, before_revision: int | None = Query(default=None, ge=1),
             limit: int = Query(default=50, ge=1, le=100),
             ctx: AuthContext = Depends(require_perm("investigation.read")),
             s: Session = Depends(db, scope="function")):
    return _call(service.versions, s, ctx.principal, inv_id, ident, before_revision=before_revision, limit=limit)


@router.get("/{ident}/versions/{version_id}")
def exact(inv_id: str, ident: str, version_id: str,
          ctx: AuthContext = Depends(require_perm("investigation.read")),
          s: Session = Depends(db, scope="function")):
    return _call(service.get, s, ctx.principal, inv_id, ident, version_id=version_id)
