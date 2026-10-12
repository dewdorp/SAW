"""Administrator-only local model intake and synthetic selection."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, StringConstraints
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application import audit
from saw.llm import model_packs

router = APIRouter(prefix="/admin/local-models", tags=["local-models"])
PackId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=5, max_length=512)]
AdminContext = Annotated[AuthContext, Depends(require_perm("ai.models.manage"))]
DbSession = Annotated[Session, Depends(db, scope="function")]


class ValidateIn(BaseModel):
    pack_id: PackId


class ActivateIn(ValidateIn):
    reason: Reason


class DeactivateIn(BaseModel):
    reason: Reason


def _operation(s, ctx, action, pack_id, operation):
    try:
        return operation()
    except (ValueError, OSError) as exc:
        # Roll back selection and success audit together, then retain only a safe failure code.
        s.rollback()
        code = str(exc) if isinstance(exc, ValueError) and str(exc).startswith(("model_", "cpu_", "foundation_", "active_model_")) else "cpu_native_failed"
        audit.record(s, f"ai.model.{action}", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                     target_type="local_model", target_id=pack_id, outcome="failure", detail={"code": code})
        s.commit()
        raise HTTPException(400, code) from None


@router.get("")
def get_status(ctx: AdminContext, s: DbSession):
    return model_packs.status(s)


@router.post("/validate")
def validate(body: ValidateIn, ctx: AdminContext, s: DbSession):
    return _operation(s, ctx, "validate", body.pack_id, lambda: model_packs.register(s, ctx.principal, body.pack_id))


@router.post("/activate")
def activate(body: ActivateIn, ctx: AdminContext, s: DbSession):
    return _operation(s, ctx, "activate", body.pack_id, lambda: model_packs.activate(s, ctx.principal, body.pack_id, body.reason, session_id=ctx.session.id))


@router.post("/deactivate")
def deactivate(body: DeactivateIn, ctx: AdminContext, s: DbSession):
    return _operation(s, ctx, "deactivate", "", lambda: model_packs.deactivate(s, ctx.principal, body.reason))