"""Administrator-only metadata cleanup API."""
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application import data_deletion as svc
from saw.core.application.investigations import NotFound
from saw.storage.models import DataDeletion

router = APIRouter(prefix="/admin/data", tags=["admin"])
Kind = Literal["case", "investigation", "evidence"]


class TargetIn(BaseModel):
    target_type: Kind
    target_id: str = Field(min_length=1, max_length=36)


class DeleteIn(TargetIn):
    reason: str = Field(min_length=5, max_length=500)
    confirmation: str = Field(min_length=1, max_length=64)
    preview_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("reason")
    @classmethod
    def clean_reason(cls, value):
        value = value.strip()
        if len(value) < 5:
            raise ValueError("삭제 사유를 5자 이상 입력하세요.")
        return value


@router.get("")
def list_(target_type: Kind = "investigation", offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100),
          ctx: AuthContext = Depends(require_perm("admin.data.delete")), s: Session = Depends(db, scope="function")):
    return svc.listing(s, target_type, offset, limit)


@router.post("/deletion-preview")
def preview(body: TargetIn, ctx: AuthContext = Depends(require_perm("admin.data.delete")),
            s: Session = Depends(db, scope="function")):
    return svc.preview(s, body.target_type, body.target_id)


@router.post("/deletions")
def start(body: DeleteIn, ctx: AuthContext = Depends(require_perm("admin.data.delete")),
          s: Session = Depends(db, scope="function")):
    return svc.receipt(svc.start(s, ctx.principal, body.target_type, body.target_id, body.confirmation,
                                 body.preview_fingerprint, body.reason))


@router.get("/deletions/{did}")
def get(did: str, ctx: AuthContext = Depends(require_perm("admin.data.delete")),
        s: Session = Depends(db, scope="function")):
    op = s.get(DataDeletion, did)
    if op is None:
        raise NotFound("deletion receipt not found")
    return svc.receipt(op)


@router.post("/deletions/{did}/retry")
def retry(did: str, ctx: AuthContext = Depends(require_perm("admin.data.delete")),
          s: Session = Depends(db, scope="function")):
    return svc.receipt(svc.resume(s, did, requested_by=ctx.principal))
