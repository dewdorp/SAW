"""Golden examples remain part of the existing SOC knowledge review workflow."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.knowledge import golden

router = APIRouter(prefix="/knowledge/golden", tags=["knowledge"])


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrepareIn(StrictIn):
    expected_experience_rev: int = Field(ge=1)
    check_ids: list[str] | None = Field(default=None, max_length=100)


class EditIn(StrictIn):
    expected_content_sha256: str = Field(min_length=64, max_length=64)
    answers: dict


class GoldenDecision(StrictIn):
    expected_content_sha256: str = Field(min_length=64, max_length=64)
    decision: Literal["adopt", "decline"]
    split: Literal["train", "dev", "holdout"] = "dev"
    confirmations: dict[str, bool] = Field(default_factory=dict)
    review_answers: dict | None = None


class LinkedGoldenDecision(GoldenDecision):
    version_id: str


class ExportIn(StrictIn):
    version_ids: list[str] = Field(min_length=1, max_length=100)
    split: Literal["train", "dev", "holdout"]
    format: Literal["csv", "jsonl", "bundle"]
    audience: Literal["agent", "evaluator"]


@router.get("")
def list_(q: str | None = None, category: str | None = None, verdict: str | None = None,
          status: str | None = None, reviewer: str | None = None, methodology_version: str | None = None,
          split: str | None = None, ctx: AuthContext = Depends(require_perm("knowledge.read")),
          s: Session = Depends(db, scope="function")):
    return golden.list_for(s, ctx.principal, q=q, category=category, verdict=verdict, status=status,
                           reviewer=reviewer, methodology_version=methodology_version, split=split)


@router.post("/export")
def export(body: ExportIn, ctx: AuthContext = Depends(require_perm("knowledge.read")),
           s: Session = Depends(db, scope="function")):
    data, media, filename = golden.export(s, ctx.principal, **body.model_dump())
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                                   "Cache-Control": "no-store"})


@router.get("/experience/{eid}")
def detail(eid: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
           s: Session = Depends(db, scope="function")):
    return golden.for_experience(s, ctx.principal, eid)


@router.post("/experience/{eid}/prepare", status_code=201)
def prepare(eid: str, body: PrepareIn, ctx: AuthContext = Depends(require_perm("knowledge.write")),
            s: Session = Depends(db, scope="function")):
    return golden.to_dict(s, ctx.principal, golden.prepare(s, ctx.principal, eid, **body.model_dump()), True)


@router.patch("/{vid}")
def edit(vid: str, body: EditIn, ctx: AuthContext = Depends(require_perm("knowledge.write")),
         s: Session = Depends(db, scope="function")):
    return golden.to_dict(s, ctx.principal, golden.edit(s, ctx.principal, vid, **body.model_dump()), True)


@router.post("/{vid}/review")
def review(vid: str, body: GoldenDecision, ctx: AuthContext = Depends(require_perm("knowledge.approve")),
           s: Session = Depends(db, scope="function")):
    return golden.to_dict(s, ctx.principal, golden.review(s, ctx.principal, vid, **body.model_dump()), True)
