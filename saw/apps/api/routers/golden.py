"""Golden examples remain part of the existing SOC knowledge review workflow."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.knowledge import golden, golden_profiles
from saw.knowledge.golden_schemas import PrepareIn, ProfileIn, ReleaseRequest, ApprovalIn, RevokeIn, AttemptIn, ResultIn

router = APIRouter(prefix="/knowledge/golden", tags=["knowledge"])


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


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
    schema_version: Literal["saw.golden.export.v2"] | None = None
    purpose: Literal["internal_evaluation"] | None = None


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


@router.post("/releases", status_code=202)
def create_release(body: ReleaseRequest, ctx: AuthContext = Depends(require_perm("golden.release.create")),
                   s: Session = Depends(db, scope="function")):
    from saw.knowledge.golden_release_http import submit_release
    return submit_release(body, ctx, s)


@router.get("/releases")
def releases(limit: int = 50, cursor: str | None = None,
             ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_releases
    return golden_releases.list_for(s, ctx.principal, limit=limit, cursor=cursor)


@router.get("/releases/{release_id}")
def release_detail(release_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
                   s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_releases
    return golden_releases.to_dict(s, ctx.principal, release_id)


@router.post("/releases/{release_id}/versions", status_code=202)
def release_new_version(release_id: str, body: ReleaseRequest,
                        ctx: AuthContext = Depends(require_perm("golden.release.create")), s: Session = Depends(db, scope="function")):
    from saw.knowledge.golden_release_http import submit_release
    return submit_release(body, ctx, s, release_id=release_id)


@router.get("/releases/{release_id}/versions")
def release_versions(release_id: str, limit: int = 50, cursor: str | None = None,
                     ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_releases
    return golden_releases.versions_for(s, ctx.principal, release_id, limit=limit, cursor=cursor)


@router.get("/releases/{release_id}/versions/{version_id}")
def release_version(release_id: str, version_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
                    s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_releases
    return golden_releases.to_dict(s, ctx.principal, release_id, version_id=version_id)


@router.get("/releases/{release_id}/versions/{version_id}/preview")
def release_preview(release_id: str, version_id: str, ctx: AuthContext = Depends(auth),
                    s: Session = Depends(db, scope="function")):
    from saw.knowledge.golden_release_http import preview_release
    return preview_release(release_id, version_id, ctx, s)


@router.post("/releases/{release_id}/versions/{version_id}/approve")
def release_approve(release_id: str, version_id: str, body: ApprovalIn,
                    ctx: AuthContext = Depends(require_perm("golden.release.approve")), s: Session = Depends(db, scope="function")):
    from saw.knowledge.golden_release_http import decide_release
    return decide_release(release_id, version_id, body, ctx, s)


@router.post("/releases/{release_id}/versions/{version_id}/revoke")
def release_revoke(release_id: str, version_id: str, body: RevokeIn,
                   ctx: AuthContext = Depends(require_perm("golden.release.approve")), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_releases
    golden_releases.to_dict(s, ctx.principal, release_id, version_id=version_id)
    return golden_releases.revoke(s, ctx.principal, version_id, body.model_dump())


@router.get("/releases/{release_id}/versions/{version_id}/download")
def release_download(release_id: str, version_id: str, attempt_id: str | None = None,
                     ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.knowledge.golden_release_http import download_release
    return download_release(release_id, version_id, ctx, s, attempt_id=attempt_id)


@router.post("/holdout-attempts", status_code=201)
def create_attempt(body: AttemptIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_holdout
    return golden_holdout.create(s, ctx.principal, body.model_dump())


@router.get("/holdout-attempts")
def attempts(limit: int = 50, cursor: str | None = None,
             ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_holdout
    return golden_holdout.list_for(s, ctx.principal, limit=limit, cursor=cursor)


@router.get("/holdout-attempts/{attempt_id}")
def attempt(attempt_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_holdout
    return golden_holdout.to_dict(s, ctx.principal, golden_holdout.get(s, ctx.principal, attempt_id))


@router.post("/holdout-attempts/{attempt_id}/result")
def attempt_result(attempt_id: str, body: ResultIn, ctx: AuthContext = Depends(auth),
                   s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_holdout
    return golden_holdout.record_result(s, ctx.principal, attempt_id, body.model_dump())


@router.get("/holdout-attempts/{attempt_id}/answers")
def attempt_answers(attempt_id: str, ctx: AuthContext = Depends(require_perm("golden.evaluate.read")),
                    s: Session = Depends(db, scope="function")):
    from saw.knowledge import golden_holdout
    data = golden_holdout.answers(s, ctx.principal, attempt_id)
    s.commit()
    return Response(data, media_type="application/x-ndjson", headers={"Cache-Control": "no-store"})


@router.get("/profiles")
def profiles(kind: str, limit: int = 50, cursor: str | None = None,
             ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return golden_profiles.list_for(s, ctx.principal, kind, limit=limit, cursor=cursor)


@router.post("/profiles", status_code=201)
def create_profile(body: ProfileIn, ctx: AuthContext = Depends(require_perm("knowledge.write")),
                   s: Session = Depends(db, scope="function")):
    return golden_profiles.to_dict(golden_profiles.create(s, ctx.principal, body.model_dump()))


@router.get("/profiles/{profile_id}")
def profile(profile_id: str, ctx: AuthContext = Depends(require_perm("knowledge.read")),
            s: Session = Depends(db, scope="function")):
    return golden_profiles.to_dict(golden_profiles.get(s, ctx.principal, profile_id))


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
