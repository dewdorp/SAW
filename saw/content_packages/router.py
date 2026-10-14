"""Authenticated browser flow for offline declarative content."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.content_packages import format as fmt, service
from saw.content_packages.example import example_document
from saw.core.application import audit

router = APIRouter(prefix="/content-packages", tags=["content packages"])


class DigestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActionIn(DigestIn):
    reason: str = Field(min_length=1, max_length=1000)


async def _command(request: Request, model):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 8192:
            raise HTTPException(413, "승인·시험 요청이 너무 큽니다.")
    try:
        return model.model_validate(fmt.read_json(data.decode("utf-8")), strict=True)
    except UnicodeError:
        raise ValueError("올바른 UTF-8 JSON 요청이 아닙니다.") from None


async def _digest_body(request: Request):
    return await _command(request, DigestIn)


async def _action_body(request: Request):
    return await _command(request, ActionIn)


def _call(fn, *args):
    try:
        return fn(*args)
    except service.Conflict as error:
        raise HTTPException(409, str(error)) from None
    except fmt.TooLarge as error:
        raise HTTPException(413, str(error)) from None


async def _document(request: Request, *, sealed=True):
    # A JSON string wrapper can escape each source byte; bound transport before materializing it.
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 6 * fmt.MAX_BYTES + 4096:
            raise HTTPException(413, "콘텐츠 파일은 최대 1MiB입니다.")
    try:
        body = json.loads(data.decode("utf-8"), object_pairs_hook=fmt._pairs)
        if not isinstance(body, dict) or set(body) != {"text"}:
            raise ValueError("text 필드에 JSON 파일 내용을 입력하세요.")
        document = fmt.read_json(body["text"])
        return fmt.validate(document) if sealed else document
    except fmt.TooLarge as error:
        raise HTTPException(413, str(error)) from None
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("올바른 JSON 요청이 아닙니다.") from None


@router.get("")
def listing(ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return {"packages": service.list_packages(s, ctx.principal)}


@router.get("/example")
def example(ctx: AuthContext = Depends(require_perm("analyze.run"))):
    return example_document()


@router.post("/build")
async def build(request: Request, ctx: AuthContext = Depends(require_perm("analyze.run"))):
    return _call(fmt.seal, await _document(request, sealed=False))


@router.post("/verify")
async def verify(request: Request, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.verify, s, await _document(request))


@router.post("/stage", status_code=201)
async def stage(request: Request, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.stage, s, ctx.principal, await _document(request))


@router.get("/{ident}")
def detail(ident: str, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return service.to_dict(service._get(s, ident), ctx.principal)


@router.post("/{ident}/test")
def test(ident: str, body: DigestIn = Depends(_digest_body), ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.test_package, s, ctx.principal, ident, body.digest)


@router.post("/{ident}/apply")
def apply(ident: str, body: ActionIn = Depends(_action_body), ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.apply_package, s, ctx.principal, ident, body.digest, body.reason)


@router.get("/{ident}/rollback-preview")
def rollback_preview(ident: str, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.rollback_preview, s, ctx.principal, ident)


@router.post("/{ident}/rollback")
def rollback(ident: str, body: ActionIn = Depends(_action_body), ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return _call(service.rollback_package, s, ctx.principal, ident, body.digest, body.reason)


@router.get("/{ident}/export")
def export(ident: str, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    package = service._get(s, ident)
    _call(service._checked, package, package.digest)
    audit.record(s, "content_package.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="content_package", target_id=package.id, detail={"digest": package.digest})
    return JSONResponse(package.document, headers={"Content-Disposition": f'attachment; filename="saw-content-{package.package_id}-r{package.revision}.json"'})
