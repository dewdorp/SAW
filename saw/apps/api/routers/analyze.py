from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application import analyze as svc

router = APIRouter(prefix="/analyze", tags=["analyze"])


def _limit(text: str) -> None:
    if len(text.encode("utf-8")) > container.get().settings.sync_input_max_bytes:
        raise HTTPException(413, "Input exceeds sync limit (5 MB). Use upload.")


class TextIn(BaseModel):
    input: str = Field(min_length=1)


class IocIn(BaseModel):
    observables: list[str] = Field(min_length=1, max_length=200)
    org_unit_id: str | None = Field(None, max_length=36)  # narrows internal (private) addresses to one affiliate


class HttpIn(BaseModel):
    request: str = Field(min_length=1)
    response: str | None = None


class PayloadIn(BaseModel):
    input: str = Field(min_length=1)
    chain: list[str] | None = None


class DiffIn(BaseModel):
    requests: list[str] = Field(min_length=1, max_length=200)


class LogIn(BaseModel):
    text: str = Field(min_length=1)
    parser_id: str | None = None


@router.post("/universal")
def universal(body: TextIn, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    _limit(body.input)
    return svc.universal(s, ctx.principal, body.input)


@router.post("/ioc")
def ioc(body: IocIn, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return {"items": svc.ioc(s, ctx.principal, body.observables, org_unit_id=body.org_unit_id)}


@router.post("/ioc/external")
def ioc_external(body: IocIn, ctx: AuthContext = Depends(require_perm("analyze.run"))):
    # Egress is disabled by default (docs/12 §4.5, ENV-10)
    raise HTTPException(409, "External enrichment is disabled by policy in this deployment (enrich profile off).")


@router.post("/http")
def http(body: HttpIn, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    _limit(body.request + (body.response or ""))
    return svc.http(s, ctx.principal, body.request, body.response)


@router.post("/payload")
def payload(body: PayloadIn, ctx: AuthContext = Depends(require_perm("analyze.run"))):
    _limit(body.input)
    return svc.payload(body.input, body.chain)


@router.post("/diff")
def diff(body: DiffIn, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    _limit("\n".join(body.requests))
    return svc.diff(s, ctx.principal, body.requests)


@router.post("/log")
def log(body: LogIn, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    _limit(body.text)
    return svc.log(s, ctx.principal, body.text, body.parser_id)
