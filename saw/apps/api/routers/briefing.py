"""Report summary of an investigation (view, rewrite, printable page) and the board over investigations."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, client_ip, db
from saw.core.application import audit, briefing
from saw.core.application.investigations import require
from saw.core.security.authz import can
from saw.detection.derived_access import (
    require_investigation_results,
)

router = APIRouter(tags=["briefing"])


class BriefingIn(BaseModel):
    fields: dict[str, Any]


def _out(s: Session, ctx: AuthContext, inv_id: str, mask: bool) -> dict:
    inv = require(s, ctx.principal, "investigation.read", inv_id)
    require_investigation_results(s, ctx.principal, inv_id)
    out = briefing.build(s, inv, mask=mask)
    from saw.core.application.investigations import access_of

    out["can_edit"] = can(ctx.principal, "investigation.write", access_of(s, ctx.principal, inv_id))
    return out


@router.get("/investigations/{inv_id}/briefing")
def get(inv_id: str, mask: bool = True, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return _out(s, ctx, inv_id, mask)


@router.put("/investigations/{inv_id}/briefing")
def put(inv_id: str, body: BriefingIn, mask: bool = True, ctx: AuthContext = Depends(auth),
        s: Session = Depends(db, scope="function")):
    briefing.save(s, ctx.principal, inv_id, body.fields)
    s.flush()
    return _out(s, ctx, inv_id, mask)


@router.get("/investigations/{inv_id}/briefing.html")
def page(inv_id: str, request: Request, mask: bool = True, ctx: AuthContext = Depends(auth),
         s: Session = Depends(db, scope="function")):
    """Self-contained page for printing or saving as PDF; leaving the system, so the export is audited."""
    inv = require(s, ctx.principal, "investigation.read", inv_id)
    require_investigation_results(s, ctx.principal, inv_id)
    body = briefing.render_html(briefing.build(s, inv, mask=mask), ctx.principal.username)
    audit.record(s, "briefing.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="investigation", target_id=inv_id, investigation_id=inv_id,
                 detail={"masked": mask})
    return HTMLResponse(body, headers={"Content-Disposition": f'attachment; filename="{inv.display_id}-report.html"',
                                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})


@router.get("/board")
def board(days: int = Query(30, ge=1, le=365), ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Every investigation the caller may read (a SOC manager: all of them), with what needs attention first."""
    return briefing.board(s, ctx.principal, days)
