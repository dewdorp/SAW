from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.attack import views
from saw.attack.catalog import ATTACK_VERSION, CATALOG_SOURCE, TACTICS, TECHNIQUES
from saw.core.application import audit
from saw.core.application.analysis import finding_dict, present_sources
from saw.core.application.investigations import require
from saw.storage.models import Finding

router = APIRouter(tags=["attack"])


def _findings(s: Session, inv_id: str) -> list[dict]:
    out = []
    for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id,
                                             Finding.status.notin_(["false_positive", "duplicate"]))).scalars():
        d = finding_dict(f)
        d["time_start"] = d["time_start"].isoformat() if d["time_start"] else None
        out.append(d)
    return out


@router.get("/attack/techniques")
def techniques(ctx: AuthContext = Depends(auth)):
    return {"version": ATTACK_VERSION, "source": CATALOG_SOURCE, "tactics": [{"id": a, "short": b, "name": c} for a, b, c in TACTICS],
            "techniques": [{"technique_id": k, **v} for k, v in TECHNIQUES.items()]}


@router.get("/investigations/{inv_id}/attack/matrix")
def matrix(inv_id: str, mode: str = "compact", ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return views.matrix(_findings(s, inv_id), mode)


@router.get("/investigations/{inv_id}/attack/timeline")
def timeline(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return views.technique_timeline(_findings(s, inv_id))


@router.get("/investigations/{inv_id}/attack/inferred")
def inferred(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    return views.inferred(_findings(s, inv_id), set(present_sources(inv_id)))


@router.get("/investigations/{inv_id}/attack/navigator-layer")
def layer(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv = require(s, ctx.principal, "investigation.read", inv_id)
    audit.record(s, "attack.export_layer", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 investigation_id=inv_id)
    return views.navigator_layer(_findings(s, inv_id), f"SAW {inv.display_id}")
