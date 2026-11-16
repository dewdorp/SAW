"""Assets and business context."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, auth, db
from saw.assets import service

router = APIRouter(tags=["assets"])


@router.get("/asset-book")
def listing(org_unit_id: str | None = None, q: str = Query("", max_length=200), ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    return service.listing(s, ctx.principal, org_unit_id=org_unit_id, q=q)


@router.post("/asset-book", status_code=201)
def quick(body: service.QuickIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.quick_create(s, ctx.principal, body)


@router.post("/asset-book/import/preview")
def import_preview(body: service.ImportIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.import_preview(s, ctx.principal, body)


@router.post("/asset-book/import/apply")
def import_apply(body: service.ImportIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.import_apply(s, ctx.principal, body)


@router.put("/asset-book/{asset_pk}")
def update(asset_pk: str, body: service.UpdateIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.update(s, ctx.principal, asset_pk, body)


@router.get("/asset-book/{asset_pk}/history")
def history(asset_pk: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return {"revisions": service.history(s, ctx.principal, asset_pk)}


@router.get("/investigations/{inv_id}/asset-candidates")
def candidates(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.candidates(s, ctx.principal, inv_id)
