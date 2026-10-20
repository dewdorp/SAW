"""Authorized analysis history and frozen HTML report endpoints."""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.analysis_runs import service
from saw.analysis_runs.models import AnalysisRun
from saw.apps.api.deps import AuthContext, auth, db
from saw.core.application.investigations import require
from saw.reports import service as reports

router = APIRouter(tags=["analysis-runs"])


@router.get("/investigations/{inv_id}/analysis-runs")
def listing(inv_id: str, limit: int = Query(50, ge=1, le=200),
            before_version: int | None = Query(None, ge=1), ctx: AuthContext = Depends(auth),
            s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    query = select(AnalysisRun).where(AnalysisRun.investigation_id == inv_id)
    if before_version is not None:
        query = query.where(AnalysisRun.version < before_version)
    rows = list(s.scalars(query.order_by(AnalysisRun.version.desc()).limit(limit + 1)))
    visible = []
    from saw.core.application.investigations import Forbidden, NotFound
    for row in rows[:limit]:
        try:
            service.get(s, ctx.principal, inv_id, row.id)
        except (Forbidden, NotFound):
            continue
        visible.append(service.run_dict(s, row, full=False))
    return {"runs": visible, "next_before_version": rows[limit - 1].version if len(rows) > limit else None}


@router.get("/investigations/{inv_id}/analysis-runs/{run_id}")
def get(inv_id: str, run_id: str, ctx: AuthContext = Depends(auth),
        s: Session = Depends(db, scope="function")):
    return service.run_dict(s, service.get(s, ctx.principal, inv_id, run_id))


@router.get("/investigations/{inv_id}/report-versions")
def report_listing(inv_id: str, before_version: int | None = Query(None, ge=1),
                   limit: int = Query(50, ge=1, le=200), ctx: AuthContext = Depends(auth),
                   s: Session = Depends(db, scope="function")):
    from saw.reports.models import ReportVersion
    require(s, ctx.principal, "investigation.read", inv_id)
    query = select(ReportVersion).where(ReportVersion.investigation_id == inv_id)
    if before_version is not None:
        query = query.where(ReportVersion.version < before_version)
    rows = list(s.scalars(query.order_by(ReportVersion.version.desc()).limit(limit + 1)))
    visible = []
    from saw.core.application.investigations import Forbidden, NotFound
    for row in rows[:limit]:
        try:
            reports.get(s, ctx.principal, inv_id, row.id)
        except (Forbidden, NotFound):
            continue
        visible.append({"id": row.id, "version": row.version, "created_at": row.created_at,
                        "content_sha256": row.content_sha256})
    return {"reports": visible, "next_before_version": rows[limit - 1].version if len(rows) > limit else None}


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_run_id: str


@router.post("/investigations/{inv_id}/report-versions", status_code=201)
def create_report(inv_id: str, body: ReportIn, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    return reports.to_dict(reports.create(s, ctx.principal, inv_id, analysis_run_id=body.analysis_run_id))


@router.get("/investigations/{inv_id}/report-versions/{report_id}")
def get_report(inv_id: str, report_id: str, ctx: AuthContext = Depends(auth),
               s: Session = Depends(db, scope="function")):
    return reports.to_dict(reports.get(s, ctx.principal, inv_id, report_id))


@router.get("/investigations/{inv_id}/report-versions/{report_id}/html", response_class=HTMLResponse)
def report_html(inv_id: str, report_id: str, ctx: AuthContext = Depends(auth),
                s: Session = Depends(db, scope="function")):
    from saw.reports.html import csp, render
    return HTMLResponse(render(reports.get(s, ctx.principal, inv_id, report_id)),
        headers={"Content-Security-Policy": csp()})


from saw.analysis_runs.scoped import ScopedRequest


@router.post("/investigations/{inv_id}/analysis-runs", status_code=202)
def submit_scoped(inv_id: str, body: ScopedRequest, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    from saw import container
    from saw.analysis_runs.scoped import submit
    from saw.apps.api.routers.evidence import job_out
    job, created = submit(s, ctx.principal, inv_id, body.model_dump())
    s.commit()
    if created:
        container.get().runner.submit("device_analysis.run", job_id=job.id)
    s.refresh(job)
    return job_out(job)
