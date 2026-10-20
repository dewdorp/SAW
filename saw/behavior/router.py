"""Investigation-authorized persisted behavior calculations and report exports."""
import base64
import hashlib
import re

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from saw import container
from saw.apps.api.deps import AuthContext, auth, db
from saw.apps.api.routers.evidence import job_out
from saw.behavior import service
from saw.core.application import audit, checks

router = APIRouter(tags=["behavior"])

@router.post("/investigations/{inv_id}/behavior", status_code=202)
def submit(inv_id: str, body: service.BehaviorRequest, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    job, created = service.submit(s, ctx.principal, inv_id, body.model_dump())
    s.commit()
    if created:
        container.get().runner.submit("behavior.run", job_id=job.id)
    s.refresh(job)
    return job_out(job)

@router.get("/investigations/{inv_id}/behavior")
def listing(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    return service.list_results(s, ctx.principal, inv_id)

@router.get("/investigations/{inv_id}/behavior/{result_id}")
def result(inv_id: str, result_id: str, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    return service.to_dict(service.get(s, ctx.principal, inv_id, result_id))

@router.get("/investigations/{inv_id}/behavior/{result_id}/report", response_class=HTMLResponse)
def report(inv_id: str, result_id: str, ctx: AuthContext = Depends(auth),
           s: Session = Depends(db, scope="function")):
    from saw.behavior.report import render_report
    row = service.get(s, ctx.principal, inv_id, result_id)
    records = [checks.to_dict(c) for c in checks.list_checks(s, inv_id, principal=ctx.principal)
               if (c.scope or {}).get("behavior", {}).get("result_id") == row.id]
    audit.record(s, "behavior.report_export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="behavior_result", target_id=row.id, investigation_id=inv_id,
                 detail={"result_sha256": row.result_sha256, "check_ids": [c["id"] for c in records]})
    html = render_report(service.to_dict(row), analyst_checks=records)
    # Permit the exact generated stylesheet; untrusted report values are escaped.
    styles = re.findall(r"<style>(.*?)</style>", html, re.S)
    hashes = " ".join("'sha256-" + base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode() + "'"
                      for css in styles)
    return HTMLResponse(html, headers={"Content-Security-Policy":
        f"default-src 'none'; style-src {hashes or chr(39) + 'none' + chr(39)}; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
