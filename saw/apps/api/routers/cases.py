from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.application import audit
from saw.core.application.analysis import finding_dict
from saw.core.application.ids import next_display_id
from saw.core.application.investigations import NotFound, list_for, require
from saw.core.security.masking import mask_text
from saw.storage.db import utcnow
from saw.storage.models import AttackStory, Case, CaseItem, CaseRevision, Finding, Investigation

router = APIRouter(prefix="/cases", tags=["cases"])
ITEM_TYPES = {"finding", "event_ref", "entity", "evidence", "story_snapshot", "note", "detection"}


class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    severity: str = "medium"
    investigation_ids: list[str] = Field(default_factory=list)
    summary_md: str = ""


class CasePatch(BaseModel):
    title: str | None = None
    severity: str | None = None
    status: str | None = None
    assignee_id: str | None = None
    summary_md: str | None = None
    response_md: str | None = None
    verdict: str | None = None


class ItemIn(BaseModel):
    item_type: str
    ref_id: str
    investigation_id: str | None = None


def _readable(s: Session, ctx: AuthContext, c: Case) -> None:
    s.execute(update(Case).where(Case.id == c.id).values(id=c.id).execution_options(synchronize_session=False))
    s.refresh(c)
    if c.status in ("deleted", "deleting"):
        raise NotFound("case not found")
    ok = {i.id for i in list_for(s, ctx.principal, 500)}
    if c.created_by != ctx.principal.user_id and not (set(c.investigation_ids or []) & ok):
        from saw.core.application.investigations import Forbidden

        raise Forbidden("case.read")


def case_out(s: Session, c: Case, items: bool = False) -> dict:
    d = {"id": c.id, "display_id": c.display_id, "title": c.title, "severity": c.severity, "status": c.status,
         "assignee_id": c.assignee_id, "summary_md": c.summary_md, "response_md": c.response_md, "verdict": c.verdict,
         "investigation_ids": c.investigation_ids, "related_detection_ids": c.related_detection_ids,
         "created_at": c.created_at, "closed_at": c.closed_at}
    if items:
        d["items"] = [{"id": i.id, "type": i.item_type, "ref_id": i.ref_id, "snapshot": i.snapshot, "added_at": i.added_at}
                      for i in s.execute(select(CaseItem).where(CaseItem.case_id == c.id)).scalars()]
    return d


@router.post("", status_code=201)
def create(body: CaseIn, ctx: AuthContext = Depends(require_perm("case.write")), s: Session = Depends(db, scope="function")):
    for iid in body.investigation_ids:
        require(s, ctx.principal, "investigation.read", iid)
    c = Case(display_id=next_display_id(s, "CASE"), title=body.title, severity=body.severity,
             investigation_ids=body.investigation_ids, summary_md=body.summary_md, created_by=ctx.principal.user_id)
    s.add(c)
    s.flush()
    s.add(CaseRevision(case_id=c.id, rev=1, diff={"created": body.model_dump()}, actor=ctx.principal.username))
    audit.record(s, "case.create", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="case", target_id=c.id)
    return case_out(s, c)


@router.get("")
def list_cases(ctx: AuthContext = Depends(require_perm("case.read")), s: Session = Depends(db, scope="function")):
    ok = {i.id for i in list_for(s, ctx.principal, 500)}
    return [case_out(s, c) for c in s.execute(select(Case).where(Case.status.notin_(["deleted", "deleting"])).order_by(Case.created_at.desc())).scalars()
            if c.created_by == ctx.principal.user_id or set(c.investigation_ids or []) & ok]


@router.get("/{cid}")
def get(cid: str, ctx: AuthContext = Depends(require_perm("case.read")), s: Session = Depends(db, scope="function")):
    c = s.get(Case, cid)
    if c is None:
        raise NotFound("case not found")
    _readable(s, ctx, c)
    return case_out(s, c, items=True)


@router.patch("/{cid}")
def patch(cid: str, body: CasePatch, ctx: AuthContext = Depends(require_perm("case.write")), s: Session = Depends(db, scope="function")):
    c = s.get(Case, cid)
    if c is None:
        raise NotFound("case not found")
    _readable(s, ctx, c)
    if body.status in ("deleted", "deleting"):
        raise HTTPException(403, "관리자 데이터 관리에서만 폐기할 수 있습니다.")
    diff = {}
    for k, v in body.model_dump(exclude_none=True).items():
        if getattr(c, k) != v:
            diff[k] = {"from": getattr(c, k), "to": v}
            setattr(c, k, v)
    if body.status == "closed" and c.closed_at is None:
        c.closed_at = utcnow()
    if diff:
        rev = len(s.execute(select(CaseRevision).where(CaseRevision.case_id == cid)).scalars().all()) + 1
        s.add(CaseRevision(case_id=cid, rev=rev, diff=diff, actor=ctx.principal.username))
        audit.record(s, "case.update", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                     target_type="case", target_id=cid, detail={"fields": sorted(diff)})
    return case_out(s, c)


@router.post("/{cid}/items", status_code=201)
def add_item(cid: str, body: ItemIn, ctx: AuthContext = Depends(require_perm("case.write")), s: Session = Depends(db, scope="function")):
    c = s.get(Case, cid)
    if c is None:
        raise NotFound("case not found")
    _readable(s, ctx, c)
    if body.item_type not in ITEM_TYPES:
        raise HTTPException(400, "unknown item type")
    snap: dict = {}
    if body.item_type == "finding":
        f = s.get(Finding, body.ref_id)
        if f is None:
            raise NotFound("finding not found")
        require(s, ctx.principal, "investigation.read", f.investigation_id)
        snap = finding_dict(f)
        for k in ("time_start", "time_end"):
            snap[k] = snap[k].isoformat() if snap[k] else None
        if f.investigation_id not in (c.investigation_ids or []):
            c.investigation_ids = list(c.investigation_ids or []) + [f.investigation_id]
    elif body.item_type == "story_snapshot":
        st = s.get(AttackStory, body.ref_id)
        if st is None:
            raise NotFound("story not found")
        require(s, ctx.principal, "investigation.read", st.investigation_id)
        snap = {"version": st.version, "graph": st.graph}
    elif body.item_type == "event_ref" and body.investigation_id:
        from saw import container

        require(s, ctx.principal, "investigation.read", body.investigation_id)
        e = container.get().events.get(body.investigation_id, body.ref_id)
        if e:
            from saw.core.security.masking import mask_event

            snap = mask_event(e)[0]
    else:
        snap = {"ref": body.ref_id}
    item = CaseItem(case_id=cid, item_type=body.item_type, ref_id=body.ref_id, snapshot=snap,
                    added_by=ctx.principal.user_id)
    s.add(item)
    audit.record(s, "case.item_add", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="case", target_id=cid, detail={"type": body.item_type, "ref": body.ref_id})
    s.flush()
    return {"id": item.id}


@router.get("/{cid}/history")
def history(cid: str, ctx: AuthContext = Depends(require_perm("case.read")), s: Session = Depends(db, scope="function")):
    c = s.get(Case, cid)
    if c is None:
        raise NotFound("case not found")
    _readable(s, ctx, c)
    return [{"rev": r.rev, "diff": r.diff, "actor": r.actor, "at": r.at} for r in s.execute(
        select(CaseRevision).where(CaseRevision.case_id == cid).order_by(CaseRevision.rev)).scalars()]


@router.get("/{cid}/export", response_class=PlainTextResponse)
def export_md(cid: str, ctx: AuthContext = Depends(require_perm("case.read")), s: Session = Depends(db, scope="function")):
    """Markdown report (masking applied, watermark). PDF/DOCX conversion is a later phase."""
    c = s.get(Case, cid)
    if c is None:
        raise NotFound("case not found")
    _readable(s, ctx, c)
    items = s.execute(select(CaseItem).where(CaseItem.case_id == cid)).scalars().all()
    lines = [f"# {c.display_id} {c.title}", "", f"- Severity: {c.severity}", f"- Status: {c.status}",
             f"- Verdict: {c.verdict or '-'}", "", "## Summary", mask_text(c.summary_md or "-").text, "",
             "## Findings"]
    for it in items:
        if it.item_type == "finding":
            f = it.snapshot
            lines.append(f"### {f.get('display_id')} {f.get('title')} ({f.get('risk_level')})")
            for ch in f.get("checks", []):
                mark = "✓" if ch.get("passed") else ("✗" if ch.get("passed") is False else "·")
                lines.append(f"- {mark} {ch.get('label')}: {ch.get('value')}")
            att = ", ".join(f"{a['technique_id']} ({a['confidence']})" for a in f.get("attack", []))
            if att:
                lines.append(f"- ATT&CK: {att}")
    lines += ["", "## Response", mask_text(c.response_md or "-").text, "",
              f"---\nExported by {ctx.principal.username} at {utcnow().isoformat()} · SAW (masked)"]
    audit.record(s, "case.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="case", target_id=cid, detail={"format": "md"})
    return "\n".join(lines)


_ = Investigation
