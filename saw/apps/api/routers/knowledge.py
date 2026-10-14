from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.apps.api.routers.golden import LinkedGoldenDecision
from saw.core.application.analysis import finding_dict
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.schemas.query import AggRequest, Filter
from saw.knowledge import asset as asset_svc
from saw.knowledge import experience as exp_svc
from saw.knowledge import fp as fp_svc
from saw.knowledge import similar
from saw.knowledge.models import Asset, Experience, FalsePositiveRule, SimilarFeedback
from saw.storage.models import Finding

router = APIRouter(tags=["knowledge"])


class ExpIn(BaseModel):
    data: dict


class ReviewIn(BaseModel):
    comment: str = ""
    ack_fp_conflicts: bool = False
    golden: LinkedGoldenDecision | None = None


class AssetIn(BaseModel):
    asset_id: str = Field(min_length=1, max_length=64)
    service: str = Field(min_length=1, max_length=256)
    criticality: str = "medium"
    data: dict = Field(default_factory=dict)


class CsvIn(BaseModel):
    csv: str = Field(min_length=1, max_length=5_000_000)


class FpIn(BaseModel):
    title: str
    detector_id: str | None = None
    conditions: list[dict]
    reason: str = ""
    days: int = 180


class PlaybookIn(BaseModel):
    title: str
    applies_to: list[str] = Field(default_factory=list)
    steps: list[dict] = Field(default_factory=list)


class SimilarIn(BaseModel):
    investigation_id: str | None = None
    finding_id: str | None = None
    text: str = ""
    features: dict | None = None
    k: int = Field(10, le=50)


class FeedbackIn(BaseModel):
    query_ref: str
    result_ref: str
    useful: bool
    score: float = 0


class ContextIn(BaseModel):
    finding_id: str | None = None
    entity: dict | None = None


# ---------------------------------------------------------------- experiences
@router.get("/experiences")
def list_exp(status: str | None = None, q: str | None = None, ctx: AuthContext = Depends(require_perm("knowledge.read")),
             s: Session = Depends(db, scope="function")):
    return [exp_svc.to_dict(e) for e in exp_svc.list_for(s, ctx.principal, status, q)]


@router.post("/experiences", status_code=201)
def create_exp(body: ExpIn, ctx: AuthContext = Depends(require_perm("knowledge.write")), s: Session = Depends(db, scope="function")):
    return exp_svc.to_dict(exp_svc.create(s, ctx.principal, body.data))


@router.get("/experiences/{eid}")
def get_exp(eid: str, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    e = s.get(Experience, eid)
    if e is None or not exp_svc.visible(e, ctx.principal):
        raise NotFound("experience not found")
    e.views += 1
    d = exp_svc.to_dict(e)
    d["fp_conflicts"] = exp_svc.fp_conflicts(s, ctx.principal, e.data.get("false_positive_conditions") or [])
    return d


@router.patch("/experiences/{eid}")
def update_exp(eid: str, body: ExpIn, ctx: AuthContext = Depends(require_perm("knowledge.write")), s: Session = Depends(db, scope="function")):
    return exp_svc.to_dict(exp_svc.update(s, ctx.principal, eid, body.data))


@router.post("/experiences/{eid}/submit")
def submit_exp(eid: str, ctx: AuthContext = Depends(require_perm("knowledge.write")), s: Session = Depends(db, scope="function")):
    return exp_svc.to_dict(exp_svc.submit(s, ctx.principal, eid))


@router.post("/experiences/{eid}/approve")
def approve_exp(eid: str, body: ReviewIn, ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    e = exp_svc.approve(s, ctx.principal, eid, body.comment, body.ack_fp_conflicts)
    if body.golden:
        from saw.knowledge import golden
        from saw.knowledge.golden_models import GoldenVersion
        g = s.get(GoldenVersion, body.golden.version_id)
        if g is None or g.experience_id != eid:
            raise ValueError("golden_experience_mismatch")
        golden.review(s, ctx.principal, body.golden.version_id,
                      **body.golden.model_dump(exclude={"version_id"}))
    return exp_svc.to_dict(e)


@router.post("/experiences/{eid}/reject")
def reject_exp(eid: str, body: ReviewIn, ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    return exp_svc.to_dict(exp_svc.reject(s, ctx.principal, eid, body.comment))


@router.post("/experiences/{eid}/deprecate")
def deprecate_exp(eid: str, body: ReviewIn, ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    return exp_svc.to_dict(exp_svc.deprecate(s, ctx.principal, eid, body.comment))


@router.get("/experiences/{eid}/revisions")
def exp_revisions(eid: str, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    e = s.get(Experience, eid)
    if e is None or not exp_svc.visible(e, ctx.principal):
        raise NotFound("experience not found")
    return exp_svc.revisions(s, eid)


# ---------------------------------------------------------------- assets
@router.get("/assets")
def list_assets(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return [asset_svc.to_dict(a) for a in asset_svc.all_assets(s)]


@router.post("/assets", status_code=201)
def upsert_asset(body: AssetIn, ctx: AuthContext = Depends(require_perm("asset.write")), s: Session = Depends(db, scope="function")):
    return asset_svc.to_dict(asset_svc.upsert(s, ctx.principal, body.asset_id, body.service, body.criticality, body.data))


@router.post("/assets/import")
def import_assets(body: CsvIn, ctx: AuthContext = Depends(require_perm("asset.write")), s: Session = Depends(db, scope="function")):
    return asset_svc.import_csv(s, ctx.principal, body.csv)


@router.get("/assets/match")
def match_asset(ip: str | None = None, host: str | None = None, path: str | None = None,
                ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    a = asset_svc.match(asset_svc.all_assets(s), ip, host, path)
    return asset_svc.to_dict(a) if a else None


# ---------------------------------------------------------------- fp rules / playbooks
@router.get("/fp-rules")
def list_fp(ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return [fp_svc.fp_dict(r) for r in s.execute(select(FalsePositiveRule).order_by(FalsePositiveRule.created_at.desc())).scalars()]


@router.post("/fp-rules", status_code=201)
def create_fp(body: FpIn, ctx: AuthContext = Depends(require_perm("knowledge.write")), s: Session = Depends(db, scope="function")):
    return fp_svc.fp_dict(fp_svc.create_fp(s, ctx.principal, body.title, body.detector_id, body.conditions, body.reason, body.days))


@router.post("/fp-rules/{rid}/approve")
def approve_fp(rid: str, body: ReviewIn, ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    return fp_svc.fp_dict(fp_svc.approve_fp(s, ctx.principal, rid, body.ack_fp_conflicts))


@router.get("/playbooks")
def list_pb(category: str | None = None, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    return fp_svc.playbooks_for(s, category)


@router.post("/playbooks", status_code=201)
def create_pb(body: PlaybookIn, ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    return fp_svc.pb_dict(fp_svc.upsert_playbook(s, ctx.principal, body.title, body.applies_to, body.steps))


# ---------------------------------------------------------------- similar
@router.post("/similar/search")
def similar_search(body: SimilarIn, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    if body.investigation_id:
        require(s, ctx.principal, "investigation.read", body.investigation_id)
        feats, text = similar.features_for_investigation(s, body.investigation_id, body.finding_id)
    else:
        feats, text = body.features or {}, body.text
    res = similar.search(s, feats, body.text or text, body.k, exclude_ref=body.investigation_id)
    return {"query_features": feats, "results": _visible_results(s, ctx, res)}


def _visible_results(s: Session, ctx: AuthContext, res: list[dict]) -> list[dict]:
    from saw.core.application.investigations import list_for

    readable = {i.id for i in list_for(s, ctx.principal, 1000)}
    return [r for r in res if r["ref_type"] != "investigation" or r["ref_id"] in readable]


@router.post("/similar/feedback")
def similar_feedback(body: FeedbackIn, ctx: AuthContext = Depends(require_perm("knowledge.read")), s: Session = Depends(db, scope="function")):
    s.add(SimilarFeedback(query_ref=body.query_ref, result_ref=body.result_ref, useful=body.useful,
                          user_id=ctx.principal.user_id, score=body.score))
    return {"ok": True}


@router.post("/similar/rebuild")
def similar_rebuild(ctx: AuthContext = Depends(require_perm("knowledge.approve")), s: Session = Depends(db, scope="function")):
    return {"indexed": similar.rebuild(s)}


# ---------------------------------------------------------------- workbench context panel
@router.post("/investigations/{inv_id}/context")
def context(inv_id: str, body: ContextIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Right panel: Asset → Similar → Experience → Assistant (docs/15 §1.4)."""
    require(s, ctx.principal, "investigation.read", inv_id)
    es = container.get().events
    finding = None
    if body.finding_id:
        f = s.get(Finding, body.finding_id)
        if f is None or f.investigation_id != inv_id:
            raise NotFound("finding not found")
        finding = finding_dict(f)
    flt = []
    if body.entity and body.entity.get("type") == "ip":
        flt = [Filter(field="src_ip", value=body.entity.get("value"))]
    inv_ents = {
        "dst_ips": [b["key"] for b in es.aggregate(inv_id, flt, AggRequest(type="terms", field="dst_ip", size=5))["buckets"]],
        "hosts": [b["key"] for b in es.aggregate(inv_id, flt, AggRequest(type="terms", field="hostname", size=5))["buckets"]],
        "paths": [b["key"] for b in es.aggregate(inv_id, flt, AggRequest(type="terms", field="url_path", size=5))["buckets"]],
        "countries": [b["key"] for b in es.aggregate(inv_id, flt, AggRequest(type="terms", field="src_geo_country", size=3))["buckets"]],
    }
    assets = asset_svc.context_for(s, finding, inv_ents)
    feats, text = similar.features_for_investigation(s, inv_id, body.finding_id)
    sims = _visible_results(s, ctx, similar.search(s, feats, text, 6, exclude_ref=inv_id))
    exps = []
    for r in sims:
        if r["ref_type"] == "experience":
            exps.append({"id": r["ref_id"], "display_id": r["display_id"], "title": r["title"], "verdict": r["verdict"],
                         "score": r["score"], "date": (r["extra"].get("created") or "")[:10],
                         "fp_conditions": r["extra"].get("fp_conditions", []),
                         "recommended_checks": r["extra"].get("recommended_checks", []), "same": r["same"],
                         "different": r["different"]})
    from saw.knowledge.fp import playbooks_for

    return {"assets": assets, "similar": [r for r in sims if r["ref_type"] != "experience"] + [r for r in sims if r["ref_type"] == "experience"][:2],
            "experiences": exps, "playbooks": playbooks_for(s, finding["category"] if finding else None)[:3],
            "query_features": feats, "assistant_available": _llm_available()}


def _llm_available() -> bool:
    try:
        from saw.llm.service import provider_status
    except ImportError:
        return False
    return provider_status().get("available", False)


_ = Asset, Forbidden
