"""Investigation workbench queries (docs/11 Investigation section)."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saw import container
from saw.analyzers.timeline.collapse import collapse
from saw.apps.api.deps import AuthContext, auth, db, require_perm
from saw.core.application import audit
from saw.core.application.analysis import finding_dict
from saw.core.application.investigations import NotFound, require
from saw.core.application.rawref import hydrate_raw
from saw.core.schemas.query import AggRequest, AggregateRequest, Filter, GroupMetric, SearchRequest, TimeRange
from saw.core.security.authz import has_permission
from saw.core.security.masking import mask_event, mask_text
from saw.storage.models import (
    AttackStory, Entity, EvidenceFile, Evidence, Finding, FindingFeedback, Investigation, Note, ParameterProfile,
    Pattern, Relation, SavedView,
)

router = APIRouter(prefix="/investigations/{inv_id}", tags=["workbench"])


class FiltersIn(BaseModel):
    filters: list[Filter] = Field(default_factory=list)
    time: TimeRange | None = None


class StatisticsIn(FiltersIn):
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    group_by: Literal["data_source", "source_file", "src_ip", "dst_ip", "dst_port"] = "data_source"
    size: int = Field(20, ge=1, le=50)

    @model_validator(mode="after")
    def valid_time(self):
        if self.time:
            values = []
            for raw in (self.time.start, self.time.end):
                value = datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None
                if value is not None and value.tzinfo is None:
                    raise ValueError("timezone required")
                values.append(value)
            if all(values) and values[0] > values[1]:
                raise ValueError("time range must be increasing")
        return self


class PivotIn(BaseModel):
    entity_field: str
    value: str
    target_field: str
    size: int = Field(10, le=100)
    filters: list[Filter] = Field(default_factory=list)


class UnmaskIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class NoteIn(BaseModel):
    body_md: str = Field(min_length=1, max_length=20000)
    ts: str | None = None
    links: list[str] = Field(default_factory=list)


class ViewIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    state: dict


class FeedbackIn(BaseModel):
    verdict: str = Field(pattern="^(valid|benign|false_positive|duplicate)$")
    comment: str = ""


class StoryIn(BaseModel):
    graph: dict


def _es():
    return container.get().events


def _read(s: Session, ctx: AuthContext, inv_id: str) -> Investigation:
    return require(s, ctx.principal, "investigation.read", inv_id)


# ------------------------------------------------------------------ overview
@router.post("/overview")
def overview(inv_id: str, body: FiltersIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    inv = _read(s, ctx, inv_id)
    es, f, t = _es(), body.filters, body.time
    total = es.count(inv_id, f, t)
    from saw.core.application.statistics import bounds

    lo, hi = bounds(es, inv_id, f, t)

    def terms(field: str, size: int = 10):
        return es.aggregate(inv_id, f, AggRequest(type="terms", field=field, size=size), t)

    def card(field: str):
        return es.aggregate(inv_id, f, AggRequest(type="cardinality", field=field), t)

    files = s.execute(select(EvidenceFile).join(Evidence, Evidence.id == EvidenceFile.evidence_id)
                      .where(Evidence.investigation_id == inv_id)).scalars().all()
    leaves = [x for x in files if x.parse_status in ("done", "degraded", "failed", "skipped", "parsing")]
    parsed = sum(x.events_parsed for x in files)
    failed = sum(x.events_failed for x in files)
    fc = dict(s.execute(select(Finding.risk_level, func.count()).where(Finding.investigation_id == inv_id)
                        .group_by(Finding.risk_level)).all())
    top_findings = [finding_dict(x) for x in s.execute(
        select(Finding).where(Finding.investigation_id == inv_id).order_by(Finding.risk_score.desc()).limit(3)).scalars()]
    vol = es.histogram_metrics(inv_id, f, None, [], t, split_field="status_class")
    size = es.histogram_metrics(inv_id, f, vol["interval_sec"], [
        GroupMetric(type="avg", field="bytes_out", name="avg"), GroupMetric(type="max", field="bytes_out", name="max")], t)
    uip = es.histogram_metrics(inv_id, f, vol["interval_sec"], [
        GroupMetric(type="cardinality", field="src_ip", name="unique_ip")], t)
    uniq_ip, uniq_uri = card("src_ip"), card("url_path")
    return {
        "investigation": {"id": inv.id, "display_id": inv.display_id},
        "summary": {"files": len(leaves), "events": total, "time_range": [lo, hi],
                    "unique_ip": uniq_ip["value"], "unique_uri": uniq_uri["value"],
                    "approximate": bool(uniq_ip.get("approximate")),
                    "findings": fc, "parse_error_rate": round(failed / max(1, parsed + failed), 5),
                    "data_sources": terms("data_source", 20)["buckets"]},
        "top_findings": top_findings,
        "charts": {
            "volume": vol, "status": terms("status_code", 15), "size_trend": size, "unique_ip_trend": uip,
            "top_src": terms("src_ip"), "top_uri": terms("uri_template"), "top_ua": terms("user_agent"),
            "top_asn": terms("src_as_org"), "top_country": terms("src_geo_country"), "top_cloud": terms("src_cloud"),
        },
    }


@router.post("/statistics")
def statistics(inv_id: str, body: StatisticsIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    from saw.core.application.statistics import summarize

    return summarize(_es(), inv_id, body.filters, body.time, body.group_by, body.size)


# ------------------------------------------------------------------ events
@router.post("/query/events")
def query_events(inv_id: str, body: SearchRequest, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    page = _es().search(inv_id, body.filters, body.time, body.sort, body.limit, body.cursor)
    evs = []
    want_raw = bool(body.fields) and "raw_event" in body.fields  # list views show fields; detail reads the line
    for e in page["events"]:
        m, _ = mask_event(hydrate_raw(e) if want_raw else e)
        m.pop("raw_event", None) if body.fields and "raw_event" not in body.fields else None
        if body.fields:
            m = {k: m.get(k) for k in set(body.fields) | {"event_id", "timestamp", "data_source"}}
        evs.append(m)
    audit.record(s, "events.query", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 investigation_id=inv_id, detail={"filter_fields": sorted({x.field for x in body.filters})})
    return {"events": evs, "next_cursor": page["next_cursor"]}


@router.post("/query/aggregate")
def query_aggregate(inv_id: str, body: AggregateRequest, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    return _es().aggregate(inv_id, body.filters, body.agg, body.time)


@router.post("/query/pivot")
def pivot(inv_id: str, body: PivotIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    flt = body.filters + [Filter(field=body.entity_field, value=body.value)]
    return _es().aggregate(inv_id, flt, AggRequest(type="terms", field=body.target_field, size=body.size))


@router.get("/events/{event_id}")
def event_detail(inv_id: str, event_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    e = _es().get(inv_id, event_id)
    if e is None:
        raise NotFound("event not found")
    e = hydrate_raw(e)
    m, kinds = mask_event(e)
    from saw.core.security.sanitize import contains_bidi, visualize_controls

    m["raw_visual"] = visualize_controls(m.get("raw_event", ""))
    m["raw_has_bidi"] = contains_bidi(e.get("raw_event", ""))
    related = [finding_dict(f) for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars()
               if event_id in (f.evidence_refs or {}).get("sample_event_ids", [])]
    return {"event": m, "masked_kinds": kinds, "related_findings": related,
            "can_unmask": has_permission(ctx.principal, "data.unmask")}


@router.post("/events/{event_id}/unmask")
def unmask(inv_id: str, event_id: str, body: UnmaskIn, ctx: AuthContext = Depends(require_perm("data.unmask")),
           s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    e = _es().get(inv_id, event_id)
    if e is None:
        raise NotFound("event not found")
    audit.record(s, "data.unmask", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="event", target_id=event_id, investigation_id=inv_id, detail={"reason": body.reason})
    return {"event": hydrate_raw(e)}


@router.get("/events/{event_id}/context")
def raw_context(inv_id: str, event_id: str, lines: int = Query(50, le=200), ctx: AuthContext = Depends(auth),
                s: Session = Depends(db, scope="function")):
    """Original file lines around the event (S3 range read), masked."""
    _read(s, ctx, inv_id)
    e = _es().get(inv_id, event_id)
    if e is None or not (e.get("raw_ref") or {}).get("object_key"):
        raise NotFound("raw reference not available")
    ref = e["raw_ref"]
    bucket, _, key = ref["object_key"].partition("/")
    off = int(ref["offset"])
    span = 400 * lines
    start = max(0, off - span)
    data = container.get().objects.read_range(bucket, key, start, span * 2)
    enc = ref.get("enc") or "utf-8"
    rel = off - start  # byte offset: split bytes first, decode per line (multibyte text / CP949 files)
    head = data[:rel].split(b"\n")
    if start > 0:
        head = head[1:]  # first piece may be a partial line
    before = [x.decode(enc, errors="replace").rstrip("\r") for x in head[-(lines + 1):-1]] if rel else []
    after_all = [x.decode(enc, errors="replace").rstrip("\r") for x in data[rel:].split(b"\n")]
    target, after = after_all[0], after_all[1:lines + 1]
    first_no = ref["line_no"] - len(before)
    return {"source_file": e.get("source_file"), "first_line_no": first_no,
            "lines": [mask_text(x).text for x in before + [target] + after], "target_index": len(before)}


# ------------------------------------------------------------------ timeline
@router.post("/timeline")
def timeline(inv_id: str, body: SearchRequest, collapse_runs: bool = True, min_run: int = Query(5, ge=2),
             ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    body.limit = min(body.limit, 500)
    page = _es().search(inv_id, body.filters, body.time, "asc", body.limit, body.cursor)
    evs = [mask_event(e)[0] for e in page["events"]]
    items = collapse(evs, min_run) if collapse_runs else [{"kind": "event", "event": e} for e in evs]
    for it in items:
        if it["kind"] == "event":
            it["event"].pop("ext", None)
    notes = [{"id": n.id, "ts": n.ts, "body_md": n.body_md, "author": n.author_name}
             for n in s.execute(select(Note).where(Note.investigation_id == inv_id, Note.ts.isnot(None))).scalars()]
    fmarks = [{"id": f.id, "display_id": f.display_id, "title": f.title, "risk_level": f.risk_level,
               "ts": f.time_start, "end": f.time_end, "stage": f.stage}
              for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars()]
    inv = s.get(Investigation, inv_id)
    return {"items": items, "next_cursor": page["next_cursor"], "notes": notes, "finding_marks": fmarks,
            "clock_skew": (inv.settings or {}).get("clock_skew", {})}


@router.post("/timeline/density")
def density(inv_id: str, body: FiltersIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    return _es().histogram_metrics(inv_id, body.filters, None, [], body.time, split_field="data_source")


# ------------------------------------------------------------------ graph
TYPE_CAP = {"uri": 25, "user_agent": 12, "session": 20, "user": 30, "domain": 40}


@router.get("/graph")
def graph(inv_id: str, types: str | None = None, min_count: int = 1, focus: str | None = None, hops: int = 2,
          group_by: str = Query("cloud", pattern="^(none|structure|cloud|asn|country)$"),
          max_nodes: int = Query(300, le=1000), ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Entity graph with grouping/filter/focus/caps so it stays readable (docs/22 §4)."""
    _read(s, ctx, inv_id)
    ents = {e.id: e for e in s.execute(select(Entity).where(Entity.investigation_id == inv_id)).scalars()}
    rels = [r for r in s.execute(select(Relation).where(Relation.investigation_id == inv_id)).scalars()
            if r.count >= min_count]
    allowed = set(types.split(",")) if types else None
    if allowed:
        rels = [r for r in rels if ents[r.src_entity_id].type in allowed and ents[r.dst_entity_id].type in allowed]
    focus_ids: set[str] = set()
    if focus:
        ftype, _, fval = focus.partition(":")
        start = [e.id for e in ents.values() if e.type == ftype and e.value == fval]
        focus_ids = set(start)
        adj = defaultdict(set)
        for r in rels:
            adj[r.src_entity_id].add(r.dst_entity_id)
            adj[r.dst_entity_id].add(r.src_entity_id)
        keep, frontier = set(start), set(start)
        for _ in range(hops):
            frontier = {n for x in frontier for n in adj[x]} - keep
            keep |= frontier
        rels = [r for r in rels if r.src_entity_id in keep and r.dst_entity_id in keep]
    # per-type caps on non-IP nodes (keep the busiest), never dropping the focused entity
    weight: dict[str, int] = defaultdict(int)
    for r in rels:
        weight[r.src_entity_id] += r.count
        weight[r.dst_entity_id] += r.count
    capped: set[str] = set()
    if not focus:
        by_type: dict[str, list[str]] = defaultdict(list)
        for nid in weight:
            by_type[ents[nid].type].append(nid)
        for t, ids in by_type.items():
            cap = TYPE_CAP.get(t)
            if cap and len(ids) > cap:
                capped |= set(sorted(ids, key=lambda x: -weight[x])[cap:])
        rels = [r for r in rels if r.src_entity_id not in capped and r.dst_entity_id not in capped]
    # grouping of IP nodes
    group_key: dict[str, str] = {}
    if group_by == "structure":
        neigh = defaultdict(set)
        for r in rels:
            neigh[r.src_entity_id].add((r.edge_type, r.dst_entity_id))
        buckets: dict[frozenset, list[str]] = defaultdict(list)
        for nid, ns in neigh.items():
            if ents[nid].type == "ip":
                buckets[frozenset(ns)].append(nid)
        for i, members in enumerate(buckets.values()):
            if len(members) >= 3:
                for m in members:
                    group_key[m] = f"structure:{i}"
    elif group_by in ("cloud", "asn", "country"):
        attr = {"cloud": "cloud", "asn": "as_org", "country": "country"}[group_by]
        for nid, e in ents.items():
            if e.type == "ip" and nid not in focus_ids:
                a = e.attrs or {}
                label = a.get(attr) or ("internal" if a.get("scope") == "internal" else "unknown")
                group_key[nid] = f"{group_by}:{label}"
    members: dict[str, list[str]] = defaultdict(list)
    for nid, gk in group_key.items():
        members[gk].append(nid)
    group_of = {nid: gk for gk, ms in members.items() if len(ms) >= 2 for nid in ms}
    nodes: dict[str, dict] = {}
    for gk, ms in members.items():
        if len(ms) < 2:
            continue
        lbl = gk.split(":", 1)[1]
        nodes[gk] = {"id": gk, "type": "group", "label": f"{len(ms)} IPs · {lbl}", "members": len(ms),
                     "group": lbl, "member_values": [ents[m].value for m in ms][:500],
                     "count": sum(ents[m].event_count for m in ms)}
    edges: dict[tuple, dict] = {}
    for r in rels:
        a, b = group_of.get(r.src_entity_id, r.src_entity_id), group_of.get(r.dst_entity_id, r.dst_entity_id)
        for nid in (a, b):
            if nid not in nodes:
                e = ents[nid]
                nodes[nid] = {"id": nid, "type": e.type, "label": e.value, "value": e.value, "count": e.event_count,
                              "first": e.first_seen, "last": e.last_seen, "attrs": e.attrs}
        k = (a, r.edge_type, b)
        if k in edges:
            edges[k]["count"] += r.count
        else:
            edges[k] = {"source": a, "target": b, "type": r.edge_type, "count": r.count}
    node_list = sorted(nodes.values(), key=lambda n: -n.get("count", 0))
    hidden = max(0, len(node_list) - max_nodes) + len(capped)
    node_list = node_list[:max_nodes]
    kept = {n["id"] for n in node_list}
    edge_list = [e for e in edges.values() if e["source"] in kept and e["target"] in kept]
    return {"nodes": node_list, "edges": edge_list, "truncated": {"hidden_nodes": hidden}, "group_by": group_by}


# ------------------------------------------------------------------ story
def _story_out(st: AttackStory | None) -> dict | None:
    if st is None:
        return None
    return {"id": st.id, "version": st.version, "origin": st.origin, "algo_version": st.algo_version,
            "graph": st.graph, "created_at": st.created_at}


@router.get("/story")
def story(inv_id: str, version: int | None = None, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    q = select(AttackStory).where(AttackStory.investigation_id == inv_id)
    q = q.where(AttackStory.version == version) if version else q.order_by(AttackStory.version.desc())
    st = s.execute(q).scalars().first()
    versions = [{"version": v.version, "origin": v.origin, "created_at": v.created_at} for v in s.execute(
        select(AttackStory).where(AttackStory.investigation_id == inv_id).order_by(AttackStory.version)).scalars()]
    return {"story": _story_out(st), "versions": versions}


@router.put("/story")
def edit_story(inv_id: str, body: StoryIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.write", inv_id)
    last = s.execute(select(AttackStory).where(AttackStory.investigation_id == inv_id)
                     .order_by(AttackStory.version.desc())).scalars().first()
    g = body.graph
    for n in g.get("nodes", []):
        n.setdefault("origin", "analyst")
    st = AttackStory(investigation_id=inv_id, version=(last.version + 1) if last else 1, origin="analyst",
                     algo_version=last.algo_version if last else "", graph=g, edited_by=ctx.principal.user_id)
    s.add(st)
    audit.record(s, "story.edit", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 investigation_id=inv_id, target_type="story", target_id=str(st.version))
    s.flush()
    return _story_out(st)


# ------------------------------------------------------------------ patterns / parameters / entity
@router.get("/patterns")
def patterns(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    return [{"id": p.id, "seq": p.seq, "template": p.template, "key": p.key, "count": p.event_count,
             "srcs": p.src_count, "success_ratio": p.success_ratio, "first": p.first_ts, "last": p.last_ts,
             "tags": p.tags} for p in s.execute(select(Pattern).where(Pattern.investigation_id == inv_id)
                                               .order_by(Pattern.seq)).scalars()]


@router.get("/parameters")
def parameters(inv_id: str, uri_template: str | None = None, ctx: AuthContext = Depends(auth),
               s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    q = select(ParameterProfile).where(ParameterProfile.investigation_id == inv_id)
    if uri_template:
        q = q.where(ParameterProfile.uri_template == uri_template)
    out = []
    for p in s.execute(q).scalars():
        prof = dict(p.profile)
        prof["samples"] = [mask_text(str(x)).text for x in prof.get("samples", [])]
        out.append({"uri_template": p.uri_template, "param": p.param_name, "location": p.location, "profile": prof})
    out.sort(key=lambda x: -(x["profile"].get("sequential_ratio") or 0))
    return out


ENTITY_FIELDS = {"ip": ["src_ip", "dst_ip"], "uri": ["uri_template"], "ja4": ["ja4"], "user": ["user"],
                 "user_agent": ["user_agent"], "domain": ["domain"], "session": ["session_id"],
                 "asset": ["dst_asset_id"]}


@router.get("/entities/{etype}")
def entity(inv_id: str, etype: str, value: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    es = _es()
    fields = ENTITY_FIELDS.get(etype, [etype])
    stats = {}
    total = 0
    for fld in fields:
        flt = [Filter(field=fld, value=value)]
        n = es.count(inv_id, flt)
        if not n:
            continue
        total += n
        lo, hi = es.time_bounds(inv_id, flt)
        stats[fld] = {"count": n, "first": lo, "last": hi,
                      "by_source": es.aggregate(inv_id, flt, AggRequest(type="terms", field="data_source"))["buckets"],
                      "top_uri": es.aggregate(inv_id, flt, AggRequest(type="terms", field="uri_template", size=5))["buckets"],
                      "top_status": es.aggregate(inv_id, flt, AggRequest(type="terms", field="status_code", size=5))["buckets"]}
    key = f"{'ip' if etype == 'ip' else etype}:{value}"
    finds = [{"id": f.id, "display_id": f.display_id, "title": f.title, "risk_level": f.risk_level}
             for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars()
             if any(x == key or x.endswith(f":{value}") for x in f.entities)]
    offline = None
    if etype == "ip":
        from saw.analyzers.ioc.analyze import analyze_observable

        offline = analyze_observable(value)
    return {"type": etype, "value": value, "total": total, "stats": stats, "findings": finds, "ioc": offline}


# ------------------------------------------------------------------ findings
@router.get("/findings")
def findings(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    rows = s.execute(select(Finding).where(Finding.investigation_id == inv_id)
                     .order_by(Finding.risk_score.desc())).scalars().all()
    fb = defaultdict(list)
    for x in s.execute(select(FindingFeedback).where(FindingFeedback.finding_id.in_([r.id for r in rows]))).scalars():
        fb[x.finding_id].append(x.verdict)
    out = []
    for r in rows:
        d = finding_dict(r)
        d["feedback"] = fb.get(r.id, [])
        out.append(d)
    return out


def _finding(s: Session, ctx: AuthContext, inv_id: str, fid: str) -> Finding:
    _read(s, ctx, inv_id)
    f = s.get(Finding, fid)
    if f is None or f.investigation_id != inv_id:
        raise NotFound("finding not found")
    return f


@router.get("/findings/{fid}")
def finding(inv_id: str, fid: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    f = _finding(s, ctx, inv_id, fid)
    d = finding_dict(f)
    d["feedback"] = [{"verdict": x.verdict, "comment": x.comment, "at": x.at, "claim": "VERDICT"} for x in s.execute(
        select(FindingFeedback).where(FindingFeedback.finding_id == fid)).scalars()]
    try:
        from saw.knowledge.fp import match_fp_rules

        d["fp_matches"] = match_fp_rules(s, f)
    except ImportError:
        d["fp_matches"] = []
    return d


@router.post("/findings/{fid}/events")
def finding_events(inv_id: str, fid: str, body: SearchRequest, ctx: AuthContext = Depends(auth),
                   s: Session = Depends(db, scope="function")):
    f = _finding(s, ctx, inv_id, fid)
    q = (f.evidence_refs or {}).get("query", {})
    flt = [Filter(**x) for x in q.get("filters", [])] + body.filters
    page = _es().search(inv_id, flt, body.time, body.sort, body.limit, body.cursor)
    return {"events": [mask_event(e)[0] for e in page["events"]], "next_cursor": page["next_cursor"],
            "query": q, "total": _es().count(inv_id, flt)}


@router.post("/findings/{fid}/feedback")
def feedback(inv_id: str, fid: str, body: FeedbackIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.write", inv_id)
    f = _finding(s, ctx, inv_id, fid)
    s.add(FindingFeedback(finding_id=fid, user_id=ctx.principal.user_id, verdict=body.verdict, comment=body.comment))
    f.status = body.verdict
    audit.record(s, "finding.feedback", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 target_type="finding", target_id=fid, investigation_id=inv_id, detail={"verdict": body.verdict})
    from saw.core.application import reviews

    need = reviews.on_finding_feedback(s, ctx.principal, f, body.verdict)  # lowering a high-risk detection is reviewed
    return {"ok": True, "status": f.status, "review_needed": need.id if need else None}


class EventDiffIn(BaseModel):
    src_ip: str | None = None
    url_path: str | None = None
    event_ids: list[str] = Field(default_factory=list, max_length=200)


@router.post("/diff")
def event_diff(inv_id: str, body: EventDiffIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Request Diff over log events (partial requests: no headers/body) (docs/18 §1)."""
    from saw.analyzers.diff.request_diff import evolution, from_event

    _read(s, ctx, inv_id)
    es = _es()
    if body.event_ids:
        evs = [hydrate_raw(e) for e in (es.get(inv_id, i) for i in body.event_ids) if e]
        evs.sort(key=lambda e: e.get("timestamp") or "")
    else:
        if not body.src_ip:
            raise ValueError("src_ip or event_ids required")
        flt = [Filter(field="src_ip", value=body.src_ip), Filter(field="data_source", op="in", value=["web", "waf"])]
        if body.url_path:
            flt.append(Filter(field="url_path", value=body.url_path))
        evs = es.search(inv_id, flt, limit=200)["events"]
    # collapse consecutive identical requests so the evolution shows changes, not repetition
    canons, last = [], None
    for e in evs:
        k = (e.get("method"), e.get("uri_template"), e.get("status_code"))
        if k != last:
            canons.append(from_event(e, len(canons)))
            last = k
    if len(canons) < 2:
        raise ValueError("need at least two distinct requests")
    return evolution(canons[:200])


@router.get("/correlations")
def correlations(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.storage.models import Correlation

    _read(s, ctx, inv_id)
    rows = s.execute(select(Correlation).where(Correlation.investigation_id == inv_id)).scalars().all()
    order = {"finding_chain": 0, "same_ip_cross_source": 1}
    return [{"id": c.id, "kind": c.kind, "strength": c.strength, "entity_keys": c.entity_keys, "steps": c.steps,
             "explanation": c.explanation} for c in sorted(rows, key=lambda c: (order.get(c.kind, 9), c.strength != "strong"))]


# ------------------------------------------------------------------ notes / views
@router.get("/notes")
def notes(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    return [{"id": n.id, "body_md": n.body_md, "ts": n.ts, "links": n.links, "author": n.author_name,
             "created_at": n.created_at} for n in s.execute(
        select(Note).where(Note.investigation_id == inv_id).order_by(Note.created_at)).scalars()]


@router.post("/notes", status_code=201)
def add_note(inv_id: str, body: NoteIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.write", inv_id)
    n = Note(investigation_id=inv_id, author_id=ctx.principal.user_id, author_name=ctx.principal.username,
             body_md=body.body_md, ts=body.ts, links=body.links)
    s.add(n)
    s.flush()
    audit.record(s, "note.create", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 investigation_id=inv_id, target_type="note", target_id=n.id)
    return {"id": n.id}


@router.get("/saved-views")
def views(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    return [{"id": v.id, "name": v.name, "state": v.state} for v in s.execute(
        select(SavedView).where(SavedView.investigation_id == inv_id)).scalars()]


@router.post("/saved-views", status_code=201)
def save_view(inv_id: str, body: ViewIn, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    _read(s, ctx, inv_id)
    v = SavedView(investigation_id=inv_id, owner_id=ctx.principal.user_id, name=body.name, state=body.state)
    s.add(v)
    s.flush()
    return {"id": v.id}
