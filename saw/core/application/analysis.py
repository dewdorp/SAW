"""Investigation analysis run: detectors -> findings, patterns, parameters, relations, story (docs/10 §3)."""
from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from saw import container
from saw.analyzers.parameter.profile import collect_many, profile_values
from saw.analyzers.pattern.cluster import STRUCTURED_SOURCES, text_patterns, web_patterns
from saw.analyzers.relation.build import build as build_relations
from saw.analyzers.story.build import ALGO_VERSION, build_story
from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.detectors.base import DetectorContext, FindingDraft
from saw.storage.db import utcnow
from saw.storage.models import (
    AttackStory,
    Correlation,
    Entity,
    Finding,
    Investigation,
    ParameterProfile,
    Pattern,
    Relation,
)

RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def all_detectors():
    from saw.detectors.anomaly import ANOMALY_DETECTORS
    from saw.detectors.network import NETWORK_DETECTORS
    from saw.detectors.pcap_forensics import PCAP_DETECTORS
    from saw.detectors.web import WEB_DETECTORS

    from saw.detectors.signatures import SignatureMatch
    from saw.detectors.ndr_policy import NdrPolicy

    return WEB_DETECTORS + NETWORK_DETECTORS + PCAP_DETECTORS + ANOMALY_DETECTORS + [SignatureMatch(), NdrPolicy()]


def _flow_roles(finding: Finding) -> dict[str, list[str]]:
    """Use explicit roles or exact structured evidence filters, never entity-list position."""
    query = (finding.evidence_refs or {}).get("query") or {}
    roles = dict(query.get("entity_roles") or {})
    for condition in query.get("filters") or []:
        role = {"src_ip": "source", "dst_ip": "destination"}.get(condition.get("field"))
        if role and role not in roles and condition.get("op", "is") in ("is", "in"):
            value = condition.get("value")
            values = value if isinstance(value, list) else [value]
            roles[role] = [str(v) for v in values if v]
    return roles


def _flows(s: Session, inv_id: str) -> list[FindingDraft]:
    """Named attack flows over the findings of this run (and the reviewed ones that were kept)."""
    from saw.core.application.briefing import _succeeded
    from saw.detectors import scenarios

    rows = [{"id": f.id, "display_id": f.display_id, "title": f.title, "category": f.category, "stage": f.stage,
             "risk_level": f.risk_level, "success": _succeeded(f), "entities": f.entities or [],
             "entity_roles": _flow_roles(f),
             "time_start": f.time_start, "time_end": f.time_end}
            for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars()
            if f.detector_id != scenarios.DETECTOR_ID and f.status not in ("false_positive", "duplicate", "benign")]
    es = container.get().events
    drafts = scenarios.match(rows)
    for d in drafts:  # evidence: what this address did, whichever side of the connection it was on
        ip = d.entities[0][3:]
        side = "src_ip" if es.count(inv_id, [Filter(field="src_ip", value=ip)]) else "dst_ip"
        d.evidence_query = {"filters": [{"field": side, "op": "is", "value": ip}],
                            "time": {"start": d.time_start, "end": d.time_end},
                            "finding_ids": d.evidence_query.get("finding_ids", [])}
        from saw.core.schemas.query import TimeRange

        d.total_events = es.count(inv_id, [Filter(field=side, value=ip)], time=TimeRange(start=d.time_start, end=d.time_end))
    return drafts


def history_baseline(s: Session, exclude_inv: str, max_invs: int = 50) -> dict:
    """Known-normal values from investigations closed as normal / false_positive (attack periods excluded, T-20)."""
    es = container.get().events
    uas, ja4s, edges = set(), set(), set()
    invs = s.execute(select(Investigation).where(Investigation.verdict.in_(["normal", "false_positive"]),
                                                 Investigation.id != exclude_inv)
                     .order_by(Investigation.closed_at.desc()).limit(max_invs)).scalars().all()
    for inv in invs:
        uas |= {b["key"] for b in es.aggregate(inv.id, [], AggRequest(type="terms", field="user_agent", size=1000))["buckets"]}
        ja4s |= {b["key"] for b in es.aggregate(inv.id, [], AggRequest(type="terms", field="ja4", size=1000))["buckets"]}
        for r in es.group_by(inv.id, [Filter(field="data_source", value="zeek_conn")], ["src_ip", "dst_ip"], [], size=20000):
            edges.add((r["key"]["src_ip"], r["key"]["dst_ip"]))
    return {"user_agent": sorted(uas), "ja4": sorted(ja4s), "edges": sorted(edges), "investigations": len(invs)}


def present_sources(inv_id: str) -> list[str]:
    es = container.get().events
    return [b["key"] for b in es.aggregate(inv_id, [], AggRequest(type="terms", field="data_source", size=50))["buckets"]]


def next_finding_id(s: Session) -> str:
    """F-<n>, one above the highest number in use (a count would hand out a used number after detections are removed)."""
    used = [int(x[2:]) for x in s.execute(select(Finding.display_id)).scalars() if x and x[2:].isdigit()]
    return f"F-{max(used, default=1000) + 1}"


def _finding_from_draft(s: Session, inv_id: str, d: FindingDraft) -> Finding:
    score, level, factors = d.risk()
    existing = s.execute(select(Finding).where(Finding.investigation_id == inv_id,
                                               Finding.dedup_key == d.dedup_key)).scalar_one_or_none()
    f = existing or Finding(investigation_id=inv_id, dedup_key=d.dedup_key)
    if existing is None:
        f.display_id = next_finding_id(s)
        s.add(f)
    f.detector_id, f.detector_version = d.detector_id, d.detector_version
    f.title, f.category, f.stage = d.title, d.category, d.stage
    f.risk_score, f.risk_level, f.risk_factors, f.confidence = score, level, factors, d.confidence
    f.metrics, f.checks, f.counter_evidence, f.entities = d.metrics, d.checks, d.counter_evidence, d.entities
    f.evidence_refs = {"query": d.evidence_query, "sample_event_ids": d.sample_event_ids, "total": d.total_events}
    f.attack = [a.to_dict() for a in d.attack]
    f.attack_unmapped_reason = d.attack_unmapped_reason
    f.explanation_md = d.explanation
    from datetime import datetime, timezone

    def dt(x):
        value = datetime.fromisoformat(x.replace("Z", "+00:00")) if isinstance(x, str) else x
        return value.astimezone(timezone.utc) if value and value.tzinfo is not None else value

    f.time_start, f.time_end = dt(d.time_start), dt(d.time_end)
    return f


def finding_dict(f: Finding) -> dict:
    from saw.core.domain.claims import annotate_finding

    return annotate_finding({"id": f.id, "display_id": f.display_id, "title": f.title, "category": f.category, "stage": f.stage,
            "risk_level": f.risk_level, "risk_score": f.risk_score, "risk_factors": f.risk_factors,
            "confidence": f.confidence, "status": f.status, "time_start": f.time_start, "time_end": f.time_end,
            "metrics": f.metrics, "checks": f.checks, "counter_evidence": f.counter_evidence,
            "entities": f.entities, "evidence_refs": f.evidence_refs, "attack": f.attack,
            "attack_unmapped_reason": f.attack_unmapped_reason, "explanation_md": f.explanation_md,
            "detector": {"id": f.detector_id, "version": f.detector_version},
            "investigation_id": f.investigation_id})


def run_detectors(s: Session, inv_id: str, progress=None) -> list[Finding]:
    es = container.get().events
    sources = set(present_sources(inv_id))
    assets = None
    try:
        from saw.knowledge.asset import AssetPortImpl

        assets = AssetPortImpl(s)
    except ImportError:
        pass
    iocs = [(e.type, e.value) for e in s.execute(select(Entity).where(Entity.investigation_id == inv_id)).scalars()
            if (e.attrs or {}).get("ioc") or (e.attrs or {}).get("source") in ("ioc_list", "paste")]
    from saw.storage.models import SignatureSetting

    off = set(s.execute(select(SignatureSetting.sig_id).where(SignatureSetting.enabled.is_(False))).scalars())
    ctx = DetectorContext(inv_id, es, assets=assets, data_sources=sources,
                          params={"history": history_baseline(s, inv_id), "iocs": iocs, "sig_disabled": off})
    out = []
    every = all_detectors()
    dets = [d for d in every if d.data_sources & sources]
    settled = {d.id for d in every if not d.data_sources & sources}  # their data is gone: nothing can support them
    for i, det in enumerate(dets):
        try:
            drafts = det.run(ctx)
        except Exception as e:  # noqa: BLE001 - one detector must not abort the run
            import logging

            logging.getLogger("saw.detectors").exception("detector %s failed: %s", det.id, e)
            continue
        settled.add(det.id)
        for d in drafts:
            out.append(_finding_from_draft(s, inv_id, d))
        if progress:
            progress((i + 1) / max(1, len(dets)))
    s.flush()
    from saw.detectors import scenarios
    from saw.detection.auto import run_approved

    sigma_drafts, sigma_settled = run_approved(s, ctx)
    settled.update(sigma_settled)
    out.extend(_finding_from_draft(s, inv_id, draft) for draft in sigma_drafts)
    s.flush()

    # Retire unsupported untouched findings before they can become evidence for a fresh flow.
    _drop_unsupported(s, inv_id, settled, {f.id for f in out})
    try:
        out += [_finding_from_draft(s, inv_id, d) for d in _flows(s, inv_id)]
        settled.add(scenarios.DETECTOR_ID)
        s.flush()
    except Exception as e:  # noqa: BLE001 - flows are a reading aid: their failure must not cost the findings
        import logging

        logging.getLogger("saw.detectors").exception("attack flows failed: %s", e)
    _drop_unsupported(s, inv_id, settled, {f.id for f in out})
    return out


def _drop_unsupported(s: Session, inv_id: str, settled: set[str], produced: set[str]) -> int:
    """Detections of an earlier run that this run no longer produces (evidence re-processed, rule corrected) would
    stay on the list as if they still held. Untouched ones are removed; anything an analyst acted on (feedback,
    status, case) is kept as a record of that work."""
    from saw.storage.models import CaseItem, FindingFeedback

    stale = [f for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id, Finding.status == "new",
                                                        Finding.detector_id.in_(settled))).scalars()
             if f.id not in produced]
    if not stale:
        return 0
    ids = [f.id for f in stale]
    keep = set(s.execute(select(FindingFeedback.finding_id).where(FindingFeedback.finding_id.in_(ids))).scalars())
    keep |= set(s.execute(select(CaseItem.ref_id).where(CaseItem.item_type == "finding", CaseItem.ref_id.in_(ids))).scalars())
    gone = [f for f in stale if f.id not in keep]
    for f in gone:
        s.delete(f)
    s.flush()
    return len(gone)


def run_patterns(s: Session, inv_id: str) -> None:
    es = container.get().events
    s.execute(delete(Pattern).where(Pattern.investigation_id == inv_id))
    pats = web_patterns(es, inv_id)
    if set(present_sources(inv_id)) - set(STRUCTURED_SOURCES):
        pats += text_patterns(es, inv_id)
    for i, p in enumerate(pats[:300], 1):
        s.add(Pattern(investigation_id=inv_id, seq=i, template=p["template"], key=p["key"], event_count=p["count"],
                      src_count=p["srcs"], success_ratio=p["success"], first_ts=p["first"], last_ts=p["last"],
                      tags=p["tags"]))


def run_parameters(s: Session, inv_id: str, top: int = 30) -> None:
    es = container.get().events
    s.execute(delete(ParameterProfile).where(ParameterProfile.investigation_id == inv_id))
    rows = es.group_by(inv_id, [Filter(field="data_source", op="in", value=["web", "waf"]),
                                Filter(field="param_names", op="exists")], ["uri_template"], [], size=top)
    for r in rows:
        tpl = r["key"]["uri_template"]
        names = set()
        for e in es.search(inv_id, [Filter(field="uri_template", value=tpl)], limit=20)["events"]:
            names |= set(e.get("param_names") or [])
        pnames = sorted(names)[:20]
        values = collect_many(es, inv_id, tpl, pnames)
        for pn in pnames:
            prof = profile_values(values[pn])
            loc = "path" if pn.startswith("path[") else "query"
            s.add(ParameterProfile(investigation_id=inv_id, uri_template=tpl, param_name=pn, location=loc,
                                   profile=prof))


def run_relations(s: Session, inv_id: str) -> None:
    es = container.get().events
    ents, edges = build_relations(es, inv_id, present_sources(inv_id))
    s.execute(delete(Relation).where(Relation.investigation_id == inv_id))
    # analyst-provided entities (IOC lists, pasted observables) survive the rebuild; derived ones are recomputed
    kept = {(r.type, r.value): r for r in s.execute(select(Entity).where(Entity.investigation_id == inv_id)).scalars()
            if (r.attrs or {}).get("ioc") or (r.attrs or {}).get("source") in ("ioc_list", "paste")}
    keep_ids = [r.id for r in kept.values()]
    s.execute(delete(Entity).where(Entity.investigation_id == inv_id, Entity.id.notin_(keep_ids)))
    ids = {}
    from saw.analyzers.ioc.enrichment import default_enricher
    from saw.analyzers.ioc.observables import ip_scope

    en = default_enricher()
    for k, e in ents.items():
        attrs = {}
        if e["type"] == "ip":
            scope = ip_scope(e["value"])
            attrs["scope"] = scope
            if scope == "external":
                info = en.lookup_ip(e["value"])
                attrs.update(cloud=info.get("cloud", "none"), asn=info.get("asn"), as_org=info.get("as_org"),
                             country=info.get("country"))
        row = kept.get((e["type"], e["value"][:1024]))
        if row is not None:
            row.first_seen, row.last_seen, row.event_count = e["first"], e["last"], e["count"]
            row.attrs = {**attrs, **(row.attrs or {})}
        else:
            row = Entity(investigation_id=inv_id, type=e["type"], value=e["value"][:1024], first_seen=e["first"],
                         last_seen=e["last"], event_count=e["count"], attrs=attrs)
            s.add(row)
        s.flush()
        ids[k] = row.id
    for ed in edges:
        s.add(Relation(investigation_id=inv_id, src_entity_id=ids[ed["src"]], edge_type=ed["type"],
                       dst_entity_id=ids[ed["dst"]], count=ed["count"], first_seen=ed["first"], last_seen=ed["last"],
                       sources=[ed["source"]]))


def run_story(s: Session, inv_id: str) -> AttackStory:
    fs = [finding_dict(f) for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id,
                                                                   Finding.status.notin_(["false_positive", "duplicate"]))).scalars()]
    for f in fs:
        for k in ("time_start", "time_end"):
            if f[k] is not None and not isinstance(f[k], str):
                f[k] = f[k].isoformat()
    cors = [{"kind": c.kind, "strength": c.strength, "steps": c.steps, "explanation": c.explanation}
            for c in s.execute(select(Correlation).where(Correlation.investigation_id == inv_id)).scalars()]
    graph = build_story(fs, cors)
    last = s.execute(select(AttackStory).where(AttackStory.investigation_id == inv_id)
                     .order_by(AttackStory.version.desc())).scalars().first()
    if last and last.origin == "analyst":
        # keep analyst edits: carry pinned/manual nodes forward and flag new auto nodes
        keep = [n for n in last.graph.get("nodes", []) if n.get("origin") == "analyst" or n.get("pinned")]
        known = {fid for n in last.graph.get("nodes", []) for fid in n.get("finding_ids", [])}
        for n in graph["nodes"]:
            if not set(n["finding_ids"]) <= known:
                n["new_since_edit"] = True
        graph["nodes"] = keep + [n for n in graph["nodes"] if not (set(n["finding_ids"]) & {f for k in keep for f in k.get("finding_ids", [])})]
    st = AttackStory(investigation_id=inv_id, version=(last.version + 1) if last else 1, origin="auto",
                     algo_version=ALGO_VERSION, graph=graph)
    s.add(st)
    return st


def refresh_investigation(s: Session, inv_id: str) -> None:
    inv = s.get(Investigation, inv_id)
    es = container.get().events
    lo, hi = es.time_bounds(inv_id)
    from datetime import datetime

    if lo:
        inv.time_start = datetime.fromisoformat(lo.replace("Z", "+00:00"))
        inv.time_end = datetime.fromisoformat(hi.replace("Z", "+00:00"))
    best = s.execute(select(Finding).where(Finding.investigation_id == inv_id,
                                           Finding.status.notin_(["false_positive", "benign", "duplicate"]))
                     .order_by(Finding.risk_score.desc())).scalars().first()
    inv.risk_score = best.risk_score if best else 0
    inv.risk_level = best.risk_level if best else "info"
    if inv.status == "open":
        inv.status = "in_progress"


def run_all(s: Session, inv_id: str, progress=None) -> None:
    from saw.core.application.correlation import run_correlation

    steps = [("findings", lambda: run_detectors(s, inv_id)), ("patterns", lambda: run_patterns(s, inv_id)),
             ("parameters", lambda: run_parameters(s, inv_id)), ("relations", lambda: run_relations(s, inv_id)),
             ("correlation", lambda: run_correlation(s, inv_id)), ("story", lambda: run_story(s, inv_id)),
             ("refresh", lambda: refresh_investigation(s, inv_id))]
    for i, (name, fn) in enumerate(steps):
        fn()
        s.flush()
        if progress:
            progress(name, (i + 1) / len(steps))
    _ = utcnow, GroupMetric
