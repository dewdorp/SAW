"""Investigation analysis run: detectors -> findings, patterns, parameters, relations, story (docs/10 §3)."""
from __future__ import annotations

import time
import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, object_session

from saw import container
from saw.analysis_runs import service as run_history
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
    from saw.detectors.device_observation import (
        DdosObservation,
        IpsObservation,
        NdrObservation,
        WafObservation,
    )
    from saw.detectors.firewall_observation import FirewallObservation
    from saw.detectors.ndr_policy import NdrPolicy
    from saw.detectors.network import NETWORK_DETECTORS
    from saw.detectors.pcap_forensics import PCAP_DETECTORS
    from saw.detectors.peer_behavior import PeerBehavior
    from saw.detectors.signatures import SignatureMatch
    from saw.detectors.temporal_behavior import TemporalBehavior
    from saw.detectors.web import WEB_DETECTORS

    return WEB_DETECTORS + NETWORK_DETECTORS + PCAP_DETECTORS + ANOMALY_DETECTORS + [SignatureMatch(), NdrPolicy(), PeerBehavior(), TemporalBehavior(), FirewallObservation(), WafObservation(), IpsObservation(), DdosObservation(), NdrObservation()]


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
    from saw.detection.derived_access import source_ids

    es = container.get().events
    drafts = scenarios.match(rows)
    for d in drafts:  # evidence: what this address did, whichever side of the connection it was on
        ip = d.entities[0][3:]
        side = "src_ip" if es.count(inv_id, [Filter(field="src_ip", value=ip)]) else "dst_ip"
        d.evidence_query = {"filters": [{"field": side, "op": "is", "value": ip}],
                            "time": {"start": d.time_start, "end": d.time_end},
                            "finding_ids": d.evidence_query.get("finding_ids", [])}
        d.evidence_query["source_investigation_ids"] = sorted({
            source for fid in d.evidence_query["finding_ids"]
            for source in source_ids(s.get(Finding, fid))})
        from saw.core.schemas.query import TimeRange

        d.total_events = es.count(inv_id, [Filter(field=side, value=ip)], time=TimeRange(start=d.time_start, end=d.time_end))
    return drafts


def history_baseline(s: Session, exclude_inv: str, max_invs: int = 50) -> dict:
    """Fail closed: a normal verdict is not approval to share private source data.

    Findings are visible to every member of the destination investigation, not just
    the actor who triggered analysis. Cross-investigation baselines require an
    explicit shared-baseline approval/revocation contract, which is not implemented.
    Current-investigation peer detectors remain available without shared history.
    """
    return {"user_agent": [], "ja4": [], "edges": [], "investigations": 0}


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
    f = existing or Finding(id=str(uuid.uuid5(uuid.NAMESPACE_URL, "saw:finding:" + inv_id + ":" + d.dedup_key)),
                            investigation_id=inv_id, dedup_key=d.dedup_key)
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
    from saw.detection.derived_access import require_finding

    session = object_session(f)
    if session is not None and session.info.get("principal") is not None:
        require_finding(session, session.info["principal"], f)
    return annotate_finding({"id": f.id, "display_id": f.display_id, "title": f.title, "category": f.category, "stage": f.stage,
            "risk_level": f.risk_level, "risk_score": f.risk_score, "risk_factors": f.risk_factors,
            "confidence": f.confidence, "status": f.status, "time_start": f.time_start, "time_end": f.time_end,
            "metrics": f.metrics, "checks": f.checks, "counter_evidence": f.counter_evidence,
            "entities": f.entities, "evidence_refs": f.evidence_refs, "attack": f.attack,
            "attack_unmapped_reason": f.attack_unmapped_reason, "explanation_md": f.explanation_md,
            "detector": {"id": f.detector_id, "version": f.detector_version},
            "investigation_id": f.investigation_id})


def run_detectors(s: Session, inv_id: str, progress=None, *, analysis_run=None) -> list[Finding]:
    owns_run = analysis_run is None
    analysis_run = analysis_run or run_history.start(s, inv_id)
    from saw.detection.runtime import run_device_scopes
    from saw.detection.runtime_capture import authorize, pin_run
    actor, runtime_pin = pin_run(s, analysis_run, s.get(Investigation, inv_id))
    es = container.get().events
    sources = set(present_sources(inv_id))
    assets = None
    try:
        from saw.knowledge.asset import AssetPortImpl

        assets = AssetPortImpl(s, org_unit_id=s.get(Investigation, inv_id).org_unit_id)
    except ImportError:
        pass
    iocs = [(e.type, e.value) for e in s.execute(select(Entity).where(Entity.investigation_id == inv_id)).scalars()
            if (e.attrs or {}).get("ioc") or (e.attrs or {}).get("source") in ("ioc_list", "paste")]
    from saw.storage.models import SignatureSetting

    off = set(s.execute(select(SignatureSetting.sig_id).where(SignatureSetting.enabled.is_(False))).scalars())
    ctx = DetectorContext(inv_id, es, assets=assets, data_sources=sources,
                          params={"history": history_baseline(s, inv_id), "iocs": iocs, "sig_disabled": off, "runtime_pin": runtime_pin})
    from saw.workers.pipeline import Cancelled, StaleLease, _cancelled
    ctx.params["cancelled"] = (lambda: _cancelled(analysis_run.job_id)) if analysis_run.job_id else (lambda: False)
    out = []
    every = all_detectors()
    dets = [d for d in every if d.data_sources & sources]
    settled = {d.id for d in every if not d.data_sources & sources}  # their data is gone: nothing can support them
    for det in every:
        if det.id in settled:
            run_history.record(s, analysis_run, det.id, det.version, "not_applicable",
                               detail={"reason": "required_source_missing"})
    if analysis_run.job_id:
        s.commit()
    for i, det in enumerate(dets):
        if ctx.params["cancelled"]():
            raise Cancelled()
        started = time.monotonic()
        input_count = es.count(inv_id, [Filter(field="data_source", op="in", value=sorted(det.data_sources))])
        try:
            drafts = (run_device_scopes(det, ctx, runtime_pin)
                      if det.id in {"fw.observation", "waf.observation", "ips.observation", "ddos.observation", "ndr.observation", "sig.match"}
                      else det.run(ctx))
        except (Cancelled, StaleLease):
            raise
        except Exception as e:  # noqa: BLE001 - one detector must not abort the run
            import logging

            logging.getLogger("saw.detectors").warning("detector %s failed (%s)", det.id, type(e).__name__)
            run_history.record(s, analysis_run, det.id, det.version, "failed", input_count=input_count,
                elapsed_ms=round((time.monotonic() - started) * 1000), detail={"error_type": type(e).__name__})
            continue
        report = ctx.params.get("execution_reports", {}).get(det.id) or {}
        result_status = {"partial": "partial", "insufficient_data": "insufficient_data", "failed": "failed",
                         "disabled": "not_applicable", "not_applicable": "not_applicable", "cancelled": "cancelled"}.get(report.get("status"), "complete")
        authorize(s, actor, inv_id, runtime_pin, writing=True)
        run_history.record(s, analysis_run, det.id, det.version, result_status, input_count=input_count,
            match_count=None if result_status in {"not_applicable", "insufficient_data", "cancelled"} else len(drafts),
            elapsed_ms=round((time.monotonic() - started) * 1000), detail=report,
            effective_config={"source_types": sorted(det.data_sources), "match_unit": "finding",
                              **({"policy": report["policy"]} if "policy" in report else {})})
        if result_status == "cancelled" or ctx.params["cancelled"]():
            if analysis_run.job_id:
                s.commit()
            raise Cancelled()
        if result_status == "complete":
            settled.add(det.id)
        for d in drafts:
            d.evidence_query["source_investigation_ids"] = _runtime_finding_sources(runtime_pin, det.id)
            out.append(_finding_from_draft(s, inv_id, d))
        run_history.capture_findings(s, analysis_run, out)
        if analysis_run.job_id:
            s.commit()
        if progress:
            progress((i + 1) / max(1, len(dets)))
    s.flush()
    from saw.detection.auto import run_approved
    from saw.detectors import scenarios

    sigma_started = time.monotonic()
    sigma_drafts, sigma_settled, sigma_reports = _run_pinned_sigma(s, ctx, runtime_pin, run_approved)
    authorize(s, actor, inv_id, runtime_pin, writing=True)
    sigma_status = "partial" if any(r.get("status") in {"partial", "failed", "insufficient_data", "unsupported"} for r in sigma_reports) else "complete"
    run_history.record(s, analysis_run, "sigma.approved", "1", sigma_status,
        input_count=es.count(inv_id, []), match_count=len(sigma_drafts),
        elapsed_ms=round((time.monotonic() - sigma_started) * 1000),
        detail={"settled_rule_ids": sorted(sigma_settled), "match_unit": "finding", "executions": sigma_reports})
    settled.update(sigma_settled)
    out.extend(_finding_from_draft(s, inv_id, draft) for draft in sigma_drafts)
    s.flush()

    # Retire unsupported untouched findings before they can become evidence for a fresh flow.
    _drop_unsupported(s, inv_id, settled, {f.id for f in out})
    try:
        flow_drafts = _flows(s, inv_id)
        out += [_finding_from_draft(s, inv_id, d) for d in flow_drafts]
        run_history.record(s, analysis_run, scenarios.DETECTOR_ID, "1", "complete",
                           match_count=len(flow_drafts), detail={"match_unit": "flow"})
        settled.add(scenarios.DETECTOR_ID)
        s.flush()
    except Exception as e:  # noqa: BLE001 - flows are a reading aid: their failure must not cost the findings
        import logging

        logging.getLogger("saw.detectors").warning("attack flows failed (%s)", type(e).__name__)
        run_history.record(s, analysis_run, scenarios.DETECTOR_ID, "1", "failed",
                           detail={"error_type": type(e).__name__})
    _drop_unsupported(s, inv_id, settled, {f.id for f in out})
    run_history.capture_findings(s, analysis_run, out)
    if owns_run:
        run_history.finish(s, analysis_run)
    return out


def _runtime_finding_sources(pinset, detector_id):
    """Freeze source authority into derived findings, including approved policy layers."""
    from saw.detection.runtime_capture import sources

    if detector_id.startswith("sigma.approved:"):
        selected = {"rules": [pin for pin in pinset.get("rules", [])
                              if "sigma.approved:" + pin["rule"]["id"] == detector_id]}
    elif detector_id == "sig.match":
        selected = {"signatures": pinset.get("signatures", [])}
    else:
        selected = {"devices": [pin for pin in pinset.get("devices", [])
                                if pin.get("detector_id") == detector_id]}
    return sorted(sources(selected))


def _run_pinned_sigma(s, ctx, pinset, evaluate):
    from copy import deepcopy

    from saw.core.application.provenance import digest
    from saw.detection.runtime import ScopedEventStore, scope_filters
    budget = {"deadline": time.monotonic() + 30, "evaluations": 0, "rules": 0}
    by_scope = {}
    for pin in pinset.get("rules", []):
        scope = pin["context_scope"]
        by_scope.setdefault(digest(scope), {"scope": scope, "pins": []})["pins"].append(pin)
    if not by_scope:
        by_scope["none"] = {"scope": {"kind": "group"}, "pins": []}
    findings, reports, settled = [], list(pinset.get("execution_reports", [])), set()
    unfinished = set()
    for partition in by_scope.values():
        scope = partition["scope"]
        params = {**ctx.params, "runtime_scope": scope, "sigma_runtime_budget": budget, "execution_reports": [],
                  "runtime_pin": {"schema": "det-runtime-set/1", "rules": deepcopy(partition["pins"])}}
        with ScopedEventStore(ctx.events, ctx.investigation_id, scope_filters(scope),
                              cancelled=ctx.params.get("cancelled"), max_records=500000) as view:
            child = DetectorContext(ctx.investigation_id, view, data_sources=ctx.data_sources,
                                    assets=ctx.assets, params=params)
            found, completed = evaluate(s, child)
            for draft in found:
                draft.dedup_key += ":" + digest(scope)[:16]
                draft.evidence_query["runtime_scope"] = deepcopy(scope)
                draft.evidence_query["source_investigation_ids"] = _runtime_finding_sources(
                    {"rules": partition["pins"]}, draft.detector_id)
            findings.extend(found)
            reports.extend({**r, "runtime_scope": scope} for r in params["execution_reports"])
            settled.update(completed)
            expected = {"sigma.approved:" + pin["rule"]["id"] for pin in partition["pins"]}
            unfinished.update(expected - completed)
    incomplete = {r["detector_id"] for r in reports if r.get("status") in {"partial", "failed", "insufficient_data", "unsupported"}}
    return findings, settled - unfinished - incomplete, reports


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
    from saw.detection.derived_access import source_ids

    graph = build_story(fs, cors)
    graph["_source_investigation_ids"] = sorted(source_ids(fs) | source_ids(cors))
    last = s.execute(select(AttackStory).where(AttackStory.investigation_id == inv_id)
                     .order_by(AttackStory.version.desc())).scalars().first()
    if last and last.origin == "analyst":
        graph["_source_investigation_ids"] = sorted(source_ids(graph) | source_ids(last.graph))
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


def run_all(s: Session, inv_id: str, progress=None, *, job_id=None):
    from saw.core.application.correlation import run_correlation

    run = run_history.start(s, inv_id, job_id=job_id)
    if job_id:
        s.commit()  # A later stage failure must leave a discoverable run to seal.
    steps = [("findings", lambda: run_detectors(s, inv_id, analysis_run=run)), ("patterns", lambda: run_patterns(s, inv_id)),
             ("parameters", lambda: run_parameters(s, inv_id)), ("relations", lambda: run_relations(s, inv_id)),
             ("correlation", lambda: run_correlation(s, inv_id)), ("story", lambda: run_story(s, inv_id)),
             ("refresh", lambda: refresh_investigation(s, inv_id))]
    from saw.workers.pipeline import Cancelled, StaleLease, _cancelled, _lease
    for i, (name, fn) in enumerate(steps):
        if job_id and _cancelled(job_id):
            raise Cancelled()
        fn()
        s.flush()
        if progress:
            progress(name, (i + 1) / len(steps))
        if job_id:
            s.commit()
            if _cancelled(job_id):
                raise Cancelled()
    if job_id:
        from saw.core.application.data_deletion import lock_investigation
        from saw.storage.models import Job
        lock_investigation(s, inv_id)
        job = s.get(Job, job_id, populate_existing=True)
        lease = _lease.get()
        if job is None or (lease and lease[0] == job_id and (job.attempt or 0) != lease[1]):
            raise StaleLease("analysis publication lease changed")
        if job.cancel_requested:
            raise Cancelled()
    _ = utcnow, GroupMetric
    return run_history.finish(s, run)
