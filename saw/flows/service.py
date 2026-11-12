"""Flow analysis runs: apply the current knowledge to an investigation's records and keep the result.

A run is never rewritten. The same records, knowledge versions and scope give the same run (a repeated request
reuses it); changed knowledge or new records give a new run that says what changed and why. A judgement stays
with the knowledge versions it was made under.
"""
from __future__ import annotations

import hashlib
import json
import time as _time

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import NotFound, require
from saw.core.schemas.query import Filter, TimeRange
from saw.flows import engine, knowledge
from saw.flows.models import FlowJudgement, FlowKnowledge, FlowRun
from saw.storage.db import utcnow
from saw.storage.models import Evidence, Investigation

WEB_FIELDS = ["event_id", "timestamp", "data_source", "src_ip", "src_port", "dst_ip", "dst_port", "hostname",
              "method", "uri", "uri_template", "status_code", "user_agent", "ext"]
SIDE_FIELDS = ["event_id", "timestamp", "data_source", "src_ip", "dst_ip", "dst_port", "hostname", "method", "uri",
               "status_code", "user", "alert_name", "enforcement_action", "ext"]
NETWORK_FLOWS = 30


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time: TimeRange | None = None
    baseline_end: str | None = Field(None, max_length=40)  # records before this instant are the baseline
    reason: str = Field("manual", pattern="^(manual|knowledge_changed|ingest)$")
    force: bool = False


class JudgementIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    run_id: str | None = Field(None, max_length=36)
    flow_key: str = Field("", max_length=128)
    verdict: str = Field(pattern="^(normal|suspicious|undetermined)$")
    note: str = Field("", max_length=4000)
    event_ids: list[str] = Field(default_factory=list, max_length=200)


def _manifest(s, inv: Investigation, es) -> dict:
    evidence = sorted(s.scalars(select(Evidence.id).where(Evidence.investigation_id == inv.id)))
    first, last = es.time_bounds(inv.id)
    return {"evidence": evidence, "events": es.count(inv.id), "first": first, "last": last}


def _input_sha(manifest: dict, items: list[dict], scope: dict) -> str:
    body = {"engine": engine.ENGINE_VERSION, "manifest": manifest, "knowledge": knowledge.digest(items), "scope": scope}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _signature_lookup(s):
    from saw.internal_kb.models import DeviceSignature
    from saw.internal_kb.signatures import match_key

    rows = {r.match_key: r for r in s.scalars(select(DeviceSignature))}

    def lookup(vendor: str, product: str, signature_id: str, name: str):
        row = rows.get(match_key(vendor, product, signature_id, name)) or rows.get(match_key(vendor, product, "", name))
        if row is None:
            return {"registered": False, "text": "이 장비 공격명의 해석이 등록되어 있지 않습니다. 이름이 비슷한 다른 항목을 적용하지 않았습니다."}
        c = row.content or {}
        return {"registered": True, "id": row.id, "version": row.current_version, "status": row.status,
                "meaning": c.get("meaning") or "", "observes": c.get("observes") or [],
                "cannot_prove": c.get("cannot_prove") or [], "benign_cases": c.get("benign_cases") or [],
                "checks": c.get("checks") or [], "followup_data": c.get("followup_data") or []}

    return lookup


def _history(s, inv: Investigation, first: str | None) -> set:
    """Transitions seen by earlier analyses of the same affiliate whose records all precede this scope."""
    if not first or not inv.org_unit_id:
        return set()
    out = set()
    rows = s.execute(select(FlowRun.result).join(Investigation, Investigation.id == FlowRun.investigation_id).where(
        Investigation.org_unit_id == inv.org_unit_id, FlowRun.investigation_id != inv.id,
        FlowRun.status.in_(("complete", "partial"))).order_by(FlowRun.created_at.desc()).limit(50))
    for (result,) in rows:
        last = ((result or {}).get("time") or {}).get("last")
        if not last or last >= first:
            continue  # a baseline never includes records at or after the scope being evaluated
        for tr in ((result or {}).get("discovery") or {}).get("transitions") or []:
            out.add((tr["host"], tr["from"], tr["to"]))
    return out


def _network(es, inv_id: str, flow: dict, skew: int) -> dict | None:
    """Connection records (FW, NDR) between the same addresses in the flow's period, by the device's action."""
    targets = sorted({(st.get("dst_ip"), st.get("dst_port")) for st in flow["steps"] if st.get("dst_ip")})[:3]
    if not targets or not flow["src_ips"]:
        return None
    start, end = engine.epoch(flow["start"]), engine.epoch(flow["end"])
    window = TimeRange(start=engine._iso(start - skew), end=engine._iso(end + skew))
    rows = []
    for dst_ip, dst_port in targets:
        base = [Filter(field="data_source", op="in", value=["connection", "firewall", "zeek_conn"]),
                Filter(field="src_ip", op="in", value=flow["src_ips"]), Filter(field="dst_ip", value=dst_ip)]
        if dst_port:
            base.append(Filter(field="dst_port", value=dst_port))
        total = es.count(inv_id, base, window)
        if not total:
            continue
        blocked = es.count(inv_id, [*base, Filter(field="enforcement_action", value="blocked")], window)
        allowed = es.count(inv_id, [*base, Filter(field="enforcement_action", value="allowed")], window)
        rows.append({"dst_ip": dst_ip, "dst_port": dst_port, "records": total, "allowed": allowed, "blocked": blocked,
                     "filters": [f.model_dump() for f in base], "time": window.model_dump()})
    if not rows:
        return {"records": 0, "text": "같은 주소 사이의 FW·연결 기록이 이 기간에 없습니다(자료가 없는 것일 수 있음)."}
    return {"records": sum(r["records"] for r in rows), "pairs": rows,
            "text": "같은 출발지·목적지 사이의 FW·연결 기록입니다. 통신이 있었다는 근거이며, 같은 요청이라는 근거는 아닙니다."}


def _changes(previous: FlowRun | None, result: dict, items: list[dict], manifest: dict) -> dict:
    if previous is None:
        return {"first_run": True}
    old_k, new_k = previous.knowledge or {}, {i["id"]: i["version"] for i in items}
    titles = {i["id"]: i["title"] for i in items}
    knowledge_changes = ([{"id": k, "title": titles.get(k, ""), "from": old_k.get(k), "to": v}
                          for k, v in new_k.items() if old_k.get(k) != v]
                         + [{"id": k, "title": "", "from": v, "to": None} for k, v in old_k.items() if k not in new_k])
    before = {f["key"]: f for f in (previous.result or {}).get("flows") or []}
    after = {f["key"]: f for f in result.get("flows") or []}
    changed = [{"key": k, "before": before[k]["summary"], "after": after[k]["summary"],
                "flags_added": sorted(set(after[k]["flags"]) - set(before[k]["flags"])),
                "flags_removed": sorted(set(before[k]["flags"]) - set(after[k]["flags"]))}
               for k in after if k in before and (before[k]["summary"] != after[k]["summary"]
                                                  or before[k]["flags"] != after[k]["flags"])]
    old_counts = (previous.result or {}).get("counts") or {}
    reasons = []
    if knowledge_changes:
        reasons.append(f"지식 {len(knowledge_changes)}건이 바뀌었습니다.")
    if (previous.summary or {}).get("manifest_events") != manifest["events"]:
        reasons.append(f"기록 수가 {(previous.summary or {}).get('manifest_events')}건에서 {manifest['events']}건으로 바뀌었습니다.")
    return {"first_run": False, "previous_version": previous.version, "reasons": reasons,
            "knowledge": knowledge_changes,
            "labeled": {"before": old_counts.get("labeled"), "after": result["counts"]["labeled"]},
            "flows": {"added": [after[k]["summary"] for k in after if k not in before][:50],
                      "removed": [before[k]["summary"] for k in before if k not in after][:50],
                      "changed": changed[:50]}}


def run(s, p, inv_id: str, body: RunIn | dict | None = None, *, system: bool = False) -> dict:
    """Analyse now. `system` is the automatic run after ingest (already authorised as that job's requester)."""
    body = RunIn.model_validate(body or {})
    inv = s.get(Investigation, inv_id) if system else require(s, p, "investigation.write", inv_id)
    if inv is None:
        raise NotFound("investigation not found")
    es = container.get().events
    items = knowledge.snapshot(s, inv.org_unit_id)
    manifest = _manifest(s, inv, es)
    scope = {"time": body.time.model_dump() if body.time else None, "baseline_end": body.baseline_end,
             "org_unit_id": inv.org_unit_id}
    sha = _input_sha(manifest, items, scope)
    previous = s.scalar(select(FlowRun).where(FlowRun.investigation_id == inv_id).order_by(FlowRun.version.desc()))
    # Only the latest run is reused: an older run with the same input would leave a newer, different one on screen.
    if (not body.force and previous is not None and previous.input_sha256 == sha
            and previous.status in ("complete", "partial", "no_data")):
        return {**run_out(s, previous), "reused": True}
    started = _time.monotonic()
    number = (s.scalar(select(func.max(FlowRun.version)).where(FlowRun.investigation_id == inv_id)) or 0) + 1
    row = FlowRun(investigation_id=inv_id, version=number, reason=body.reason, input_sha256=sha,
                  knowledge={i["id"]: i["version"] for i in items}, scope=scope,
                  created_by=getattr(p, "user_id", "") or "")
    s.add(row)
    s.flush()
    try:
        compiled = engine.Compiled(items)
        side = _side(es, inv_id, body.time)
        web = es.iterate(inv_id, [Filter(field="data_source", value="web"), Filter(field="uri", op="exists")],
                         body.time, fields=WEB_FIELDS, batch=5000)
        first = es.time_bounds(inv_id)[0] if body.time is None else body.time.start
        result = engine.analyze(web, app_events=side["app"], alerts=side["alerts"], ddos=side["ddos"],
                                compiled=compiled, options={"baseline_end": body.baseline_end},
                                history=_history(s, inv, first), signature=_signature_lookup(s))
        for flow in result["flows"][:NETWORK_FLOWS]:
            flow["network"] = _network(es, inv_id, flow, engine.DEFAULTS["skew_seconds"])
        result["side"]["truncated"] = side["truncated"]
        if side["truncated"]:
            result["status"] = "partial" if result["status"] == "complete" else result["status"]
            result["completeness"]["note"] = (result["completeness"]["note"] + " 보조 기록(애플리케이션·보안장비) 일부만 읽었습니다.").strip()
        if not items:
            result["knowledge_note"] = "적용할 지식이 없습니다. 로그에서 '메모하고 기억하기'로 업무 의미를 등록하면 다음 분석부터 적용됩니다."
        row.status = result["status"]
        row.result = result
        row.changes = _changes(previous, result, items, manifest)
        row.summary = {"manifest_events": manifest["events"], "records_read": result["counts"]["records_read"],
                       "labeled": result["counts"]["labeled"], "flows": result["completeness"]["flows_total"],
                       "attention": sum(1 for f in result["flows"] if f["attention"] > 0),
                       "knowledge_items": len(items), "conflicts": len(result["conflicts"])}
    except Exception as exc:  # noqa: BLE001 - a failed run is recorded as failed, never shown as "nothing found"
        row.status = "failed"
        row.result = {"error": type(exc).__name__, "detail": str(exc)[:500]}
    row.finished_at, row.elapsed_ms = utcnow(), int((_time.monotonic() - started) * 1000)
    s.flush()
    if not system:
        audit.record(s, "flow_run.create", actor_id=p.user_id, actor_name=p.username, target_type="flow_run",
                     target_id=row.id, investigation_id=inv_id, detail={"version": row.version, "status": row.status})
    return {**run_out(s, row), "reused": False}


def _side(es, inv_id: str, time: TimeRange | None) -> dict:
    limit, out, truncated = engine.DEFAULTS["max_side_records"], {"app": [], "alerts": [], "ddos": []}, False
    for name, sources in (("app", ["app"]), ("alerts", ["waf", "ips"]), ("ddos", ["ddos"])):
        for e in es.iterate(inv_id, [Filter(field="data_source", op="in", value=sources)], time,
                            fields=SIDE_FIELDS, batch=5000):
            if len(out[name]) >= limit:
                truncated = True
                break
            out[name].append(e)
    return {**out, "truncated": truncated}


def auto_run(s, inv_id: str, requested_by: str = "") -> dict | None:
    """After ingest or analysis: run when knowledge applies to this affiliate. Never raises into the ingest job."""
    inv = s.get(Investigation, inv_id)
    if inv is None:
        return None

    class _System:
        user_id, username = requested_by, "system"

    out = run(s, _System(), inv_id, {"reason": "ingest"}, system=True)
    return {"run_id": out["id"], "version": out["version"], "status": out["status"], "summary": out["summary"]}


def _stale(s, inv: Investigation, row: FlowRun) -> dict:
    items = knowledge.snapshot(s, inv.org_unit_id)
    now = {i["id"]: i["version"] for i in items}
    reasons = []
    if now != (row.knowledge or {}):
        changed = [i["title"] for i in items if (row.knowledge or {}).get(i["id"]) != i["version"]]
        gone = len([k for k in (row.knowledge or {}) if k not in now])
        reasons.append(f"지식이 바뀌었습니다({', '.join(changed[:3])}{' 외' if len(changed) > 3 else ''}"
                       f"{f', 중지 {gone}건' if gone else ''}).")
    events = container.get().events.count(inv.id)
    if (row.summary or {}).get("manifest_events") not in (None, events):
        reasons.append(f"기록이 {(row.summary or {}).get('manifest_events')}건에서 {events}건으로 바뀌었습니다.")
    return {"stale": bool(reasons), "reasons": reasons}


def run_out(s, row: FlowRun, *, full: bool = True) -> dict:
    out = {"id": row.id, "investigation_id": row.investigation_id, "version": row.version, "status": row.status,
           "reason": row.reason, "knowledge": row.knowledge, "scope": row.scope, "summary": row.summary,
           "changes": row.changes, "created_at": row.created_at, "finished_at": row.finished_at,
           "elapsed_ms": row.elapsed_ms}
    if full:
        result = dict(row.result or {})
        judged = {}
        for j in s.scalars(select(FlowJudgement).where(FlowJudgement.investigation_id == row.investigation_id)
                           .order_by(FlowJudgement.created_at)):
            judged[j.flow_key] = judgement_out(j)
        result["flows"] = [{**{k: v for k, v in f.items() if k != "steps"}, "step_count": len(f.get("steps") or []),
                            "judgement": judged.get(f["key"])} for f in result.get("flows") or []]
        out["result"] = result
    return out


def latest(s, p, inv_id: str) -> dict:
    inv = require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(FlowRun).where(FlowRun.investigation_id == inv_id).order_by(FlowRun.version.desc()))
    active = s.scalar(select(func.count()).select_from(FlowKnowledge).where(FlowKnowledge.status == "active")) or 0
    if row is None:
        return {"run": None, "stale": {"stale": False, "reasons": []}, "knowledge_items": active}
    return {"run": run_out(s, row), "stale": _stale(s, inv, row), "knowledge_items": active}


def get_run(s, p, inv_id: str, run_id: str) -> dict:
    require(s, p, "investigation.read", inv_id)
    row = s.get(FlowRun, run_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("run not found")
    return run_out(s, row)


def list_runs(s, p, inv_id: str) -> list[dict]:
    require(s, p, "investigation.read", inv_id)
    rows = s.scalars(select(FlowRun).where(FlowRun.investigation_id == inv_id).order_by(FlowRun.version.desc()).limit(100))
    return [run_out(s, r, full=False) for r in rows]


def flow_detail(s, p, inv_id: str, run_id: str, key: str) -> dict:
    require(s, p, "investigation.read", inv_id)
    row = s.get(FlowRun, run_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("run not found")
    flow = next((f for f in (row.result or {}).get("flows") or [] if f["key"] == key), None)
    if flow is None:
        raise NotFound("flow not found")
    used = {st["knowledge"]["id"]: st["knowledge"]["version"] for st in flow["steps"]}
    titles = {k.id: k for k in s.scalars(select(FlowKnowledge).where(FlowKnowledge.id.in_(list(used))))} if used else {}
    judgements = [judgement_out(j) for j in s.scalars(select(FlowJudgement).where(
        FlowJudgement.investigation_id == inv_id, FlowJudgement.flow_key == key).order_by(FlowJudgement.created_at.desc()))]
    return {**flow, "run": {"id": row.id, "version": row.version, "created_at": row.created_at},
            "knowledge_used": [{"id": k, "applied_version": v, "current_version": titles[k].current_version if k in titles else None,
                                "status": titles[k].status if k in titles else "deleted",
                                "title": titles[k].title if k in titles else ""} for k, v in used.items()],
            "judgements": judgements}


def judgement_out(j: FlowJudgement) -> dict:
    return {"id": j.id, "verdict": j.verdict, "note": j.note, "event_ids": j.event_ids, "run_id": j.run_id,
            "flow_key": j.flow_key, "knowledge": j.knowledge, "by": j.created_by_name, "created_at": j.created_at,
            "scope_text": "이 사건에만 남는 판단입니다. 다른 조사나 같은 주소의 다른 흐름에 자동으로 적용되지 않습니다."}


def judge(s, p, inv_id: str, body: JudgementIn | dict) -> dict:
    """An analyst's judgement of one observed flow. It is evidence for this investigation, not reusable knowledge."""
    body = JudgementIn.model_validate(body)
    require(s, p, "investigation.write", inv_id)
    applied = {}
    if body.run_id:
        row = s.get(FlowRun, body.run_id)
        if row is None or row.investigation_id != inv_id:
            raise NotFound("run not found")
        applied = row.knowledge or {}
    j = FlowJudgement(investigation_id=inv_id, run_id=body.run_id, flow_key=body.flow_key, verdict=body.verdict,
                      note=body.note, event_ids=body.event_ids, knowledge=applied, created_by=p.user_id,
                      created_by_name=p.username)
    s.add(j)
    s.flush()
    audit.record(s, "flow_judgement.create", actor_id=p.user_id, actor_name=p.username, target_type="flow_judgement",
                 target_id=j.id, investigation_id=inv_id, detail={"verdict": j.verdict})
    return judgement_out(j)


def affected(s, p, kid: str) -> list[dict]:
    """Investigations whose latest run would change if this knowledge changes: same affiliate scope, same service."""
    from saw.core.security.authz import can
    from saw.core.application.investigations import access_of

    row = s.get(FlowKnowledge, kid)
    if row is None:
        raise NotFound("knowledge not found")
    out = []
    latest_runs = s.execute(select(FlowRun, Investigation).join(Investigation, Investigation.id == FlowRun.investigation_id)
                            .order_by(FlowRun.investigation_id, FlowRun.version.desc()))
    seen = set()
    for run_row, inv in latest_runs:
        if inv.id in seen:
            continue
        seen.add(inv.id)
        if row.org_unit_id and inv.org_unit_id != row.org_unit_id:
            continue
        hosts = {svc["host"] for svc in (run_row.result or {}).get("services") or []}
        if row.host not in hosts or inv.status == "closed":
            continue
        if not can(p, "investigation.read", access_of(s, p, inv.id)):
            continue
        out.append({"investigation_id": inv.id, "display_id": inv.display_id, "title": inv.title,
                    "run_version": run_row.version, "applied_version": (run_row.knowledge or {}).get(kid),
                    "current_version": row.current_version})
    return out[:200]
