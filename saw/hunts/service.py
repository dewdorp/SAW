"""Hunt runs: one list of activities worth checking, from every built-in analysis, over the whole selected data.

Nothing here asks the analyst for a suspect, a hypothesis or a scenario first. Each method says what it needs, what
it examined and why it could or could not answer; a method that could not run is "insufficient data" or
"unsupported", never an empty result. This is the built-in analysis: no AI model takes part in it.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time as _time
from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import NotFound, access_of, require
from saw.core.schemas.query import Filter, TimeRange
from saw.core.security.authz import can
from saw.hunts.models import HuntReview, HuntRun
from saw.storage.db import utcnow
from saw.storage.models import Evidence, Finding, Investigation, Job

ENGINE = "saw.hunt/1"
MAX_ACTIVITIES = 500
REVIEW_STATES = ("unreviewed", "needs_check", "normal_work", "threat_confirmed")
STATUS_KO = {"found": "후보 있음", "no_match": "조건 일치 없음", "insufficient_data": "자료 부족", "partial": "일부 처리",
             "failed": "실패", "unsupported": "미지원", "looked_none": "조건 일치 없음"}


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time: TimeRange | None = None
    reason: str = Field("manual", pattern="^(manual|ingest|knowledge_changed)$")


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    activity_id: str = Field(min_length=1, max_length=64)
    state: str = Field(pattern="^(unreviewed|needs_check|normal_work|threat_confirmed)$")
    note: str = Field("", max_length=4000)


def _lines(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value if v]


def _aid(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str, ensure_ascii=False).encode()).hexdigest()[:24]


def _activity(method, title, *, observed, why, normal, unknown, next_checks=(), time=None, entities=(), evidence=None,
              counts=None, strength="관측", key=None, attention=1) -> dict:
    return {"id": _aid(method, key or title), "method": method, "title": title, "observed": _lines(observed),
            "why": _lines(why), "normal": _lines(normal), "unknown": _lines(unknown), "next_checks": _lines(next_checks),
            "time": time or {}, "entities": list(entities)[:20], "evidence": evidence or {}, "counts": counts or {},
            "strength": strength, "attention": attention}


# ---------------------------------------------------------------------------------------------------------------
# Methods. Each returns (method record, activities).

def _questions(inv, time) -> tuple[list[dict], list[dict]]:
    """The four log-derived questions (web, transfer, periodic, spread), computed over every matching record."""
    from saw.core.application import question_bundles as qb

    built = qb.build(inv, time=time)
    methods, activities = [], []
    for b in built["bundles"]:
        status = {"looked_none": "no_match"}.get(b["status"], b["status"])
        if status == "found" and b.get("completeness") == "partial":
            status = "partial"
        methods.append({"id": f"q.{b['id']}", "name": b["title"], "status": status, "needs": b.get("missing") or [],
                        "condition": b.get("description"), "records": b.get("records"), "found": b.get("found", 0),
                        "shown": b.get("shown", 0), "partial_reasons": b.get("partial_reasons") or [],
                        "examined": b.get("examined") or {}, "error": b.get("error")})
        for item in b.get("items") or []:
            activities.append(_activity(
                f"q.{b['id']}", item["title"], observed=item.get("observed"),
                why=[f"{k}: {v}" for k, v in (item.get("basis") or {}).items()] if isinstance(item.get("basis"), dict)
                else item.get("basis"),
                normal=item.get("normal_possibilities"), unknown=item.get("unknown"), next_checks=item.get("next_questions"),
                time=item.get("time"), entities=item.get("entities") or (),
                evidence={"filters": item.get("filters") or [], "time": item.get("time") or None, "records": item.get("records")},
                counts={"records": item.get("records")}, strength=item.get("strength") or "관측"))
    return methods, activities


def _findings(s, inv_id: str) -> tuple[list[dict], list[dict]]:
    """Results the detectors stored for this investigation (anomaly, peer, temporal, signature, device observation)."""
    rows = list(s.scalars(select(Finding).where(Finding.investigation_id == inv_id,
                                                Finding.status.notin_(["false_positive", "duplicate"]))
                          .order_by(Finding.risk_score.desc()).limit(300)))
    activities = []
    for f in rows:
        metrics = [f"{m.get('label') or m.get('name')}: {m.get('value')}" for m in (f.metrics or [])[:6] if isinstance(m, dict)]
        counter = [c.get("text") or c.get("label") or str(c) for c in (f.counter_evidence or [])[:5]] if f.counter_evidence else []
        open_checks = [c.get("label") for c in (f.checks or []) if isinstance(c, dict) and c.get("passed") is None][:5]
        activities.append(_activity(
            f"detectors.{f.detector_id}", f.title, observed=metrics or [f.explanation_md.splitlines()[0] if f.explanation_md else f.title],
            why=[str(r.get("label") or r) if isinstance(r, dict) else str(r) for r in (f.risk_factors or [])[:5]],
            normal=counter or ["정상 업무로 설명될 수 있는지 이 탐지에는 기록되어 있지 않습니다."],
            unknown=open_checks or ["이 탐지의 확인 항목을 '조사 제안'에서 확인하세요."],
            time={"start": f.time_start.isoformat() if f.time_start else None, "end": f.time_end.isoformat() if f.time_end else None},
            entities=[str(e) for e in (f.entities or [])[:10]], evidence={"finding_id": f.id, "display_id": f.display_id},
            counts={"risk": f.risk_level}, key=f.id))
    total = s.scalar(select(func.count()).select_from(Finding).where(Finding.investigation_id == inv_id)) or 0
    return [{"id": "detectors", "name": "저장된 탐지(이상·동종 비교·시간 변화·장비 관측)", "status": "found" if rows else "no_match",
             "found": len(rows), "shown": len(rows), "records": total, "needs": [],
             "partial_reasons": [f"탐지 {total}건 중 위험도 순 300건만 활동으로 표시"] if total > 300 else []}], activities


FLAG_WHY = {"lookup_after_failed_auth": "인증이 실패로 확인된 뒤 같은 흐름에서 조회 요청이 이어졌습니다.",
            "lookup_after_logout": "로그아웃 기록 뒤 재인증 없이 조회 요청이 이어졌습니다.",
            "other_target": "조회 대상이 확인된 계정과 다릅니다.",
            "device_block_vs_success": "장비 차단 기록과 요청 처리 기록이 함께 있습니다.",
            "deviates_from_registered_flow": "등록된 흐름과 순서·결과가 다릅니다.",
            "several_accounts": "한 흐름에서 계정이 여러 개 확인됩니다."}


def _flows(s, inv: Investigation) -> tuple[list[dict], list[dict]]:
    """Business flows from the analysts' registered meanings, and transitions nothing registered explains."""
    from saw.flows.models import FlowRun

    row = s.scalar(select(FlowRun).where(FlowRun.investigation_id == inv.id).order_by(FlowRun.version.desc()))
    name = "업무 흐름(등록한 업무 의미 적용)"
    if row is None or row.status == "failed":
        return [{"id": "flows", "name": name, "status": "failed" if row else "insufficient_data", "found": 0, "shown": 0,
                 "needs": ["HTTP 요청 기록"] if row is None else [], "partial_reasons": []}], []
    res = row.result or {}
    activities = []
    for f in res.get("flows") or []:
        if not f.get("attention"):
            continue
        activities.append(_activity(
            "flows", f["summary"], observed=f.get("confirmed"), why=[FLAG_WHY[x] for x in f.get("flags") or [] if x in FLAG_WHY]
            or f.get("inferred"), normal=["사용자가 화면을 다시 불러 왔거나, 다른 유효 세션·SSO·기존 세션이 있었을 수 있습니다.",
                                           "등록된 흐름과 순서가 같더라도 이 사건의 정상 판단은 분석가가 남깁니다."],
            unknown=f.get("unknown"), next_checks=f.get("next_checks"), time={"start": f.get("start"), "end": f.get("end")},
            entities=[*f.get("src_ips", []), *f.get("accounts", [])],
            evidence={"flow_key": f["key"], "flow_run_id": row.id, "tab": "flows"}, counts={"requests": f.get("requests")},
            strength="세션으로 연결" if f.get("link") == "session" else "IP·시간 후보", key=f["key"], attention=f["attention"]))
    for t in (res.get("discovery") or {}).get("transitions") or []:
        if t.get("explained_by_registered_flow") or not (res.get("counts") or {}).get("labeled"):
            continue
        if t.get("new_since_baseline") is False or t.get("sessions", 0) > 3:
            continue  # shown in the flow tab; only rarely seen, unexplained transitions become activities
        activities.append(_activity(
            "flows.transition", f"'{t['from']}' 뒤에 '{t['to']}'(으)로 이어진 흐름 {t['sessions']}개가 등록된 흐름으로 설명되지 않습니다.",
            observed=[f"{t['count']}회 관측, 앞뒤 간격 중앙값 {t.get('median_gap_seconds')}초, 처음 본 시각 {t.get('first')}"],
            why=["등록된 흐름에 없는 순서입니다. 처음 보였다는 것은 공격이라는 뜻이 아닙니다."],
            normal=["아직 의미를 등록하지 않은 정상 기능일 수 있습니다."], unknown=["이 경로의 업무 의미와 권한"],
            next_checks=["업무 흐름에서 이 경로의 의미를 기억시키거나 서비스 담당에게 기능을 확인"],
            time={"start": t.get("first"), "end": t.get("last")}, evidence={"event_ids": t.get("example_event_ids") or [], "tab": "flows"},
            counts={"sessions": t["sessions"]}, strength="전이 집계", key=[t["host"], t["from"], t["to"]]))
    counts = res.get("counts") or {}
    status = "partial" if row.status == "partial" else "found" if activities else "insufficient_data" if not counts.get("labeled") else "no_match"
    return [{"id": "flows", "name": name, "status": status, "found": len(activities), "shown": len(activities),
             "records": counts.get("records_read"), "needs": [] if counts.get("labeled") else ["등록된 업무 의미(없으면 전이 집계만 합니다)"],
             "partial_reasons": [res["completeness"]["note"]] if (res.get("completeness") or {}).get("note") else [],
             "examined": {"labeled": counts.get("labeled"), "flows": (res.get("completeness") or {}).get("flows_total")},
             "flow_run_version": row.version}], activities


def _target_variation(es, inv_id: str, time, *, min_targets: int = 8) -> tuple[list[dict], list[dict]]:
    """Who asked one function for many different targets, compared with everyone else asking the same function.

    No knowledge is needed: a "function" is a host + path, a "target" is the value of one query parameter. Every HTTP
    record in scope is read; the comparison is the peers' median, so a function everyone uses broadly is not flagged.
    """
    from saw.flows.engine import epoch, norm_host, split_uri
    from saw.flows.service import ordered

    name = "조회 대상 변화(같은 기능을 여러 대상으로 요청)"
    filters = [Filter(field="data_source", value="web"), Filter(field="uri", op="exists")]
    total = es.count(inv_id, filters, time)
    if not total:
        return [{"id": "target_variation", "name": name, "status": "insufficient_data", "needs": ["쿼리 파라미터가 있는 HTTP 요청 기록"],
                 "found": 0, "shown": 0, "records": 0, "partial_reasons": []}], []
    seen: dict[tuple, dict] = defaultdict(lambda: defaultdict(lambda: {"values": set(), "n": 0, "first": None, "last": None, "ids": []}))
    read = with_params = 0
    for e in ordered(es, inv_id, filters, time):
        read += 1
        path, params = split_uri(e.get("uri"))
        if not params or not e.get("src_ip"):
            continue
        with_params += 1
        host = norm_host(e.get("hostname"))
        for pname, value in list(params.items())[:6]:
            if not value or len(value) > 128:
                continue
            slot = seen[(host, path, pname)][e["src_ip"]]
            slot["n"] += 1
            if len(slot["values"]) < 5000:
                slot["values"].add(value)
            slot["first"] = slot["first"] or e.get("timestamp")
            slot["last"] = e.get("timestamp")
            if len(slot["ids"]) < 50:
                slot["ids"].append(e.get("event_id"))
    activities = []
    for (host, path, pname), actors in seen.items():
        sizes = sorted(len(a["values"]) for a in actors.values())
        median = statistics.median(sizes)
        for src, a in actors.items():
            distinct = len(a["values"])
            if distinct < min_targets or distinct < 4 * max(median, 1) or len(actors) < 2 and distinct < 3 * min_targets:
                continue
            span = (epoch(a["last"]) or 0) - (epoch(a["first"]) or 0)
            activities.append(_activity(
                "target_variation", f"{src}에서 {host}{path}의 {pname} 값을 {distinct}가지로 바꿔 가며 요청했습니다.",
                observed=[f"요청 {a['n']}건, 서로 다른 {pname} 값 {distinct}개, {a['first']} ~ {a['last']} (약 {int(span // 60)}분)",
                          f"같은 기능을 요청한 출발지 {len(actors)}곳의 값 가짓수 중앙값은 {median:g}개입니다."],
                why=[f"같은 기능을 쓰는 다른 출발지보다 대상이 {distinct / max(median, 1):.0f}배 많습니다(기준: {min_targets}개 이상이면서 중앙값의 4배 이상)."],
                normal=["상담·정산·배치처럼 여러 고객을 차례로 조회하는 업무일 수 있습니다.", "프록시·NAT 뒤 여러 사용자의 요청이 한 주소로 보일 수 있습니다."],
                unknown=[f"{pname} 값이 조회 대상을 뜻하는지(파라미터 의미 미확인)", "요청이 실제로 처리됐는지(HTTP 상태만으로는 알 수 없음)",
                         "이 출발지의 업무와 권한"],
                next_checks=["자산·업무에서 이 기능의 의미와 정상 사용 범위를 확인", "애플리케이션 기록으로 처리 결과와 계정을 확인"],
                time={"start": a["first"], "end": a["last"]}, entities=[src, host],
                evidence={"filters": [{"field": "src_ip", "op": "is", "value": src}, {"field": "hostname", "op": "is", "value": host},
                                      {"field": "url_path", "op": "is", "value": path}], "event_ids": a["ids"][:50], "records": a["n"]},
                counts={"records": a["n"], "distinct_targets": distinct, "peers": len(actors), "peer_median": median},
                strength="같은 출발지 IP 기준(같은 사용자라는 근거 아님)", key=[host, path, pname, src]))
    activities.sort(key=lambda x: -x["counts"]["distinct_targets"])
    return [{"id": "target_variation", "name": name, "status": "found" if activities else "no_match" if with_params else "insufficient_data",
             "needs": [] if with_params else ["쿼리 파라미터가 있는 HTTP 요청 기록"], "found": len(activities), "shown": len(activities),
             "records": total, "examined": {"records_read": read, "with_parameters": with_params, "functions": len(seen)},
             "partial_reasons": [], "condition": f"서로 다른 값 {min_targets}개 이상이고 같은 기능 이용자 중앙값의 4배 이상"}], activities


def _scenarios(s, inv: Investigation, es, time) -> tuple[list[dict], list[dict]]:
    try:
        from saw.scenarios import service as scenarios
    except ImportError:
        return [], []
    return scenarios.run_active(s, inv, es, time)


# ---------------------------------------------------------------------------------------------------------------

def _scope(s, inv: Investigation, es, time) -> dict:
    by_source = {}
    try:
        from saw.core.schemas.query import AggRequest

        agg = es.aggregate(inv.id, [], AggRequest(type="terms", field="data_source", size=30), time)
        by_source = {str(b["key"]): b["count"] for b in agg.get("buckets") or []}
    except Exception:  # noqa: BLE001 - the breakdown is information; its absence is said, not guessed
        by_source = {}
    first, last = es.time_bounds(inv.id)
    selected = es.count(inv.id, [], time)
    no_time = es.count(inv.id, [Filter(field="timestamp", op="not_exists")], None)
    evidence = [{"id": e.id, "title": e.title, "status": e.status} for e in
                s.scalars(select(Evidence).where(Evidence.investigation_id == inv.id))]
    return {"org_unit_id": inv.org_unit_id, "org_unit": inv.org_unit, "time": time.model_dump() if time else None,
            "period": {"start": inv.time_start.isoformat() if inv.time_start else None,
                       "end": inv.time_end.isoformat() if inv.time_end else None},
            "observed": {"first": first, "last": last}, "selected_records": selected, "by_source": by_source,
            "records_without_time": no_time, "evidence": evidence,
            "note": "선택 자료 건수는 저장된 기록 수입니다. 각 분석이 실제로 읽은 건수는 분석 방법별로 따로 표시합니다."}


def compute(s, inv: Investigation, time: TimeRange | None = None) -> dict:
    es = container.get().events
    methods, activities, failed = [], [], 0
    for fn in (lambda: _questions(inv, time), lambda: _target_variation(es, inv.id, time), lambda: _flows(s, inv),
               lambda: _scenarios(s, inv, es, time), lambda: _findings(s, inv.id)):
        try:
            m, a = fn()
            methods += m
            activities += a
        except Exception as exc:  # noqa: BLE001 - one method failing is reported as failed; the others still answer
            failed += 1
            methods.append({"id": f"error.{failed}", "name": "분석 방법 실행 오류", "status": "failed", "found": 0, "shown": 0,
                            "error": type(exc).__name__, "needs": [], "partial_reasons": []})
    for m in methods:
        m["status_label"] = STATUS_KO.get(m["status"], m["status"])
    seen, unique = set(), []
    for a in sorted(activities, key=lambda a: (-a.get("attention", 1), a["method"])):
        if a["id"] not in seen:
            seen.add(a["id"])
            unique.append(a)
    _with_assets(s, inv, unique[:MAX_ACTIVITIES])
    statuses = {m["status"] for m in methods}
    status = "failed" if statuses == {"failed"} else "partial" if statuses & {"partial", "failed"} or len(unique) > MAX_ACTIVITIES else "complete"
    return {"scope": _scope(s, inv, es, time), "methods": methods, "activities": unique[:MAX_ACTIVITIES], "status": status,
            "summary": {"activities": len(unique), "shown": min(len(unique), MAX_ACTIVITIES),
                        "methods": {st: sum(1 for m in methods if m["status"] == st) for st in sorted(statuses)}}}


def _with_assets(s, inv: Investigation, activities: list[dict]) -> None:
    """Put what is registered about an activity's addresses next to it. An asset explains; it never hides."""
    from saw.assets import service as assets
    from saw.knowledge import asset as store

    rows = [assets.out(a) for a in store.all_assets(s)]
    if not rows:
        return
    for a in activities:
        found = assets.context_lines(rows, org_unit_id=inv.org_unit_id, entities=a.get("entities") or [], at=(a.get("time") or {}).get("start"))
        if found:
            a["assets"] = found
            a["normal"] = [*a["normal"], *[f["text"] for f in found]][:8]


def _versions(s, inv: Investigation) -> dict:
    from saw.flows import knowledge

    items = knowledge.snapshot(s, inv.org_unit_id)
    return {"engine": ENGINE, "knowledge": {i["id"]: i["version"] for i in items}, "knowledge_digest": knowledge.digest(items)}


def run(s, p, inv_id: str, body: RunIn | dict | None = None, *, system: bool = False) -> dict:
    body = RunIn.model_validate(body or {})
    inv = s.get(Investigation, inv_id) if system else require(s, p, "investigation.write", inv_id)
    if inv is None:
        raise NotFound("investigation not found")
    started = _time.monotonic()
    versions = _versions(s, inv)
    if not system:
        s.commit()  # nothing is held in the database while the analysis reads the logs
        inv = s.get(Investigation, inv_id)
    try:
        out = compute(s, inv, body.time)
    except Exception as exc:  # noqa: BLE001
        out = {"scope": {}, "methods": [], "activities": [], "status": "failed", "summary": {"error": type(exc).__name__}}
    if not system:
        require(s, p, "investigation.write", inv_id)
    last = s.scalar(select(func.max(HuntRun.version)).where(HuntRun.investigation_id == inv_id)) or 0
    row = HuntRun(investigation_id=inv_id, version=last + 1, status=out["status"], reason=body.reason, scope=out["scope"],
                  versions=versions, methods=out["methods"], activities=out["activities"], summary=out["summary"],
                  created_by=getattr(p, "user_id", "") or "", elapsed_ms=int((_time.monotonic() - started) * 1000))
    s.add(row)
    s.flush()
    if not system:
        audit.record(s, "hunt_run.create", actor_id=p.user_id, actor_name=p.username, target_type="hunt_run",
                     target_id=row.id, investigation_id=inv_id, detail={"version": row.version, "status": row.status})
    return run_out(s, row)


def auto_run(s, inv_id: str, requested_by: str = "") -> dict:
    class _System:
        user_id, username = requested_by, "system"

    out = run(s, _System(), inv_id, {"reason": "ingest"}, system=True)
    return {"run_id": out["id"], "version": out["version"], "status": out["status"], "summary": out["summary"]}


def _reviews(s, inv_id: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in s.scalars(select(HuntReview).where(HuntReview.investigation_id == inv_id).order_by(HuntReview.created_at)):
        history = out.get(r.activity_id, {}).get("history", [])
        history.append({"state": r.state, "note": r.note, "by": r.created_by_name, "at": r.created_at, "run_version": r.run_version})
        out[r.activity_id] = {"state": r.state, "note": r.note, "by": r.created_by_name, "at": r.created_at, "history": history[-20:]}
    return out


def run_out(s, row: HuntRun) -> dict:
    reviews = _reviews(s, row.investigation_id)
    activities = [{**a, "review": reviews.get(a["id"], {"state": "unreviewed", "note": "", "history": []})} for a in row.activities or []]
    known = {a["id"] for a in activities}
    # A reviewed activity that the latest run no longer produces stays visible: the judgement is not lost.
    carried = []
    for aid, rv in reviews.items():
        if aid not in known and rv["state"] != "unreviewed":
            src = s.scalar(select(HuntReview).where(HuntReview.investigation_id == row.investigation_id,
                                                    HuntReview.activity_id == aid).order_by(HuntReview.created_at.desc()))
            carried.append({**(src.activity or {}), "id": aid, "review": rv, "not_in_this_run": True})
    counts = defaultdict(int)
    for a in activities + carried:
        counts[a["review"]["state"]] += 1
    return {"id": row.id, "investigation_id": row.investigation_id, "version": row.version, "mode": row.mode,
            "mode_label": "기본 분석 · AI 미연결", "status": row.status, "reason": row.reason, "scope": row.scope,
            "versions": row.versions, "methods": row.methods, "activities": activities, "carried": carried,
            "summary": {**(row.summary or {}), "review": dict(counts)}, "created_at": row.created_at, "elapsed_ms": row.elapsed_ms}


def _jobs(s, inv_id: str) -> dict:
    terminal = ("COMPLETED", "FAILED", "CANCELLED")
    active = list(s.scalars(select(Job).where(Job.investigation_id == inv_id, Job.state.notin_(terminal)).limit(5)))
    last = s.scalar(select(Job).where(Job.investigation_id == inv_id).order_by(Job.created_at.desc()))
    state = "running" if active else "idle" if last is None else {"FAILED": "failed", "CANCELLED": "stopped"}.get(last.state, "complete")
    return {"state": state, "active": [{"id": j.id, "kind": j.kind, "state": j.state, "item": j.current_item} for j in active],
            "label": {"running": "실행 중", "idle": "자료 대기", "failed": "마지막 작업 실패", "stopped": "중단됨", "complete": "완료"}[state]}


def latest(s, p, inv_id: str) -> dict:
    inv = require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(HuntRun).where(HuntRun.investigation_id == inv_id).order_by(HuntRun.version.desc()))
    progress = _jobs(s, inv_id)
    stale = []
    if row is not None:
        now = _versions(s, inv)
        if now["knowledge_digest"] != (row.versions or {}).get("knowledge_digest"):
            stale.append("등록한 업무 지식이 바뀌었습니다.")
        events = container.get().events.count(inv_id)
        if (row.scope or {}).get("selected_records") not in (None, events):
            stale.append(f"기록이 {(row.scope or {}).get('selected_records')}건에서 {events}건으로 바뀌었습니다.")
    return {"run": run_out(s, row) if row else None, "progress": progress, "stale": stale}


def review(s, p, inv_id: str, body: ReviewIn | dict) -> dict:
    body = ReviewIn.model_validate(body)
    inv = require(s, p, "investigation.write", inv_id)
    row = s.scalar(select(HuntRun).where(HuntRun.investigation_id == inv_id).order_by(HuntRun.version.desc()))
    activity = next((a for a in (row.activities if row else []) if a["id"] == body.activity_id), None)
    if activity is None:
        prior = s.scalar(select(HuntReview).where(HuntReview.investigation_id == inv_id, HuntReview.activity_id == body.activity_id)
                         .order_by(HuntReview.created_at.desc()))
        if prior is None:
            raise NotFound("activity not found")
        activity = prior.activity or {}
    r = HuntReview(investigation_id=inv_id, activity_id=body.activity_id, state=body.state, note=body.note,
                   activity={k: activity.get(k) for k in ("method", "title", "time", "entities", "evidence", "observed")},
                   run_version=row.version if row else None, versions=_versions(s, inv), created_by=p.user_id,
                   created_by_name=p.username)
    s.add(r)
    s.flush()
    audit.record(s, "hunt_review.create", actor_id=p.user_id, actor_name=p.username, target_type="hunt_review",
                 target_id=r.id, investigation_id=inv_id, detail={"state": r.state})
    return {"activity_id": r.activity_id, **_reviews(s, inv_id)[r.activity_id]}


def listing(s, p, *, limit: int = 300) -> dict:
    """Every hunt the analyst may open, with progress, what the last run found and what is still unreviewed."""
    rows = list(s.scalars(select(Investigation).order_by(Investigation.created_at.desc()).limit(1000)))
    out = []
    for inv in rows:
        if not can(p, "investigation.read", access_of(s, p, inv.id)):
            continue
        run_row = s.scalar(select(HuntRun).where(HuntRun.investigation_id == inv.id).order_by(HuntRun.version.desc()))
        reviews = _reviews(s, inv.id) if run_row else {}
        total = len(run_row.activities or []) if run_row else 0
        unreviewed = sum(1 for a in (run_row.activities or []) if reviews.get(a["id"], {}).get("state", "unreviewed") == "unreviewed") if run_row else 0
        needs_check = sum(1 for r in reviews.values() if r["state"] == "needs_check")
        progress = _jobs(s, inv.id)
        bucket = ("done" if inv.status == "closed" else "running" if progress["state"] == "running"
                  else "review" if unreviewed or needs_check or run_row is None else "review_done")
        out.append({"id": inv.id, "display_id": inv.display_id, "title": inv.title, "org_unit": inv.org_unit,
                    "status": inv.status, "verdict": inv.verdict, "created_at": inv.created_at,
                    "period": {"start": inv.time_start, "end": inv.time_end}, "progress": progress, "bucket": bucket,
                    "run": {"version": run_row.version, "status": run_row.status, "at": run_row.created_at,
                            "records": (run_row.scope or {}).get("selected_records"),
                            "by_source": (run_row.scope or {}).get("by_source")} if run_row else None,
                    "activities": total, "unreviewed": unreviewed, "needs_check": needs_check,
                    "threat_confirmed": sum(1 for r in reviews.values() if r["state"] == "threat_confirmed")})
        if len(out) >= limit:
            break
    return {"items": out, "buckets": {b: sum(1 for i in out if i["bucket"] == b) for b in ("running", "review", "review_done", "done")}}


# ---------------------------------------------------------------------------------------------------------------
# Evidence of one activity: the records the statement was computed from, shown where the statement is read.

EVIDENCE_ROWS = 20
SOURCE_KO = {"web": "NDR HTTP", "connection": "FW·연결", "firewall": "방화벽", "zeek_conn": "연결", "waf": "WAF", "ips": "IPS",
             "ddos": "DDoS", "app": "애플리케이션"}


def _evidence_row(e: dict) -> dict:
    from saw.core.security.masking import mask_event

    m, _ = mask_event(e)
    request = " ".join(str(x) for x in (m.get("method"), m.get("hostname"), m.get("uri")) if x)
    return {"event_id": m.get("event_id"), "time": m.get("timestamp"), "source": SOURCE_KO.get(m.get("data_source"), m.get("data_source")),
            "src": m.get("src_ip"), "dst": ":".join(str(x) for x in (m.get("dst_ip"), m.get("dst_port")) if x not in (None, "")),
            "what": request or m.get("alert_name") or m.get("event_type") or "",
            "result": " · ".join(str(x) for x in (m.get("status_code"), m.get("enforcement_action")) if x not in (None, ""))}


def activity_evidence(s, p, inv_id: str, activity_id: str) -> dict:
    """Up to twenty of the records behind one activity, with how many there are in all and how they were chosen."""
    from saw.flows.models import FlowRun
    from saw.core.application.investigations import NotFound

    require(s, p, "investigation.read", inv_id)
    row = s.scalar(select(HuntRun).where(HuntRun.investigation_id == inv_id).order_by(HuntRun.version.desc()))
    activity = next((a for a in (row.activities if row else None) or [] if a["id"] == activity_id), None)
    if activity is None:
        kept = s.scalar(select(HuntReview).where(HuntReview.investigation_id == inv_id, HuntReview.activity_id == activity_id)
                        .order_by(HuntReview.created_at.desc()))
        activity = (kept.activity if kept else None) or None
    if activity is None:
        raise NotFound("activity not found")
    ev = activity.get("evidence") or {}
    es = container.get().events
    ids, filters, time, total, basis = list(ev.get("event_ids") or []), ev.get("filters") or [], ev.get("time"), ev.get("records"), ""
    if ev.get("finding_id"):
        f = s.get(Finding, ev["finding_id"])
        refs = (f.evidence_refs or {}) if f is not None and f.investigation_id == inv_id else {}
        ids, total = list(refs.get("sample_event_ids") or []), refs.get("total")
        basis = f"탐지 {ev.get('display_id') or ''}가 근거로 저장한 표본 기록입니다."
    elif ev.get("flow_key"):
        run = s.get(FlowRun, ev.get("flow_run_id"))
        flow = next((x for x in ((run.result or {}).get("flows") or []) if x.get("key") == ev["flow_key"]), None) \
            if run is not None and run.investigation_id == inv_id else None
        ids = [st.get("event_id") for st in (flow or {}).get("steps") or [] if st.get("event_id")]
        total = (flow or {}).get("requests")
        basis = "이 흐름의 단계로 묶인 기록입니다(시간순)."
    rows = []
    if ids:
        for i in ids[:EVIDENCE_ROWS]:
            e = es.get(inv_id, i)
            if e is not None:
                rows.append(_evidence_row(e))
        basis = basis or "이 활동을 계산할 때 쓰인 기록입니다."
        total = total if total is not None else len(ids)
    elif filters:
        fs = [Filter(**f) for f in filters]
        tr = TimeRange(**time) if isinstance(time, dict) and time.get("start") and time.get("end") else None
        rows = [_evidence_row(e) for e in es.search(inv_id, fs, tr, limit=EVIDENCE_ROWS)["events"]]
        total = es.count(inv_id, fs, tr)
        basis = "이 활동의 조건(대상·기간)에 해당하는 기록입니다(시간순 앞부분)."
    rows.sort(key=lambda r: str(r.get("time") or ""))
    missing = "" if rows else ("이 활동은 집계 값으로 계산되어 개별 기록 참조가 저장되지 않았습니다. 아래 단추로 원문에서 확인하세요."
                               if not (ids or filters) else "참조한 기록을 지금 자료에서 찾지 못했습니다. 자료가 바뀌었으면 다시 분석하세요.")
    return {"activity_id": activity_id, "rows": rows, "shown": len(rows), "total": total, "basis": basis, "missing": missing}
