"""Deterministic contextual investigation guidance and immutable answer captures."""
from __future__ import annotations
from saw.detection.derived_access import source_ids, require_finding

import copy
import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from saw import container
from saw.core.application.investigations import require
from saw.core.application.statistics import bounds
from saw.core.schemas.query import AggRequest, Filter, TimeRange
from saw.core.security.masking import mask_event, mask_text
from saw.storage.db import utcnow
from saw.storage.models import Check, Evidence, EvidenceFile, Finding, Investigation, ProcessingRun

VERSION = "soc-guidance/1.0"
STATES = ("available", "no_match", "partial", "not_collected", "query_failed", "forbidden", "not_queried", "not_applicable")
BROAD_QUESTIONS = {"A": ["success", "impact"], "B": ["nature"], "C": ["nature", "business"],
                   "D": ["business"], "E": ["success", "impact"], "F": ["impact"], "G": ["success", "impact"]}
MAX_SAMPLES = 20
MAX_CAPTURE = 256 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def aware(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class ScopeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_type: Literal["entity", "investigation", "finding"] = "investigation"
    target_key: str = Field("", max_length=512)
    role: Literal["src", "dst", "either"] = "either"
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    time: TimeRange | None = None
    as_of: str | None = None
    methodology_version: Literal["soc-guidance/1.0"] = VERSION

    @model_validator(mode="after")
    def valid_scope(self):
        for value in [self.as_of, self.time.start if self.time else None, self.time.end if self.time else None]:
            if value and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                raise ValueError("timezone required")
        if self.time and self.time.start and self.time.end and aware(self.time.start) > aware(self.time.end):
            raise ValueError("time range must be increasing")
        if self.target_type == "entity":
            kind, _, value = self.target_key.partition(":")
            if kind != "ip":
                raise ValueError("guidance entity must be an IP")
            self.target_key = "ip:" + str(ipaddress.ip_address(value))
        return self


class MaterialState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=80)
    state: Literal["available", "no_match", "partial", "not_collected", "query_failed", "forbidden", "not_queried", "not_applicable"]
    reason: str = Field("", max_length=1000)


class FollowUp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field("", max_length=256)
    due_at: str | None = Field(None, max_length=80)
    needed_data: list[str] = Field(default_factory=list, max_length=20)
    items: list[str] = Field(default_factory=list, max_length=20)
    priority: Literal["normal", "high", "low"] = "normal"


class AnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    methodology_version: Literal["soc-guidance/1.0"] = VERSION
    rule_id: Literal["A", "B", "C", "D", "E", "F", "G"]
    scope: ScopeIn
    answer_status: Literal["answered", "follow_up", "not_applicable"]
    data_states: list[MaterialState] = Field(default_factory=list, max_length=20)
    answer: str = Field(min_length=1, max_length=2000)
    follow_up: FollowUp = Field(default_factory=FollowUp)
    query_ref: str | None = Field(None, max_length=100)

    @model_validator(mode="after")
    def valid_answer(self):
        if not self.answer.strip():
            raise ValueError("answer reason required")
        if self.answer_status == "follow_up" and not (
            self.follow_up.target.strip() and (self.follow_up.items or self.follow_up.needed_data)
        ):
            raise ValueError("follow-up target and required information are required")
        for value in [*self.follow_up.items, *self.follow_up.needed_data]:
            if len(value) > 1000:
                raise ValueError("follow-up item too long")
        return self


@lru_cache(maxsize=1)
def methodology():
    data = yaml.safe_load(Path(__file__).with_name("guidance_rules.yaml").read_text(encoding="utf-8"))
    return data


def method_info():
    d = methodology()
    return {"id": d["id"], "version": d["version"], "digest": digest(d)}


def _manifest(s, inv_id, cutoff):
    evs = list(s.scalars(select(Evidence).where(Evidence.investigation_id == inv_id)))
    out = []
    for ev in evs:
        if cutoff and aware(ev.uploaded_at) > cutoff:
            continue
        files = list(s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id == ev.id)))
        metadata = []
        for f in files:
            run = s.scalars(select(ProcessingRun).where(ProcessingRun.file_id == f.id)
                            .order_by(ProcessingRun.finished_at.desc()).limit(1)).first()
            metadata.append({"id": f.id, "sha256": f.sha256, "parser_id": f.parser_id,
                             "parser_version": f.parser_version, "parse_status": f.parse_status,
                             "events_failed": f.events_failed,
                             "processing_run": ({"id": run.id, "run_digest": run.run_digest,
                                                 "finished_at": aware(run.finished_at).isoformat(),
                                                 "input_sha256": run.input_sha256} if run else None)})
        out.append({"evidence_id": ev.id, "uploaded_at": aware(ev.uploaded_at).isoformat(), "status": ev.status,
                    "files": metadata})
    return out


def _scope(s, inv, body):
    request = body.model_dump()
    if body.target_type == "investigation":
        if body.target_key and body.target_key != inv.id:
            raise ValueError("investigation target does not match route")
        request["target_key"] = inv.id
    base = list(body.filters)
    time = body.time
    if body.target_type == "finding":
        finding = s.get(Finding, body.target_key)
        if not finding or finding.investigation_id != inv.id:
            raise ValueError("finding not in investigation")
        require_finding(s, s.info.get("principal"), finding)
        if source_ids(finding):
            request["_source_investigation_ids"] = sorted(source_ids(finding))
        from saw.llm.service import _evidence_scope
        more, ft, available = _evidence_scope(finding.evidence_refs or {})
        if not available:
            base.append(Filter(field="event_id", op="in", value=[]))
        base += more
        starts = [x for x in [time.start if time else None, ft.start if ft else None] if x]
        ends = [x for x in [time.end if time else None, ft.end if ft else None] if x]
        time = TimeRange(start=max(starts, key=aware) if starts else None, end=min(ends, key=aware) if ends else None)
    cutoff = aware(body.as_of) if body.as_of else None
    if cutoff and cutoff > utcnow():
        raise ValueError("as_of cannot be in the future")
    if cutoff:
        time = TimeRange(start=time.start if time else None, end=min(
            [v for v in [time.end if time else None, body.as_of] if v], key=aware))
    manifest = _manifest(s, inv.id, cutoff)
    base += [Filter(field="evidence_id", op="in", value=[e["evidence_id"] for e in manifest])]
    if time and time.start and time.end and aware(time.start) > aware(time.end):
        base.append(Filter(field="event_id", op="in", value=[]))
    branches = [base]
    if body.target_type == "entity":
        ip = request["target_key"].split(":", 1)[1]
        src, dst = Filter(field="src_ip", value=ip), Filter(field="dst_ip", value=ip)
        branches = ([base + [src]] if body.role == "src" else [base + [dst]] if body.role == "dst" else
                    [base + [src], base + [dst, Filter(field="src_ip", op="is_not", value=ip)]])
    # The logical scope remains stable; actual capture timestamps are separate.
    key = digest({"investigation_id": inv.id, **request})
    return {**request, "investigation_id": inv.id, "investigation_title": inv.title, "org_unit": inv.org_unit, "scope_key": key,
            "effective_time": time.model_dump() if time else None, "evidence_manifest": manifest}, branches, time


def _matching_checks(s, inv_id, scope_key):
    return [c for c in s.scalars(select(Check).where(Check.investigation_id == inv_id, Check.state == "active"))
            if (c.scope or {}).get("guidance", {}).get("scope_key") == scope_key]



def _attack_evidence(es, inv_id, branches, time, scope_key, state):
    """Query bounded pattern candidates independently of the general event sample."""
    from saw.analyzers.patterns import pattern_tags
    # These are candidate selectors, not verdicts. Reuse the detector on each returned URI.
    selectors = [("tags", "sig:"), ("tags", "pattern:")] + [
        ("uri", token) for token in (
            "../", "..\\", "..%", "%2e", "/etc/", "win.ini", "boot.ini", "/proc/self/",
            ".env", ".git/config", "://", "union", "sleep", "benchmark", "waitfor",
            "<", "%3c", "javascript:", "onerror", "$(", "`", ";", "||", "&&",
            "{{", "${", "jndi:", "rO0AB", "aced0005", "AAEAAAD", "$type",
        )
    ]
    refs, receipts = {}, []
    for index, (field, token) in enumerate(selectors):
        extra = [Filter(field=field, op="contains", value=token)]
        selected_branches = [b + extra for b in branches]
        count = sum(es.count(inv_id, b, time) for b in selected_branches)
        if not count:
            continue
        rows = {}
        for branch in selected_branches:
            for event in es.search(inv_id, branch, time, sort="asc", limit=MAX_SAMPLES)["events"]:
                rows[event["event_id"]] = event
        rows = dict(sorted(rows.items(), key=lambda x: (x[1].get("timestamp") or "", x[0]))[:MAX_SAMPLES])
        receipt = {
            "id": f"attack_candidates_{index}:" + scope_key[:24],
            "query": {"branches": [[f.model_dump() for f in b] for b in selected_branches],
                      "time": time.model_dump() if time else None},
            "executed_at": utcnow().isoformat(), "data_state": state, "matched_count": count,
            "sampled_count": len(rows), "limit": MAX_SAMPLES, "truncated": count > len(rows),
            "missing_count": None, "evidence_refs": list(rows),
        }
        receipts.append(receipt)
        for eid, event in rows.items():
            if any(str(tag).startswith(("sig:", "pattern:")) for tag in event.get("tags", [])) or pattern_tags(
                str(event.get("uri") or "")[:8192]
            ):
                refs[eid] = None
        if len(refs) >= MAX_SAMPLES:
            break
    if not refs:
        return None, receipts
    selected = list(refs)[:MAX_SAMPLES]
    evidence_branches = [b + [Filter(field="event_id", op="in", value=selected)] for b in branches]
    receipt = {
        "id": "attack_request_evidence:" + scope_key[:24],
        "query": {"branches": [[f.model_dump() for f in b] for b in evidence_branches],
                  "time": time.model_dump() if time else None},
        "executed_at": utcnow().isoformat(), "data_state": "partial",
        "matched_count": sum(es.count(inv_id, b, time) for b in evidence_branches),
        "sampled_count": len(selected), "limit": MAX_SAMPLES, "truncated": False, "coverage": "sample",
        "missing_count": None, "evidence_refs": selected,
    }
    receipts.append(receipt)
    return {"id": "attack_request_evidence", "label": "공격 패턴이 있는 표본 요청",
            "value": receipt["matched_count"], "data_state": "partial", "query_ref": receipt["id"],
            "evidence_refs": selected}, receipts

def preview(s, p, inv_id, raw, *, include_answers=True):
    inv = require(s, p, "investigation.read", inv_id)
    body = raw if isinstance(raw, ScopeIn) else ScopeIn.model_validate(raw)
    scope, branches, time = _scope(s, inv, body)
    es = container.get().events
    now = utcnow().isoformat()
    receipt = {"id": "events:" + scope["scope_key"][:24],
               "query": {"branches": [[f.model_dump() for f in b] for b in branches],
                         "time": time.model_dump() if time else None},
               "executed_at": now, "data_state": "not_queried", "matched_count": None,
               "sampled_count": 0, "limit": MAX_SAMPLES, "truncated": False, "evidence_refs": []}
    facts, unknowns, limits, queries = [], [], [], [receipt]
    counts, sources, samples, first, last = {}, {}, [], None, None
    attack = False
    metric_filters = {
        "blocked": [Filter(field="enforcement_action", value="blocked")],
        "allowed": [Filter(field="enforcement_action", value="allowed")],
        "action_unknown": [Filter(field="enforcement_action", op="not_in", value=["blocked", "allowed"])],
        "http_200": [Filter(field="status_code", value=200)],
        "large_response": [Filter(field="bytes_out", op="range", value={"gte": 1048576})],
        "process_known": [Filter(field="process", op="exists")],
        "external_connections": [Filter(field="data_source", op="in", value=["zeek_conn", "suricata", "connection", "firewall"]),
                                 Filter(field="dst_ip_scope", value="external")],
    }
    def count(extra=()):
        return sum(es.count(inv_id, branch + list(extra), time) for branch in branches)
    def sample(extra=(), limit=MAX_SAMPLES):
        rows = []
        for branch in branches:
            rows.extend(es.search(inv_id, branch + list(extra), time, sort="asc", limit=limit)["events"])
        return list({e["event_id"]: e for e in rows}.values())[:limit]
    try:
        total = count()
        counts["events"] = total
        samples = sample()
        missing = count([Filter(field="timestamp", op="not_exists")])
        for name, extra in metric_filters.items():
            counts[name] = count(extra)
        for branch in branches:
            for b in es.aggregate(inv_id, branch, AggRequest(type="terms", field="data_source", size=50), time)["buckets"]:
                sources[str(b["key"])] = sources.get(str(b["key"]), 0) + b["count"]
            lo, hi = bounds(es, inv_id, branch, time)
            first = min([x for x in (first, lo) if x], default=None)
            last = max([x for x in (last, hi) if x], default=None)
        incomplete = any(f["parse_status"] in ("failed", "degraded", "parsing", "pending") or f["events_failed"]
                         for e in scope["evidence_manifest"] for f in e["files"])
        state = ("not_collected" if not scope["evidence_manifest"] else "partial" if incomplete else
                 "available" if total else "no_match")
        receipt.update(data_state=state, matched_count=None if state == "not_collected" else total,
                       sampled_count=len(samples), truncated=total > len(samples), missing_count=missing,
                       evidence_refs=[e["event_id"] for e in samples])
        labels = {"events": "현재 범위의 이벤트", "blocked": "명시적으로 차단된 요청", "allowed": "명시적으로 허용된 요청",
                  "action_unknown": "차단·허용 값이 없거나 상충하는 기록", "http_200": "HTTP 200 응답",
                  "large_response": "1MiB 이상 응답", "process_known": "프로세스 정보가 있는 기록",
                  "external_connections": "외부 목적지 기록(세션 수 아님)"}
        for key, label in labels.items():
            q = receipt
            if key != "events":
                extra = metric_filters[key]
                refs = [e["event_id"] for e in sample(extra, 3)] if counts[key] else []
                q = {"id": key + ":" + scope["scope_key"][:24],
                     "query": {"branches": [[f.model_dump() for f in b + extra] for b in branches],
                               "time": time.model_dump() if time else None},
                     "executed_at": utcnow().isoformat(), "data_state": state if counts[key] else
                                   (state if state in ("partial", "not_collected") else "no_match"),
                     "matched_count": None if state == "not_collected" else counts[key],
                     "sampled_count": len(refs), "limit": 3, "truncated": counts[key] > len(refs),
                     "missing_count": None, "evidence_refs": refs}
                queries.append(q)
            facts.append({"id": key, "label": label, "value": q["matched_count"], "data_state": q["data_state"],
                          "query_ref": q["id"], "evidence_refs": q["evidence_refs"][:3]})
        facts.append({"id": "observed_time", "label": "최초·최종 관측 시각", "value": {"first": first, "last": last},
                      "data_state": state, "query_ref": receipt["id"], "evidence_refs": []})
        if total:
            attack_fact, attack_queries = _attack_evidence(es, inv_id, branches, time, scope["scope_key"], state)
            queries.extend(attack_queries)
            attack = attack_fact is not None
            if attack_fact:
                facts.append(attack_fact)
            limits.append("공격 패턴은 제한된 후보 조회와 표본 검사를 사용합니다. 표시 건수는 전체 공격 건수가 아닙니다.")
        if incomplete:
            limits.append("수집·처리가 끝나지 않았거나 일부 자료를 처리하지 못했습니다.")
    except Exception as exc:  # A failed read is an explicit state, never a zero or a verdict.
        failed_state = "forbidden" if isinstance(exc, PermissionError) or getattr(exc, "status_code", None) == 403 else "query_failed"
        receipt.update(data_state=failed_state, matched_count=None, sampled_count=0, evidence_refs=[],
                       truncated=False, missing_count=None,
                       error_code="event_query_" + failed_state)
        counts, samples, sources = {}, [], {}
        attack = False
        queries = [receipt]
        facts = [{"id": "events", "label": "현재 범위의 이벤트", "value": None, "data_state": failed_state,
                  "query_ref": receipt["id"], "evidence_refs": []}]
        limits.append("이벤트 조회 권한이 없습니다. 자료 유무를 확인할 수 없습니다." if failed_state == "forbidden" else
                      "이벤트 조회에 실패했습니다. 현재 자료를 정상 또는 악성으로 판단할 근거가 아닙니다.")
    if body.as_of:
        limits.append("과거 기준시점의 자료 상태를 재현한 저장본이 아닙니다. 이 조회는 평가용 당시 입력으로 채택할 수 없습니다.")
    limits.append("표시된 근거는 제한된 표본이며 전체 건수는 서버 집계입니다. 주소만으로 실제 행위자를 단정하지 않습니다.")
    state = receipt["data_state"]
    uncertain = state in ("query_failed", "forbidden", "partial")
    origin = None if state in ("query_failed", "forbidden", "not_collected") else sum(
        sources.get(k, 0) for k in ("web", "was", "application"))
    process = None if state in ("query_failed", "forbidden", "not_collected") else counts.get("process_known", 0)
    reasons = {"query_failed": "조회 실패로 자료 유무를 확인할 수 없습니다.",
               "forbidden": "조회 권한이 없어 자료 유무를 확인할 수 없습니다.",
               "partial": "일부 자료만 조회·처리됐습니다. 관측 건수는 확인 가능한 자료에 한정됩니다."}
    unknowns.append({"source": "origin_service", "state": state if uncertain else "available" if origin else "not_collected",
                     "observed_count": origin, "query_ref": receipt["id"],
                     "reason": reasons.get(state) or ("관련 서비스 기록이 있습니다. 실제 처리 결과는 별도 확인이 필요합니다." if origin else
                               "현재 범위에 웹·WAS 원본 처리 기록이 없습니다.")})
    unknowns.append({"source": "threat_intelligence", "state": "not_queried",
                     "reason": "외부 위협 평판 조회를 실행하지 않았습니다. 미신고·정상을 뜻하지 않습니다."})
    unknowns.append({"source": "edr", "state": "not_queried", "reason": "연결된 EDR 조회를 실행하지 않았습니다."})
    if uncertain or not process:
        unknowns.append({"source": "process", "state": state if uncertain else "not_collected",
                         "observed_count": process, "query_ref": receipt["id"],
                         "reason": reasons.get(state) or "현재 자료에서 연결 프로세스를 확인하지 못했습니다."})
    if state in ("query_failed", "forbidden", "partial", "no_match", "not_collected"):
        unknowns.append({"source": "events", "state": receipt["data_state"], "reason": "조회 상태와 수집 범위를 확인하세요."})
    relevant = _matching_checks(s, inv_id, scope["scope_key"])
    business = any("business" in (c.questions or []) and c.judgement == "normal" for c in relevant)
    # Legacy confirmations can suggest a scope comparison only with their explicit query and selected evidence.
    for c in s.scalars(select(Check).where(Check.investigation_id == inv_id, Check.state == "active")):
        if receipt["data_state"] in ("query_failed", "forbidden"):
            break
        if c.kind != "direct" or c.judgement != "normal" or "business" not in (c.questions or []) or not c.evidence:
            continue
        query = (c.scope or {}).get("query") or {}
        if not query or query.get("time") != (time.model_dump() if time else None):
            continue
        try:
            old_filters = sorted(canonical(Filter.model_validate(f).model_dump()) for f in query.get("filters", []))
        except ValueError:
            continue
        for branch in branches:
            current = sorted(canonical(f.model_dump()) for f in branch if f.field != "evidence_id")
            if old_filters == current and all(
                es.count(inv_id, branch + [Filter(field="event_id", value=eid)], time) for eid in c.evidence
            ):
                business = True
    direct = any(c.judgement == "malicious" and set(c.questions or []) & {"success", "impact"} and c.evidence and
                 (c.scope or {}).get("guidance", {}).get("answer_status") == "answered" and
                 any(x.get("source") == "direct_compromise" and x.get("state") == "available"
                     for x in c.scope["guidance"].get("data_states", [])) for c in relevant)

    # A follow-up question may be prompted by repeated records; this is not a session or beacon verdict.
    repeated_records = counts.get("external_connections", 0) >= 3
    if repeated_records:
        limits.append("외부 목적지 기록 3건 이상은 같은 세션의 시작·중간·종료 기록일 수 있습니다. "
                      "기록 수는 실제 연결 수나 주기성을 뜻하지 않습니다.")
    applies = {"A": bool(counts.get("blocked") and counts.get("allowed")), "B": attack,
               "C": repeated_records, "D": business, "E": bool(counts.get("http_200") or counts.get("large_response")),
               "F": any(x["state"] not in ("available", "not_applicable") for x in unknowns), "G": direct}
    answers = _matching_checks(s, inv_id, scope["scope_key"])
    questions = []
    for rule in methodology()["rules"]:
        rid = rule["id"]
        same = [c for c in answers if c.scope["guidance"]["rule_id"] == rid]
        if not applies[rid] and not same:
            continue
        states = {c.scope["guidance"]["answer_status"] for c in same}
        status = "open" if not states or len(states) > 1 else next(iter(states))
        questions.append({"rule_id": rid, "question_id": f"{VERSION}:{rid}", "title": rule["question"],
                          "purpose": rule["purpose"], "status": status, "allowed_actions": rule["allowed_actions"],
                          "needed_sources": rule["needed_sources"], "resolution_conditions": rule["resolution_conditions"],
                          "forbidden_claims": rule["forbidden_claims"], "answer_check_ids": [c.id for c in same],
                          "priority": "high" if rid == "G" else "normal"})
    if include_answers:
        for c in relevant:
            for state in c.scope["guidance"].get("data_states", []):
                unknowns.append({**state, "check_id": c.id, "author": c.author_name})
    return {"methodology": method_info(), "scope": scope, "facts": facts, "unknowns": unknowns,
            "questions": sorted(questions, key=lambda q: q["rule_id"] != "G"), "queries": queries, "limits": limits}


def prepare_check(data):
    """Validate author input before the legacy Check validator; never accept query result assertions."""
    raw = dict(data)
    if len(raw.get("evidence") or []) > 20:
        raise ValueError("select at most 20 evidence records per answer")
    g = AnswerIn.model_validate(raw["guidance"])
    raw["guidance"] = g.model_dump()
    raw["questions"] = raw.get("questions") or BROAD_QUESTIONS[g.rule_id]
    raw["note"] = raw.get("note") or g.answer
    tt = "set" if g.scope.target_type == "investigation" else g.scope.target_type
    if raw.get("target_type") and raw["target_type"] != tt:
        raise ValueError("answer target type does not match guidance scope")
    if tt != "set" and raw.get("target_key") and raw["target_key"] != g.scope.target_key:
        raise ValueError("answer target does not match guidance scope")
    raw["target_type"], raw["target_key"] = tt, g.scope.target_key
    raw["scope"] = {**(raw.get("scope") or {}), "query": g.scope.model_dump()}
    return raw


def attach_capture(s, p, inv_id, check, raw, previous=None):
    if not raw.get("guidance"):
        if previous and (previous.scope or {}).get("guidance"):
            if check.evidence != previous.evidence or check.target_key != previous.target_key or "scope" in raw:
                raise ValueError("changing guidance evidence or scope requires a new validated guidance capture")
            check.scope = {**check.scope, "guidance": {**copy.deepcopy(previous.scope["guidance"]), "answer": mask_text(check.note).text}}
            check.context = {**check.context, "guidance": copy.deepcopy(previous.context["guidance"])}
        return
    g = AnswerIn.model_validate(raw["guidance"])
    d = preview(s, p, inv_id, g.scope, include_answers=False)
    if g.query_ref and g.query_ref not in {q["id"] for q in d["queries"]}:
        raise ValueError("query reference does not match actual scoped query")
    if g.answer_status == "answered" and not check.evidence:
        raise ValueError("resolved answer requires selected evidence")
    es, selected = container.get().events, []
    from saw.core.application.rawref import hydrate_raw
    actual_time = TimeRange.model_validate(d["scope"]["effective_time"]) if d["scope"]["effective_time"] else None
    for eid in check.evidence:
        event = es.get(inv_id, eid)
        if event is None:
            raise ValueError("evidence does not belong to this investigation")
        if not any(es.count(inv_id, [Filter.model_validate(f) for f in branch] + [Filter(field="event_id", value=eid)], actual_time)
                   for branch in d["queries"][0]["query"]["branches"]):
            raise ValueError("selected evidence is outside guidance scope")
        masked, _ = mask_event(hydrate_raw(event))
        allowed = {"event_id", "timestamp", "data_source", "event_type", "src_ip", "src_port", "dst_ip", "dst_port",
                   "method", "uri", "url_path", "status_code", "bytes_in", "bytes_out", "enforcement_action", "process",
                   "user", "domain", "protocol", "tags", "source_file", "evidence_id", "line_no", "raw_event", "raw_ref"}
        clean = {k: v for k, v in masked.items() if k in allowed}
        selected.append({"event_id": eid, "event": clean, "sha256": digest(clean)})
    now = utcnow().isoformat()
    for row in selected:
        row["known_at"] = now
    capture = {"schema_version": 1, "captured_at": now, "known_at": now, "as_of": g.scope.as_of or now,
               "temporally_valid": g.scope.as_of is None, "methodology": d["methodology"], "scope": d["scope"],
               "input": {"request": g.scope.model_dump(), "scope": d["scope"], "facts": d["facts"],
                         "unknowns": d["unknowns"], "queries": d["queries"], "limits": d["limits"]},
               "evidence_refs": list(check.evidence), "selected_events": selected}
    if len(canonical(capture).encode()) > MAX_CAPTURE:
        raise ValueError("selected evidence capture exceeds 256 KiB; select fewer records")
    check.scope = {**check.scope, "guidance": {"rule_id": g.rule_id, "methodology_version": VERSION,
                   "scope_key": d["scope"]["scope_key"], "scope": g.scope.model_dump(), "answer_status": g.answer_status,
                   "data_states": [{**x.model_dump(), "source_kind": "analyst_statement"} for x in g.data_states],
                   "follow_up": g.follow_up.model_dump(), "answer": mask_text(g.answer).text,
                   "forbidden_claims": copy.deepcopy(next(r for r in methodology()["rules"] if r["id"] == g.rule_id)["forbidden_claims"])}}
    check.context = {**check.context, "guidance": capture}
    inv = s.get(Investigation, inv_id)
    inv.settings = {**(inv.settings or {}), "guidance_methodology": method_info()}


def build_closure_draft(s, p, inv_id):
    """Reuse recorded answers, without inventing checks from clicks or detection existence."""
    require(s, p, "investigation.read", inv_id)
    rows = list(s.scalars(select(Check).where(Check.investigation_id == inv_id, Check.state == "active")
                         .order_by(Check.created_at)))
    behavior, impact, limits, follow, evidence, scopes, ids = [], [], [], [], [], [], []
    for c in rows:
        g = (c.scope or {}).get("guidance", {})
        if c.kind == "cited":
            limits.append("다른 조사의 확인을 참고한 기록입니다: " + c.id)
        note = mask_text(c.note or g.get("answer", "")).text
        if not note:
            continue
        ids.append(c.id)
        if set(c.questions or []) & {"nature", "business"}:
            behavior.append(note)
        if set(c.questions or []) & {"success", "impact"}:
            impact.append(note)
        evidence.extend({"check_id": c.id, "event_id": eid} for eid in c.evidence or [])
        if g:
            capture = (c.context or {}).get("guidance", {})
            scopes.append(capture.get("scope", {}))
            limits.extend(capture.get("input", {}).get("limits", []))
            limits.extend(x["reason"] for x in g.get("data_states", []) if x.get("reason") and x["state"] not in ("available", "not_applicable"))
            if g.get("answer_status") == "follow_up":
                follow.append({"check_id": c.id, **g["follow_up"]})
        b = (c.scope or {}).get("behavior") or {}
        if b:
            if b.get("answer_status") == "follow_up":
                follow.append({"check_id": c.id, **b.get("follow_up", {})})
            scopes.append({"scope_key": b["result_sha256"], "behavior_result_id": b["result_id"],
                           **((c.scope or {}).get("query") or {})})
        if (c.scope or {}).get("coverage") == "sample":
            limits.append("표본을 확인한 기록이 있으며 조사 전체의 확인을 의미하지 않습니다.")
    return {"methodology_version": VERSION, "behavior_assessment": "\n".join(dict.fromkeys(behavior)),
            "impact_assessment": "\n".join(dict.fromkeys(impact)) or "현재 기록으로 실제 침해·영향은 확인되지 않았습니다.",
            "evidence": evidence, "limits": list(dict.fromkeys(limits)), "follow_up": follow,
            "check_ids": ids, "scopes": list({x.get("scope_key", ""): x for x in scopes if x}.values())}
