"""SOC Assistant service: minimal masked context → provider → validated, cited, audited output (docs/29)."""
from __future__ import annotations
from saw.detection.derived_access import source_ids, require_snapshot, require_finding

import hashlib
import json
import time
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw import container
from saw.core.application import audit
from saw.core.application.identity import principal_of
from saw.core.application.analysis import finding_dict
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.schemas.query import Filter, TimeRange
from saw.core.security.authz import Principal, can
from saw.core.security.masking import mask_event, mask_text
from saw.llm.context_policy import allowed_experiences, knowledge_snapshot, knowledge_still_allowed, mask_context
from saw.llm.prompt import build, injection_signals
from saw.llm.providers import LLMRequest, OllamaProvider, OpenAICompatibleProvider, TemplateProvider, describe_baseline
from saw.storage.db import Base, new_id, utcnow
from saw.storage.models import AttackStory, Finding, Investigation, Note, User, UserSession

ACTIONS = {"explain_finding", "next_steps", "compare_cases", "ioc_summary", "hunting_query", "timeline_summary",
           "detection_idea", "report_draft", "summarize", "ask"}
SAMPLE_FIELDS = ["event_id", "timestamp", "data_source", "src_ip", "method", "uri", "status_code", "user_agent", "domain"]
MAX_SAMPLES = 20
MAX_FIELD = 512
SELECTED_SAMPLE_LIMIT = 3
SELECTED_ACTIONS = {"explain_finding", "next_steps", "report_draft"}


class LlmInteraction(Base):
    __tablename__ = "ai_llm_interaction"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36))
    investigation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64))
    prompt_hash: Mapped[str] = mapped_column(String(64))  # prompt text itself is not stored (docs/07 ai)
    context_refs: Mapped[list] = mapped_column(JSON, default=list)
    output_md: Mapped[str] = mapped_column(Text, default="")
    citations: Mapped[list] = mapped_column(JSON, default=list)
    citation_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    injection_signals: Mapped[list] = mapped_column(JSON, default=list)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    feedback: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def provider():
    from saw.llm.model_packs import selected_provider
    s = container.get().settings
    selected = selected_provider(s)
    if selected is not None:
        return selected
    kind = getattr(s, "llm_provider", "template")
    if kind == "ollama":  # ENV-08
        return OllamaProvider(s.llm_url, s.llm_model)
    if kind == "openai_compat":  # ENV-08
        return OpenAICompatibleProvider(s.llm_url, s.llm_model)
    if kind == "none":
        return None
    return TemplateProvider()


def provider_status() -> dict:
    p = provider()
    if p is None:
        return {"available": False, "provider": "none"}
    return {**p.health(), "provider": p.name, "model": p.model, "is_llm": p.is_llm}


def _samples(inv_id: str, flt: list[Filter], time_range: TimeRange | None = None, *, limit: int = MAX_SAMPLES) -> list[dict]:
    out = []
    for e in container.get().events.search(inv_id, flt, time_range, limit=limit)["events"]:
        m, _ = mask_event(e)
        out.append({k: (mask_text(str(m.get(k))).text[:MAX_FIELD] if m.get(k) is not None else None) for k in SAMPLE_FIELDS})
    return out


def _evidence_scope(refs: dict) -> tuple[list[Filter], TimeRange | None, bool]:
    """Reject invalid scopes; absence of a scope must never select every event."""
    try:
        query = (refs or {}).get("query") or {}
        if not isinstance(query, dict):
            raise ValueError()
        filters = [Filter(**row) for row in query.get("filters", [])]
        time_range = TimeRange(**query["time"]) if query.get("time") else None
        bounds = []
        for raw in (time_range.start, time_range.end) if time_range else (None, None):
            instant = datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None
            if instant is not None and instant.tzinfo is None:
                raise ValueError()
            bounds.append(instant)
        if all(bounds) and bounds[0] > bounds[1]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ValueError("invalid finding evidence scope") from None
    return filters, time_range, bool(filters or any(bounds))


def _selected_finding(s: Session, inv_id: str, finding_id: str, p=None) -> Finding:
    finding = s.get(Finding, finding_id)
    if finding is None or finding.investigation_id != inv_id:
        raise NotFound("finding not found")
    require_finding(s, p or s.info.get("principal"), finding)
    return finding


def _short(value, limit=120):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = mask_text(str(value)).text
    return text if len(text) <= limit else text[:limit] + "…[생략]"


def _metric_value(value, depth=0):
    if isinstance(value, dict):
        if depth >= 3:
            return "[깊은 값 생략]"
        result = {str(key): _metric_value(item, depth + 1) for key, item in list(value.items())[:12]}
        if len(value) > 12:
            result["_omitted"] = len(value) - 12
        return result
    if isinstance(value, list):
        if depth >= 3:
            return "[깊은 값 생략]"
        return [_metric_value(item, depth + 1) for item in value[:12]] + (["[나머지 생략]"] if len(value) > 12 else [])
    return _short(value, 160)


def _value_text(value):
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)


def _selected_context(s: Session, p: Principal, inv_id: str, finding_id: str, *, sample_limit: int) -> dict:
    require(s, p, "investigation.read", inv_id)
    finding = _selected_finding(s, inv_id, finding_id, p)
    filters, time_range, has_scope = _evidence_scope(finding.evidence_refs)
    matched = container.get().events.count(inv_id, filters, time_range) if has_scope else None
    samples = _samples(inv_id, filters, time_range, limit=sample_limit) if has_scope and sample_limit else []
    metrics = [{"name": _short(m.get("name", "지표"), 64), "observed": _metric_value(m.get("observed")),
                "baseline": _metric_value(m.get("baseline")),
                **({"label": _short(m["label"], 100)} if m.get("label") else {}),
                **({"unit": _short(m["unit"], 32)} if m.get("unit") else {})}
               for m in (finding.metrics or [])[:4]]
    checks = [{"label": _short(c.get("label", "확인"), 100), "passed": c.get("passed"),
               "value": _short(c.get("value"))} for c in (finding.checks or [])[:4]]
    scope = {"investigation_id": inv_id, "finding_id": finding_id, "finding_display_id": finding.display_id,
             "time": time_range.model_dump() if time_range else None,
             "query_available": has_scope, "matched_events": matched, "sampled_events": len(samples), "sample_limit": sample_limit,
             "truncated": matched is not None and matched > len(samples)}
    observations = [f"선택한 탐지의 근거 조건에 맞는 현재 로그는 {matched}건입니다."] if has_scope else []
    for metric in metrics:
        if metric["observed"] is not None:
            baseline = f", 저장된 비교 기준 {describe_baseline(metric['baseline'])}" if metric["baseline"] is not None else ", 비교 기준 없음"
            observations.append(f"{metric.get('label') or metric['name']}: 관측 {_value_text(metric['observed'])}{baseline}.")
    for check in checks:
        result = "충족" if check["passed"] is True else "미충족" if check["passed"] is False else "미확인"
        observations.append(f"{check['label']}: 탐지 조건 {result} ({check['value'] if check['value'] is not None else '값 없음'}).")
    limitations = ["선택한 탐지의 저장된 지표·체크만 설명합니다. 기준값은 정상 판정이 아니며 현재 로그 건수와 집계 시점이 다를 수 있습니다.",
                   "침해 성공·정상·오탐 확정 근거가 아닙니다. 최종 판단과 조치는 분석가가 검토합니다."]
    if not has_scope:
        limitations.append("유효한 근거 조회 범위가 없어 로그를 조회하지 않았습니다.")
    elif not matched:
        limitations.append("근거 조건에 맞는 현재 로그가 없습니다. 수집·보관 상태와 탐지 시점을 확인하세요.")
    if sample_limit == 0:
        limitations.append("원문·이벤트 표본·조사 전체 메모·다른 탐지·과거 경험은 모델에 전달하지 않습니다.")
    else:
        limitations.append(f"표본 참조는 최대 {sample_limit}건이며 원문 내용은 이 미리보기에 포함하지 않습니다.")
    if len(finding.metrics or []) > 4 or len(finding.checks or []) > 4 or len(finding.attack or []) > 4:
        limitations.append("표시·전달은 지표·체크·ATT&CK 각각 앞 4개로 제한됩니다. 전체 근거는 탐지 상세에서 확인하세요.")
    limitations.append("긴 글자 값과 중첩 값은 생략 표시로 제한합니다. 원문은 탐지 상세에서 확인하세요.")
    return {"scope": scope,
            "finding": {"display_id": finding.display_id, "title": _short(finding.title, 160),
                        "risk_level": finding.risk_level, "metrics": metrics, "checks": checks,
                        "attack": [_short(a.get("technique_id", ""), 32) for a in (finding.attack or [])[:4]]},
            "observations": observations,
            "alternatives": ["정상 배치·백업·자동 재시도·장애도 변화의 원인일 수 있으므로 작업 일정과 비교하세요.",
                             "악성 시도 가능성은 실제 실행·파일 변경·통신 등 별도 근거와 비교해야 합니다."],
            "next_checks": ["같은 시간대·같은 출발지의 원문과 수집 누락 여부를 확인하세요.",
                            "자산 담당자의 승인된 작업 일정·정상 기준과 대조하세요.",
                            "요청 결과와 프로세스·파일 변경을 연결해 차단된 시도와 실제 실행 여부를 구분하세요."],
            "limitations": limitations,
            "citations": [{"id": finding.display_id, "type": "finding", "finding_id": finding_id}] +
                         [{"id": f"evt:{row['event_id']}", "type": "event", "event_id": row["event_id"]}
                          for row in samples if row.get("event_id")]}


def preview_context(s: Session, p: Principal, inv_id: str, finding_id: str) -> dict:
    if not can(p, "ai.use"):
        raise Forbidden("ai.use required")
    return _selected_context(s, p, inv_id, finding_id, sample_limit=SELECTED_SAMPLE_LIMIT)


def build_context(s: Session, p: Principal, inv_id: str, action: str, finding_id: str | None, *,
                  synthetic_only: bool = False) -> tuple[dict, list[dict], list[str]]:
    if finding_id:
        _selected_finding(s, inv_id, finding_id, p)
    if finding_id and action in SELECTED_ACTIONS:
        preview = _selected_context(s, p, inv_id, finding_id, sample_limit=0)
        trusted = {"context_scope": "selected_finding", "scope": preview["scope"], "findings": [preview["finding"]],
                   "limitations": preview["limitations"]}
        return trusted, [], [preview["finding"]["display_id"]]
    inv = s.get(Investigation, inv_id)
    q = select(Finding).where(Finding.investigation_id == inv_id).order_by(Finding.risk_score.desc())
    if finding_id:
        q = q.where(Finding.id == finding_id)
    fs = [finding_dict(f) for f in s.execute(q.limit(8)).scalars()]
    trusted: dict = {"investigation": {"display_id": inv.display_id, "title": mask_text(inv.title).text},
                     "findings": [{"display_id": f["display_id"], "title": f["title"], "risk_level": f["risk_level"],
                                   "time_start": str(f["time_start"]), "stage": f["stage"],
                                   "metrics": [{"name": m["name"], "observed": m.get("observed"), "baseline": m.get("baseline")}
                                               for m in f["metrics"] if m.get("observed") is not None][:8],
                                   "checks": [{"label": c["label"], "passed": c["passed"], "value": str(c["value"])[:120]} for c in f["checks"]],
                                   "attack": [a["technique_id"] for a in f["attack"]]} for f in fs]}
    refs = [f["display_id"] for f in fs]
    ents = sorted({e for f in fs for e in f["entities"]})[:40]
    trusted["entities"] = ents
    if action in ("next_steps", "compare_cases", "detection_idea") and not synthetic_only:
        from saw.knowledge import similar
        from saw.knowledge.fp import playbooks_for

        feats, text = similar.features_for_investigation(s, inv_id, finding_id)
        sims = similar.search(s, feats, text, 5, exclude_ref=inv_id, types=("experience",),
                              allowed_ref_ids=allowed_experiences(s, p))
        trusted["similar"] = [{"display_id": x["display_id"], "score": x["score"], "same": x["same"], "different": x["different"],
                               "verdict": x["verdict"]} for x in sims]
        refs += [x["display_id"] for x in sims]
        checks = [c for x in sims for c in (x["extra"].get("recommended_checks") or []) if c]
        for pb in playbooks_for(s, fs[0]["category"] if fs else None):
            checks += [st.get("check") for st in pb["steps"]]
        trusted["recommended_checks"] = list(dict.fromkeys(checks))[:10]
    if not finding_id and action in ("summarize", "timeline_summary", "report_draft"):
        st = s.execute(select(AttackStory).where(AttackStory.investigation_id == inv_id).order_by(AttackStory.version.desc())).scalars().first()
        if st:
            require_snapshot(s, p, st.graph)
            trusted["story"] = [{"stage": n["stage"], "title": n["title"]} for n in st.graph.get("nodes", [])][:12]
        trusted["notes"] = [mask_text(n.body_md).text[:300] for n in s.execute(select(Note).where(Note.investigation_id == inv_id)).scalars()][:10]
    flt, time_range, has_scope = [], None, True
    if fs:
        flt, time_range, has_scope = _evidence_scope(fs[0]["evidence_refs"])
    untrusted = _samples(inv_id, flt, time_range) if has_scope else []
    refs += [f"evt:{e['event_id']}" for e in untrusted if e.get("event_id")]
    trusted["citation_ids"] = refs
    if finding_id:
        matched = container.get().events.count(inv_id, flt, time_range) if has_scope else None
        trusted["context_scope"] = "selected_finding"
        trusted["scope"] = {"investigation_id": inv_id, "finding_id": finding_id,
                            "finding_display_id": fs[0]["display_id"], "time": time_range.model_dump() if time_range else None,
                            "query_available": has_scope, "matched_events": matched,
                            "sampled_events": len(untrusted), "sample_limit": MAX_SAMPLES,
                            "truncated": matched is not None and matched > len(untrusted)}
    return mask_context(trusted), untrusted, refs


def run(s: Session, p: Principal, inv_id: str, action: str, question: str = "", finding_id: str | None = None, *, session_id: str | None = None) -> dict:
    from saw.core.application.data_deletion import epoch
    data_epoch = epoch(require(s, p, "investigation.read", inv_id))
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action}")
    prov = provider()
    if prov is None:
        raise ValueError("SOC Assistant is disabled (no LLM provider configured)")
    synthetic_only = getattr(prov, "synthetic_only", False)
    if synthetic_only and inv_id not in container.get().settings.llm_synthetic_investigation_ids:
        raise Forbidden("local_ai_synthetic_investigation_required")
    trusted, untrusted, refs = build_context(s, p, inv_id, action, finding_id, synthetic_only=synthetic_only)
    derived_sources = set()
    if finding_id:
        derived_sources.update(source_ids(_selected_finding(s, inv_id, finding_id, p)))
    elif action in {"summarize", "timeline_summary", "report_draft"}:
        story = s.scalar(select(AttackStory).where(AttackStory.investigation_id == inv_id).order_by(AttackStory.version.desc()))
        if story:
            derived_sources.update(source_ids(story.graph))
    signals = injection_signals([json.dumps(untrusted, ensure_ascii=False), question])
    system, user = build(action, mask_text(question).text[:2000], trusted, untrusted,
                         compact_selected=prov.is_llm and action in SELECTED_ACTIONS)
    knowledge_versions = knowledge_snapshot(s, [row["display_id"] for row in trusted.get("similar", [])])
    # Release the read transaction during bounded native execution.
    s.commit()
    t0 = time.perf_counter()
    from saw.llm.cpu_provider import CPUExecutionError, sanitize_diagnostics
    try:
        resp = prov.generate(LLMRequest(system, user, json_mode=True))
    except CPUExecutionError as exc:
        s.rollback()
        audit.record(s, "ai.failure", actor_id=p.user_id, actor_name=p.username, target_type="llm",
                     investigation_id=inv_id, outcome="failure",
                     detail={"action": action, "provider": prov.name, "code": str(exc),
                             "actual_inference": exc.actual_inference, **sanitize_diagnostics(exc.diagnostics)})
        s.commit()
        raise ValueError(str(exc)) from None
    latency = int((time.perf_counter() - t0) * 1000)
    s.expire_all()
    current_user = s.get(User, p.user_id)
    if current_user is None or current_user.status != "active":
        raise Forbidden("ai_authorization_changed")
    if session_id:
        current_session = s.get(UserSession, session_id)
        if (current_session is None or current_session.user_id != p.user_id
                or current_session.revoked_at is not None or not current_session.mfa_passed
                or current_session.expires_at.replace(tzinfo=UTC) <= utcnow()):
            raise Forbidden("ai_session_changed")
    current_principal = principal_of(current_user)
    require_snapshot(s, current_principal, {"_source_investigation_ids": sorted(derived_sources)})
    if not can(current_principal, "ai.use"):
        raise Forbidden("ai_authorization_changed")
    if epoch(require(s, current_principal, "investigation.read", inv_id)) != data_epoch:
        raise Forbidden("ai_evidence_changed_output_not_published")
    if not knowledge_still_allowed(s, current_principal, knowledge_versions):
        raise Forbidden("ai_context_authorization_changed")
    if synthetic_only and inv_id not in container.get().settings.llm_synthetic_investigation_ids:
        raise Forbidden("local_ai_synthetic_investigation_required")
    if getattr(prov, "pack_id", None):
        from saw.llm.model_packs import LocalModelSelection
        selection = s.get(LocalModelSelection, 1)
        if (selection is None or selection.pack_id != prov.pack_id
                or selection.epoch != getattr(prov, "selection_epoch", selection.epoch)):
            raise ValueError("model_selection_changed_output_not_published")
    output_reason = None
    out, answer, cites = {}, "", []
    try:
        parsed = json.loads(resp.text)
        if (not isinstance(parsed, dict) or not isinstance(parsed.get("answer_md"), str)
                or not parsed["answer_md"].strip() or len(parsed["answer_md"]) > 16000
                or not isinstance(parsed.get("citations"), list) or len(parsed["citations"]) > 50
                or any(not isinstance(c, str) or not c or len(c) > 128 for c in parsed["citations"])):
            raise ValueError("invalid generated response")
        out, answer, cites = parsed, mask_text(parsed["answer_md"]).text, parsed["citations"]
    except (ValueError, TypeError):
        output_reason = "invalid_structure"
    ref_set = set(refs)
    invalid = [c for c in cites if c not in ref_set]
    if output_reason is None and (invalid or (prov.is_llm and ref_set and not cites)):
        output_reason = "invalid_citations"
    if output_reason:
        out, answer, cites = {}, "", []
    citation_valid = output_reason is None
    output_status = "rejected" if output_reason else ("validated_draft" if prov.is_llm else "template")
    execution_status = "executed" if prov.is_llm else "not_applicable"
    claim_support = "NOT_VALIDATED" if prov.is_llm else "DETERMINISTIC_TEMPLATE"
    query = None
    if action == "hunting_query" and isinstance(out.get("query"), dict):
        try:  # LLM output is data: validate against the SAW Query Model before showing
            query = {"filters": [Filter(**f).model_dump() for f in out["query"].get("filters", [])], "aggs": out["query"].get("aggs", [])}
        except Exception as e:  # noqa: BLE001
            query = {"error": f"invalid query rejected: {e}"[:200]}
    rec = LlmInteraction(user_id=p.user_id, investigation_id=inv_id, action=action, provider=prov.name, model=resp.model,
                         prompt_hash=hashlib.sha256((system + user).encode()).hexdigest(), context_refs=refs,
                         output_md=answer, citations=cites, citation_valid=citation_valid, injection_signals=signals,
                         latency_ms=latency)
    s.add(rec)
    s.flush()
    audit.record(s, "ai.action", actor_id=p.user_id, actor_name=p.username, target_type="llm", target_id=rec.id,
                 investigation_id=inv_id, detail={"action": action, "provider": prov.name, "invalid_citations": len(invalid),
                                                  "injection_signals": len(signals), "output_status": output_status,
                                                  "execution_status": execution_status, "output_reason": output_reason})
    return {"id": rec.id, "answer_md": answer, "citations": [{"id": c, "valid": c in ref_set} for c in cites],
            "citation_valid": citation_valid, "injection_signals": signals, "provider": prov.name, "model": resp.model,
            "is_llm": prov.is_llm, "label": ("AI 출력 검증 실패 · 답변 미채택" if output_reason else
                                               "AI 생성 초안 · 사실 검토 필요" if prov.is_llm else "오프라인 템플릿 (LLM 아님)"),
            "output_status": output_status, "output_reason": output_reason,
            "execution_status": execution_status, "claim_support": claim_support,
            "runtime_receipt": getattr(prov, "last_receipt", None),
            "query": query, "context_size": {"findings": len(trusted["findings"]), "samples": len(untrusted)},
            "context_scope": trusted.get("context_scope", "selected_finding" if finding_id else "investigation"),
            "scope": trusted.get("scope"),
            "context_projection": ("selected_finding_compact_v1" if finding_id and action in SELECTED_ACTIONS and prov.is_llm
                                   else "selected_finding_template_v1" if finding_id and action in SELECTED_ACTIONS else "legacy_v1"),
            "latency_ms": latency}
