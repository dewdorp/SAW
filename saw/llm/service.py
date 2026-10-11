"""SOC Assistant service: minimal masked context → provider → validated, cited, audited output (docs/29)."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime
from functools import lru_cache

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw import container
from saw.core.application import audit
from saw.core.application.analysis import finding_dict
from saw.core.application.investigations import require
from saw.core.schemas.query import Filter
from saw.core.security.authz import Principal
from saw.core.security.masking import mask_event, mask_text
from saw.llm.prompt import build, injection_signals
from saw.llm.providers import LLMRequest, OllamaProvider, OpenAICompatibleProvider, TemplateProvider
from saw.storage.db import Base, new_id, utcnow
from saw.storage.models import AttackStory, Finding, Investigation, Note

ACTIONS = {"explain_finding", "next_steps", "compare_cases", "ioc_summary", "hunting_query", "timeline_summary",
           "detection_idea", "report_draft", "summarize", "ask"}
SAMPLE_FIELDS = ["event_id", "timestamp", "data_source", "src_ip", "method", "uri", "status_code", "user_agent", "domain"]
MAX_SAMPLES = 20
MAX_FIELD = 512


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


@lru_cache
def provider():
    s = container.get().settings
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


def _samples(inv_id: str, flt: list[Filter]) -> list[dict]:
    out = []
    for e in container.get().events.search(inv_id, flt, limit=MAX_SAMPLES)["events"]:
        m, _ = mask_event(e)
        out.append({k: (str(m.get(k))[:MAX_FIELD] if m.get(k) is not None else None) for k in SAMPLE_FIELDS})
    return out


def build_context(s: Session, inv_id: str, action: str, finding_id: str | None) -> tuple[dict, list[dict], list[str]]:
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
    if action in ("next_steps", "compare_cases", "detection_idea"):
        from saw.knowledge import similar
        from saw.knowledge.fp import playbooks_for

        feats, text = similar.features_for_investigation(s, inv_id, finding_id)
        sims = similar.search(s, feats, text, 5, exclude_ref=inv_id)
        trusted["similar"] = [{"display_id": x["display_id"], "score": x["score"], "same": x["same"], "different": x["different"],
                               "verdict": x["verdict"]} for x in sims]
        refs += [x["display_id"] for x in sims]
        checks = [c for x in sims for c in (x["extra"].get("recommended_checks") or []) if c]
        for pb in playbooks_for(s, fs[0]["category"] if fs else None):
            checks += [st.get("check") for st in pb["steps"]]
        trusted["recommended_checks"] = list(dict.fromkeys(checks))[:10]
    if action in ("summarize", "timeline_summary", "report_draft"):
        st = s.execute(select(AttackStory).where(AttackStory.investigation_id == inv_id).order_by(AttackStory.version.desc())).scalars().first()
        if st:
            trusted["story"] = [{"stage": n["stage"], "title": n["title"]} for n in st.graph.get("nodes", [])][:12]
        trusted["notes"] = [mask_text(n.body_md).text[:300] for n in s.execute(select(Note).where(Note.investigation_id == inv_id)).scalars()][:10]
    flt = []
    if fs:
        flt = [Filter(**x) for x in (fs[0]["evidence_refs"].get("query") or {}).get("filters", [])]
    untrusted = _samples(inv_id, flt)
    refs += [f"evt:{e['event_id']}" for e in untrusted if e.get("event_id")]
    return trusted, untrusted, refs


def run(s: Session, p: Principal, inv_id: str, action: str, question: str = "", finding_id: str | None = None) -> dict:
    require(s, p, "investigation.read", inv_id)
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action}")
    prov = provider()
    if prov is None:
        raise ValueError("SOC Assistant is disabled (no LLM provider configured)")
    trusted, untrusted, refs = build_context(s, inv_id, action, finding_id)
    signals = injection_signals([json.dumps(untrusted, ensure_ascii=False), question])
    system, user = build(action, mask_text(question).text[:2000], trusted, untrusted)
    t0 = time.perf_counter()
    resp = prov.generate(LLMRequest(system, user, json_mode=True))
    latency = int((time.perf_counter() - t0) * 1000)
    try:
        out = json.loads(resp.text)
        answer = str(out.get("answer_md", ""))
        cites = [str(c) for c in out.get("citations", [])][:50]
    except (ValueError, AttributeError):
        out, answer, cites = {}, resp.text[:4000], []
    ref_set = set(refs)
    invalid = [c for c in cites if c not in ref_set]
    query = None
    if action == "hunting_query" and isinstance(out.get("query"), dict):
        try:  # LLM output is data: validate against the SAW Query Model before showing
            query = {"filters": [Filter(**f).model_dump() for f in out["query"].get("filters", [])], "aggs": out["query"].get("aggs", [])}
        except Exception as e:  # noqa: BLE001
            query = {"error": f"invalid query rejected: {e}"[:200]}
    rec = LlmInteraction(user_id=p.user_id, investigation_id=inv_id, action=action, provider=prov.name, model=resp.model,
                         prompt_hash=hashlib.sha256((system + user).encode()).hexdigest(), context_refs=refs,
                         output_md=answer, citations=cites, citation_valid=not invalid, injection_signals=signals,
                         latency_ms=latency)
    s.add(rec)
    s.flush()
    audit.record(s, "ai.action", actor_id=p.user_id, actor_name=p.username, target_type="llm", target_id=rec.id,
                 investigation_id=inv_id, detail={"action": action, "provider": prov.name, "invalid_citations": len(invalid),
                                                  "injection_signals": len(signals)})
    return {"id": rec.id, "answer_md": answer, "citations": [{"id": c, "valid": c in ref_set} for c in cites],
            "citation_valid": not invalid, "injection_signals": signals, "provider": prov.name, "model": resp.model,
            "is_llm": prov.is_llm, "label": "AI 생성 · 검증 필요" if prov.is_llm else "오프라인 템플릿 (LLM 아님)",
            "query": query, "context_size": {"findings": len(trusted["findings"]), "samples": len(untrusted)},
            "latency_ms": latency}
