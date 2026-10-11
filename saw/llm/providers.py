"""LocalLLMProvider abstraction (docs/29 §1). Only local/private endpoints are allowed — never cloud LLMs."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse


@dataclass
class LLMRequest:
    system: str
    user: str
    json_mode: bool = True
    max_tokens: int = 1200
    temperature: float = 0.1


@dataclass
class LLMResponse:
    text: str
    model: str
    tokens_in: int | None = None
    tokens_out: int | None = None


class LocalLLMProvider(Protocol):
    name: str
    model: str
    is_llm: bool

    def generate(self, req: LLMRequest) -> LLMResponse: ...
    def health(self) -> dict: ...


class EgressPolicyError(ValueError):
    pass


def assert_local_endpoint(url: str) -> None:
    """Allow loopback/private addresses only (Zone L). Public hosts are rejected (docs/29 §1)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise EgressPolicyError("LLM endpoint must be http(s)://<private host>")
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, None)}
    except socket.gaierror:
        raise EgressPolicyError(f"cannot resolve {u.hostname}") from None
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%")[0])
        if not (ip.is_private or ip.is_loopback):
            raise EgressPolicyError(f"LLM endpoint {u.hostname} resolves to public address {a} — cloud LLMs are not allowed")


class OllamaProvider:  # pragma: no cover - ENV-08
    name, is_llm = "ollama", True

    def __init__(self, url: str, model: str, timeout: float = 120):
        assert_local_endpoint(url)
        self.url, self.model, self.timeout = url.rstrip("/"), model, timeout

    def generate(self, req: LLMRequest) -> LLMResponse:
        import httpx

        r = httpx.post(f"{self.url}/api/chat", timeout=self.timeout, json={
            "model": self.model, "stream": False, "format": "json" if req.json_mode else None,
            "options": {"temperature": req.temperature, "num_predict": req.max_tokens},
            "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}]})
        r.raise_for_status()
        d = r.json()
        return LLMResponse(d["message"]["content"], self.model, d.get("prompt_eval_count"), d.get("eval_count"))

    def health(self) -> dict:
        import httpx

        try:
            r = httpx.get(f"{self.url}/api/tags", timeout=5)
            return {"available": r.status_code == 200, "detail": f"ollama {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"available": False, "detail": str(e)[:200]}


class OpenAICompatibleProvider:  # pragma: no cover - ENV-08
    name, is_llm = "openai_compat", True

    def __init__(self, url: str, model: str, api_key: str | None = None, timeout: float = 120):
        assert_local_endpoint(url)
        self.url, self.model, self.key, self.timeout = url.rstrip("/"), model, api_key, timeout

    def generate(self, req: LLMRequest) -> LLMResponse:
        import httpx

        h = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        body = {"model": self.model, "temperature": req.temperature, "max_tokens": req.max_tokens,
                "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}]}
        if req.json_mode:
            body["response_format"] = {"type": "json_object"}
        r = httpx.post(f"{self.url}/v1/chat/completions", headers=h, json=body, timeout=self.timeout)
        r.raise_for_status()
        d = r.json()
        u = d.get("usage") or {}
        return LLMResponse(d["choices"][0]["message"]["content"], self.model, u.get("prompt_tokens"), u.get("completion_tokens"))

    def health(self) -> dict:
        import httpx

        try:
            r = httpx.get(f"{self.url}/v1/models", timeout=5)
            return {"available": r.status_code == 200, "detail": f"openai-compat {r.status_code}"}
        except Exception as e:  # noqa: BLE001
            return {"available": False, "detail": str(e)[:200]}


class TemplateProvider:
    """Deterministic, offline, NOT an LLM: renders answers from the TRUSTED context only.

    Lets the assistant workflow (context building, citations, validation, audit, UI) run without a model.
    Responses are labelled so nobody mistakes them for model output.
    """

    name, model, is_llm = "template", "offline-template-v1", False

    def generate(self, req: LLMRequest) -> LLMResponse:
        m = re.search(r"<trusted_context>\s*(\{.*?\})\s*</trusted_context>", req.user, re.S)
        ctx = json.loads(m.group(1)) if m else {}
        action = ctx.get("action", "ask")
        lines, cites = [], []
        for f in ctx.get("findings", [])[:5]:
            cites.append(f["display_id"])
            passed = [c["label"] for c in f.get("checks", []) if c.get("passed")]
            lines.append(f"- [{f['display_id']}] {f['title']} ({f['risk_level']}): " + (", ".join(passed[:4]) or "근거 체크 없음"))
        if action == "next_steps":
            steps = ctx.get("recommended_checks", []) or ["동일 출발지/지문의 다른 활동 확인", "응답 크기·성공 여부 확인", "자산 담당자에게 정상 여부 확인"]
            answer = "추가 확인사항 (Playbook/Experience 기반):\n" + "\n".join(f"- [ ] {x}" for x in steps[:8])
        elif action == "compare_cases":
            sims = ctx.get("similar", [])
            answer = "과거 사례 비교 (점수는 결정적 계산 결과):\n" + "\n".join(
                f"- {x['display_id']} {round(x['score'] * 100)}% — 같음: {', '.join(x['same'][:4])} / 다름: {', '.join(x['different'][:3])}" for x in sims[:3]) if sims else "비교할 과거 사례가 없습니다."
            cites += [x["display_id"] for x in sims[:3]]
        elif action == "ioc_summary":
            answer = "관련 IOC:\n" + "\n".join(f"- {e}" for e in ctx.get("entities", [])[:20])
        elif action == "hunting_query":
            ent = next((e for e in ctx.get("entities", []) if e.startswith("ja4:") or e.startswith("ip:")), None)
            q = {"filters": [{"field": "ja4" if ent and ent.startswith("ja4:") else "src_ip", "op": "is", "value": ent.split(":", 1)[1]}] if ent else [],
                 "aggs": [{"type": "terms", "field": "src_ip", "size": 50}]}
            answer = "동일 지문/출발지의 다른 활동을 찾는 구조화 질의 초안입니다 (실행 전 검토 필요)."
            return LLMResponse(json.dumps({"answer_md": answer, "citations": cites, "query": q}, ensure_ascii=False), self.model)
        else:
            head = {"explain_finding": "이 Finding이 이상한 이유 (근거 체크 기준):", "summarize": "Investigation 요약:",
                    "timeline_summary": "Timeline 요약 (Finding 시각 순):", "detection_idea": "탐지 조건 아이디어:",
                    "report_draft": "보고서 초안:"}.get(action, "질문에 대한 근거 기반 정리:")
            answer = head + "\n" + ("\n".join(lines) or "- 근거로 사용할 Finding이 없습니다.")
        answer += "\n\n※ 오프라인 템플릿 응답 (LLM 아님): Local LLM 연결 시 자연어 설명으로 대체됩니다 (ENV-08)."
        return LLMResponse(json.dumps({"answer_md": answer, "citations": cites}, ensure_ascii=False), self.model)

    def health(self) -> dict:
        return {"available": True, "detail": "offline template provider (not an LLM)"}
