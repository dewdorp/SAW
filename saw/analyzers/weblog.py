"""Pasted web server logs: the same web detectors as an investigation, run on a temporary in-memory store.

Nothing is saved. The pasted lines are parsed, indexed into a private SQLite memory database for the length of one
request, the web detectors run over it, and the store is closed. Results point back to pasted line numbers.
"""
from __future__ import annotations

import re
import uuid
from collections import Counter, defaultdict

from saw.core.security.masking import mask_text

# What the analyst sees for the format the parser recognised. Several servers share one log format: the parser
# cannot tell Apache from Tomcat in a common-format line, so the label names the format and the servers that use it.
FORMAT_KO = {
    "nginx_combined": "NCSA combined/common 형식 (Nginx·Apache·Tomcat·WebtoB·JEUS 등 공통)",
    "apache_combined": "NCSA combined/common 형식 (Apache·Nginx·Tomcat·WebtoB·JEUS 등 공통)",
    "apache_vhost_combined": "가상 호스트가 앞에 붙은 combined 형식 (Apache vhost_combined, Nginx $host 앞붙임)",
    "iis_w3c": "IIS W3C 확장 형식",
    "haproxy_http": "HAProxy HTTP 로그 (option httplog)",
    "web_json_access": "JSON 접근 로그 (Nginx JSON·Caddy·ECS 형식 등)",
    "apache_error": "Apache 오류 로그 (error_log, ModSecurity 메시지 포함)",
    "nginx_error": "Nginx 오류 로그 (error.log)",
    "cloudflare_http": "Cloudflare HTTP 로그",
}

CHECK_KO = {
    "404 burst": "404 응답이 몰림", "Path diversity": "서로 다른 경로가 많음", "Any success from same sources": "같은 출발지의 성공 응답",
    "Sensitive path dictionary match": "민감 경로 목록과 일치", "Successful response (2xx)": "성공 응답(2xx)",
    "High attempt volume": "시도 횟수가 많음", "High failure ratio": "실패 비율이 높음", "Many distinct accounts": "서로 다른 계정이 많음",
    "Success after attempts": "시도 뒤 성공", "Payload pattern in parameters": "요청 값에 공격 구문", "Success / error signal": "성공·오류 응답",
    "Blocked responses": "그 밖의 응답(차단 등)", "Non-browser User-Agent": "브라우저가 아닌 User-Agent", "Known scanner signature": "알려진 스캐너 표시",
    "Outlier vs other sources": "다른 출발지보다 훨씬 큼", "Denied then succeeded on same path": "거부 뒤 같은 경로에서 성공",
    "Request mutated": "요청이 바뀜", "Single external source with 2xx": "외부 출발지 하나만 성공", "Administrative / export keyword": "관리·내보내기 성격 경로",
    "Sequential identifier": "번호가 순서대로 바뀜", "High success ratio": "성공 비율이 높음", "Automated interval": "자동화된 간격",
    "Multiple Cloud IP": "여러 클라우드 주소", "Same fingerprint": "같은 지문", "Known batch window": "알려진 배치 시간",
}
METRIC_KO = {
    "404 responses": "404 응답", "Distinct paths": "서로 다른 경로", "Sources": "출발지", "Requests": "요청", "Paths": "경로",
    "2xx": "성공(2xx)", "5xx": "서버 오류(5xx)", "Attempts": "시도", "Failure ratio": "실패 비율", "Accounts": "계정",
    "Successful": "성공", "Share of traffic": "전체 중 비율", "Bytes returned": "응답 바이트", "Denied attempts": "거부된 시도",
    "Status": "응답 변화", "Rare paths": "드문 경로", "Unique objects": "서로 다른 대상", "Sequential ratio": "순차 비율",
    "HTTP 2xx ratio": "성공 비율", "Source IPs": "출발지 주소", "Request rate": "분당 요청",
}
TITLE_KO = {
    "Possible Forced Browsing / Discovery": "경로 대량 탐색(스캔) 가능성", "Possible Sensitive File Probing": "민감 파일 탐색 가능성",
    "Possible Credential Stuffing": "여러 계정 대입(크리덴셜 스터핑) 가능성", "Possible Password Guessing / Brute Force": "비밀번호 무차별 대입 가능성",
    "Possible Vulnerability Scanner Activity": "취약점 스캐너 접속 가능성", "Possible Scripted / Automated Client": "자동화 도구 접속 가능성",
    "Possible Large Data Retrieval": "큰 응답(대량 반출) 가능성", "Possible Access Control Bypass via Request Mutation": "요청 변조로 접근 제한 우회 가능성",
    "Possible Rare Sensitive Path Access": "드문 관리·내보내기 경로 접근", "Possible API Enumeration": "번호를 바꿔 가며 대량 조회 가능성",
    "Potential SQL Injection Attempts": "SQL 주입 시도", "Potential XSS Attempts": "XSS(스크립트 삽입) 시도",
    "Potential Directory Traversal / LFI Attempts": "경로 조작(디렉터리 이동) 시도", "Potential Command Injection Attempts": "명령 주입 시도",
    "Potential SSTI / Expression Injection Attempts": "템플릿·표현식 주입 시도", "Potential SSRF / RFI Attempts": "SSRF·원격 파일 포함 시도",
    "Potential Insecure Deserialization Attempts": "역직렬화 공격 시도",
}
UA_CLASS_KO = {"browser": "브라우저", "script": "스크립트·도구", "scanner": "스캐너", "empty": "비어 있음", "bot": "검색 로봇", "mobile": "모바일 앱"}
ERROR_KIND_KO = {"file_not_found": "없는 파일 요청", "access_forbidden": "접근 금지 규칙", "rate_limited": "요청 수 제한",
                 "upstream_failure": "뒤쪽 서버 연결 실패", "auth_failure": "인증 실패", "request_too_large": "너무 큰 요청"}


_VALUE_KO = [(" attempts (web login)", "건(웹 로그인)"), (" attempts (auth log)", "건(인증 로그)"), ("web login", "웹 로그인"),
             ("auth log", "인증 로그"), (" success", "건 성공"), (" accounts", "개 계정"), (" × 404", "건(404)"),
             (" × 2xx", "건(2xx)"), (" paths", "개 경로"), (" requests", "건"), (" other", "건 기타"), ("none", "없음")]


def _ko(value):
    if not isinstance(value, str):
        return value
    for a, b in _VALUE_KO:
        value = value.replace(a, b)
    return value


def _store(events: list[dict]):
    from saw.storage.eventstore import SQLiteEventStore

    store = SQLiteEventStore(f"file:saw-paste-{uuid.uuid4().hex}?mode=memory&cache=shared")
    store.index(events)
    return store


def _close(store) -> None:
    for conn in (getattr(store._local, "c", None), store._anchor):
        if conn is not None:
            conn.close()


def run_web_detectors(events: list[dict], investigation_id: str) -> list[dict]:
    """Web detector results over pasted events, each pointing to the pasted line numbers it stands on."""
    from saw.core.application.briefing import CATEGORY_KO, NEXT_KO
    from saw.detectors.base import DetectorContext
    from saw.detectors.web import WEB_DETECTORS

    web = [dict(e, investigation_id=investigation_id) for e in events if e.get("data_source") in ("web", "waf")]
    if not web:
        return []
    lines = {e["event_id"]: e["raw_ref"]["line_no"] for e in web}
    has_user = any(e.get("user") for e in web)  # combined/common logs rarely carry the account name
    store = _store(web)
    out: list[dict] = []
    try:
        ctx = DetectorContext(investigation_id, store, data_sources={"web", "waf"})
        for det in WEB_DETECTORS:
            try:
                drafts = det.run(ctx)
            except Exception as exc:  # noqa: BLE001 - one detector failing is reported, the others still run
                out.append({"detector_id": det.id, "state": "failed", "reason": type(exc).__name__})
                continue
            for d in drafts:
                score, level, _ = d.risk()
                nexts = next((v for k, v in sorted(NEXT_KO.items(), key=lambda kv: -len(kv[0])) if d.category.startswith(k)), [])
                out.append({
                    "detector_id": d.detector_id, "state": "found", "category": d.category,
                    "category_ko": CATEGORY_KO.get(d.category, d.category), "title": d.title,
                    "title_ko": TITLE_KO.get(d.title, d.title), "explanation": _ko(d.explanation if has_user else
                                                                          re.sub(r", 계정 \d+개", "", d.explanation)),
                    "risk_score": score, "risk_level": level, "confidence": d.confidence,
                    "time_start": d.time_start, "time_end": d.time_end, "total_events": d.total_events,
                    "metrics": [{"label": METRIC_KO.get(m.get("label"), m.get("label")), "value": m.get("observed"),
                                 "unit": m.get("unit", "")} for m in d.metrics
                                if m.get("observed") is not None and (has_user or m.get("name") != "accounts")],
                    "checks": [{"label": CHECK_KO.get(c["label"], c["label"]),
                                "passed": None if not has_user and c["label"] == "Many distinct accounts" else c["passed"],
                                "value": "로그에 계정 이름 없음" if not has_user and c["label"] == "Many distinct accounts" else _ko(c["value"])}
                               for c in d.checks],
                    "entities": [mask_text(str(x)).text for x in d.entities[:10]],
                    "line_nos": sorted(lines[i] for i in d.sample_event_ids if i in lines)[:20],
                    "next_checks": nexts,
                    "attack": [a.technique_id for a in d.attack if a.condition_met],
                })
    finally:
        _close(store)
    out.sort(key=lambda f: (f.get("state") != "found", -(f.get("risk_score") or 0)))
    return out


def source_summary(events: list[dict], limit: int = 10) -> list[dict]:
    """Per client address: request count, response mix, distinct paths, client kinds and lines with attack syntax."""
    rows: dict[str, dict] = defaultdict(lambda: {"requests": 0, "status": Counter(), "paths": set(), "ua": Counter(),
                                                 "tagged": [], "first": None, "last": None})
    for e in events:
        if e.get("data_source") not in ("web", "waf") or not e.get("src_ip"):
            continue
        r = rows[e["src_ip"]]
        r["requests"] += 1
        r["status"][e.get("status_class") or "없음"] += 1
        if e.get("url_path"):
            r["paths"].add(e["url_path"])
        if e.get("ua_class"):
            r["ua"][e["ua_class"]] += 1
        if any(str(t).startswith("pattern:") for t in e.get("tags", [])) and len(r["tagged"]) < 10:
            r["tagged"].append(e["raw_ref"]["line_no"])
        ts = e.get("timestamp")
        if ts:
            r["first"] = ts if r["first"] is None or ts < r["first"] else r["first"]
            r["last"] = ts if r["last"] is None or ts > r["last"] else r["last"]
    ranked = sorted(rows.items(), key=lambda kv: (-kv[1]["requests"], kv[0]))[:limit]
    return [{"src_ip": ip, "requests": r["requests"], "status": dict(r["status"]), "distinct_paths": len(r["paths"]),
             "clients": [{"kind": k, "kind_ko": UA_CLASS_KO.get(k, k), "count": v} for k, v in r["ua"].most_common(3)],
             "attack_syntax_lines": r["tagged"], "first": r["first"], "last": r["last"]} for ip, r in ranked]


def error_summary(events: list[dict]) -> list[dict]:
    """Error-log records grouped by what went wrong (Nginx error kind, Apache AH code, ModSecurity rule)."""
    groups: dict[tuple, dict] = {}
    for e in events:
        if e.get("event_type") not in ("http_error", "waf_event"):
            continue
        x = next(iter((e.get("ext") or {}).values()), {}) or {}
        if x.get("modsecurity_id"):
            key = ("modsecurity", x["modsecurity_id"], x.get("modsecurity_msg") or "")
            label = f"ModSecurity 규칙 {x['modsecurity_id']}: {x.get('modsecurity_msg') or ''}".strip()
        elif x.get("error_kind"):
            key = ("nginx", x["error_kind"], "")
            label = ERROR_KIND_KO.get(x["error_kind"], x["error_kind"])
        elif x.get("error_code"):
            key = ("apache", x["error_code"], "")
            label = f"Apache {x['error_code']}"
        else:
            key = ("other", e.get("severity") or "", "")
            label = f"기타({e.get('severity') or '수준 없음'})"
        g = groups.setdefault(key, {"label": mask_text(label).text, "count": 0, "sources": set(), "lines": []})
        g["count"] += 1
        if e.get("src_ip"):
            g["sources"].add(e["src_ip"])
        if len(g["lines"]) < 10:
            g["lines"].append(e["raw_ref"]["line_no"])
    return [{"label": g["label"], "count": g["count"], "sources": len(g["sources"]), "lines": g["lines"]}
            for g in sorted(groups.values(), key=lambda g: -g["count"])][:20]
