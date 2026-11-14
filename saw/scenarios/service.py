"""Scenario templates, the executor, the preview on current data and the run inside a hunt.

A scenario is stored as versioned knowledge (kind "scenario"); this module turns its definition into a result.
Every result says what was counted and in which unit, how the actor was tied together, which records were read,
what almost matched (reversed order, just outside the time window) and what could not be checked.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select

from saw import container
from saw.core.application.investigations import require
from saw.core.schemas.query import Filter, TimeRange
from saw.flows import knowledge
from saw.flows.engine import Activity, epoch, ext, norm_host, split_uri
from saw.flows.models import FlowKnowledge
from saw.hunts.service import _activity

MAX_MATCHES = 200

# What ships with the product. "executable" templates run on the data named in `needs`; the others are honest
# about not having an executor yet and can be read as reference only.
TEMPLATES = [
    {"id": "auth_then_lookup_variation", "name": "인증 관련 접근 뒤 조회 대상 변화", "executable": True, "kind": "then_variation",
     "purpose": "인증 관련 요청 뒤에 같은 대상이 조회 기능을 여러 대상으로 바꿔 가며 요청하는 흐름을 찾습니다.",
     "needs": ["HTTP 요청 기록(경로·쿼리)"], "normal_note": "상담·정산처럼 여러 고객을 차례로 조회하는 업무일 수 있습니다.",
     "defaults": {"steps": [{"label": "인증 관련 접근", "method": "", "path": "/auth.html", "match": "exact"},
                            {"label": "회원정보 조회", "method": "", "path": "/memberinfo", "match": "exact"}],
                  "count_unit": "distinct_param", "count_param": "id", "min_count": 5, "window_seconds": 600, "entity": "src_ip"},
     "caution": "인증 '성공'은 이 시나리오로 알 수 없습니다. 인증 관련 접근이 있었다는 것만 확인합니다."},
    {"id": "explore_then_focus", "name": "탐색성 요청 뒤 특정 기능에 집중", "executable": True, "kind": "sequence",
     "purpose": "먼저 한 요청 뒤에 특정 기능 요청이 이어지는 순서를 찾습니다.", "needs": ["HTTP 요청 기록"],
     "normal_note": "정상 이용 순서와 같을 수 있습니다. 순서가 맞는다는 것만 확인합니다.",
     "defaults": {"steps": [{"label": "탐색 요청", "method": "", "path": "/", "match": "prefix"},
                            {"label": "집중 기능", "method": "", "path": "/export", "match": "prefix"}],
                  "count_unit": "requests", "min_count": 1, "window_seconds": 900, "entity": "src_ip"}},
    {"id": "low_slow_external", "name": "소량·장기간 반복되는 외부 통신", "executable": True, "kind": "periodic_external",
     "purpose": "같은 출발지가 같은 목적지로 일정한 간격으로 오래 반복 접속하는 통신을 찾습니다.", "needs": ["FW·연결 기록 또는 NDR 기록(시각·주소)"],
     "normal_note": "모니터링·업데이트·시간 동기화처럼 주기적인 정상 통신이 많습니다.", "defaults": {"min_count": 8, "window_seconds": 3600}},
    {"id": "internal_spread", "name": "내부 여러 자산으로 진행되는 접근", "executable": True, "kind": "spread_internal",
     "purpose": "한 출발지가 짧은 시간에 여러 대상이나 포트에 접촉한 기록을 찾습니다.", "needs": ["FW·연결 기록"],
     "normal_note": "자산 점검·취약점 진단·관리 서버의 정기 작업일 수 있습니다.", "defaults": {"min_count": 8, "window_seconds": 600}},
    {"id": "ips_then_traffic", "name": "IPS·WAF 경보 뒤 관련 FW·NDR 관측", "executable": True, "kind": "alert_then_traffic",
     "purpose": "보안장비 경보 뒤 같은 출발지·목적지 사이에 통신 기록이 이어졌는지 확인합니다.", "needs": ["IPS 또는 WAF 경보", "FW·연결 또는 NDR 기록"],
     "normal_note": "경보 뒤의 통신은 차단되지 않았다는 뜻일 수도, 다른 정상 요청일 수도 있습니다.", "defaults": {"min_count": 1, "window_seconds": 300}},
    {"id": "ddos_window", "name": "DDoS 시간대의 서비스 접속 흐름", "executable": True, "kind": "ddos_window_access",
     "purpose": "DDoS 관측 구간 안에서 같은 서비스로 들어온 요청과 오류 응답을 구간 밖과 나란히 봅니다.", "needs": ["DDoS 구간 기록", "HTTP 요청 기록"],
     "normal_note": "같은 시간대의 접속은 DDoS와 무관한 정상 이용일 수 있습니다. 같은 공격자로 묶지 않습니다.", "defaults": {"window_seconds": 300}},
    {"id": "fw_volume", "name": "짧은 시간에 큰 전송량 (방화벽)", "executable": True, "kind": "threshold",
     "purpose": "같은 출발지·목적지 사이에 정한 시간 안에 주고받은 양이 기준을 넘는 통신을 찾습니다.", "needs": ["방화벽·연결 기록(바이트 열)"],
     "normal_note": "백업·배포·영상 회의·대용량 파일 전송 업무일 수 있습니다.",
     "defaults": {"sources": ["fw"], "group_by": "pair", "measure": "bytes_total", "threshold": 50, "byte_unit": "MB", "window_seconds": 600}},
    {"id": "fw_blocked_burst", "name": "차단이 몰린 출발지 (방화벽)", "executable": True, "kind": "threshold",
     "purpose": "한 출발지의 통신이 짧은 시간에 여러 번 차단된 기록을 찾습니다.", "needs": ["방화벽·연결 기록(조치 열)"],
     "normal_note": "잘못 설정된 프로그램이나 만료된 정책 때문에 반복 차단될 수 있습니다.",
     "defaults": {"sources": ["fw"], "conditions": [{"field": "enforcement_action", "op": "is", "value": "차단"}], "group_by": "src_ip",
                  "measure": "records", "threshold": 100, "window_seconds": 60}},
    {"id": "fw_port_sweep", "name": "한 출발지가 여러 포트에 접촉 (방화벽)", "executable": True, "kind": "threshold",
     "purpose": "한 출발지가 짧은 시간에 서로 다른 목적지 포트 여러 개에 접촉한 기록을 찾습니다.", "needs": ["방화벽·연결 기록"],
     "normal_note": "자산 점검·취약점 진단·모니터링 서버의 정기 작업일 수 있습니다.",
     "defaults": {"sources": ["fw"], "group_by": "src_ip", "measure": "distinct_dst_port", "threshold": 20, "window_seconds": 600}},
    {"id": "ips_alert_burst", "name": "같은 출발지의 IPS 경보 반복", "executable": True, "kind": "threshold",
     "purpose": "한 출발지에서 IPS 경보가 짧은 시간에 여러 번 난 기록을 찾습니다.", "needs": ["IPS 경보 기록"],
     "normal_note": "취약점 진단 장비나 오탐이 잦은 서명일 수 있습니다. 경보는 공격 성공을 뜻하지 않습니다.",
     "defaults": {"sources": ["ips"], "group_by": "src_ip", "measure": "records", "threshold": 10, "window_seconds": 600}},
    {"id": "alert_many_names", "name": "한 출발지에서 여러 종류의 공격명 (IPS·WAF)", "executable": True, "kind": "threshold",
     "purpose": "한 출발지에서 서로 다른 공격명이 여러 개 관측된 기록을 찾습니다.", "needs": ["IPS 또는 WAF 경보 기록"],
     "normal_note": "취약점 진단·모의 해킹 일정일 수 있습니다.",
     "defaults": {"sources": ["ips", "waf"], "group_by": "src_ip", "measure": "distinct_alert", "threshold": 3, "window_seconds": 3600}},
    {"id": "waf_block_burst", "name": "WAF 차단이 몰린 출발지", "executable": True, "kind": "threshold",
     "purpose": "한 출발지의 요청이 WAF에서 짧은 시간에 여러 번 차단된 기록을 찾습니다.", "needs": ["WAF 기록(조치 열)"],
     "normal_note": "정상 요청을 막는 룰(오탐)일 수 있습니다.",
     "defaults": {"sources": ["waf"], "conditions": [{"field": "enforcement_action", "op": "is", "value": "차단"}], "group_by": "src_ip",
                  "measure": "records", "threshold": 20, "window_seconds": 600}},
    {"id": "web_error_burst", "name": "오류 응답이 몰린 출발지 (웹)", "executable": True, "kind": "threshold",
     "purpose": "한 출발지의 요청에 4xx·5xx 응답이 짧은 시간에 많이 난 기록을 찾습니다.", "needs": ["HTTP 요청 기록(응답 코드)"],
     "normal_note": "끊어진 링크·만료된 세션·장애 시간대일 수 있습니다.",
     "defaults": {"sources": ["web"], "conditions": [{"field": "status_code", "op": "gte", "value": "400"}], "group_by": "src_ip",
                  "measure": "records", "threshold": 30, "window_seconds": 300}},
    {"id": "web_large_response", "name": "응답 전송량이 큰 출발지 (웹)", "executable": True, "kind": "threshold",
     "purpose": "한 출발지가 한 서비스에서 정한 시간 안에 받은 응답의 양이 기준을 넘는 경우를 찾습니다.", "needs": ["HTTP 요청 기록(바이트 열)"],
     "normal_note": "보고서·첨부 파일 내려받기 업무일 수 있습니다.",
     "defaults": {"sources": ["web"], "group_by": "src_ip", "measure": "bytes_out", "threshold": 100, "byte_unit": "MB", "window_seconds": 600}},
    {"id": "ddos_repeat", "name": "같은 대상의 DDoS 기록 반복", "executable": True, "kind": "threshold",
     "purpose": "같은 대상에 DDoS 관측 기록이 정한 시간 안에 여러 번 남은 경우를 찾습니다.", "needs": ["DDoS 구간 기록"],
     "normal_note": "행사·공지로 접속이 몰린 시간대일 수 있습니다. 집계 기록이며 공격자를 가리키지 않습니다.",
     "defaults": {"sources": ["ddos"], "group_by": "dst_ip", "measure": "records", "threshold": 2, "window_seconds": 3600}},
    {"id": "auth_fail_then_success", "name": "반복 인증 실패 뒤 성공과 이후 활동", "executable": False,
     "purpose": "인증 실패가 이어진 뒤 성공하고 조회가 이어지는 흐름.", "needs": ["인증 결과를 알려 주는 애플리케이션 기록", "업무 의미와 결과 확인 기준"],
     "reason": "인증 결과는 '업무 흐름' 분석이 등록된 결과 확인 기준으로 판정합니다(헌팅의 '인증 실패 뒤 조회' 활동). 실패 횟수 조건을 거는 전용 실행기는 아직 없습니다."},
    {"id": "waf_action_vs_backend", "name": "WAF 차단·허용과 백엔드 결과의 구분", "executable": False,
     "purpose": "WAF 조치와 같은 요청의 서버 응답을 나란히 놓습니다.", "needs": ["WAF 기록", "요청 ID가 확인된 NDR 기록"],
     "reason": "'업무 흐름' 분석이 같은 요청(요청 ID 일치)과 관련 후보를 나눠 보여 줍니다. 조건을 고쳐 쓰는 전용 실행기는 아직 없습니다."},
    {"id": "new_destination_time", "name": "새 목적지·새 시간대·송신량 변화", "executable": False,
     "purpose": "이전에 없던 목적지나 시간대, 늘어난 송신.", "needs": ["FW·연결 기록(기준 기간 포함)"],
     "reason": "기본 분석의 시간 변화·대량 전송 탐지가 담당합니다. 시나리오로 조건을 바꾸는 실행기는 아직 없습니다."},
    {"id": "normal_batch", "name": "정기 백업·점검·배치의 정상 반례", "executable": False,
     "purpose": "매일 같은 시각에 같은 대상으로 반복되는 정상 작업을 반례로 등록.", "needs": ["FW·연결 기록", "자산·업무의 정기 작업 정보"],
     "reason": "정기 작업은 자산·업무에 등록해 활동의 '정상 가능성'으로 비교합니다. 반례 전용 실행기는 아직 없습니다."},
]
KIND_NEEDS = {"then_variation": ["web"], "sequence": ["web"], "periodic_external": ["connection", "firewall", "zeek_conn", "web"],
              "spread_internal": ["connection", "firewall", "zeek_conn"], "alert_then_traffic": ["waf", "ips"],
              "ddos_window_access": ["ddos"]}


# The ways a scenario can look at data, in the analyst's words. A scenario written from scratch picks one of these.
KINDS = [
    {"kind": "threshold", "name": "기준을 넘는 통신·기록 (건수·전송량·서로 다른 값)",
     "hint": "방화벽·웹·WAF·IPS·DDoS 기록을 조건으로 고르고, 출발지·목적지 등으로 묶어, 정한 시간 안에 건수·전송량·서로 다른 값의 수가 기준을 넘는 경우를 찾습니다.",
     "needs": ["고른 자료 종류의 기록"]},
    {"kind": "sequence", "name": "요청이 이 순서로 이어짐", "hint": "웹 요청 2~6단계가 정한 순서대로 이어진 흐름을 찾습니다.", "needs": ["HTTP 요청 기록"]},
    {"kind": "then_variation", "name": "앞 요청 뒤 대상을 바꿔 가며 반복", "hint": "첫 요청 뒤 둘째 요청을 여러 대상(파라미터 값)으로 반복한 흐름을 찾습니다.", "needs": ["HTTP 요청 기록(경로·쿼리)"]},
    {"kind": "periodic_external", "name": "같은 곳으로 반복 통신", "hint": "같은 출발지·목적지 사이에 일정한 간격으로 반복된 통신을 찾습니다.", "needs": ["FW·연결 또는 NDR 기록"]},
    {"kind": "spread_internal", "name": "여러 대상·포트 접촉", "hint": "한 출발지가 짧은 시간에 여러 대상이나 포트에 접촉한 기록을 찾습니다.", "needs": ["FW·연결 기록"]},
    {"kind": "alert_then_traffic", "name": "보안장비 경보 뒤 통신", "hint": "IPS·WAF 경보 뒤 같은 주소 사이에 통신이 이어졌는지 봅니다.", "needs": ["IPS 또는 WAF 경보", "FW·연결 또는 NDR 기록"]},
    {"kind": "ddos_window_access", "name": "DDoS 시간대의 접속", "hint": "DDoS 관측 구간 안의 서비스 요청과 오류 응답을 봅니다.", "needs": ["DDoS 구간 기록", "HTTP 요청 기록"]},
]


def templates() -> list[dict]:
    return TEMPLATES


def describe(c: dict) -> str:
    """The definition in a sentence: the same text the analyst confirms in the wizard and the run reports."""
    who = "같은 세션(확인된 세션 쿠키)" if c.get("entity") == "session" else "같은 출발지 IP(같은 사용자라는 근거는 아님)"
    window = _span(c.get("window_seconds") or 0)
    steps = c.get("steps") or []
    if c["kind"] == "threshold":
        return _describe_threshold(c)
    if c["kind"] == "then_variation":
        unit = f"서로 다른 {c.get('count_param')} 값" if c.get("count_unit") == "distinct_param" else "중복을 뺀 요청"
        return (f"{who}에서 '{steps[0]['label']}'({_req(steps[0])}) 뒤 {window} 안에 '{steps[1]['label']}'({_req(steps[1])})을(를) "
                f"{unit} {c['min_count']}개 이상 요청한 흐름")
    if c["kind"] == "sequence":
        return f"{who}에서 " + " → ".join(f"'{s['label']}'({_req(s)})" for s in steps) + f" 순서가 {window} 안에 이어진 흐름"
    return {"periodic_external": f"같은 출발지·목적지 사이에 일정한 간격으로 {c['min_count']}회 이상 반복된 통신",
            "spread_internal": f"한 출발지가 {window} 안에 대상 또는 포트 {c['min_count']}개 이상에 접촉한 기록",
            "alert_then_traffic": f"보안장비 경보 뒤 {window} 안에 같은 출발지·목적지 사이에 이어진 통신 기록",
            "ddos_window_access": "DDoS 관측 구간 안의 같은 서비스 요청과 오류 응답"}[c["kind"]]


def _req(step: dict) -> str:
    extra = f", '{step['contains']}' 포함" if step.get("contains") else ""
    return f"{step.get('method') or '모든 메서드'} {step['path']}{'…' if step.get('match') == 'prefix' else ''}{extra}"


def _span(seconds: int) -> str:
    return f"{seconds // 86400}일" if seconds % 86400 == 0 and seconds >= 86400 else f"{seconds // 3600}시간" if seconds % 3600 == 0 and seconds >= 3600 \
        else f"{seconds // 60}분" if seconds % 60 == 0 and seconds >= 60 else f"{seconds}초"


def _matcher(step: dict, host: str) -> Activity:
    return Activity({"id": "s", "version": 0, "org_unit_id": None,
                     "content": {"host": host, "method": step.get("method") or "", "path": step["path"],
                                 "match": step.get("match") or "exact", "meaning": step["label"]}})


def _sources(es, inv_id: str, time, names: list[str]) -> int:
    return es.count(inv_id, [Filter(field="data_source", op="in", value=names)], time)


def execute(s, inv, es, time, c: dict, *, limit: int = MAX_MATCHES) -> dict:
    """Run one definition on the whole selected data. Returns status, matches, near misses and what was examined."""
    base = {"description": describe(c), "unit": _unit(c), "matches": [], "near": [], "examined": {}, "missing": [], "notes": []}
    if c["kind"] == "threshold":
        return {**base, **_threshold(es, inv.id, time, c, limit)}
    have = _sources(es, inv.id, time, KIND_NEEDS[c["kind"]])
    if not have:
        return {**base, "status": "insufficient_data", "missing": [_need_text(c["kind"])]}
    if c["kind"] in ("then_variation", "sequence"):
        return {**base, **_request_flow(s, inv, es, time, c, limit)}
    if c["kind"] in ("periodic_external", "spread_internal"):
        return {**base, **_bundle(inv, time, c)}
    if c["kind"] == "alert_then_traffic":
        return {**base, **_alert_then_traffic(es, inv.id, time, c, limit)}
    return {**base, **_ddos_window(s, inv)}


def _unit(c: dict) -> str:
    if c["kind"] == "threshold":
        return MEASURE_WORD[c["measure"]] + (f"({c.get('byte_unit') or 'MB'})" if c["measure"].startswith("bytes") else "")
    if c["kind"] == "then_variation":
        return f"서로 다른 {c.get('count_param')} 값의 수" if c.get("count_unit") == "distinct_param" else "중복 전달을 뺀 요청 수"
    return {"sequence": "순서가 완성된 횟수", "periodic_external": "출발지·목적지 쌍의 접속 횟수", "spread_internal": "서로 다른 대상·포트 수",
            "alert_then_traffic": "경보 뒤 통신 기록 수", "ddos_window_access": "구간 안 HTTP 요청 수"}[c["kind"]]


def _need_text(kind: str) -> str:
    return {"threshold": "고른 자료 종류의 기록", "then_variation": "HTTP 요청 기록", "sequence": "HTTP 요청 기록", "periodic_external": "FW·연결 또는 NDR 기록",
            "spread_internal": "FW·연결 기록", "alert_then_traffic": "IPS 또는 WAF 경보 기록", "ddos_window_access": "DDoS 구간 기록"}[kind]


def _request_flow(s, inv, es, time, c: dict, limit: int) -> dict:
    from saw.flows.service import ordered

    host = c.get("host") or ""
    matchers = [_matcher(st, host) for st in c["steps"]]
    link = None
    if c["entity"] == "session":
        items = [i for i in knowledge.snapshot(s, inv.org_unit_id) if i["kind"] == "link" and (not host or norm_host(i["content"]["host"]) == host)]
        link = {norm_host(i["content"]["host"]): i["content"].get("session_cookie") for i in items if i["content"].get("session_cookie")}
        if not link:
            return {"status": "insufficient_data", "missing": ["세션 식별 쿠키(자산·업무의 연결 기준). 출발지 IP 기준으로 바꾸면 후보로 볼 수 있습니다."]}
    filters = [Filter(field="data_source", value="web"), Filter(field="uri", op="exists")]
    if host:
        filters.append(Filter(field="hostname", value=host))
    window, need, variation = c["window_seconds"], c["min_count"], c["kind"] == "then_variation"
    state: dict[tuple, dict] = {}
    matches, near_reverse, near_window, best_below = [], [], [], {}
    read = no_entity = dup = 0
    last = None
    for e in ordered(es, inv.id, filters, time):
        read += 1
        t = epoch(e.get("timestamp"))
        if t is None:
            continue
        sig = (t, e.get("src_ip"), e.get("uri"), ext(e, "uuid"))
        if sig == last:
            dup += 1  # the same record delivered twice is one request
            continue
        last = sig
        ehost = norm_host(e.get("hostname"))
        path, params = split_uri(e.get("uri"))
        method = (e.get("method") or "").upper()
        uri = str(e.get("uri") or "")
        hits = [i for i, m in enumerate(matchers) if (not host or ehost == host) and m.matches(method, path, params)
                and (c["steps"][i].get("contains") or "") in uri]
        if not hits:
            continue
        if c["entity"] == "session":
            cookie = link.get(ehost)
            ref = next((str(x).partition("=")[2] for x in (ext(e, "req_cookie_refs") or []) if cookie and str(x).startswith(cookie + "=")), None)
            if not ref:
                no_entity += 1
                continue
            key = (ehost, "세션 " + ref[:8])
        else:
            if not e.get("src_ip"):
                no_entity += 1
                continue
            key = (ehost, e["src_ip"])
        st = state.setdefault(key, {"anchor": None, "pos": 0, "first": None, "ids": [], "values": {}, "count": 0, "done": False, "early": None})
        # A request that fits several steps counts as the step this actor is waiting for; otherwise as the first step.
        expected = 1 if variation else st["pos"]
        hit = expected if st["anchor"] is not None and expected in hits else (0 if 0 in hits else hits[0])
        if hit == 0:
            st.update(anchor=t, pos=1, first=e.get("timestamp"), ids=[e.get("event_id")], values={}, count=0, done=False)
            continue
        if st["anchor"] is None:
            if st["early"] is None:
                st["early"] = {"entity": key[1], "host": key[0], "time": e.get("timestamp"), "event_ids": [e.get("event_id")],
                               "text": f"'{c['steps'][hit]['label']}'이(가) '{c['steps'][0]['label']}'보다 먼저 관측됨(순서가 반대이거나 앞 단계가 자료 밖)"}
                if len(near_reverse) < 20:
                    near_reverse.append(st["early"])
            continue
        if t - st["anchor"] > window:
            if not st["done"] and len(near_window) < 20:
                near_window.append({"entity": key[1], "host": key[0], "time": e.get("timestamp"), "event_ids": [e.get("event_id")],
                                    "text": f"'{c['steps'][hit]['label']}'이(가) 앞 단계 {int(t - st['anchor'])}초 뒤에 관측됨(시간창 {window}초 밖)"})
            continue
        if variation:
            if hit != 1:
                continue
            value = params.get(c.get("count_param") or "", "") if c["count_unit"] == "distinct_param" else (ext(e, "uuid") or e.get("event_id"))
            if value in ("", None):
                continue
            if value not in st["values"]:
                st["values"][value] = e.get("event_id")
            count = len(st["values"])
            if count > best_below.get(key, 0):
                best_below[key] = count
            if count >= need:
                rec = {"entity": key[1], "host": key[0], "start": st["first"], "end": e.get("timestamp"), "count": count,
                       "event_ids": [st["ids"][0], *list(st["values"].values())[:60]],
                       "steps": [{"label": c["steps"][0]["label"], "time": st["first"]},
                                 {"label": c["steps"][1]["label"], "time": e.get("timestamp"), "count": count}]}
                if st["done"]:
                    matches[st["done"] - 1] = rec  # the same flow kept growing: one match, latest numbers
                elif len(matches) < limit:
                    matches.append(rec)
                    st["done"] = len(matches)
        elif hit == st["pos"]:
            st["pos"] += 1
            st["ids"].append(e.get("event_id"))
            if st["pos"] == len(matchers) and len(matches) < limit:
                matches.append({"entity": key[1], "host": key[0], "start": st["first"], "end": e.get("timestamp"), "count": 1,
                                "event_ids": st["ids"][:60], "steps": [{"label": x["label"]} for x in c["steps"]]})
                st.update(anchor=None, pos=0)
    below = sorted(((n, k) for k, n in best_below.items() if n < need), reverse=True)[:5]
    near = ([{"kind": "below", "text": f"{k[1]}: 조건 미달 — {_unit(c)} {n} (기준 {need})", "entity": k[1]} for n, k in below]
            + [{"kind": "reversed", **n} for n in near_reverse[:5]] + [{"kind": "outside_window", **n} for n in near_window[:5]])
    notes = []
    if c["entity"] == "src_ip":
        notes.append("같은 출발지 IP로 묶었습니다. NAT·프록시 뒤 여러 사용자가 한 흐름으로 보일 수 있습니다.")
    if dup:
        notes.append(f"같은 기록이 두 번 전달된 {dup}건은 한 요청으로 셌습니다.")
    if no_entity:
        notes.append(f"묶는 기준 값이 없는 요청 {no_entity}건은 넣지 않았습니다.")
    return {"status": "found" if matches else "no_match", "matches": matches, "near": near, "notes": notes,
            "examined": {"records_read": read, "actors": len(state), "shown": len(matches), "limit": limit}}


def _bundle(inv, time, c: dict) -> dict:
    from saw.core.application import question_bundles as qb

    bundle = "periodic" if c["kind"] == "periodic_external" else "spread"
    defaults = qb.defaults(bundle)
    values = dict(defaults)
    for name, value in (("min_count", c["min_count"]), ("min_events", c["min_count"]), ("min_targets", c["min_count"]),
                        ("min_ports", c["min_count"]), ("window_seconds", c["window_seconds"])):
        if name in values:
            values[name] = value
    try:
        res = qb.run_one(inv, bundle, values, time=time)
    except ValueError:
        res = qb.run_one(inv, bundle, None, time=time)
    status = {"looked_none": "no_match"}.get(res["status"], res["status"])
    matches = [{"entity": ", ".join(str(x) for x in (i.get("entities") or [])[:2]), "host": "", "start": (i.get("time") or {}).get("start"),
                "end": (i.get("time") or {}).get("end"), "count": i.get("records"), "title": i["title"], "filters": i.get("filters") or [],
                "normal": i.get("normal_possibilities") or [], "unknown": i.get("unknown") or []} for i in res.get("items") or []]
    return {"status": "partial" if status == "found" and res.get("completeness") == "partial" else status, "matches": matches[:MAX_MATCHES],
            "missing": res.get("missing") or [], "notes": [res.get("description") or "", *(res.get("partial_reasons") or [])],
            "examined": {**(res.get("examined") or {}), "records": res.get("records")}}


def _alert_then_traffic(es, inv_id: str, time, c: dict, limit: int) -> dict:
    alerts = list(es.iterate(inv_id, [Filter(field="data_source", op="in", value=["waf", "ips"])], time, batch=5000))
    conn = _sources(es, inv_id, time, ["connection", "firewall", "zeek_conn", "web"])
    if not conn:
        return {"status": "insufficient_data", "missing": ["FW·연결 또는 NDR 기록"]}
    matches, none_after = [], 0
    for a in alerts[:5000]:
        t = epoch(a.get("timestamp"))
        if t is None or not a.get("src_ip") or not a.get("dst_ip"):
            continue
        from saw.flows.engine import _iso

        window = TimeRange(start=_iso(t), end=_iso(t + c["window_seconds"]))
        filters = [Filter(field="data_source", op="in", value=["connection", "firewall", "zeek_conn", "web"]),
                   Filter(field="src_ip", value=a["src_ip"]), Filter(field="dst_ip", value=a["dst_ip"])]
        n = es.count(inv_id, filters, window)
        if n < c["min_count"]:
            none_after += 1
            continue
        allowed = es.count(inv_id, [*filters, Filter(field="enforcement_action", value="allowed")], window)
        blocked = es.count(inv_id, [*filters, Filter(field="enforcement_action", value="blocked")], window)
        if len(matches) < limit:
            matches.append({"entity": a["src_ip"], "host": a.get("hostname") or a["dst_ip"], "start": a.get("timestamp"), "end": window.end,
                            "count": n, "event_ids": [a.get("event_id")], "filters": [f.model_dump() for f in filters], "time": window.model_dump(),
                            "title": f"{str(a.get('data_source')).upper()} '{a.get('alert_name')}' 경보(장비 조치 {ext(a, 'action') or '미기록'}) 뒤 "
                                     f"{a['src_ip']} → {a['dst_ip']} 통신 {n}건(허용 {allowed} · 차단 {blocked})"})
    return {"status": "found" if matches else "no_match", "matches": matches,
            "notes": ["경보 뒤 통신 기록은 '같은 주소 사이에 통신이 있었다'는 관측입니다. 공격 성공이나 같은 요청이라는 근거가 아닙니다.",
                      f"뒤이은 통신이 기준에 못 미친 경보 {none_after}건"] if alerts else [],
            "examined": {"alerts": len(alerts), "alerts_checked": min(len(alerts), 5000), "shown": len(matches)}}


def _ddos_window(s, inv) -> dict:
    from saw.flows.models import FlowRun

    row = s.scalar(select(FlowRun).where(FlowRun.investigation_id == inv.id).order_by(FlowRun.version.desc()))
    intervals = ((row.result or {}).get("ddos") or []) if row else []
    if not intervals:
        return {"status": "insufficient_data", "missing": ["DDoS 구간 기록(업무 흐름 분석이 읽은 구간이 없습니다)"]}
    matches = [{"entity": d.get("host") or d.get("target_ip"), "host": d.get("host") or "", "start": d.get("start"), "end": d.get("end_raw"),
                "count": d.get("requests"), "event_ids": [d.get("event_id")],
                "title": f"{d.get('vector')} {d.get('value')} {d.get('unit')} 구간({d.get('start')} ~ {d.get('end_raw')}) 안의 HTTP 요청 "
                         f"{d.get('requests')}건, 5xx {d.get('server_errors')}건 · 탐지 {d.get('detection_state')} · 완화 {d.get('mitigation_state')}"}
               for d in intervals]
    return {"status": "found", "matches": matches, "examined": {"intervals": len(intervals)},
            "notes": ["집계 구간입니다. 구간 안의 요청을 DDoS와 같은 공격자의 행위로 묶지 않습니다. 5xx 수는 HTTP 기록에서 센 값입니다."]}


SOURCE_SETS = {"fw": ["connection", "firewall", "zeek_conn"], "web": ["web"], "waf": ["waf"], "ips": ["ips"], "ddos": ["ddos"], "app": ["app"]}
SOURCE_WORD = {"fw": "방화벽·연결", "web": "웹(NDR HTTP)", "waf": "WAF", "ips": "IPS", "ddos": "DDoS", "app": "애플리케이션"}
FIELD_WORD = {"enforcement_action": "조치", "src_ip": "출발지 IP", "dst_ip": "목적지 IP", "dst_port": "목적지 포트", "protocol": "프로토콜",
              "hostname": "서비스(호스트)", "method": "메서드", "uri": "요청 경로·쿼리", "status_code": "응답 코드", "alert_name": "공격명",
              "severity": "심각도"}
OP_WORD = {"is": "=", "is_not": "≠", "contains": "에 포함:", "gte": "≥", "lte": "≤"}
GROUP_WORD = {"src_ip": "같은 출발지 IP", "dst_ip": "같은 목적지 IP", "pair": "같은 출발지 → 목적지", "dst_service": "같은 목적지 IP·포트",
              "hostname": "같은 서비스(호스트)", "alert_name": "같은 공격명", "all": "전체(묶지 않음)"}
GROUP_FIELDS = {"src_ip": ["src_ip"], "dst_ip": ["dst_ip"], "pair": ["src_ip", "dst_ip"], "dst_service": ["dst_ip", "dst_port"],
                "hostname": ["hostname"], "alert_name": ["alert_name"], "all": []}
MEASURE_WORD = {"records": "기록 수", "bytes_total": "전송량 합계(보낸 양+받은 양)", "bytes_out": "보낸 양(bytes_out)", "bytes_in": "받은 양(bytes_in)",
                "distinct_dst_ip": "서로 다른 목적지 IP 수", "distinct_dst_port": "서로 다른 목적지 포트 수", "distinct_src_ip": "서로 다른 출발지 IP 수",
                "distinct_alert": "서로 다른 공격명 수", "distinct_path": "서로 다른 요청 경로 수"}
DISTINCT_FIELD = {"distinct_dst_ip": "dst_ip", "distinct_dst_port": "dst_port", "distinct_src_ip": "src_ip", "distinct_alert": "alert_name"}
BYTE_UNIT = {"KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}
ACTION_WORD = {"허용": "allowed", "allow": "allowed", "accept": "allowed", "permit": "allowed", "차단": "blocked", "block": "blocked",
               "deny": "blocked", "drop": "blocked", "denied": "blocked"}
# What the wizard offers for a threshold scenario, in the analyst's words.
THRESHOLD_OPTIONS = {
    "sources": [{"id": k, "name": v} for k, v in SOURCE_WORD.items()],
    "fields": [{"id": k, "name": v} for k, v in FIELD_WORD.items()],
    "ops": [{"id": "is", "name": "같음(쉼표로 여러 값, IP는 대역 10.0.0.0/8 가능)"}, {"id": "is_not", "name": "다름"}, {"id": "contains", "name": "이 글자 포함"},
            {"id": "gte", "name": "이상(숫자)"}, {"id": "lte", "name": "이하(숫자)"}],
    "group_by": [{"id": k, "name": v} for k, v in GROUP_WORD.items()],
    "measures": [{"id": k, "name": v, "bytes": k.startswith("bytes")} for k, v in MEASURE_WORD.items()],
    "byte_units": list(BYTE_UNIT),
}


def _threshold_text(c: dict) -> str:
    amount = f"{c['threshold']:g}{c.get('byte_unit') or 'MB'}" if c["measure"].startswith("bytes") else f"{int(c['threshold'])}"
    return amount


def _cond_text(cond: dict) -> str:
    return f"{FIELD_WORD[cond['field']]} {OP_WORD[cond['op']]} {cond['value']}"


def _describe_threshold(c: dict) -> str:
    src = "·".join(SOURCE_WORD[x] for x in c["sources"])
    conds = [_cond_text(x) for x in c.get("conditions") or []]
    if c.get("host"):
        conds.insert(0, f"서비스 = {c['host']}")
    which = f" 중 [{', '.join(conds)}]인 것" if conds else ""
    return (f"{src} 기록{which}을 {GROUP_WORD[c['group_by']]}(으)로 묶어, {_span(c['window_seconds'])} 안에 "
            f"{MEASURE_WORD[c['measure']]}이(가) {_threshold_text(c)} 이상인 경우")


def _cond_ok(e: dict, cond: dict) -> bool:
    import ipaddress

    v, want = e.get(cond["field"]), cond["value"].strip()
    if v in (None, ""):
        return cond["op"] == "is_not"
    text = str(v).strip().lower()
    if cond["op"] in ("gte", "lte"):
        try:
            a, b = float(text), float(want)
        except ValueError:
            return False
        return a >= b if cond["op"] == "gte" else a <= b
    if cond["op"] == "contains":
        return want.lower() in text
    hit = False
    for one in (x.strip().lower() for x in want.split(",") if x.strip()):
        if cond["field"] == "enforcement_action":
            one = ACTION_WORD.get(one, one)
        if cond["field"] in ("src_ip", "dst_ip") and "/" in one:
            try:
                hit = ipaddress.ip_address(text) in ipaddress.ip_network(one, strict=False)
            except ValueError:
                hit = False
        else:
            hit = text == one
        if hit:
            break
    return hit if cond["op"] == "is" else not hit


def _threshold(es, inv_id: str, time, c: dict, limit: int) -> dict:
    """Records of the chosen sources, grouped, measured over a moving time window, against one threshold.

    A group that stays over the threshold is one match that keeps growing; it ends when the window falls below.
    """
    from collections import Counter, deque

    from saw.flows.service import ordered

    names = [n for x in c["sources"] for n in SOURCE_SETS[x]]
    missing = [SOURCE_WORD[x] + " 기록" for x in c["sources"] if not _sources(es, inv_id, time, SOURCE_SETS[x])]
    if len(missing) == len(c["sources"]):
        return {"status": "insufficient_data", "missing": missing}
    filters = [Filter(field="data_source", op="in", value=names)]
    if c.get("host"):
        filters.append(Filter(field="hostname", value=c["host"]))
    measure, window, conds = c["measure"], c["window_seconds"], c.get("conditions") or []
    scale = BYTE_UNIT[c.get("byte_unit") or "MB"] if measure.startswith("bytes") else 1
    need = c["threshold"] * scale
    fields = GROUP_FIELDS[c["group_by"]]
    distinct = measure.startswith("distinct")
    groups: dict[tuple, dict] = {}
    matches, best = [], {}
    read = kept = no_group = no_value = no_time = over = 0
    for e in ordered(es, inv_id, filters, time):
        read += 1
        if not all(_cond_ok(e, x) for x in conds):
            continue
        t = epoch(e.get("timestamp"))
        if t is None:
            no_time += 1
            continue
        key = tuple(e.get(f) for f in fields)
        if any(k in (None, "") for k in key):
            no_group += 1
            continue
        if measure == "records":
            value = 1
        elif measure.startswith("bytes"):
            parts = [e.get(f) for f in (("bytes_in", "bytes_out") if measure == "bytes_total" else (measure,))]
            nums = [float(x) for x in parts if isinstance(x, (int, float))]
            if not nums:
                no_value += 1
                continue
            value = sum(nums)
        else:
            value = split_uri(e.get("uri"))[0] if measure == "distinct_path" else e.get(DISTINCT_FIELD[measure])
            if value in (None, ""):
                no_value += 1
                continue
        kept += 1
        g = groups.setdefault(key, {"q": deque(), "sum": 0.0, "seen": Counter(), "open": None})
        g["q"].append((t, value, e.get("event_id"), e.get("timestamp")))
        if distinct:
            g["seen"][value] += 1
        else:
            g["sum"] += value
        while g["q"] and t - g["q"][0][0] > window:
            _, old, _, _ = g["q"].popleft()
            if distinct:
                g["seen"][old] -= 1
                if not g["seen"][old]:
                    del g["seen"][old]
            else:
                g["sum"] -= old
        now = len(g["seen"]) if distinct else g["sum"]
        if now > best.get(key, 0):
            best[key] = now
        if now < need:
            g["open"] = None
            continue
        m = g["open"]
        if m is None:
            over += 1
            if len(matches) >= limit:
                continue
            m = g["open"] = {"entity": " → ".join(str(k) for k in key) if c["group_by"] == "pair" else ":".join(str(k) for k in key) or "전체",
                             "host": "", "start": g["q"][0][3], "end": e.get("timestamp"), "peak": now, "records": len(g["q"]),
                             "event_ids": [x[2] for x in g["q"] if x[2]][:60], "key": key}
            matches.append(m)
        else:
            m["end"], m["peak"], m["records"] = e.get("timestamp"), max(m["peak"], now), m["records"] + 1
            if len(m["event_ids"]) < 60 and e.get("event_id"):
                m["event_ids"].append(e.get("event_id"))
    if measure.startswith("bytes") and not kept and no_value:
        return {"status": "insufficient_data", "missing": ["전송량(바이트) 열 — 고른 자료의 기록에 값이 없습니다."],
                "examined": {"records_read": read}}
    show = (lambda x: round(x / scale, 2)) if scale != 1 else (lambda x: int(x))
    unit = (c.get("byte_unit") or "MB") if scale != 1 else ""
    out = []
    for m in matches:
        key = m.pop("key")
        m["count"] = show(m.pop("peak"))
        m["filters"] = [f.model_dump() for f in filters] + [{"field": f, "op": "is", "value": k} for f, k in zip(fields, key)]
        m["time"] = {"start": m["start"], "end": m["end"]}
        m["title"] = (f"{m['entity']}: {_span(window)} 안에 {MEASURE_WORD[measure]} {m['count']:,}{unit} (기준 {_threshold_text(c)}) · "
                      f"기준을 넘은 동안의 기록 {m['records']:,}건")
        out.append(m)
    done = {m["entity"] for m in out}
    below = sorted(((n, k) for k, n in best.items() if n < need), key=lambda x: -x[0])[:5]
    near = [{"kind": "below", "entity": " → ".join(str(x) for x in k) or "전체",
             "text": f"{' → '.join(str(x) for x in k) or '전체'}: 조건 미달 — 가장 컸던 {MEASURE_WORD[measure]} {show(n):,}{unit} (기준 {_threshold_text(c)})"}
            for n, k in below if (" → ".join(str(x) for x in k) or "전체") not in done]
    notes = ["시간 범위는 움직이는 구간입니다: 각 기록에서 거슬러 그 시간만큼의 기록을 더합니다. 기준을 계속 넘는 동안은 한 건으로 묶습니다."]
    if measure.startswith("bytes"):
        notes.append("전송량은 기록에 적힌 바이트 값의 합입니다. 보낸 양·받은 양의 방향은 장비가 기록한 열의 뜻을 따르며, 세션이 끝날 때 한 번에 기록하는 장비는 긴 통신이 한 시점에 몰려 보일 수 있습니다.")
    if c["group_by"] in ("src_ip", "pair"):
        notes.append("출발지 IP로 묶었습니다. NAT·프록시 뒤 여러 사용자가 한 대상으로 보일 수 있습니다.")
    if missing:
        notes.append("고른 자료 중 이 헌팅에 없는 것: " + ", ".join(missing))
    for n, text in ((no_group, "묶는 기준 값이 없는 기록"), (no_value, "세는 값이 없는 기록"), (no_time, "시각이 없는 기록")):
        if n:
            notes.append(f"{text} {n:,}건은 넣지 않았습니다.")
    if over > len(out):
        notes.append(f"기준을 넘은 경우는 모두 {over:,}번이며 앞의 {len(out):,}개만 보여 줍니다.")
    return {"status": "found" if out else "no_match", "matches": out, "near": near, "notes": notes,
            "examined": {"records_read": read, "records_matching_conditions": kept, "groups": len(groups), "shown": len(out), "limit": limit,
                         "found_total": over}}


def preview(s, p, inv_id: str, raw: dict) -> dict:
    """Try a definition on this investigation's data without saving it."""
    inv = require(s, p, "investigation.read", inv_id)
    # A trial needs no name yet: the analyst names the scenario when saving it.
    raw = {**raw, "name": str(raw.get("name") or "").strip() or "이름 없음"}
    content = knowledge.ScenarioContent.model_validate(raw).model_dump()
    es = container.get().events
    out = execute(s, inv, es, None, content, limit=50)
    return {**out, "scope": {"investigation": inv.display_id, "range": "이 헌팅의 전체 자료", "selected_records": es.count(inv_id)},
            "status_label": STATUS_KO[out["status"]]}


STATUS_KO = {"found": "조건을 만족한 흐름 있음", "no_match": "조건 일치 없음", "insufficient_data": "자료 부족", "partial": "일부 처리",
             "failed": "실패", "unsupported": "미지원"}


def run_active(s, inv, es, time) -> tuple[list[dict], list[dict]]:
    """Active scenarios that apply to this affiliate, as hunt methods and activities."""
    methods, activities = [], []
    for item in knowledge.snapshot(s, inv.org_unit_id):
        if item["kind"] != "scenario" or item["content"].get("state") != "active":
            continue
        c = item["content"]
        try:
            out = execute(s, inv, es, time, c)
        except Exception as exc:  # noqa: BLE001
            methods.append({"id": f"scenario.{item['id']}", "name": f"시나리오: {c['name']}", "status": "failed", "found": 0, "shown": 0,
                            "error": type(exc).__name__, "needs": [], "partial_reasons": [], "scenario_version": item["version"]})
            continue
        methods.append({"id": f"scenario.{item['id']}", "name": f"시나리오: {c['name']} (v{item['version']})", "status": out["status"],
                        "found": len(out["matches"]), "shown": len(out["matches"]), "needs": out.get("missing") or [],
                        "condition": out["description"], "examined": out.get("examined") or {}, "partial_reasons": [],
                        "scenario_version": item["version"]})
        for m in out["matches"]:
            title = m.get("title") or f"{m['entity']}: {out['description']} — {out['unit']} {m.get('count')}"
            activities.append(_activity(
                f"scenario.{item['id']}", title, observed=[f"{m.get('start')} ~ {m.get('end')} · {out['unit']} {m.get('count')}", *(out.get("notes") or [])[:2]],
                why=[f"시나리오 '{c['name']}' v{item['version']}의 조건을 만족했습니다: {out['description']}"],
                normal=[c.get("normal_note") or "이 시나리오에 정상 가능성이 적혀 있지 않습니다.", *(m.get("normal") or [])][:4],
                unknown=m.get("unknown") or ["요청이 실제로 처리됐는지와 이 대상의 업무·권한"], time={"start": m.get("start"), "end": m.get("end")},
                entities=[m["entity"], m.get("host") or ""],
                evidence={"event_ids": [x for x in m.get("event_ids") or [] if x], "filters": m.get("filters") or [], "time": m.get("time"),
                          "records": m.get("records", m.get("count"))},
                counts={"count": m.get("count")}, strength="세션으로 연결" if c.get("entity") == "session" else GROUP_WORD[c.get("group_by") or "src_ip"] + " 기준" if c["kind"] == "threshold" else "출발지 IP 기준",
                key=[item["id"], m["entity"], m.get("start")]))
    return methods, activities


def catalog(s, p, org_unit_id: str | None = None) -> dict:
    """My scenarios with whether each can run, and the shipped templates."""
    rows = knowledge.list_all(s, p, kind="scenario", org_unit_id=org_unit_id)
    mine = []
    for r in rows:
        c = r["content"]
        mine.append({**r, "description": describe(c),
                     "run_state": "비활성" if r["status"] == "stopped" else "다음 헌팅부터 사용" if c.get("state") == "active" else "초안(시험만)",
                     "needs": [" · ".join(SOURCE_WORD[x] for x in c.get("sources") or []) + " 기록"] if c["kind"] == "threshold" else [_need_text(c["kind"])]})
    return {"scenarios": mine, "templates": TEMPLATES, "kinds": KINDS, "threshold_options": THRESHOLD_OPTIONS}
