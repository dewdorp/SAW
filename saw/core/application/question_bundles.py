"""Investigation question bundles computed straight from the logs, with no policy, rule or scenario to write.

Four questions an analyst asks of NDR/FW data. Each bundle reports what was observed (with the metric, the
threshold and the full record count), what cannot be known from these logs, the normal explanations to rule
out and the next thing to ask. A bundle that has no records to look at says "insufficient data"; one that
looked and found nothing says so — neither is a "normal" verdict. Nothing here is a conclusion: an attack
name, an HTTP 200, a firewall allow or a large byte count never becomes an incident on its own.
"""
from __future__ import annotations

import statistics
from datetime import datetime

from saw import container
from saw.analyzers.ioc.observables import affiliate_local
from saw.core.schemas.query import Filter, GroupMetric, TimeRange

VERSION = "question-bundles/1"
WEB = Filter(field="data_source", op="in", value=["web", "waf"])
CONN = Filter(field="data_source", op="in", value=["connection", "firewall", "zeek_conn", "web"])
PATTERNS = ["pattern:sqli", "pattern:xss", "pattern:traversal", "pattern:cmdi", "pattern:ssti", "pattern:ssrf", "pattern:deser"]
# Thresholds per sensitivity: a lower setting asks for more before raising an item.
SENSITIVITY = {
    "low": {"paths": 60, "bytes": 200 * 1024 ** 2, "periodic_min": 12, "periodic_cv": 0.08, "targets": 20, "ports": 20},
    "normal": {"paths": 30, "bytes": 50 * 1024 ** 2, "periodic_min": 8, "periodic_cv": 0.15, "targets": 10, "ports": 10},
    "high": {"paths": 15, "bytes": 10 * 1024 ** 2, "periodic_min": 6, "periodic_cv": 0.25, "targets": 5, "ports": 5},
}
MAX_ITEMS = 10


def _ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _mb(n):
    return f"{n / 1024 ** 2:,.1f}MB"


def _item(title, observed, basis, records, filters, unknown, normal, questions, *, entities=(), time=None, strength="관측"):
    return {"title": title, "observed": observed, "basis": basis, "records": records, "filters": filters,
            "unknown": unknown, "normal_possibilities": normal, "next_questions": questions,
            "entities": [e for e in entities if e], "time": time or {}, "strength": strength}


def _web(es, inv, time, t) -> dict:
    total = es.count(inv, [WEB], time)
    if not total:
        return {"status": "insufficient_data", "missing": ["HTTP 요청 기록(method·path 또는 요청헤더)"], "items": []}
    rows = es.group_by(inv, [WEB], ["src_ip"], [
        GroupMetric(type="cardinality", field="url_path", name="paths"),
        GroupMetric(type="count", name="patterns", filters=[Filter(field="tags", op="in", value=PATTERNS)]),
        GroupMetric(type="count", name="ok", filters=[Filter(field="status_class", value="2xx")]),
        GroupMetric(type="count", name="errors", filters=[Filter(field="status_class", value="5xx")]),
        GroupMetric(type="cardinality", field="hostname", name="hosts"),
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=200, time=time)
    items = []
    for r in sorted(rows, key=lambda r: (-(r.get("patterns") or 0), -(r.get("paths") or 0))):
        src = r["key"]["src_ip"]
        if not src or ((r.get("patterns") or 0) == 0 and (r.get("paths") or 0) < t["paths"]):
            continue
        why = []
        if r.get("patterns"):
            why.append(f"요청 값에 공격 패턴이 든 요청 {r['patterns']}건")
        if (r.get("paths") or 0) >= t["paths"]:
            why.append(f"서로 다른 경로 {r['paths']}개 요청(기준 {t['paths']}개 이상)")
        flt = [WEB.model_dump(), {"field": "src_ip", "op": "is", "value": src}]
        items.append(_item(
            f"{src}의 웹 요청: " + " · ".join(why), " · ".join(why) + f". 대상 호스트 {r.get('hosts') or 0}개, 2xx {r.get('ok') or 0}건 · 5xx {r.get('errors') or 0}건.",
            {"metric": "url_path 고유 수·패턴 태그 수", "threshold_paths": t["paths"]}, r["count"], flt,
            ["응답 내용·서버 처리 결과(이 로그에는 없음)", "실행·파일 변경 여부", "인증 사용자"],
            ["승인된 취약점 점검·검색 엔진 크롤러", "모니터링 도구의 정기 요청"],
            ["이 출발지의 요청이 승인된 점검이었는지", "해당 시간의 웹·WAF·애플리케이션 로그와 오류 기록",
             "2xx 응답이 실제 데이터 반환인지(응답 본문·처리 결과)"],
            entities=[f"ip:{src}"], time={"start": r.get("first"), "end": r.get("last")},
            strength="패턴 일치" if r.get("patterns") else "탐색 양상"))
        if len(items) >= MAX_ITEMS:
            break
    return {"status": "found" if items else "looked_none", "records": total, "items": items}


def _transfer(es, inv, time, t) -> dict:
    flt = [CONN, Filter(field="bytes_in", op="exists")]
    total = es.count(inv, flt, time) + es.count(inv, [CONN, Filter(field="bytes_out", op="exists")], time)
    if not total:
        return {"status": "insufficient_data", "missing": ["방향별 바이트(cs/sc_bytes, sent/rcvd_bytes)"], "items": []}
    metrics = [GroupMetric(type="sum", field="bytes_in", name="bin"), GroupMetric(type="sum", field="bytes_out", name="bout"),
               GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")]
    # The largest pairs by either direction, so a large download is not hidden behind many large uploads.
    rows = list({tuple(sorted(r["key"].items(), key=lambda kv: kv[0])): r
                 for order in ("bin", "bout")
                 for r in es.group_by(inv, [CONN], ["src_ip", "dst_ip", "data_source"], metrics,
                                      size=500, time=time, order_by=order)}.values())
    rows.sort(key=lambda r: max(r.get("bin") or 0, r.get("bout") or 0), reverse=True)
    sums = [max(r.get("bin") or 0, r.get("bout") or 0) for r in rows]
    median = statistics.median(sums) if sums else 0
    items = []
    for r in rows:
        src, dst, ds = r["key"]["src_ip"], r["key"]["dst_ip"], r["key"]["data_source"]
        bin_, bout = r.get("bin") or 0, r.get("bout") or 0
        if max(bin_, bout) < t["bytes"]:
            continue
        web = ds in ("web", "waf")
        if web:
            # In an HTTP record the source is the client. Web convention (as IIS sc-bytes): bytes_out is the
            # response the server sent to the client, bytes_in the request the client sent.
            server_inside, client_inside = affiliate_local(dst) if dst else None, affiliate_local(src) if src else None
            if server_inside and client_inside is False:
                kind = f"내부 서버 {dst}가 외부 클라이언트 {src}에게 보낸 응답 {_mb(bout)} — 외부 반출 후보"
            elif server_inside is False and client_inside:
                kind = f"내부 클라이언트 {src}가 외부 서버 {dst}에서 받은 응답 {_mb(bout)} — 다운로드 후보"
            else:
                kind = f"{src}↔{dst} 응답 {_mb(bout)}·요청 {_mb(bin_)}"
        else:
            kind = f"{src}→{dst} 송신 {_mb(bout)}·수신 {_mb(bin_)} (방향 기준은 장비 확인 필요)"
        items.append(_item(
            kind, kind + f". 같은 조사의 통신 쌍 중앙값 {_mb(median)}.",
            {"metric": "통신 쌍별 바이트 합계(행 단위·헤더 포함 여부 미확인)", "threshold_bytes": t["bytes"], "median_pair_bytes": median},
            r["count"], [{"field": "src_ip", "op": "is", "value": src}, {"field": "dst_ip", "op": "is", "value": dst}],
            ["실제로 전달된 데이터 종류·민감도(바이트 수는 데이터 용량이 아님)", "누적·중복 기록 여부", "업무 승인 여부"],
            ["정상 백업·파일 배포·업무 다운로드", "대용량 업데이트·동기화"],
            ["이 시간의 대량 전송이 승인된 업무(백업·배포·다운로드)였는지", "해당 요청의 처리 내용과 애플리케이션 로그",
             "전송된 데이터의 범위"],
            entities=[f"ip:{src}", f"ip:{dst}"], time={"start": r.get("first"), "end": r.get("last")}))
        if len(items) >= MAX_ITEMS:
            break
    return {"status": "found" if items else "looked_none", "records": total, "items": items,
            "note": "바이트는 장비가 기록한 값의 합이며, 행 단위·누적 여부가 확인되지 않았으면 전체 트래픽으로 보지 않습니다."}


def _periodic(es, inv, time, t) -> dict:
    flt = [CONN, Filter(field="timestamp", op="exists")]
    if not es.count(inv, flt, time):
        return {"status": "insufficient_data", "missing": ["시각"], "items": []}
    rows = es.group_by(inv, flt, ["src_ip", "dst_ip", "dst_port"], [
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=200, time=time)
    items = []
    for r in rows:
        if r["count"] < t["periodic_min"] or not r["key"]["src_ip"]:
            continue
        src, dst, port = r["key"]["src_ip"], r["key"]["dst_ip"], r["key"]["dst_port"]
        pair = [Filter(field="src_ip", value=src), Filter(field="dst_ip", value=dst)] + (
            [Filter(field="dst_port", value=port)] if port is not None else [])
        times = sorted(x for x in (_ts(e.get("timestamp")) for e in es.search(inv, flt + pair, time, sort="asc", limit=500)["events"]) if x)
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < t["periodic_min"] - 1:
            continue
        mean = statistics.fmean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv > t["periodic_cv"]:
            continue
        items.append(_item(
            f"{src}→{dst}:{port} 기록이 약 {mean:,.0f}초 간격으로 반복",
            f"기록 {r['count']}건이 평균 {mean:,.0f}초 간격(변동계수 {cv:.2f})으로 발생했습니다. 기록 시각의 주기이며 연결 시작의 주기라고 확정하지 않습니다.",
            {"metric": "기록 간격 변동계수", "threshold_cv": t["periodic_cv"], "min_records": t["periodic_min"], "intervals_checked": len(gaps)},
            r["count"], [{"field": k, "op": "is", "value": v} for k, v in (("src_ip", src), ("dst_ip", dst), ("dst_port", port)) if v is not None],
            ["통신을 만든 프로그램·계정", "통신 내용", "기록 시각이 연결 시작인지 여부"],
            ["상태 점검·모니터링 에이전트", "업데이트·동기화·예약 작업"],
            ["이 자산에서 이 주기로 통신하는 프로그램·예약 작업이 있는지", "목적지가 승인된 서비스인지"],
            entities=[f"ip:{src}", f"ip:{dst}"], time={"start": r.get("first"), "end": r.get("last")}))
        if len(items) >= MAX_ITEMS:
            break
    return {"status": "found" if items else "looked_none", "records": es.count(inv, flt, time), "items": items}


def _spread(es, inv, time, t) -> dict:
    flt = [CONN, Filter(field="dst_ip", op="exists")]
    total = es.count(inv, flt, time)
    if not total:
        return {"status": "insufficient_data", "missing": ["목적지 IP·포트"], "items": []}
    rows = es.group_by(inv, flt, ["src_ip"], [
        GroupMetric(type="cardinality", field="dst_ip", name="targets"),
        GroupMetric(type="cardinality", field="dst_port", name="ports"),
        GroupMetric(type="count", name="blocked", filters=[Filter(field="enforcement_action", value="blocked")]),
        GroupMetric(type="count", name="allowed", filters=[Filter(field="enforcement_action", value="allowed")]),
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")],
        size=200, time=time, order_by="targets")
    items = []
    for r in rows:
        src = r["key"]["src_ip"]
        if not src or ((r.get("targets") or 0) < t["targets"] and (r.get("ports") or 0) < t["ports"]):
            continue
        inside = affiliate_local(src)
        items.append(_item(
            f"{src}가 자산 {r.get('targets')}개·포트 {r.get('ports')}개에 접근",
            f"{'관계사 내부' if inside else '외부'} 출발지 {src}의 기록 {r['count']}건: 목적지 {r.get('targets')}개, 포트 {r.get('ports')}개, 허용 {r.get('allowed') or 0}건·차단 {r.get('blocked') or 0}건.",
            {"metric": "출발지별 목적지·포트 고유 수", "threshold_targets": t["targets"], "threshold_ports": t["ports"]},
            r["count"], [{"field": "src_ip", "op": "is", "value": src}],
            ["접속 후 인증·원격 실행 여부(이 로그에는 없음)", "IP를 쓴 실제 사용자·호스트(NAT·DHCP)"],
            ["승인된 취약점 진단·자산 점검", "관리 서버·모니터링 서버의 정상 접속"],
            ["이 출발지의 접근이 승인된 점검 일정에 있었는지", "허용된 접속 대상 서버의 인증·실행 기록"],
            entities=[f"ip:{src}"], time={"start": r.get("first"), "end": r.get("last")}))
        if len(items) >= MAX_ITEMS:
            break
    return {"status": "found" if items else "looked_none", "records": total, "items": items}


BUNDLES = [
    ("web_attack", "A. 웹 공격 시도가 있었고 영향 확인이 필요한가?", _web),
    ("transfer", "B. 대량 반출·다운로드인지 정상 업무인지 확인해야 하는가?", _transfer),
    ("periodic", "C. 반복 통신이 자동 업무인지 추가 조사 대상인지?", _periodic),
    ("spread", "D. 여러 자산·관리 포트 접근이 점검인지 침해 확산 조사 대상인지?", _spread),
]


def build(inv, *, sensitivity: str = "normal", time: TimeRange | None = None) -> dict:
    es = container.get().events
    thresholds = SENSITIVITY.get(sensitivity) or SENSITIVITY["normal"]
    out = []
    for key, title, fn in BUNDLES:
        try:
            result = fn(es, inv.id, time, thresholds)
        except (ValueError, KeyError) as exc:  # a store that cannot answer one bundle leaves the rest intact
            result = {"status": "failed", "items": [], "error": type(exc).__name__}
        out.append({"id": key, "title": title, **result})
    return {"version": VERSION, "sensitivity": sensitivity, "thresholds": thresholds, "bundles": out,
            "note": "로그에서 바로 계산한 조사 질문입니다. 판정이 아니며, 근거 없음은 '이 기준에서 보이지 않음'일 뿐 정상이라는 뜻이 아닙니다."}
