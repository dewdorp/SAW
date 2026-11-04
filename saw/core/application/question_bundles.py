"""Investigation question bundles computed straight from the logs, with no policy, rule or scenario to write.

Four questions an analyst asks of NDR/FW data. Each question has one structured condition definition (PARAMS):
the same definition renders the Korean sentence, validates the analyst's edits, runs against the current logs
and is what a saved preset stores, so editing a number always changes what is computed.

Every result carries its scope (investigation, affiliate, period, condition, version, run time) and keeps three
counts apart: the unique records the condition selects, what the computation actually examined (groups and
timelines, with their limits) and what is shown (the first items). A bundle with no records to look at says
"insufficient data"; one that looked and found nothing says so; one that hit a limit says "partial" — none of
these is a "normal" verdict. An attack name, an HTTP 200, a firewall allow or a large byte count never becomes
an incident on its own.
"""
from __future__ import annotations

import ipaddress
import statistics
from collections import Counter
from datetime import datetime, timezone

from saw import container
from saw.core.schemas.query import Filter, GroupMetric, TimeRange

VERSION = "question-bundles/3"
PATTERNS = ["pattern:sqli", "pattern:xss", "pattern:traversal", "pattern:cmdi", "pattern:ssti", "pattern:ssrf", "pattern:deser"]
MAX_ITEMS = 200         # items returned per question (the screen pages them); more is reported, never dropped silently
GROUP_LIMIT = 1000      # groups one computation examines; more is reported as a partial computation
TIMELINE_LIMIT = 20000  # records read per timeline (periodic gaps, windowed spread)
CONN_SOURCES = [["connection", "FW·연결 기록"], ["firewall", "방화벽"], ["zeek_conn", "Zeek 연결"], ["web", "NDR HTTP·웹"]]
WEB_SOURCES = [["web", "NDR HTTP·웹"], ["waf", "WAF"]]

# Thresholds per sensitivity: a lower setting asks for more before raising an item. They are only the defaults
# of the editable parameters below.
SENSITIVITY = {
    "low": {"paths": 60, "bytes": 200 * 1024 ** 2, "periodic_min": 12, "periodic_cv": 0.08, "targets": 20, "ports": 20},
    "normal": {"paths": 30, "bytes": 50 * 1024 ** 2, "periodic_min": 8, "periodic_cv": 0.15, "targets": 10, "ports": 10},
    "high": {"paths": 15, "bytes": 10 * 1024 ** 2, "periodic_min": 6, "periodic_cv": 0.25, "targets": 5, "ports": 5},
}


def _p(name, label, kind, default, help_="", **extra):
    return {"name": name, "label": label, "type": kind, "default": default, "help": help_, **extra}


# One structured definition per question. Types: int (min/max/unit), float, choice, choice_list, ip_list,
# port_list, bool. `default` may name a sensitivity key ("@targets") resolved per sensitivity.
PARAMS: dict[str, list[dict]] = {
    "spread": [
        _p("data_sources", "살펴볼 로그 종류", "choice_list", ["connection", "firewall", "zeek_conn", "web"], choices=CONN_SOURCES),
        _p("window_minutes", "관측창", "int", 0, "0이면 조사 기간 전체를 한 창으로 봅니다", min=0, max=44640, unit="분"),
        _p("min_targets", "서로 다른 목적지 수", "int", "@targets", "이 수 이상이면 후보", min=1, max=100000, unit="개 이상"),
        _p("min_ports", "서로 다른 목적지 포트 수", "int", "@ports", "", min=1, max=65536, unit="개 이상"),
        _p("match", "두 기준의 결합", "choice", "any", choices=[["any", "목적지 또는 포트 중 하나라도"], ["all", "목적지와 포트 모두"]]),
        _p("dst_ports", "목적지 포트로 한정", "port_list", [], "비우면 모든 포트"),
        _p("action", "장비 처리 결과로 한정", "choice", "", choices=[["", "전체"], ["allowed", "허용"], ["blocked", "차단"]]),
        _p("exclude_src", "제외할 출발지 IP", "ip_list", [], "승인된 점검 서버 등"),
        _p("exclude_dst", "제외할 목적지 IP", "ip_list", []),
    ],
    "web_attack": [
        _p("data_sources", "살펴볼 로그 종류", "choice_list", ["web", "waf"], choices=WEB_SOURCES),
        _p("min_paths", "서로 다른 URL 경로 수", "int", "@paths", "이 수 이상이면 탐색 후보", min=1, max=100000, unit="개 이상"),
        _p("use_patterns", "요청 값의 공격 패턴도 후보로", "bool", True, "SQL 주입·경로 조작 등 패턴 태그가 1건이라도 있으면 후보"),
        _p("exclude_src", "제외할 출발지 IP", "ip_list", []),
    ],
    "transfer": [
        _p("data_sources", "살펴볼 로그 종류", "choice_list", ["connection", "firewall", "zeek_conn", "web"], choices=CONN_SOURCES),
        _p("min_mb", "통신 쌍의 방향별 바이트 합계", "int", "@bytes_mb", "1 MiB = 1,048,576바이트", min=1, max=10_000_000, unit="MiB 이상"),
        _p("direction", "어느 방향의 바이트", "choice", "any", choices=[["any", "어느 방향이든"], ["out", "bytes_out(웹: 응답, FW: 송신)"], ["in", "bytes_in(웹: 요청, FW: 수신)"]]),
        _p("exclude_src", "제외할 출발지 IP", "ip_list", []),
        _p("exclude_dst", "제외할 목적지 IP", "ip_list", []),
    ],
    "periodic": [
        _p("data_sources", "살펴볼 로그 종류", "choice_list", ["connection", "firewall", "zeek_conn", "web"], choices=CONN_SOURCES),
        _p("min_records", "같은 통신 쌍의 기록 수", "int", "@periodic_min", "", min=3, max=100000, unit="건 이상"),
        _p("max_cv", "간격의 흔들림(변동계수)", "float", "@periodic_cv", "작을수록 더 일정한 간격만 후보", min=0.01, max=1.0),
        _p("dst_ports", "목적지 포트로 한정", "port_list", [], "비우면 모든 포트"),
        _p("exclude_src", "제외할 출발지 IP", "ip_list", []),
        _p("exclude_dst", "제외할 목적지 IP", "ip_list", []),
    ],
}


def defaults(bundle: str, sensitivity: str = "normal") -> dict:
    t = {**(SENSITIVITY.get(sensitivity) or SENSITIVITY["normal"])}
    t["bytes_mb"] = t["bytes"] // 1024 ** 2
    return {p["name"]: (t[p["default"][1:]] if isinstance(p["default"], str) and p["default"].startswith("@")
                        else p["default"]) for p in PARAMS[bundle]}


def validate(bundle: str, values: dict | None, sensitivity: str = "normal") -> dict:
    """The analyst's edits checked against the definition; unknown names and wrong types are refused in Korean."""
    if bundle not in PARAMS:
        raise ValueError("알 수 없는 질문입니다")
    values = dict(values or {})
    unknown = set(values) - {p["name"] for p in PARAMS[bundle]}
    if unknown:
        raise ValueError(f"이 질문에 없는 조건입니다: {', '.join(sorted(unknown))}")
    out = defaults(bundle, sensitivity)
    for p in PARAMS[bundle]:
        if p["name"] not in values:
            continue
        v, label, kind = values[p["name"]], p["label"], p["type"]
        if kind in ("int", "float"):
            try:
                v = int(v) if kind == "int" else float(v)
            except (TypeError, ValueError):
                raise ValueError(f"{label}: 숫자를 입력하세요") from None
            if isinstance(values[p["name"]], bool) or not p["min"] <= v <= p["max"]:
                raise ValueError(f"{label}: {p['min']}~{p['max']} 사이로 입력하세요")
        elif kind == "bool":
            if not isinstance(v, bool):
                raise ValueError(f"{label}: 예/아니오로 고르세요")
        elif kind == "choice":
            if v not in [c[0] for c in p["choices"]]:
                raise ValueError(f"{label}: 목록에서 고르세요")
        elif kind == "choice_list":
            allowed = [c[0] for c in p["choices"]]
            if not isinstance(v, list) or not v or any(x not in allowed for x in v):
                raise ValueError(f"{label}: 하나 이상 목록에서 고르세요")
            v = [x for x in allowed if x in v]
        elif kind == "port_list":
            if not isinstance(v, list) or len(v) > 50:
                raise ValueError(f"{label}: 포트는 50개까지 입력할 수 있습니다")
            try:
                v = sorted({int(x) for x in v})
            except (TypeError, ValueError):
                raise ValueError(f"{label}: 포트는 숫자로 입력하세요") from None
            if any(not 0 <= x <= 65535 for x in v):
                raise ValueError(f"{label}: 포트는 0~65535 사이입니다")
        elif kind == "ip_list":
            if not isinstance(v, list) or len(v) > 200:
                raise ValueError(f"{label}: IP는 200개까지 입력할 수 있습니다")
            cleaned = []
            for x in v:
                text = str(x).strip()
                if "/" in text:
                    raise ValueError(f"{label}: CIDR 범위({text})는 아직 지원하지 않습니다. 개별 IP로 입력하세요")
                try:
                    cleaned.append(str(ipaddress.ip_address(text)))
                except ValueError:
                    raise ValueError(f"{label}: IP 주소 형식이 아닙니다({text[:60]})") from None
            v = sorted(set(cleaned))
        out[p["name"]] = v
    return out


def describe(bundle: str, v: dict) -> str:
    """The condition as one Korean sentence, built from the same values that run."""
    names = dict(c for p in PARAMS[bundle] if p["type"] == "choice_list" for c in p["choices"])
    sources = "·".join(names.get(x, x) for x in v.get("data_sources") or [])
    extra = []
    if v.get("dst_ports"):
        extra.append(f"목적지 포트 {', '.join(map(str, v['dst_ports']))}")
    if v.get("action"):
        extra.append(f"처리 결과 {'허용' if v['action'] == 'allowed' else '차단'}")
    if v.get("exclude_src"):
        extra.append(f"출발지 {len(v['exclude_src'])}개 제외")
    if v.get("exclude_dst"):
        extra.append(f"목적지 {len(v['exclude_dst'])}개 제외")
    tail = f" ({' · '.join(extra)})" if extra else ""
    if bundle == "spread":
        window = f"{v['window_minutes']}분 동안" if v["window_minutes"] else "조사 기간 전체에서"
        join = "또는" if v["match"] == "any" else "그리고"
        return (f"{sources} 기록에서 같은 출발지가 {window} 서로 다른 목적지 {v['min_targets']}개 이상 {join} "
                f"서로 다른 포트 {v['min_ports']}개 이상에 접근{tail}")
    if bundle == "web_attack":
        pattern = " 또는 요청 값에 공격 패턴이 있음" if v["use_patterns"] else ""
        return f"{sources} 기록에서 같은 출발지가 서로 다른 URL 경로 {v['min_paths']}개 이상 요청{pattern}{tail}"
    if bundle == "transfer":
        way = {"any": "두 방향 중 하나의", "out": "웹 응답 또는 장비 송신", "in": "웹 요청 또는 장비 수신"}[v["direction"]]
        return f"{sources} 기록에서 같은 출발지·목적지·로그 종류의 {way} 바이트 합계가 {v['min_mb']:,} MiB 이상{tail}"
    return (f"{sources} 기록에서 같은 출발지·목적지·포트의 기록이 {v['min_records']}건 이상이고 "
            f"간격 변동계수가 {v['max_cv']:.2f} 이하{tail}")


def _base(v: dict) -> list[Filter]:
    """The condition's record filters: every evidence query of the question starts from these."""
    out = [Filter(field="data_source", op="in", value=list(v["data_sources"]))]
    if v.get("dst_ports"):
        out.append(Filter(field="dst_port", op="in", value=list(v["dst_ports"])))
    if v.get("action"):
        out.append(Filter(field="enforcement_action", value=v["action"]))
    if v.get("exclude_src"):
        out.append(Filter(field="src_ip", op="not_in", value=list(v["exclude_src"])))
    if v.get("exclude_dst"):
        out.append(Filter(field="dst_ip", op="not_in", value=list(v["exclude_dst"])))
    return out


def _ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _kst(value) -> str:
    """A moment as Korean local time for a sentence (the item's time fields keep exact values)."""
    from zoneinfo import ZoneInfo

    t = _ts(value)
    return datetime.fromtimestamp(t, ZoneInfo("Asia/Seoul")).strftime("%m-%d %H:%M:%S") if t is not None else "?"


def _bytes_label(n):
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:,.1f} MiB"
    if n >= 1024:
        return f"{n / 1024:,.1f} KiB"
    return f"{n:,.0f} B"


def _dump(filters: list[Filter]) -> list[dict]:
    return [f.model_dump() for f in filters]


def _item(title, observed, basis, records, filters, unknown, normal, questions, *, entities=(), time=None, strength="관측"):
    return {"title": title, "observed": observed, "basis": basis, "records": records, "filters": filters,
            "unknown": unknown, "normal_possibilities": normal, "next_questions": questions,
            "entities": [e for e in entities if e], "time": time or {}, "strength": strength}


def _finish(items: list, records: int, examined: dict, *, partial: list[str] | None = None, **extra) -> dict:
    """Found / looked-none plus what was examined and shown; a limit hit makes the computation partial."""
    partial = [p for p in (partial or []) if p]
    # Every computed item is returned up to MAX_ITEMS, so the 11th and 12th of twelve can be opened too.
    return {"status": "found" if items else "looked_none", "records": records, "items": items[:MAX_ITEMS],
            "found": len(items), "shown": min(len(items), MAX_ITEMS), "returned_all": len(items) <= MAX_ITEMS,
            "completeness": "partial" if partial else "complete", "partial_reasons": partial,
            "examined": examined, **extra}


def _empty(es, inv, time, v, needed: list[Filter], missing: str) -> dict:
    """No record under the condition: either the logs lack the field at all, or the condition matched none."""
    if not es.count(inv, [Filter(field="data_source", op="in", value=list(v["data_sources"])), *needed], time):
        return {"status": "insufficient_data", "missing": [missing], "items": [], "records": 0}
    return {"status": "no_match", "items": [], "records": 0, "found": 0, "shown": 0, "completeness": "complete",
            "partial_reasons": [], "examined": {}}


def _spread(es, inv, time, v) -> dict:
    base = _base(v) + [Filter(field="dst_ip", op="exists")]
    total = es.count(inv, base, time)
    if not total:
        return _empty(es, inv, time, v, [Filter(field="dst_ip", op="exists")], "목적지 IP·포트")
    sources = es.aggregate(inv, base, _agg("src_ip"), time).get("value") or 0
    metrics = [
        GroupMetric(type="cardinality", field="dst_ip", name="targets"),
        GroupMetric(type="cardinality", field="dst_port", name="ports"),
        GroupMetric(type="value_count", field="dst_port", name="known_ports"),
        GroupMetric(type="count", name="blocked", filters=[Filter(field="enforcement_action", value="blocked")]),
        GroupMetric(type="count", name="allowed", filters=[Filter(field="enforcement_action", value="allowed")]),
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")]
    rows = es.group_by(inv, base, ["src_ip"], metrics, size=GROUP_LIMIT, time=time, order_by="targets")
    partial = [f"출발지 {sources:,}개 중 목적지 수 상위 {len(rows):,}개만 계산" if sources > len(rows) else ""]

    def hit(targets, ports):
        a, b = targets >= v["min_targets"], ports >= v["min_ports"]
        return (a or b) if v["match"] == "any" else (a and b)

    items, timelines = [], 0
    for r in rows:
        src = r["key"]["src_ip"]
        if not src or not hit(r.get("targets") or 0, r.get("ports") or 0):
            continue  # the whole-period counts bound any window's counts, so this source cannot match
        flt = base + [Filter(field="src_ip", value=src)]
        whole_span = {"start": r.get("first"), "end": r.get("last")}
        values, span, evidence_time = r, whole_span, None
        if v["window_minutes"]:
            timelines += 1
            best = _qualifying_window(es, inv, flt, time, v["window_minutes"] * 60, hit)
            if best["truncated"]:
                partial.append(f"{src}: 기록 {TIMELINE_LIMIT:,}건까지만 관측창 계산")
            if best["undated"]:
                partial.append(f"{src}: 시각을 확인할 수 없는 기록 {best['undated']:,}건은 관측창에서 제외")
            if not best["span"]:
                continue
            values, span = best, best["span"]
            evidence_time = {**span, "end_exclusive": False}
            if best["truncated"]:
                # The last examined timestamp may have additional rows beyond the cap.
                # Reconcile this one inclusive interval with the full raw-log query.
                exact = es.group_by(inv, flt, ["src_ip"], metrics, size=1, time=TimeRange(**evidence_time))
                if not exact:
                    continue
                values = exact[0]
        targets, ports = values.get("targets") or 0, values.get("ports") or 0
        port_text = _port_phrase(es, inv, flt, TimeRange(**evidence_time) if evidence_time else time, ports)
        window_note = f" ({v['window_minutes']}분 관측창)" if v["window_minutes"] else ""
        scope_label = (f"조건을 충족한 대표 구간 {_kst(span['start'])} ~ {_kst(span['end'])} KST"
                       if evidence_time else "조사 기간 전체")
        item = _item(
            f"{src}에서 {_duration_phrase(span)} 목적지 {targets}개의 {port_text}에 접촉했습니다{window_note}.",
            f"{scope_label}: 이 출발지의 근거 {values['count']:,}건 중 허용 {values.get('allowed') or 0:,}건·차단 {values.get('blocked') or 0:,}건."
            + (f" 조사 기간 전체에서 이 출발지의 조건 일치 기록은 {r['count']:,}건입니다." if evidence_time else ""),
            {"metric": "출발지별 서로 다른 목적지·포트 수", "window_minutes": v["window_minutes"],
             "threshold_targets": v["min_targets"], "threshold_ports": v["min_ports"], "match": v["match"],
             "observed_targets": targets, "observed_ports": ports, "port_records": values.get("known_ports"),
             "allowed_records": values.get("allowed") or 0, "blocked_records": values.get("blocked") or 0,
             "source_records": r["count"], "source_time": whole_span},
            values["count"], _dump(flt),
            ["접속 후 인증·원격 실행 여부(이 로그에는 없음)", "IP를 쓴 실제 사용자·호스트(NAT·DHCP)"],
            ["승인된 취약점 진단·자산 점검", "관리 서버·모니터링 서버의 정상 접속"],
            ["이 출발지의 접근이 승인된 점검 일정에 있었는지", "허용된 접속 대상 서버의 인증·실행 기록"],
            entities=[f"ip:{src}"], time=span)
        if evidence_time:
            item["evidence_time"] = evidence_time
        items.append(item)
    return _finish(items, total, {"groups": len(rows), "groups_total": sources, "group_limit": GROUP_LIMIT,
                                  "timelines": timelines, "timeline_limit": TIMELINE_LIMIT}, partial=partial)


def _duration_phrase(span: dict) -> str:
    """'약 1분 동안' from an item's first and last record."""
    a, b = _ts((span or {}).get("start")), _ts((span or {}).get("end"))
    if a is None or b is None:
        return "관측 구간 동안"
    s = max(0.0, b - a)
    if s < 1:
        return "1초 이내에"
    if s < 60:
        return f"약 {round(s)}초 동안"
    if s < 3600:
        return f"약 {round(s / 60)}분 동안"
    if s < 86400:
        return f"약 {s / 3600:.1f}시간 동안".replace(".0시간", "시간")
    return f"약 {s / 86400:.1f}일 동안".replace(".0일", "일")


def _port_phrase(es, inv, filters, time, ports: int) -> str:
    """'TCP 443 포트' when a few ports were touched, otherwise the count; a missing port is named as such."""
    from saw.core.schemas.query import AggRequest

    if not ports or ports > 3:
        return f"포트 {ports:,}개" if ports else "포트(미기록)"
    names = [b["key"] for b in es.aggregate(inv, filters, AggRequest(type="terms", field="dst_port", size=3), time).get("buckets", [])]
    protos = [b["key"] for b in es.aggregate(inv, filters, AggRequest(type="terms", field="protocol", size=2), time).get("buckets", [])]
    proto = f"{str(protos[0]).upper()} " if len(protos) == 1 and protos[0] else ""
    return f"{proto}{'·'.join(str(x) for x in names)} 포트" if names else f"포트 {ports:,}개"


def _qualifying_window(es, inv, filters, time, seconds, matches) -> dict:
    """Test the actual AND/OR condition in each sliding window, then rank only matching windows."""
    events, truncated, undated = [], False, 0
    for i, e in enumerate(es.iterate(inv, filters, time, fields=["timestamp", "dst_ip", "dst_port", "enforcement_action"])):
        if i >= TIMELINE_LIMIT:
            truncated = True
            break
        t = _ts(e.get("timestamp"))
        if t is not None:
            events.append((t, e.get("dst_ip"), e.get("dst_port"), e.get("enforcement_action")))
        else:
            undated += 1
    events.sort(key=lambda x: x[0])
    dsts, ports, actions = Counter(), Counter(), Counter()
    best = {"span": {}, "truncated": truncated, "undated": undated}
    best_rank = (0, 0, 0)
    lo = known_ports = 0
    for hi, (t, dst, port, action) in enumerate(events):
        known_ports += port is not None
        for counter, key in ((dsts, dst), (ports, port), (actions, action)):
            if key is not None:
                counter[key] += 1
        while events[lo][0] < t - seconds:
            known_ports -= events[lo][2] is not None
            for counter, key in zip((dsts, ports, actions), events[lo][1:]):
                if key is not None:
                    _drop(counter, key)
            lo += 1
        rank = (len(dsts), len(ports), hi - lo + 1)
        if matches(len(dsts), len(ports)) and rank > best_rank:
            best_rank = rank
            first, last = events[lo][0], t
            best.update(targets=len(dsts), ports=len(ports), known_ports=known_ports, count=rank[2], allowed=actions["allowed"], blocked=actions["blocked"])
    if best_rank[2]:
        best["span"] = {"start": datetime.fromtimestamp(first, timezone.utc).isoformat(),
                        "end": datetime.fromtimestamp(last, timezone.utc).isoformat()}
    return best


def _drop(counter: Counter, key) -> None:
    counter[key] -= 1
    if counter[key] <= 0:
        del counter[key]


def _agg(field: str):
    from saw.core.schemas.query import AggRequest

    return AggRequest(type="cardinality", field=field)


def _web(es, inv, time, v) -> dict:
    base = _base(v)
    total = es.count(inv, base, time)
    if not total:
        return _empty(es, inv, time, v, [], "HTTP 요청 기록(method·path 또는 요청헤더)")
    sources = es.aggregate(inv, base, _agg("src_ip"), time).get("value") or 0
    rows = es.group_by(inv, base, ["src_ip"], [
        GroupMetric(type="cardinality", field="url_path", name="paths"),
        GroupMetric(type="count", name="patterns", filters=[Filter(field="tags", op="in", value=PATTERNS)]),
        GroupMetric(type="count", name="ok", filters=[Filter(field="status_class", value="2xx")]),
        GroupMetric(type="count", name="errors", filters=[Filter(field="status_class", value="5xx")]),
        GroupMetric(type="cardinality", field="hostname", name="hosts"),
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")],
        size=GROUP_LIMIT, time=time, order_by="paths")
    partial = [f"출발지 {sources:,}개 중 경로 수 상위 {len(rows):,}개만 계산" if sources > len(rows) else ""]
    items = []
    for r in sorted(rows, key=lambda r: (-(r.get("patterns") or 0), -(r.get("paths") or 0))):
        src = r["key"]["src_ip"]
        patterns = (r.get("patterns") or 0) if v["use_patterns"] else 0
        if not src or (patterns == 0 and (r.get("paths") or 0) < v["min_paths"]):
            continue
        why = []
        if patterns:
            why.append(f"요청 값에 공격 패턴이 든 요청 {patterns}건")
        if (r.get("paths") or 0) >= v["min_paths"]:
            why.append(f"서로 다른 경로 {r['paths']}개 요청(기준 {v['min_paths']}개 이상)")
        items.append(_item(
            f"{src}의 웹 요청: " + " · ".join(why), " · ".join(why) + f". 대상 호스트 {r.get('hosts') or 0}개, 2xx {r.get('ok') or 0}건 · 5xx {r.get('errors') or 0}건.",
            {"metric": "url_path 고유 수·패턴 태그 수", "threshold_paths": v["min_paths"], "use_patterns": v["use_patterns"]},
            r["count"], _dump(base + [Filter(field="src_ip", value=src)]),
            ["응답 내용·서버 처리 결과(이 로그에는 없음)", "실행·파일 변경 여부", "인증 사용자"],
            ["승인된 취약점 점검·검색 엔진 크롤러", "모니터링 도구의 정기 요청"],
            ["이 출발지의 요청이 승인된 점검이었는지", "해당 시간의 웹·WAF·애플리케이션 로그와 오류 기록",
             "2xx 응답이 실제 데이터 반환인지(응답 본문·처리 결과)"],
            entities=[f"ip:{src}"], time={"start": r.get("first"), "end": r.get("last")},
            strength="패턴 일치" if patterns else "탐색 양상"))
    return _finish(items, total, {"groups": len(rows), "groups_total": sources, "group_limit": GROUP_LIMIT}, partial=partial)


def _transfer(es, inv, time, v) -> dict:
    base = _base(v)
    has_in, has_out = Filter(field="bytes_in", op="exists"), Filter(field="bytes_out", op="exists")
    # A record with both directions is one record: |in ∪ out| = |in| + |out| - |in ∩ out|.
    total = es.count(inv, base + [has_in], time) + es.count(inv, base + [has_out], time) - es.count(inv, base + [has_in, has_out], time)
    if not total:
        sources = Filter(field="data_source", op="in", value=list(v["data_sources"]))
        if es.count(inv, [sources, has_in], time) or es.count(inv, [sources, has_out], time):
            return _empty(es, inv, time, v, [], "")
        return {"status": "insufficient_data", "missing": ["방향별 바이트(cs/sc_bytes, sent/rcvd_bytes)"], "items": [], "records": 0}
    metrics = [GroupMetric(type="sum", field="bytes_in", name="bin"), GroupMetric(type="sum", field="bytes_out", name="bout"),
               GroupMetric(type="count", name="allowed", filters=[Filter(field="enforcement_action", value="allowed")]),
               GroupMetric(type="value_count", field="bytes_in", name="nIn"), GroupMetric(type="value_count", field="bytes_out", name="nOut"),
               GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")]
    orders = {"any": ("bin", "bout"), "out": ("bout",), "in": ("bin",)}[v["direction"]]
    # The largest pairs by the chosen direction(s), so a large download is not hidden behind many large uploads.
    batches = [es.group_by(inv, base, ["src_ip", "dst_ip", "data_source"], metrics, size=GROUP_LIMIT, time=time, order_by=o)
               for o in orders]
    rows = list({tuple(sorted(r["key"].items(), key=lambda kv: kv[0])): r for batch in batches for r in batch}.values())
    size = lambda r: {"any": max(r.get("bin") or 0, r.get("bout") or 0), "out": r.get("bout") or 0, "in": r.get("bin") or 0}[v["direction"]]  # noqa: E731
    rows.sort(key=size, reverse=True)
    median = statistics.median([size(r) for r in rows]) if rows else 0
    limit_hit = any(len(b) >= GROUP_LIMIT for b in batches)
    threshold = v["min_mb"] * 1024 ** 2
    items = []
    for r in rows:
        src, dst, ds = r["key"]["src_ip"], r["key"]["dst_ip"], r["key"]["data_source"]
        bin_, bout = r.get("bin") or 0, r.get("bout") or 0
        if size(r) < threshold:
            continue
        web = ds in ("web", "waf")
        # Roles in the normalized HTTP record are observable; address ownership, file
        # contents and business purpose are not. For FW the direction is device-relative.
        in_label, out_label = ("요청", "응답") if web else ("장비 수신", "장비 송신")
        counts = {"in": (in_label, bin_, r.get("nIn")), "out": (out_label, bout, r.get("nOut"))}
        matched = [d for d, (_, n, _) in counts.items() if v["direction"] in ("any", d) and n >= threshold]
        sides = f"클라이언트 {src or '미기록'} ↔ 서버 {dst or '미기록'}" if web else f"{src or '미기록'} ↔ {dst or '미기록'}"
        kind = sides + " · " + " · ".join(f"{counts[d][0]} {_bytes_label(counts[d][1])}" for d in matched)
        observed = " · ".join(f"{label} {_bytes_label(n) if filled else '미기록'}" for label, n, filled in counts.values())
        pair = [Filter(field="data_source", value=ds)] + [
            Filter(field=field, value=value) if value is not None else Filter(field=field, op="not_exists")
            for field, value in (("src_ip", src), ("dst_ip", dst))]
        items.append(_item(
            kind, f"{r['count']:,}건의 합계: {observed}. 선택한 기준 {_bytes_label(threshold)} 이상입니다."
            + ("" if web else " 송수신 방향은 장비의 기록 기준입니다."),
            {"metric": "통신 쌍별 바이트 합계(행 단위·헤더 포함 여부 미확인)", "threshold_bytes": threshold,
             "allowed_records": r.get("allowed") or 0,
             "observed_bytes_in": bin_ if r.get("nIn") else None,
             "observed_bytes_out": bout if r.get("nOut") else None,
             "direction": v["direction"], "matched_directions": matched, "median_pair_bytes": median},
            r["count"], _dump(base + pair),
            ["실제로 전달된 데이터 종류·민감도(바이트 수는 데이터 용량이 아님)", "누적·중복 기록 여부", "업무 승인 여부"],
            ["정상 백업·파일 배포·업무 다운로드", "대용량 업데이트·동기화"],
            ["이 시간의 대량 전송이 승인된 업무(백업·배포·다운로드)였는지", "해당 요청의 처리 내용과 애플리케이션 로그",
             "전송된 데이터의 범위"],
            entities=[f"ip:{src}", f"ip:{dst}"], time={"start": r.get("first"), "end": r.get("last")}))
    return _finish(items, total, {"groups": len(rows), "group_limit": GROUP_LIMIT},
                   partial=["바이트 상위 통신 쌍 " + f"{GROUP_LIMIT:,}개까지만 계산" if limit_hit else ""],
                   unconfirmed=["바이트 방향·누적 여부는 장비 설정에서 확인 전이면 후보 값입니다"],
                   note="바이트는 장비가 기록한 값의 합이며, 행 단위·누적 여부가 확인되지 않았으면 전체 트래픽으로 보지 않습니다. "
                        "NDR와 FW 바이트는 다른 계층의 값이라 로그 종류별로 따로 셉니다.")


def _approx_interval(seconds: float) -> str:
    """Brief duration for the title; numeric mean remains in the evidence."""
    if seconds < .001:
        return "1밀리초 미만"
    if seconds < .9995:
        return f"약 {round(seconds * 1000)}밀리초"
    remaining = round(seconds)
    parts = []
    for size, unit in ((86400, "일"), (3600, "시간"), (60, "분"), (1, "초")):
        n, remaining = divmod(remaining, size)
        if n:
            parts.append(f"{n:,}{unit}")
    return "약 " + " ".join(parts[:2])


def _periodic(es, inv, time, v) -> dict:
    base = _base(v) + [Filter(field="timestamp", op="exists")]
    total = es.count(inv, base, time)
    if not total:
        return _empty(es, inv, time, v, [Filter(field="timestamp", op="exists")], "시각")
    rows = es.group_by(inv, base, ["src_ip", "dst_ip", "dst_port", "data_source"], [
        GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=GROUP_LIMIT, time=time)
    partial = [f"기록 수 상위 통신 쌍 {GROUP_LIMIT:,}개까지만 계산" if len(rows) >= GROUP_LIMIT else ""]
    items, timelines = [], 0
    for r in rows:
        if r["count"] < v["min_records"] or not r["key"]["src_ip"]:
            continue
        src, dst, port, ds = (r["key"][k] for k in ("src_ip", "dst_ip", "dst_port", "data_source"))
        # The group's own key, including "not recorded": a missing port is not every port.
        pair = [Filter(field="data_source", value=ds), Filter(field="src_ip", value=src),
                Filter(field="dst_ip", value=dst) if dst is not None else Filter(field="dst_ip", op="not_exists"),
                Filter(field="dst_port", value=port) if port is not None else Filter(field="dst_port", op="not_exists")]
        port_label = str(port) if port is not None else "포트 미기록"
        dst_label = dst if dst is not None else "목적지 미기록"
        timelines += 1
        times = []
        for i, e in enumerate(es.iterate(inv, base + pair, time, fields=["timestamp"])):
            if i >= TIMELINE_LIMIT:
                partial.append(f"{src}→{dst_label}:{port_label}: 처음 {TIMELINE_LIMIT:,}건의 간격만 계산")
                break
            t = _ts(e.get("timestamp"))
            if t is not None:
                times.append(t)
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < v["min_records"] - 1:
            continue
        mean = statistics.fmean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv > v["max_cv"]:
            continue
        seconds = f"{mean:,.6f}".rstrip("0").rstrip(".") + "초" if mean >= 1e-6 else "0.000001초 미만"
        items.append(_item(
            f"{src}→{dst_label} ({port_label}) 기록 {r['count']:,}건이 {_approx_interval(mean)} 간격으로 반복",
            f"기록 {r['count']}건이 평균 {seconds} 간격(변동계수 {cv:.2f})으로 발생했습니다. 기록 시각의 주기이며 연결 시작의 주기라고 확정하지 않습니다.",
            {"metric": "기록 간격 변동계수", "threshold_cv": v["max_cv"], "min_records": v["min_records"],
             "observed_cv": cv, "mean_interval_seconds": mean, "intervals_checked": len(gaps)},
            r["count"], _dump(base + pair),
            ["통신을 만든 프로그램·계정", "통신 내용", "기록 시각이 연결 시작인지 여부"],
            ["상태 점검·모니터링 에이전트", "업데이트·동기화·예약 작업"],
            ["이 자산에서 이 주기로 통신하는 프로그램·예약 작업이 있는지", "목적지가 승인된 서비스인지"],
            entities=[f"ip:{src}", f"ip:{dst}"], time={"start": r.get("first"), "end": r.get("last")}))
    return _finish(items, total, {"groups": len(rows), "group_limit": GROUP_LIMIT, "timelines": timelines,
                                  "timeline_limit": TIMELINE_LIMIT}, partial=partial,
                   unconfirmed=["기록 시각이 연결 시작·요청·종료 중 무엇인지는 장비 설정에서 확인"])


BUNDLES = [
    ("web_attack", "A. 웹 공격 시도가 있었고 영향 확인이 필요한가?", _web),
    ("transfer", "B. 어느 방향의 전송량이 기준을 넘었는가?", _transfer),
    ("periodic", "C. 반복 통신이 자동 업무인지 추가 조사 대상인지?", _periodic),
    ("spread", "D. 여러 자산·관리 포트 접근이 점검인지 침해 확산 조사 대상인지?", _spread),
]
TITLES = {key: title for key, title, _ in BUNDLES}

# The ten basic questions an analyst starts from (the reviewed question map). `bundle` names the computation
# connected in SAW; the rest are kept as questions with what they still need, never shown as computed.
QUESTION_MAP = [
    {"id": "Q01", "question": "여러 웹 경로를 탐색했는가?", "bundle": "web_attack", "inputs": ["NDR"]},
    {"id": "Q02", "question": "특수한 입력 뒤 어떤 응답이 있었는가?", "bundle": None, "inputs": ["NDR"],
     "needs": "패턴 태그 집계는 A 질문에 있으나 입력→응답 순서 대조 계산은 아직 연결되지 않았습니다"},
    {"id": "Q03", "question": "로그인 경로 반복이 실제 인증과 연결되는가?", "bundle": None, "inputs": ["NDR", "인증 로그"],
     "needs": "인증 로그 원천이 필요합니다. NDR 응답 코드만으로 로그인 성공·실패를 계산하지 않습니다"},
    {"id": "Q04", "question": "큰 전송은 어떤 업무와 방향에서 발생했는가?", "bundle": "transfer", "inputs": ["NDR", "FW"]},
    {"id": "Q05", "question": "반복 통신은 자동 업무인가 확인할 활동인가?", "bundle": "periodic", "inputs": ["NDR", "FW"]},
    {"id": "Q06", "question": "한 출발지가 여러 대상 또는 포트를 접촉했는가?", "bundle": "spread", "inputs": ["FW", "NDR"]},
    {"id": "Q07", "question": "차단 뒤 허용된 흐름의 범위와 이유는 무엇인가?", "bundle": None, "inputs": ["FW", "정책 변경 기록"],
     "needs": "같은 통신 조건의 처리 결과 순서 계산은 아직 연결되지 않았습니다"},
    {"id": "Q08", "question": "새 통신 상대나 시간 변화는 설명되는가?", "bundle": None, "inputs": ["NDR", "FW", "과거 기준선"],
     "needs": "조사 기간 앞의 기준선 자료와 업무 일정이 필요합니다"},
    {"id": "Q09", "question": "WAF·IPS 경보가 실제 어떤 요청과 연결되는가?", "bundle": None, "inputs": ["WAF·IPS", "NDR", "FW"],
     "needs": "WAF·IPS 원천이 필요합니다. NDR·FW에는 공격명·시그니처가 없습니다"},
    {"id": "Q10", "question": "관측량 변화는 실제 활동인가 수집 문제인가?", "bundle": None, "inputs": ["NDR", "FW", "수집 상태"],
     "needs": "전체 현황의 일별 추이·수집 공백으로 보고, 수집기 상태 자료는 추가로 요청해야 합니다", "view": "overview"},
]


def definitions(sensitivity: str = "normal") -> dict:
    return {key: {"title": TITLES[key], "params": PARAMS[key], "defaults": defaults(key, sensitivity)} for key in PARAMS}


def run_one(inv, bundle: str, values: dict | None, *, sensitivity: str = "normal", time: TimeRange | None = None) -> dict:
    """One question with the given condition on the current logs: the preview and the saved run are this call."""
    v = validate(bundle, values, sensitivity)
    fn = {key: f for key, _, f in BUNDLES}[bundle]
    try:
        result = fn(container.get().events, inv.id, time, v)
    except (ValueError, KeyError) as exc:  # a store that cannot answer one bundle leaves the rest intact
        result = {"status": "failed", "items": [], "error": type(exc).__name__}
    return {"id": bundle, "title": TITLES[bundle], "parameters": v, "description": describe(bundle, v), **result}


def scope_of(inv, time: TimeRange | None) -> dict:
    return {"investigation_id": inv.id, "org_unit_id": getattr(inv, "org_unit_id", None),
            "time": time.model_dump() if time else None, "version": VERSION,
            "run_at": datetime.now(timezone.utc).isoformat()}


def build(inv, *, sensitivity: str = "normal", time: TimeRange | None = None, overrides: dict | None = None) -> dict:
    out = [run_one(inv, key, (overrides or {}).get(key), sensitivity=sensitivity, time=time) for key, _, _ in BUNDLES]
    by = {b["id"]: b for b in out}
    questions = [{**q, "status": by[q["bundle"]]["status"] if q["bundle"] else "not_connected",
                  "completeness": by[q["bundle"]].get("completeness") if q["bundle"] else None} for q in QUESTION_MAP]
    thresholds = SENSITIVITY.get(sensitivity) or SENSITIVITY["normal"]
    return {"version": VERSION, "sensitivity": sensitivity, "thresholds": thresholds, "bundles": out,
            "scope": scope_of(inv, time), "questions": questions, "definitions": definitions(sensitivity),
            "limits": {"items_shown": MAX_ITEMS, "groups": GROUP_LIMIT, "timeline_records": TIMELINE_LIMIT},
            "note": "로그에서 바로 계산한 조사 질문입니다. 판정이 아니며, 근거 없음은 '이 기준에서 보이지 않음'일 뿐 정상이라는 뜻이 아닙니다."}
