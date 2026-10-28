"""Compare what a reply covers with what was asked, before any reply may explain an activity away.

A reply about a different affiliate, period or target is not an explanation of the observed activity.
A reply that covers only part of it explains only that part; the rest stays an open question.
"""
from __future__ import annotations

from datetime import UTC, datetime

ORDER = {"match": 0, "unknown": 1, "partial": 2, "mismatch": 3}
LIST_LABELS = {"src_ips": "출발지", "dst_ips": "목적지", "dst_ports": "목적지 포트"}


def _time(value):
    if value in (None, ""):
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _fmt(value):
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ") if value else "미기재"


def requested_scope(payload: dict, inv_org_unit_id: str | None, inv_period: tuple) -> dict:
    """The request's own target/period, falling back to the investigation's affiliate and declared period."""
    target = payload.get("target") or {}
    period = payload.get("period") or {}
    start = _time(period.get("start")) or _time(inv_period[0] if inv_period else None)
    end = _time(period.get("end")) or _time(inv_period[1] if inv_period else None)
    return {"org_unit_id": target.get("org_unit_id") or inv_org_unit_id, "start": start, "end": end,
            "src_ips": [str(x) for x in target.get("src_ips") or []],
            "dst_ips": [str(x) for x in target.get("dst_ips") or []],
            "dst_ports": [str(x) for x in target.get("dst_ports") or []]}


def compare(requested: dict, reply_scope: dict | None, evidence_events: list[dict], investigation_id: str) -> dict:
    reply = reply_scope or {}
    parts: dict[str, dict] = {}
    uncovered: list[str] = []

    def put(name, status, detail):
        parts[name] = {"status": status, "detail": detail}
        if status in {"partial", "unknown"}:
            uncovered.append(detail)

    if requested["org_unit_id"]:
        if not reply.get("org_unit_id"):
            put("affiliate", "unknown", "회신에 관계사가 적혀 있지 않습니다.")
        elif reply["org_unit_id"] == requested["org_unit_id"]:
            put("affiliate", "match", "회신 관계사가 조사 관계사와 같습니다.")
        else:
            put("affiliate", "mismatch", "회신 관계사가 조사 관계사와 다릅니다.")
    ps, pe = requested["start"], requested["end"]
    if ps and pe:
        rs, re = _time(reply.get("start")), _time(reply.get("end"))
        asked = f"{_fmt(ps)} ~ {_fmt(pe)}"
        if not rs or not re:
            put("period", "unknown", f"회신에 작업 기간이 없어 확인 대상 기간({asked})과 비교할 수 없습니다.")
        elif rs > pe or re < ps:
            put("period", "mismatch", f"회신 기간({_fmt(rs)} ~ {_fmt(re)})이 확인 대상 기간({asked})과 겹치지 않습니다.")
        elif rs > ps or re < pe:
            put("period", "partial", f"회신 기간({_fmt(rs)} ~ {_fmt(re)})이 확인 대상 기간({asked})의 일부만 다룹니다.")
        else:
            put("period", "match", f"회신 기간이 확인 대상 기간({asked})을 포함합니다.")
    for key, label in LIST_LABELS.items():
        wanted = list(dict.fromkeys(requested[key]))
        if not wanted:
            continue
        given = {str(x) for x in reply.get(key) or []}
        if not given:
            put(key, "unknown", f"회신에 {label}가 적혀 있지 않습니다.")
            continue
        missing = [x for x in wanted if x not in given]
        if len(missing) == len(wanted):
            put(key, "mismatch", f"회신의 {label}({', '.join(sorted(given))})가 확인 대상({', '.join(wanted)})과 다릅니다.")
        elif missing:
            put(key, "partial", f"회신이 {label} {', '.join(missing)}를 다루지 않습니다.")
        else:
            put(key, "match", f"회신이 확인 대상 {label}를 모두 다룹니다.")
    if evidence_events:
        foreign = [e for e in evidence_events if e.get("investigation_id") not in (None, investigation_id)]
        outside = [e for e in evidence_events
                   if ps and pe and (_time(e.get("timestamp")) is None or not ps <= _time(e.get("timestamp")) <= pe)]
        if foreign:
            put("evidence", "mismatch", f"근거 기록 {len(foreign)}건이 다른 조사의 기록입니다.")
        elif outside and len(outside) == len(evidence_events):
            put("evidence", "mismatch", "근거 기록이 모두 확인 대상 기간 밖입니다.")
        elif outside:
            put("evidence", "partial", f"근거 기록 {len(outside)}건이 확인 대상 기간 밖입니다.")
        else:
            put("evidence", "match", f"근거 기록 {len(evidence_events)}건이 확인 대상 범위 안에 있습니다.")
    if not parts:
        return {"result": "no_request_scope", "components": {}, "uncovered": [],
                "summary": "확인 요청과 조사에 대상·기간이 없어 회신 범위를 비교하지 못했습니다."}
    stated = any(reply.get(k) for k in ("org_unit_id", "src_ips", "dst_ips", "dst_ports", "start", "end"))
    worst = max(parts.values(), key=lambda part: ORDER[part["status"]])["status"]
    if not stated and worst != "mismatch":
        # Attached records show what was observed, not what the reply covers: a reply that states no
        # affiliate, target or period cannot be matched to the activity, whatever evidence is attached.
        worst = "unknown"
        parts = {k: v for k, v in parts.items() if k != "evidence"} or parts
    if worst == "mismatch":
        result = "mismatch"
    elif worst == "match":
        result = "matches"
    elif any(part["status"] == "match" for part in parts.values()):
        result = "partial"
    else:
        result = "not_stated"
    summary = {"matches": "회신 범위가 확인 대상과 일치합니다.",
               "partial": "회신이 확인 대상의 일부만 설명합니다. 남은 부분은 계속 확인이 필요합니다.",
               "mismatch": "회신의 관계사·기간·대상이 확인 대상과 다릅니다. 이 회신으로 해당 행위를 설명할 수 없습니다.",
               "not_stated": "회신에 범위가 적혀 있지 않아 같은 행위에 대한 설명인지 확인할 수 없습니다."}[result]
    return {"result": result, "components": parts, "uncovered": uncovered, "summary": summary}
