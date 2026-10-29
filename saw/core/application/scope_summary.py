"""One investigation's whole picture for the analyst: scope, what came in, what could be used, and what happened.

Every number states its basis: all events of the investigation, or the current filter. Opening a candidate
never changes these denominators. Nothing here is a baseline or a judgement; it is counting.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from saw import container
from saw.config import get_settings
from saw.core.application.investigations import declared_period
from saw.core.application.statistics import bounds
from saw.core.schemas.query import AggRequest, Filter, TimeRange

TOP = 10
BREAKDOWNS = (("data_source", "로그 종류", 20), ("enforcement_action", "처리 결과", 10), ("alert_name", "장비 공격명", TOP),
              ("src_ip", "출발지", TOP), ("dst_ip", "목적지", TOP), ("dst_port", "목적지 포트", TOP),
              ("protocol", "프로토콜", TOP))
ACTION_KO = {"allowed": "허용", "blocked": "차단", "detected": "탐지(경보만)", "monitored": "모니터링",
             "conflicting": "기록 간 처리값 충돌", "unmapped": "해석하지 못한 처리값"}
INCOMPLETE = {"partial": "일부만 처리", "limited": "한도 도달", "insufficient_data": "자료 부족", "failed": "실패",
              "cancelled": "취소", "skipped": "미실행", "not_applicable": "적용 대상 없음"}
# Why a detector did not finish, so "not analyzed" is never read as "analyzed, nothing found".
REASONS = {"unverified_device_context": "기록의 장비(출처)가 등록·확인되지 않아 분석하지 않았습니다. 관계사·장비(출처)를 등록하면 분석됩니다.",
           "unresolved_context": "기록의 장비(출처)가 등록·확인되지 않아 분석하지 않았습니다. 관계사·장비(출처)를 등록하면 분석됩니다.",
           "no_records_in_scope": "등록된 장비 범위에 속한 기록이 없어 분석하지 않았습니다. 관계사·장비(출처)를 등록하면 분석됩니다.",
           "policy_disabled": "이 장비 관측 기준이 꺼져 있어 분석하지 않았습니다.",
           "partitioned_execution": "장비 범위별로 나눠 실행했고 일부 범위는 완료되지 않았습니다.",
           "runtime_record_limit": "기록 수 한도에 도달해 일부만 분석했습니다.",
           "required_source_missing": "필요한 로그 종류가 없어 분석하지 않았습니다."}


def _parse(value):
    if not value:
        return None
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _coverage(f: dict) -> dict:
    if isinstance(f.get("coverage"), dict):
        return f["coverage"]
    return next((x["coverage"] for x in f.get("error_samples") or [] if isinstance(x, dict) and "coverage" in x), {})


def _inputs(es, s, inv_id) -> dict:
    rows, totals = [], {"lines": 0, "events": 0, "failed_lines": 0, "rejected_events": 0,
                        "timestamp_missing": 0, "timestamp_invalid": 0}
    unsupported = with_notes = 0
    for f in es.file_state(s, inv_id):
        status = f.get("parse_status") or ""
        if status in ("", "pending", "extracted", "container") and not f.get("parser_id"):
            continue
        cov = _coverage(f)
        for key in totals:
            totals[key] += int(cov.get(key) or 0)
        if not cov:
            totals["events"] += int(f.get("events_parsed") or 0)
            totals["failed_lines"] += int(f.get("events_failed") or 0)
        if not f.get("parser_id") or status in ("failed", "skipped", "waiting_input"):
            unsupported += 1
        message = (f.get("message") or "").strip()
        with_notes += bool(message and message != "no lines parsed")
        rows.append({"name": f.get("display_name") or f.get("name") or f.get("id"), "parser_id": f.get("parser_id"),
                     "status": status, "events": int(f.get("events_parsed") or 0),
                     "failed": int(f.get("events_failed") or 0), "message": message[:1000],
                     "timestamp_missing": int(cov.get("timestamp_missing") or 0),
                     "timestamp_invalid": int(cov.get("timestamp_invalid") or 0)})
    return {"files": len(rows), "unsupported_files": unsupported, "files_with_notes": with_notes,
            **totals, "by_file": rows[:200], "files_truncated": len(rows) > 200}


def _days(es, inv_id, filters, time, start, end, zone) -> dict:
    """Daily (and ISO-weekly) counts in the investigation's timezone, with empty days kept visible."""
    if not start or not end:
        return {"daily": [], "weekly": [], "empty_days": [], "interval_sec": None}
    hist = es.aggregate(inv_id, filters, AggRequest(type="date_histogram", field="timestamp", interval_sec=3600), time)
    per_day: dict[date, int] = {}
    for bucket in hist.get("buckets", []):
        day = datetime.fromtimestamp(bucket["key"], tz=UTC).astimezone(zone).date()
        per_day[day] = per_day.get(day, 0) + bucket["count"]
    first, last = start.astimezone(zone).date(), end.astimezone(zone).date()
    daily, empty, weekly = [], [], OrderedDict()
    day = first
    while day <= last and len(daily) < 800:
        n = per_day.get(day, 0)
        daily.append({"date": day.isoformat(), "count": n})
        if not n:
            empty.append(day.isoformat())
        year, week, _ = day.isocalendar()
        key = f"{year}-W{week:02d}"
        weekly[key] = weekly.get(key, 0) + n
        day += timedelta(days=1)
    return {"daily": daily, "weekly": [{"week": k, "count": v} for k, v in weekly.items()],
            "empty_days": empty, "interval_sec": hist.get("interval_sec")}


def _analysis(s, inv_id) -> dict | None:
    from saw.analysis_runs.models import AnalysisRun, DetectorExecution

    run = s.scalar(select(AnalysisRun).where(AnalysisRun.investigation_id == inv_id)
                   .order_by(AnalysisRun.version.desc()).limit(1))
    if run is None:
        return None
    incomplete = []
    for e in s.scalars(select(DetectorExecution).where(DetectorExecution.run_id == run.id)):
        if e.status not in INCOMPLETE or e.status == "not_applicable":
            continue
        detail = e.detail if isinstance(e.detail, dict) else {}
        seen = {str(r) for r in detail.get("limitations") or []} | {str(r) for r in detail.get("quality") or {}}
        seen.add(str(detail.get("reason")))
        reason = next((r for r in REASONS if r in seen), None)
        incomplete.append({"detector_id": e.detector_id, "status": e.status, "label": INCOMPLETE[e.status],
                           "reason": reason, "reason_label": REASONS.get(reason)})
    return {"run_id": run.id, "version": run.version, "status": run.status, "finished_at": run.finished_at,
            "incomplete": sorted(incomplete, key=lambda x: x["detector_id"])[:50]}


def build(s, inv, filters: list[Filter], time: TimeRange | None) -> dict:
    es = container.get().events
    zone = ZoneInfo(get_settings().default_timezone)
    filtered = bool(filters or time)
    all_events = es.count(inv.id, [], None)
    basis_events = es.count(inv.id, filters, time) if filtered else all_events
    observed = bounds(es, inv.id, [], None)
    period = declared_period(inv)
    p_start, p_end = _parse(period[0]), _parse(period[1])
    with_time = es.count(inv.id, [Filter(field="timestamp", op="exists")], None)
    outside = None
    if p_start and p_end:
        before = es.count(inv.id, [], TimeRange(end=(p_start - timedelta(milliseconds=1)).isoformat()))
        after = es.count(inv.id, [], TimeRange(start=(p_end + timedelta(milliseconds=1)).isoformat()))
        outside = {"before": before, "after": after}
    breakdown = {}
    for field, label, size in BREAKDOWNS:
        agg = es.aggregate(inv.id, filters, AggRequest(type="terms", field=field, size=size), time)
        breakdown[field] = {"label": label, "buckets": agg.get("buckets", []), "other": agg.get("other", 0),
                            "recorded": agg.get("total", 0), "not_recorded": max(0, basis_events - agg.get("total", 0))}
    for bucket in breakdown["enforcement_action"]["buckets"]:
        bucket["label"] = ACTION_KO.get(str(bucket["key"]), str(bucket["key"]))
    range_start = p_start or _parse(observed[0])
    range_end = p_end or _parse(observed[1])
    return {
        "scope": {"org_unit": inv.org_unit or "", "org_unit_id": inv.org_unit_id,
                  "period_start": period[0], "period_end": period[1], "period_declared": bool(p_start),
                  "observed_start": observed[0], "observed_end": observed[1], "timezone": str(zone)},
        "basis": {"kind": "filter" if filtered else "all", "all_events": all_events, "events": basis_events,
                  "note": ("현재 필터·시간 범위의 기록입니다. 조사 전체는 all_events입니다." if filtered
                           else "조사 전체 기록 기준입니다.")},
        "time": {"with_timestamp": with_time, "without_timestamp": max(0, all_events - with_time),
                 "outside_period": outside, **_days(es, inv.id, filters, time, range_start, range_end, zone)},
        "inputs": _inputs(es, s, inv.id),
        "breakdown": breakdown,
        "analysis": _analysis(s, inv.id),
        "method_note": "규칙 기반 집계입니다. 모델 판단이나 장기 정상 기준선 비교가 아닙니다.",
    }
