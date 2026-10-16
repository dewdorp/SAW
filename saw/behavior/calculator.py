"""Pure bounded CES behavior measurements. No actor attribution or production verdicts."""
from __future__ import annotations

import hashlib
import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from saw.core.security.masking import mask_text

from saw.behavior.definitions import (
    FOLLOWUP_QUESTION_VERSION, followup_questions,
    DEFINITIONS_VERSION, MAX_BUCKETS, MAX_EVENTS, MAX_EVIDENCE, MAX_FIELD_LENGTH,
    MAX_INPUT_BYTES, MAX_METRIC_EVIDENCE, MAX_PARTITIONS, MAX_SECONDS, MAX_SUMMARY_VALUES, METRICS, resolve_profile,
)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FIELDS = ("event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "hostname", "method", "uri", "url_path",
           "status_code", "user_agent", "enforcement_action", "data_source", "source_file", "sensor_id", "source_id",
           "request_id", "evidence_id", "file_id", "parser", "parser_version", "product", "event_type", "raw_redacted")
_UA_STATES = ("present", "recorded_empty", "not_collected", "unknown")


class BehaviorCancelled(RuntimeError):
    pass


@dataclass
class _Budget:
    started: float
    seconds: float
    cancel: Any
    reason: str | None = None
    last_cancel: float = 0.0

    def check(self):
        now = time.monotonic()
        if self.cancel is not None and (not self.last_cancel or now - self.last_cancel >= 0.25):
            self.last_cancel = now
            if self.cancel():
                raise BehaviorCancelled("behavior calculation cancelled")
        if time.monotonic() - self.started >= self.seconds:
            self.reason = self.reason or "max_seconds"
            return False
        return True


@dataclass
class _Row:
    event: dict
    ts: int | None
    src: str | None
    service: str | None
    path: str | None
    ua_state: str
    precision: str
    refs: list[dict] = field(default_factory=list)


def _present(value):
    return value is not None and value != "" and value != "-"


def _ts(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        delta = dt.astimezone(timezone.utc) - _EPOCH
        return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    except (ValueError, OverflowError):
        return None


def _iso(value):
    if value is None:
        return None
    try:
        return (_EPOCH + timedelta(microseconds=value)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except OverflowError:
        return None


def _service(ev):
    host = ev.get("hostname") or ev.get("dst_ip")
    if not _present(host):
        return None
    # Brackets delimit colon-bearing hosts; escape literal delimiters first.
    # A bare IPv6 address ending in :443 is not the same service as IPv6 + port 443.
    host = str(host)
    escaped = host.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    label = f"[{escaped}]" if ":" in host else escaped
    if _present(ev.get("dst_port")):
        port = str(ev["dst_port"]).replace("\\", "\\\\").replace(":", "\\:")
        port = port.replace("[", "\\[").replace("]", "\\]")
        label += ":" + port
    return label


def _row(ev):
    slim = {key: ev[key] for key in _FIELDS if key in ev and isinstance(ev[key], (str, int, float, bool, type(None)))}
    ext = ev.get("ext")
    obs = ext.get("saw_observation", {}) if isinstance(ext, dict) else {}
    if not isinstance(obs, dict):
        obs = {}
    ua_state = obs.get("user_agent")
    if ua_state not in _UA_STATES:
        ua_state = "present" if _present(slim.get("user_agent")) else "unknown"
    precision = obs.get("timestamp_precision")
    if precision not in ("seconds", "subseconds"):
        precision = "unknown"
    slim["ext"] = {"saw_observation": {"user_agent": ua_state, "timestamp_precision": precision}}
    raw_ref = ev.get("raw_ref")
    if isinstance(raw_ref, dict):
        slim["raw_ref"] = {k: v for k, v in raw_ref.items() if k in (
            "object_key", "offset", "length", "line_no", "enc") and isinstance(v, (str, int))
                           and (not isinstance(v, str) or len(v) <= MAX_FIELD_LENGTH)}
    if isinstance(ev.get("raw_event"), str):
        slim["raw_event"] = mask_text(ev["raw_event"]).text[:4096]
        slim["raw_sha256"] = hashlib.sha256(ev["raw_event"].encode("utf-8")).hexdigest()
        slim["raw_truncated"] = len(ev["raw_event"]) > 4096 or bool(ev.get("raw_truncated"))
    tags = ev.get("tags")
    if isinstance(tags, list):
        slim["tags"] = sorted({t for t in tags[:256] if isinstance(t, str) and len(t) <= 128
                               and t.startswith(("sig:", "pattern:"))})[:64]
    if isinstance(slim.get("status_code"), str):
        try:
            slim["status_code"] = int(slim["status_code"])
        except ValueError:
            slim.pop("status_code")
    uri = slim.get("uri")
    path = uri.partition("?")[0] if isinstance(uri, str) and uri else slim.get("url_path")
    return _Row(slim, _ts(slim.get("timestamp")), str(slim["src_ip"]) if _present(slim.get("src_ip")) else None,
                _service(slim), path if _present(path) else None, ua_state, precision)


def _excluded(row, profile):
    return row.event.get("method") in profile["exclude_methods"] or bool(
        row.path and any(row.path.endswith(s) for s in profile["static_suffixes"]))


def _eligible(row, metric_id, profile):
    if row.ts is None or row.src is None or row.service is None:
        return False
    ev = row.event
    if metric_id in ("requests_10s", "paths_60s", "repeats_60s"):
        if _excluded(row, profile) or not _present(ev.get("method")) or not row.path:
            return False
        return metric_id != "repeats_60s" or _present(ev.get("uri"))
    if metric_id == "status404_60s":
        return isinstance(ev.get("status_code"), int) and not isinstance(ev.get("status_code"), bool)
    return row.ua_state in ("present", "recorded_empty")


def _ids(rows):
    out = []
    for row in rows:
        for ev in [row.event, *row.refs]:
            eid = ev.get("event_id")
            if eid and eid not in out:
                out.append(eid)
                if len(out) == MAX_METRIC_EVIDENCE:
                    return out
    return out


def _peak(groups, metric_id, seconds, profile, budget):
    best = qualified = None
    steps = 0
    for group_key in sorted(groups):
        full = groups[group_key]
        eligible = [r for r in full if _eligible(r, metric_id, profile)]
        rows = full if metric_id == "ua_600s" and eligible else eligible
        if not rows:
            continue
        counts, frequencies = Counter(), Counter()
        maximum = n404 = right = 0

        def key(row):
            if metric_id == "paths_60s":
                return row.path
            if metric_id == "repeats_60s":
                return (row.event["method"], row.event["uri"])
            if metric_id == "ua_600s":
                return row.event.get("user_agent") if row.ua_state == "present" else None
            return None

        def update(row, delta):
            nonlocal n404, maximum
            if row.event.get("status_code") == 404:
                n404 += delta
            k = key(row)
            if k is not None:
                before = counts[k]
                if before:
                    frequencies[before] -= 1
                after = before + delta
                if after:
                    counts[k] = after
                    frequencies[after] += 1
                    maximum = max(maximum, after)
                else:
                    del counts[k]
                while maximum and not frequencies[maximum]:
                    maximum -= 1

        left = 0
        while left < len(rows):
            steps += 1
            if steps % 256 == 0 and not budget.check():
                return best, qualified
            start = rows[left].ts
            end = start + seconds * 1_000_000
            while right < len(rows) and rows[right].ts < end:
                update(rows[right], 1)
                right += 1
            value = (right - left if metric_id == "requests_10s" else
                     n404 if metric_id == "status404_60s" else
                     maximum if metric_id == "repeats_60s" else len(counts))
            candidate = {"value": value, "start": start, "end": end, "key": group_key,
                         "rows": rows, "left": left, "right": right, "status404": n404}
            if best is None or value > best["value"]:
                best = candidate
            if metric_id == "ua_600s" and value >= profile["thresholds"][metric_id] and n404 >= profile["ua_min_404"]:
                if qualified is None or value > qualified["value"]:
                    qualified = candidate
            # Equal timestamps are an unordered group, never artificial successive starts.
            while left < len(rows) and rows[left].ts == start:
                update(rows[left], -1)
                left += 1
    return best, qualified


def _metrics(rows, groups, profile, budget):
    metrics, selected = [], []
    for metric_id, label, seconds, unit, reference in METRICS:
        excluded = sum(_excluded(r, profile) for r in rows) if metric_id in (
            "requests_10s", "paths_60s", "repeats_60s") else 0
        eligible = sum(_eligible(r, metric_id, profile) for r in rows)
        peak, qualifying = _peak(groups, metric_id, seconds, profile, budget) if eligible and budget.check() else (None, None)
        excluded_only = bool(rows) and excluded == len(rows) and all(
            r.ts is not None and r.src is not None and r.service is not None
            and _present(r.event.get("method")) and r.path for r in rows)
        window, refs, partial_window = None, [], True
        value = peak["value"] if peak else (0 if excluded_only else None)
        status404 = peak["status404"] if peak else None
        if peak:
            src, service = peak["key"]
            window = {"start": _iso(peak["start"]), "end_exclusive": _iso(peak["end"]), "src_ip": src, "service": service}
            part = groups[peak["key"]]
            partial_window = part[-1].ts < peak["end"]
            candidates = peak["rows"][peak["left"]:peak["right"]]
            if metric_id == "repeats_60s":
                counts = Counter((r.event["method"], r.event["uri"]) for r in candidates)
                repeat_key = min(k for k, n in counts.items() if n == peak["value"])
                candidates = [r for r in candidates if (r.event["method"], r.event["uri"]) == repeat_key]
            elif metric_id == "status404_60s":
                candidates = [r for r in candidates if r.event.get("status_code") == 404]
            elif metric_id in ("ua_600s", "paths_60s"):
                distinct = {}
                for r in candidates:
                    key = r.event.get("user_agent") if metric_id == "ua_600s" else r.path
                    if key is not None and key not in distinct:
                        distinct[key] = r
                candidates = list(distinct.values())
            sample = candidates[:MAX_METRIC_EVIDENCE]
            refs = _ids(sample)
            selected.extend(sample)
        missing = len(rows) - excluded - eligible
        if metric_id == "ua_600s":
            missing = max(missing, sum(not isinstance(r.event.get("status_code"), int) for r in rows))
        qualifying_window = None
        if qualifying:
            qrows = qualifying["rows"][qualifying["left"]:qualifying["right"]]
            qsample = []
            seen_ua = set()
            for r in qrows:
                ua = r.event.get("user_agent")
                if r.event.get("status_code") == 404 or (r.ua_state == "present" and ua not in seen_ua):
                    qsample.append(r)
                    seen_ua.add(ua)
                if len(qsample) >= MAX_METRIC_EVIDENCE:
                    break
            qualifying_window = {"start": _iso(qualifying["start"]), "end_exclusive": _iso(qualifying["end"]),
                                 "src_ip": qualifying["key"][0], "service": qualifying["key"][1],
                                 "value": qualifying["value"], "status404": qualifying["status404"],
                                 "evidence_ids": _ids(qsample)}
            selected.extend(qsample)
        state = ("not_collected" if not eligible and not excluded_only else
                 "partial" if missing or budget.reason else "available")
        meets = value is not None and value >= profile["thresholds"][metric_id]
        if metric_id == "ua_600s":
            meets = qualifying is not None
        result = ("unavailable" if value is None else "threshold_met" if meets else
                  "insufficient_data" if partial_window or state != "available" else "below_threshold")
        metrics.append({"id": metric_id, "label": label, "window_seconds": seconds, "unit": unit,
                        "value": value, "data_state": state, "result": result, "window": window,
                        "reference_threshold": reference, "applied_threshold": profile["thresholds"][metric_id],
                        "excluded_count": excluded, "eligible_count": eligible, "partial_window": partial_window,
                        "evidence_ids": refs, "missing_count": max(0, missing),
                        **({"status404_in_window": status404, "required_status404": profile["ua_min_404"],
                            "qualifying_window": qualifying_window}
                           if metric_id == "ua_600s" else {})})
    return metrics, selected


def _counts(rows, field):
    values = Counter(str(r.event[field]) for r in rows if _present(r.event.get(field)))
    return dict(sorted(values.items(), key=lambda pair: (-pair[1], pair[0]))[:MAX_SUMMARY_VALUES]) or None


def _timeline(rows, metrics):
    timed = [r for r in rows if r.ts is not None]
    if not timed:
        return {"interval_seconds": None, "timezone": "UTC", "buckets": [], "annotations": [],
                "coverage_label": "관측 시각 없음 · 수집 연속성 확인 불가"}
    first, last = min(r.ts for r in timed), max(r.ts for r in timed)
    interval = max(1, math.ceil((last - first + 1) / (MAX_BUCKETS * 1_000_000)))
    width = interval * 1_000_000
    size = (last - first) // width + 1
    buckets = [{"start": _iso(first + i * width), "end_exclusive": _iso(first + (i + 1) * width),
                "count": 0, "status404": None, "blocked": None, "allowed": None, "ua_values": None}
               for i in range(size)]
    uas = defaultdict(set)
    for r in timed:
        idx = (r.ts - first) // width
        bucket = buckets[idx]
        bucket["count"] += 1
        if isinstance(r.event.get("status_code"), int):
            bucket["status404"] = (bucket["status404"] or 0) + (r.event["status_code"] == 404)
        action = r.event.get("enforcement_action")
        if action in ("blocked", "allowed"):
            bucket["blocked"] = (bucket["blocked"] or 0) + (action == "blocked")
            bucket["allowed"] = (bucket["allowed"] or 0) + (action == "allowed")
        if r.ua_state in ("present", "recorded_empty"):
            if r.ua_state == "present" and _present(r.event.get("user_agent")):
                uas[idx].add(r.event["user_agent"])
            bucket["ua_values"] = len(uas[idx])
    annotations = [{"metric_id": m["id"], **m["window"], "value": m["value"]} for m in metrics if m["window"]]
    return {"interval_seconds": interval, "timezone": "UTC", "buckets": buckets, "annotations": annotations,
            "coverage_label": "빈 구간은 관측 없음 · 수집 연속성 확인 불가 · 모델 호출 기록 미수집"}


def _indicators(rows):
    indicators, selected = [], []
    definitions = (
        ("norma_ua", "norma/0.4 문자열", "norma/0.4", "conditional_code_derived",
         "코드에서 정의한 조건부 문자열. 첨부 문서의 ARTEX 기본 실행 01/02에서는 관측되지 않음."),
        ("spa_api_recon_ua", "spa-api-recon 문자열", "spa-api-recon", "conditional_code_derived",
         "코드에서 정의한 조건부 문자열. 기본 실행에서 관측되었다는 뜻이 아님."),
        ("artex_enrich_ua", "artex-enrich/1.0 문자열", "artex-enrich/1.0", "code_defined_unreachable",
         "첨부 문서가 설명한 버전에서 도달 불가능한 코드 경로의 문자열."),
    )
    known = any(r.ua_state in ("present", "recorded_empty") for r in rows)
    for iid, label, needle, verification, conditions in definitions:
        found = [r for r in rows if r.ua_state == "present" and needle in str(r.event.get("user_agent", ""))]
        selected.extend(found[:MAX_METRIC_EVIDENCE])
        indicators.append({"id": iid, "label": label, "category": "tool_string",
                           "state": "observed" if found else "not_observed" if known else "unavailable",
                           "count": len(found) if known else None, "source": "수집된 User-Agent 필드",
                           "verification": verification, "conditions": conditions, "evidence_ids": _ids(found),
                           "limits": ["문자열 일치는 도구 실행·행위자·AI 사용·침해 성공을 입증하지 않음."]})
    for iid, label, category, predicate in (
        ("existing_scanner_tool", "기존 스캐너·도구 문자열 탐지", "scanner_tool",
         lambda tag: tag.startswith(("sig:tool.", "sig:scanner."))),
        ("existing_payload", "기존 요청·페이로드 패턴 탐지", "payload",
         lambda tag: tag.startswith("pattern:") or (tag.startswith("sig:") and not tag.startswith(("sig:tool.", "sig:scanner.")))),
    ):
        found = [r for r in rows if any(predicate(t) for t in r.event.get("tags", []))]
        rule_ids = sorted({t[4:] if t.startswith("sig:") else t for r in found
                           for t in r.event.get("tags", []) if predicate(t)})
        selected.extend(found[:MAX_METRIC_EVIDENCE])
        scanned_fields = any(r.path or r.ua_state in ("present", "recorded_empty") for r in rows)
        indicators.append({"id": iid, "label": label, "category": category,
                           "state": "observed" if found else "not_observed" if scanned_fields else "unavailable",
                           "count": len(found) if scanned_fields else None,
                           "source": "기존 정규화 이벤트의 sig:/pattern: 태그",
                           "verification": "existing_normalized_tags",
                           "conditions": "수집 시 이미 기록된 탐지 태그만 집계; 규칙 재실행이나 새 규칙 적용 아님.",
                           "rule_ids": rule_ids[:100], "evidence_ids": _ids(found),
                           "limits": ["기록된 문자열·패턴 일치는 행위자·도구 실행·공격 성공 판정이 아님.",
                                      "저장 당시 태그가 없으면 현재 규칙으로 탐지되지 않았다고 단정할 수 없음."]})
    for iid, label, source in (
        ("host_artifacts", "호스트 파일·프로세스", "호스트 파일·프로세스 증거"),
        ("console_fingerprint", "관리 콘솔 응답 지문", "실제 콘솔 응답 내용"),
        ("llm_egress", "외부 모델 호출", "명시적 모델 호출 기록 또는 이그레스 증거"),
    ):
        indicators.append({"id": iid, "label": label, "category": "additional_source", "state": "unavailable",
                           "count": None, "source": source, "verification": "not_collected",
                           "conditions": "이 계산기에 검증 가능한 해당 종류의 증거가 제공되지 않음.",
                           "evidence_ids": [], "limits": ["능동 접속이나 외부 조회를 수행하지 않음."]})
    return indicators, selected


def calculate(events, profile=None, *, max_events=100000, max_seconds=120, check_cancel=None):
    """Measure a bounded observed subset; callback exceptions deliberately propagate to the worker."""
    profile = resolve_profile(profile)
    if type(max_events) is not int or max_events < 0:
        raise ValueError("max_events must be a nonnegative integer")
    if not isinstance(max_seconds, (int, float)) or not math.isfinite(max_seconds) or max_seconds < 0:
        raise ValueError("max_seconds must be a finite nonnegative number")
    row_limit = min(max_events, MAX_EVENTS)
    seconds = min(max_seconds, MAX_SECONDS)
    budget = _Budget(time.monotonic(), seconds, check_cancel)
    rows, groups, dedup = [], defaultdict(list), {}
    scanned = removed = estimated_bytes = 0
    input_ua = Counter({k: 0 for k in _UA_STATES})
    input_precision = Counter({"seconds": 0, "subseconds": 0, "unknown": 0})
    for ev in events:
        if not budget.check():
            break
        scanned += 1
        if scanned > row_limit:
            budget.reason = "max_events"
            break
        if not isinstance(ev, dict):
            budget.reason = "invalid_event"
            break
        if any(isinstance(ev.get(k), str) and len(ev[k]) > MAX_FIELD_LENGTH for k in _FIELDS):
            budget.reason = "oversized_field"
            break
        row = _row(ev)
        part = (row.src, row.service) if row.ts is not None and row.src and row.service else None
        if part and part not in groups and len(groups) >= MAX_PARTITIONS:
            budget.reason = "max_partitions"
            break
        estimated_bytes += (sum(len(v.encode("utf-8")) for v in row.event.values() if isinstance(v, str))
                            + sum(len(t.encode("utf-8")) for t in row.event.get("tags", []))
                            + sum(len(v.encode("utf-8")) for v in row.event.get("raw_ref", {}).values() if isinstance(v, str))
                            + 256)
        if estimated_bytes > MAX_INPUT_BYTES:
            budget.reason = "max_input_bytes"
            break
        input_ua[row.ua_state] += 1
        input_precision[row.precision] += 1
        source = row.event.get("sensor_id") or row.event.get("source_id") or row.event.get("source_file")
        request = row.event.get("request_id")
        identity = (request, row.src, row.service, row.event.get("dst_ip"), row.event.get("dst_port"),
                    row.event.get("method"), row.event.get("uri"), row.ts)
        can_dedup = profile["deduplicate_request_id"] and all(_present(v) for v in (
            request, row.src, row.service, row.event.get("method"), row.event.get("uri"), source)) and row.ts is not None
        if can_dedup:
            matches, source_counts = dedup.setdefault(identity, ([], Counter()))
            occurrence = source_counts[source]
            source_counts[source] += 1
            if occurrence < len(matches):
                previous = matches[occurrence]
                if len(previous.refs) < MAX_METRIC_EVIDENCE:
                    previous.refs.append(row.event)
                removed += 1
                continue
            matches.append(row)
        rows.append(row)
        if part:
            groups[part].append(row)
    for group in groups.values():
        group.sort(key=lambda r: (r.ts, str(r.event.get("event_id", ""))))
    metrics, selected = _metrics(rows, groups, profile, budget)
    if budget.reason:
        for m in metrics:
            if m["data_state"] == "available":
                m["data_state"] = "partial"
            if m["result"] == "below_threshold":
                m["result"] = "insufficient_data"
    indicators, indicator_rows = _indicators(rows)
    selected.extend(indicator_rows)
    selected.extend(rows[:16])
    evidence = {}
    wanted = {eid for item in [*metrics, *indicators] for eid in item["evidence_ids"]}
    for m in metrics:
        wanted.update((m.get("qualifying_window") or {}).get("evidence_ids", []))
    for row in selected:
        for ev in [row.event, *row.refs]:
            eid = ev.get("event_id")
            if eid and eid in wanted and eid not in evidence and len(evidence) < MAX_EVIDENCE:
                evidence[eid] = ev
    for row in rows[:16]:
        eid = row.event.get("event_id")
        if eid and eid not in evidence and len(evidence) < MAX_EVIDENCE:
            evidence[eid] = row.event
    timed = [r.ts for r in rows if r.ts is not None]
    ties = Counter(timed)
    sources = {str(r.event.get("data_source")) for r in rows if r.event.get("data_source")}
    paths = {r.path for r in rows if r.path}
    limits = [
        "참고 임계값 도달은 공격·AI 사용·침해 성공 판정이 아니며 인가 점검·배치·NAT 공유도 원인이 될 수 있음.",
        "수집된 관측의 최대값이며 전체 HTTP 요청량이나 관측하지 않은 범위를 대표하지 않음.",
        "동일 요청 후보는 메서드·원본 URI·서비스가 같은 기록이며 본문 동일성을 보장하지 않음.",
        "동일 시각 기록의 인과 순서는 판단하지 않음. 빈 구간은 관측 없음이며 수집 장애로 단정하지 않음.",
        "User-Agent의 기록된 빈 값은 헤더가 실제 없었다는 증거가 아님.",
        "서로 다른 센서·원본의 중복 관측 가능성이 있으며 기본 설정은 중복을 제거하지 않음.",
    ]
    if budget.reason:
        limits.append(f"입력 또는 계산 상한 도달({budget.reason}): 표시값은 처리된 부분집합의 관측값임.")
    cardinalities = {key: len({str(r.event[key]) for r in rows if _present(r.event.get(key))})
                     for key in ("method", "status_code", "enforcement_action", "user_agent")}
    if any(n > MAX_SUMMARY_VALUES for n in cardinalities.values()):
        limits.append("범주별 목록은 상위 100개까지만 표시하며 원래 고유 값 수는 품질 항목에 제공함.")
    source_basis = "수집된 WAF 이벤트" if sources and sources <= {"waf"} else "수집된 관측 이벤트"
    return {
        "methodology": {"definitions_version": DEFINITIONS_VERSION, "question_version": FOLLOWUP_QUESTION_VERSION,
                        "source_basis": source_basis,
                        "window": "[start, end)", "partition_by": ["src_ip", "hostname_or_dst_ip", "dst_port"],
                        "peak": "실제 관측 시각에 고정한 모든 시작점의 최대값",
                        "reference": "첨부 Theori ARTEX 백서 표 7 및 부록 A.2",
                        "static_selector": "정적 접미사 목록은 결과에 공개한 SAW 로컬 선택 조건",
                        "ua_peak": "전체 UA 최대값과 404 동반 임계값 조건을 만족한 창을 별도로 보존",
                        "deduplication": "request_id_exact_cross_source" if profile["deduplicate_request_id"] else "none"},
        "profile": profile,
        "summary": {"count": len(rows), "first": _iso(min(timed)) if timed else None,
                    "last": _iso(max(timed)) if timed else None, "methods": _counts(rows, "method"),
                    "services": sorted({r.service for r in rows if r.service})[:MAX_SUMMARY_VALUES] or None,
                    "status_codes": _counts(rows, "status_code"), "actions": _counts(rows, "enforcement_action"),
                    "unique_paths": len(paths) if paths else None, "user_agents": _counts(rows, "user_agent")},
        "quality": {"user_agent": dict(input_ua), "timestamp_precision": dict(input_precision),
                    "field_denominator": len(rows), "producer_observation_denominator": len(rows) + removed,
                    "data_sources": _counts(rows, "data_source"),
                    "timestamp_ties": sum(n for n in ties.values() if n > 1),
                    "missing_timestamp": sum(r.ts is None for r in rows),
                    "missing_src_ip": sum(r.src is None for r in rows),
                    "missing_service": sum(r.service is None for r in rows),
                    "field_coverage": {key: sum(_present(r.event.get(key)) for r in rows)
                                       for key in ("method", "uri", "status_code", "user_agent", "enforcement_action")},
                    "categorical_unique_counts": cardinalities,
                    "multi_source_duplicate_risk": len({r.event.get("sensor_id") or r.event.get("source_file")
                                                        for r in rows}) > 1,
                    "collection_continuity": "unknown"},
        "metrics": metrics, "timeline": _timeline(rows, metrics), "indicators": indicators,
        "followups": followup_questions(indicators),
        "limits": limits,
        "execution": {"scanned": scanned, "processed": len(rows) + removed, "deduplicated": removed,
                      "truncated": bool(budget.reason), "reason": budget.reason,
                      "elapsed_ms": round((time.monotonic() - budget.started) * 1000, 3), "estimated_input_bytes": estimated_bytes,
                      "limits": {"max_events": row_limit, "max_seconds": seconds, "max_partitions": MAX_PARTITIONS,
                                 "max_buckets": MAX_BUCKETS, "max_evidence": MAX_EVIDENCE, "max_input_bytes": MAX_INPUT_BYTES,
                                 "max_summary_values": MAX_SUMMARY_VALUES, "max_field_length": MAX_FIELD_LENGTH}},
        "evidence_events": list(evidence.values()),
    }
