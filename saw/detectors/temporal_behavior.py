"""Bounded same-source temporal comparisons using strictly earlier observed windows."""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone

from saw.core.schemas.query import Filter
from saw.detectors.base import FindingDraft, check, metric

SOURCES = {"web", "waf", "zeek_http", "zeek_conn"}
FIELDS = ["event_id", "data_source", "timestamp", "src_ip", "dst_ip", "dst_port", "status_code", "bytes_out"]
# max_groups bounds the windows held at once. Windows are evaluated as soon as a later window of the same series
# appears and then dropped, so a one-to-three month investigation no longer exhausts it.
LIMITS = {"max_events": 500000, "max_series": 200, "max_groups": 5000,
          "max_findings": 10, "max_samples": 20, "max_aliases": 32}
PRIOR = 6
WIDTH = 900
RULES = {"requests": (20, 4, 0, "기록 수"), "error_ratio": (0.6, 0, 0.4, "오류 응답 비율"),
         "bytes_per_event": (65536, 8, 0, "기록당 bytes_out")}


def _identity(event):
    try:
        source, destination = event.get("src_ip"), event.get("dst_ip")
        if not all(isinstance(x, str) and len(x) <= 64 for x in (source, destination)):
            return None
        source, destination = str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination))
        port = event.get("dst_port")
        if type(port) is not int or not 1 <= port <= 65535 or event.get("data_source") not in SOURCES:
            return None
        stamp = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
        if stamp.tzinfo is None or not math.isfinite(stamp.timestamp()):
            return None
        return (event["data_source"], source, destination, port), int(stamp.timestamp() // 900) * 900
    except (ValueError, TypeError, KeyError, OverflowError, OSError, AttributeError):
        return None


def _features(group):
    required = math.ceil(group["count"] * 0.8)
    return {"requests": group["count"],
            "error_ratio": group["errors"] / group["status_known"] if group["status_known"] >= required else None,
            "bytes_per_event": group["bytes"] / group["bytes_known"] if group["bytes_known"] >= required else None}


class TemporalBehavior:
    id, version, category, stage = "anomaly.temporal", "1.0.0", "anomaly.temporal", "UNCLASSIFIED"
    data_sources = SOURCES

    def run(self, ctx):
        limits = dict(LIMITS)
        supplied = ctx.params.get("temporal_limits")
        for name, value in (supplied.items() if isinstance(supplied, dict) else []):
            if name in limits and type(value) is int and 1 <= value <= LIMITS[name]:
                limits[name] = value
        # series key -> {"first": first window, "windows": {window: group}} holding only recent windows
        series, scanned, held, partial = {}, 0, 0, False
        reasons = Counter()
        found, candidates = [], 0
        first_seen = last_seen = None
        base = [Filter(field="data_source", op="in", value=sorted(SOURCES))]

        def evaluate(key, window, state):
            nonlocal candidates
            windows = state["windows"]
            group = windows[window]
            previous = [window - i * WIDTH for i in range(PRIOR, 0, -1)]
            if window == state["first"] or any(w not in windows or w == state["first"] for w in previous):
                reasons["insufficient_baseline_windows"] += 1
                return
            if group["count"] < 10 or any(windows[w]["count"] < 10 for w in previous):
                reasons["insufficient_sample_windows"] += 1
                return
            counts = [windows[w]["count"] for w in previous]
            median = statistics.median(counts)
            mad = statistics.median(abs(x - median) for x in counts)
            if mad / median > 0.25 or max(counts) / min(counts) > 2:
                reasons["unstable_baseline_windows"] += 1
                return
            features = {w: _features(windows[w]) for w in [*previous, window]}
            signals, known = [], 0
            for name, (floor, ratio, difference, label) in RULES.items():
                observed = features[window][name]
                values = [features[w][name] for w in previous]
                if observed is None or any(x is None for x in values):
                    continue
                known += 1
                median = statistics.median(values)
                mad = statistics.median(abs(x - median) for x in values)
                threshold = max(floor, median * ratio, median + difference, median + 6 * mad)
                if observed >= threshold and observed > median + 6 * mad:
                    signals.append(metric(name, round(observed, 5), {
                        "min": median, "max": threshold, "median": median, "mad": mad, "windows": PRIOR,
                        "start": datetime.fromtimestamp(previous[0], timezone.utc).isoformat(),
                        "end": datetime.fromtimestamp(window, timezone.utc).isoformat(),
                        "source": "relative:same_source_destination_service_prior_windows"}, label=label))
            if known < len(RULES):
                reasons["missing_metric_windows"] += 1
            if len(signals) < 2:
                return
            candidates += 1
            if len(found) >= limits["max_findings"]:
                return
            data_source, source, destination, port = key
            start = datetime.fromtimestamp(window, timezone.utc)
            end = start + timedelta(seconds=WIDTH, microseconds=-1)
            filters = [Filter(field="data_source", value=data_source).model_dump(),
                       Filter(field="dst_port", value=port).model_dump()]
            for field, aliases in (("src_ip", group["src_aliases"]), ("dst_ip", group["dst_aliases"])):
                values = sorted(aliases)
                filters.append(Filter(field=field, op="in" if len(values) > 1 else "is",
                                      value=values if len(values) > 1 else values[0]).model_dump())
            found.append(FindingDraft(self.id, self.version, "같은 출발지의 시간별 행동 변화 가능성",
                self.category, self.stage, 0.4, "medium",
                signals + [metric("baseline_windows", PRIOR, label="앞선 비교 구간 수")],
                [check("같은 출발지·목적지·서비스", True, f"{source} → {destination}:{port}", data_source),
                 check("앞선 연속 15분 구간만 비교", True, PRIOR,
                       "직전 90분(15분×6)만 비교합니다. 장기간 정상 기준선이 아니며, 후보 구간과 미래 기록은 제외했습니다."),
                 check("서로 다른 관측 지표 두 개 이상", True, len(signals)),
                 check("수집 연속성·악성 여부", None, "분석가 확인 필요",
                       "정상 배치·업무량·NAT 공유·수집 차이도 원인일 수 있습니다.")],
                [f"ip:{source}"], {"filters": filters, "time": {"start": start.isoformat(), "end": end.isoformat()}},
                start.isoformat(), end.isoformat(),
                f"{self.id}:{data_source}:{source}:{destination}:{port}:{window}",
                success_signal=False, attack_unmapped_reason="시간별 행동 변화는 공격 기법 확정 근거가 아닙니다.",
                explanation="같은 조사·출발지·목적지·서비스의 직전 연속 6개 15분 구간(90분)과 비교해 "
                            f"{len(signals)}개 관측 지표가 기준을 벗어났습니다. 비교 기준은 장기 정상 기준선이 아니며 "
                            "원문·업무 원인·수집 연속성을 확인하세요.",
                sample_event_ids=group["samples"], total_events=group["count"]))

        for event in ctx.events.iterate(ctx.investigation_id, base, fields=FIELDS):
            if scanned >= limits["max_events"]:
                partial = True
                break
            scanned += 1
            identity = _identity(event)
            if identity is None:
                reasons["excluded_events"] += 1
                continue
            key, window = identity
            stamp = event.get("timestamp")
            first_seen = first_seen or stamp
            last_seen = stamp
            state = series.get(key)
            if state is None:
                if len(series) >= limits["max_series"]:
                    partial = True
                    break
                state = series[key] = {"first": window, "windows": {}}
            windows = state["windows"]
            if window not in windows:
                latest = max(windows) if windows else None
                if latest is not None and window > latest:
                    # The latest window is now complete and not the last one observed: evaluate it, then keep
                    # only what the next evaluation can still need.
                    evaluate(key, latest, state)
                    for old in [w for w in windows if w < window - PRIOR * WIDTH]:
                        del windows[old]
                        held -= 1
                if held >= limits["max_groups"]:
                    partial = True
                    break
                held += 1
                windows[window] = {"count": 0, "errors": 0, "status_known": 0, "bytes": 0.0,
                                   "bytes_known": 0, "samples": [], "src_aliases": set(), "dst_aliases": set()}
            group = windows[window]
            for field, aliases in (("src_ip", "src_aliases"), ("dst_ip", "dst_aliases")):
                group[aliases].add(event[field])
                if len(group[aliases]) > limits["max_aliases"]:
                    partial = True
            if partial:
                break
            group["count"] += 1
            status = event.get("status_code")
            if type(status) is int and 100 <= status <= 599:
                group["status_known"] += 1
                group["errors"] += int(status >= 400)
            size = event.get("bytes_out")
            if type(size) in (int, float):
                try:
                    valid = math.isfinite(size) and size >= 0 and math.isfinite(group["bytes"] + size)
                except OverflowError:
                    valid = False
                if valid:
                    group["bytes"] += size
                    group["bytes_known"] += 1
            event_id = event.get("event_id")
            if isinstance(event_id, str) and len(event_id) <= 128 and len(group["samples"]) < limits["max_samples"]:
                group["samples"].append(event_id)
        # The first window of a series and the latest one (possibly cut by the end or by a limit) are partial.
        reasons["boundary_windows"] += sum(min(2, 1 + (max(s["windows"], default=None) != s["first"]))
                                           for s in series.values())
        out = found
        reasons["omitted_findings"] = max(0, candidates - len(out))
        if partial or any(reasons.values()):
            labels = {"excluded_events": "시각·비교 조건 부족 기록", "boundary_windows": "양끝 부분 구간",
                      "insufficient_baseline_windows": "앞선 연속 구간 부족", "insufficient_sample_windows": "기록 표본 부족",
                      "unstable_baseline_windows": "과거 업무량 불안정", "missing_metric_windows": "측정값 부족 구간",
                      "omitted_findings": "표시 상한으로 생략한 후보"}
            scope = (f"분석한 기록 범위: {first_seen} ~ {last_seen} ({scanned:,}건 읽음)" if first_seen
                     else f"{scanned:,}건 읽음")
            out.append(FindingDraft(self.id, self.version, "시간별 행동 분석 범위 확인 필요",
                self.category + ".coverage", self.stage, 0.1, "low",
                [metric("scanned_events", scanned, label="읽은 기록"), metric("partial", int(partial), label="입력 상한 도달")]
                + [metric(name, reasons[name], label=label) for name, label in labels.items()],
                [check("전체 범위 평가", not partial, scanned, scope + ". 제외·표본 부족·상한은 정상 판정이 아닙니다.")],
                [], {"filters": [f.model_dump() for f in base]}, None, None, self.id + ":coverage",
                success_signal=False, attack_unmapped_reason="분석 범위 안내",
                explanation="같은 출발지·목적지·서비스의 15분 구간을 직전 6개 구간(90분)과 비교합니다. 장기 정상 기준선 비교가 "
                            "아닙니다. 첫·마지막 관측 구간은 부분 구간으로 제외하고, 최초 비교에는 최소 9개 관측 구간이 "
                            "필요하며, 앞선 6개 연속 구간의 충분하고 안정된 기록만 비교합니다. 측정값은 각 구간에서 "
                            "80% 이상 있어야 사용합니다. "
                            + ("입력 상한에 도달해 그 이후 기록은 분석하지 않았습니다. " + scope + ". " if partial else "")
                            + "제외는 정상 판정이 아니며 로그만으로 수집 연속성을 보장하지 않습니다."))
        return out
