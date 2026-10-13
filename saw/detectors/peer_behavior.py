"""Explainable comparisons between sources using the same destination/service/window."""
from __future__ import annotations

from bisect import bisect_left

import ipaddress
import math
from datetime import datetime, timedelta, timezone

from saw.core.schemas.query import Filter
from saw.detectors.base import FindingDraft, check, metric

LIMITS = {"max_events": 100000, "max_cohorts": 200, "max_groups": 5000, "max_findings": 10, "max_samples": 20}
FIELDS = ["event_id", "data_source", "timestamp", "src_ip", "dst_ip", "dst_port", "url_path", "status_code", "bytes_out"]
SOURCES = {"web", "waf", "zeek_http", "zeek_conn"}


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        return None
    return float(value)


def _identity(event):
    try:
        source, destination = event.get("src_ip"), event.get("dst_ip")
        if not isinstance(source, str) or not isinstance(destination, str) or len(source) > 64 or len(destination) > 64:
            return None
        source = str(ipaddress.ip_address(source))
        destination = str(ipaddress.ip_address(destination))
        port = event.get("dst_port")
        if type(port) is not int or not 1 <= port <= 65535:
            return None
        stamp = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
        if stamp.tzinfo is None or not math.isfinite(stamp.timestamp()):
            return None
        window = int(stamp.timestamp() // 900) * 900
        return (event["data_source"], destination, port, window), source
    except (ValueError, TypeError, KeyError, OverflowError, OSError, AttributeError):
        return None


def _features(group):
    required = max(5, math.ceil(group["count"] * 0.8))
    return {"requests": group["count"],
            "error_ratio": group["errors"] / group["status_known"] if group["status_known"] >= required else None,
            "unique_paths": len(group["paths"]) if group["path_known"] >= required else None,
            "bytes_per_event": group["bytes"] / group["bytes_known"] if group["bytes_known"] >= required else None}


def _median_without(values, removed):
    count = len(values) - 1
    def item(index):
        return values[index + int(index >= removed)]
    middle = count // 2
    return item(middle) if count % 2 else (item(middle - 1) + item(middle)) / 2


class PeerBaselines:
    """Exact leave-one-out median/MAD with at most three deviation sorts per feature."""
    def __init__(self, features):
        self.values = {name: sorted(row[name] for row in features.values() if row[name] is not None)
                       for name in ("requests", "error_ratio", "unique_paths", "bytes_per_event")}
        self.deviations = {}
        self.cache = {}

    def baseline(self, name, observed):
        values = self.values[name]
        if observed is None or len(values) < 21:
            return None
        key = (name, observed)
        if key not in self.cache:
            median = _median_without(values, bisect_left(values, observed))
            dev_key = (name, median)
            if dev_key not in self.deviations:
                self.deviations[dev_key] = sorted(abs(value - median) for value in values)
            deviations = self.deviations[dev_key]
            mad = _median_without(deviations, bisect_left(deviations, abs(observed - median)))
            self.cache[key] = (median, mad, len(values) - 1)
        return self.cache[key]


def _signals(value, baseline):
    rules = {"requests": (20, 4, 0), "error_ratio": (0.6, 0, 0.4),
             "unique_paths": (10, 4, 0), "bytes_per_event": (65536, 8, 0)}
    signals = []
    labels = {"requests": "기록 수", "error_ratio": "오류 응답 비율", "unique_paths": "서로 다른 경로", "bytes_per_event": "기록당 bytes_out"}
    for name, (floor, ratio, difference) in rules.items():
        observed = value[name]
        comparison = baseline.baseline(name, observed)
        if comparison is None:
            continue
        median, mad, peers = comparison
        threshold = max(floor, median * ratio, median + difference, median + 6 * mad)
        if observed >= threshold and observed > median + 6 * mad:
            signals.append(metric(name, round(observed, 5), {"min": median, "max": threshold,
                                  "source": "relative:same_destination_service_window", "median": median,
                                  "mad": mad, "peer_sources": peers}, label=labels[name]))
    return signals


class PeerBehavior:
    id, version, category, stage = "anomaly.peer", "1.0.0", "anomaly.peer", "UNCLASSIFIED"
    data_sources = SOURCES

    def run(self, ctx):
        limits = dict(LIMITS)
        for key, value in ctx.params.get("peer_limits", {}).items():
            if key in limits and type(value) is int and 1 <= value <= LIMITS[key]:
                limits[key] = value
        cohorts = {}
        destination_aliases = {}
        scanned = excluded = group_count = 0
        partial = False
        base = [Filter(field="data_source", op="in", value=sorted(SOURCES))]
        for event in ctx.events.iterate(ctx.investigation_id, base, fields=FIELDS):
            if scanned >= limits["max_events"]:
                partial = True
                break
            scanned += 1
            identity = _identity(event)
            if identity is None:
                excluded += 1
                continue
            key, source = identity
            if key not in cohorts:
                if len(cohorts) >= limits["max_cohorts"]:
                    partial = True
                    break
                cohorts[key] = {}
                destination_aliases[key] = set()
            destination_aliases[key].add(event["dst_ip"])
            if len(destination_aliases[key]) > 32:
                partial = True
                break
            cohort = cohorts[key]
            if source not in cohort:
                if group_count >= limits["max_groups"]:
                    partial = True
                    break
                group_count += 1
                cohort[source] = {"count": 0, "errors": 0, "status_known": 0, "bytes": 0.0,
                                  "bytes_known": 0, "paths": set(), "path_known": 0, "samples": [], "aliases": set()}
            group = cohort[source]
            group["aliases"].add(event["src_ip"])
            if len(group["aliases"]) > 32:
                partial = True
                break
            group["count"] += 1
            status = event.get("status_code")
            if type(status) is int and 100 <= status <= 599:
                group["status_known"] += 1
                group["errors"] += int(status >= 400)
            byte_count = _number(event.get("bytes_out"))
            if byte_count is not None:
                group["bytes"] += byte_count
                group["bytes_known"] += 1
            path = event.get("url_path")
            if isinstance(path, str) and path:
                group["paths"].add(path[:2048])
                group["path_known"] += 1
            event_id = event.get("event_id")
            if isinstance(event_id, str) and len(event_id) <= 128 and len(group["samples"]) < limits["max_samples"]:
                group["samples"].append(event_id)
        out = []
        skipped_cohorts = 0
        candidate_count = 0
        # Partial groups do not provide a defensible peer distribution.
        if not partial:
            for key, cohort in sorted(cohorts.items()):
                eligible = {src: group for src, group in cohort.items() if group["count"] >= 5}
                if len(eligible) < 21:
                    skipped_cohorts += 1
                    continue
                features = {src: _features(group) for src, group in eligible.items()}
                baseline = PeerBaselines(features)
                peer_count = len(eligible) - 1
                for source, group in sorted(eligible.items()):
                    signals = _signals(features[source], baseline)
                    if len(signals) < 2:
                        continue
                    candidate_count += 1
                    if len(out) >= limits["max_findings"]:
                        continue
                    data_source, destination, port, window = key
                    start = datetime.fromtimestamp(window, timezone.utc)
                    end = start + timedelta(seconds=900, microseconds=-1)
                    filters = [Filter(field="data_source", value=data_source).model_dump(),
                               Filter(field="dst_port", value=port).model_dump()]
                    for field, aliases in (("dst_ip", destination_aliases[key]), ("src_ip", group["aliases"])):
                        values = sorted(aliases)
                        filters.append(Filter(field=field, op="in" if len(values) > 1 else "is",
                                              value=values if len(values) > 1 else values[0]).model_dump())
                    out.append(FindingDraft(self.id, self.version, "동일 서비스 대비 행동 차이 가능성", self.category,
                        self.stage, 0.4, "medium", signals + [metric("peer_sources", peer_count, label="비교 출발지 수")],
                        [check("같은 목적지·서비스·15분 구간", True, f"{destination}:{port}", data_source),
                         check("서로 다른 관측 지표 두 개 이상", True, len(signals)),
                         check("악성 여부 확인", None, "분석가 확인 필요", "정상 배치·업무량·NAT 공유·수집 차이도 원인일 수 있습니다.")],
                        [f"ip:{source}"], {"filters": filters, "time": {"start": start.isoformat(), "end": end.isoformat()}},
                        start.isoformat(), end.isoformat(), f"{self.id}:{data_source}:{destination}:{port}:{window}:{source}",
                        success_signal=False, attack_unmapped_reason="조건별 행동 차이는 공격 기법 확정 근거가 아닙니다.",
                        explanation=f"같은 서비스·시간의 다른 출발지 {peer_count}개와 비교해 {len(signals)}개 지표가 기준을 벗어났습니다. 실제 원문과 업무 원인을 확인하세요.",
                        sample_event_ids=group["samples"], total_events=group["count"]))
        if excluded or partial or skipped_cohorts or candidate_count > len(out):
            out.append(FindingDraft(self.id, self.version, "행동 비교 분석 범위 확인 필요", self.category + ".coverage",
                self.stage, 0.1, "low", [metric("scanned_events", scanned, label="읽은 기록"),
                    metric("excluded_events", excluded, label="비교 조건 부족 기록"),
                    metric("partial", int(partial), label="입력 상한 도달"),
                    metric("insufficient_cohorts", skipped_cohorts, label="비교 표본 부족 구간"),
                    metric("omitted_findings", max(0, candidate_count - len(out)), label="표시 상한으로 생략한 후보")],
                [check("전체 범위 평가", False, scanned, "제외·표본 부족·상한은 정상 판정이 아닙니다.")],
                [], {"filters": [f.model_dump() for f in base]}, None, None, self.id + ":coverage",
                success_signal=False, attack_unmapped_reason="분석 범위 안내", explanation=(
                    "목적지·포트·시각이 없거나 비교할 출발지가 부족한 기록은 평가하지 않았습니다. "
                    "입력 상한 도달 시 불완전한 기준선으로 후보를 만들지 않습니다. 파일·시간 범위를 나누어 다시 조사하세요.")))
        return out
