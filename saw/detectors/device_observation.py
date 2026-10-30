"""Adapters from producer-owned device reports to existing FindingDraft records."""
from __future__ import annotations

from saw.core.application.provenance import digest
from saw.core.schemas.query import Filter
from saw.detection.specs import get_spec
from saw.detectors.base import FindingDraft, metric
from saw.observation.device import analyze_device

LABELS = {"multi_path_discovery": "여러 경로 탐색", "attack_repetition": "공격 패턴 요청 반복",
          "attack_mutation": "공격 패턴 요청 변형", "object_id_walk": "객체 ID 변화와 자동화·공격 근거",
          "allowed_attack": "공격 패턴 요청의 허용 기록", "response_location_difference": "Edge·Origin 응답 차이",
          "pattern_repeat": "IPS 같은 패턴 반복", "target_spread": "IPS 여러 대상 확산",
          "pattern_diversity": "IPS 한 대상의 여러 패턴", "detect_only": "IPS 탐지 전용 중요 경보",
          "followup_communication": "IPS 경보 뒤 통신 연관 후보", "rate_burst": "관측 구간 대비 전송률 급증",
          "sustained_rate": "기준 이상 전송률 지속", "repeated_intervals": "기준 이상 구간 반복",
          "mitigation_comparison": "비교 가능한 완화 전후 관측", "target_concentration": "특정 대상의 관측 구간 집중",
          "dns_characteristics": "긴 DNS 질의 특성", "http_characteristics": "HTTP 자동화·공격 또는 오류 특성",
          "tls_characteristics": "취약 TLS 프로토콜 관측", "combined_change": "복수 통신 지표 변화 구간",
          "scan": "목적지·포트 탐색 가능성", "beacon": "새 연결 주기성 후보", "long_flow": "장기 세션",
          "transfer_asymmetry": "방향별 전송량 차이", "deny_to_allow": "거부 뒤 허용 기록"}


def _metric_unit(name, value, metrics, parameter_units):
    # A rate's physical unit applies only to rate values, never its denominator or labels.
    if name in {"value", "before", "after", "residual_observed_rate", "max_observed_rate", "previous_observed_mean"}:
        return metrics.get("unit", "")
    if name.endswith(("_seconds", "_epoch")):
        return "seconds"
    if name.endswith("_bytes"):
        return "bytes"
    if name == "ratio" or name.endswith("_ratio"):
        return ""
    if name in parameter_units:
        return parameter_units[name]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "count"
    return ""


class DeviceObservation:
    stage = "observation"

    def __init__(self, detector_id):
        spec = get_spec(detector_id)
        self.id, self.version = detector_id, spec["engine"]["version"]
        self.category = "device." + detector_id.split(".")[0]
        self.data_sources = set(spec["data_sources"])

    def run(self, ctx):
        events = ctx.events.iterate(ctx.investigation_id,
            [Filter(field="data_source", op="in", value=sorted(self.data_sources))], batch=500)
        pin = (ctx.params.get("device_runtime_pins") or {}).get(self.id) or ctx.params.get("runtime_pin")
        result = analyze_device(self.id, events, runtime_pin=pin, cancelled=ctx.params.get("cancelled"),
            max_records=ctx.params.get("device_max_records", 1_000_000), max_results=ctx.params.get("device_max_results", 100))
        ctx.params.setdefault("execution_reports", {})[self.id] = result
        drafts = []
        for candidate in result["candidates"]:
            ids = list(dict.fromkeys(ref["event_id"] for ref in candidate["event_refs"] if ref.get("event_id")))
            values, kind = candidate["metrics"], candidate["kind"]
            # The span of the kept representative records gives the candidate a time to join timelines and
            # scenarios; it is labelled as such, never as the full extent of the activity.
            times = []
            for event_id in ids:
                try:
                    event = ctx.events.get(ctx.investigation_id, event_id)
                except Exception:  # noqa: BLE001 - a missing record only narrows the representative span
                    event = None
                if event and event.get("timestamp"):
                    times.append(str(event["timestamp"]))
            entities = list(dict.fromkeys("ip:" + str(values[key]) for key in ("src_ip", "client_ip", "dst_ip")
                                          if values.get(key)))
            units = {row["key"]: row["unit"] for row in get_spec(self.id)["parameters"]}
            drafts.append(FindingDraft(detector_id=self.id, detector_version=self.version,
                title="관측 후보: " + LABELS.get(kind, kind), category=self.category + "." + kind,
                stage=self.stage, severity=0.5, confidence="medium",
                metrics=[metric(key, value, unit=_metric_unit(key, value, values, units)) for key, value in values.items()],
                checks=[{"label": "근거와 정상 업무 확인 필요", "passed": None, "value": None,
                         "detail": "관측과 승인 업무·실제 처리·영향을 구분하여 확인하세요."}],
                entities=entities,
                evidence_query={"filters": [{"field": "event_id", "op": "in", "value": ids}],
                                "reference_scope": "bounded_representative"},
                time_start=min(times) if times else None, time_end=max(times) if times else None,
                dedup_key=self.id+":"+digest([kind, values, ids]),
                sample_event_ids=ids, total_events=values.get("denominator", len(ids)), success_signal=False,
                attack_unmapped_reason="장비 관측만으로 침해나 기법을 확정할 수 없습니다.",
                explanation=("검증된 원천 문맥·단위와 같은 실행의 근거·자료 한계를 확인하세요."
                             + (f" 시각은 대표 근거 {len(times)}건의 범위입니다." if times else " 대표 근거에 시각이 없어 시간 흐름에 넣지 못했습니다."))))
        return drafts


class WafObservation(DeviceObservation):
    def __init__(self):
        super().__init__("waf.observation")


class IpsObservation(DeviceObservation):
    def __init__(self):
        super().__init__("ips.observation")


class DdosObservation(DeviceObservation):
    def __init__(self):
        super().__init__("ddos.observation")


class NdrObservation(DeviceObservation):
    def __init__(self):
        super().__init__("ndr.observation")
