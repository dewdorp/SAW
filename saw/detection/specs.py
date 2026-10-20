"""Shipped detector specifications shared by runtime, governance and editors."""
from __future__ import annotations

import hashlib
import json
import math
from copy import deepcopy

from saw.observation.firewall import DEFAULT_POLICY

DEVICE_DEFAULTS = {
    "waf": {"enabled": True, "window_seconds": 300, "min_requests": 5, "min_paths": 5,
            "min_repetitions": 5, "min_object_ids": 3, "attack_min_requests": 2},
    "ips": {"enabled": True, "window_seconds": 300, "repeat_count": 5, "target_count": 3,
            "pattern_count": 3, "followup_seconds": 600},
    "ddos": {"enabled": True, "window_seconds": 60, "baseline_min_intervals": 3, "burst_ratio": 3.0,
             "rate_min_value": 1000.0, "sustain_seconds": 120, "repeat_min_intervals": 3,
             "concentration_ratio": 0.8},
    "ndr": {"enabled": True, "window_seconds": 300, "min_dns_queries": 5, "long_domain_length": 60,
            "long_domain_ratio": 0.5, "min_http_requests": 5, "http_error_ratio": 0.5,
            "min_tls_records": 3, "change_ratio": 0.5, "enable_new_relationships": False,
            **DEFAULT_POLICY},
    "fw": {"enabled": True, **DEFAULT_POLICY},
    "sigma": {"enabled": True},
}
_TITLES = {"waf": "WAF 요청·룰 적중 관측", "ips": "IPS 패턴·후속 통신 관측",
           "ddos": "DDoS 구간별 단위 관측", "ndr": "NDR 수집 범위·통신 관측",
           "fw": "방화벽 세션 관측", "sigma": "선택 규칙 평가"}
_SOURCES = {"waf": ["waf", "web", "zeek_http", "custom"], "ips": ["ips", "suricata", "custom", "connection"],
            "ddos": ["ddos", "custom", "connection"], "ndr": ["ndr", "zeek_conn", "zeek_dns", "zeek_http",
                 "zeek_ssl", "suricata", "connection", "custom"], "fw": ["connection", "firewall", "zeek_conn"],
            "sigma": ["custom", "web", "waf", "zeek_conn", "suricata"]}
_LABELS = {"enabled": "사용", "window_seconds": "관측 창", "min_requests": "최소 요청 수",
 "min_paths": "고유 경로 수", "min_repetitions": "반복 요청 수", "min_object_ids": "고유 객체 ID 수",
 "attack_min_requests": "공격 패턴 요청 수", "repeat_count": "반복 경보 수", "target_count": "고유 대상 수",
 "pattern_count": "고유 패턴 수", "followup_seconds": "후속 통신 기간", "baseline_min_intervals": "이전 관측 구간 수",
 "burst_ratio": "이전 관측 대비 배수", "rate_min_value": "지속·반복 관측 기준", "sustain_seconds": "지속 기간",
 "repeat_min_intervals": "반복 구간 수", "concentration_ratio": "한 대상의 관측 구간 비중",
 "min_dns_queries": "최소 DNS 기록 수", "long_domain_length": "긴 질의 길이", "long_domain_ratio": "긴 질의 비중",
 "min_http_requests": "최소 HTTP 기록 수", "http_error_ratio": "오류 응답 비중", "min_tls_records": "최소 TLS 기록 수",
 "change_ratio": "이전 창 대비 비중 변화", "enable_new_relationships": "승인 기준선 신규 관계 비교",
 "scan_min_targets": "탐색 고유 목적지 수", "scan_min_ports": "탐색 고유 포트 수", "transfer_min_bytes": "전송량 기준",
 "asymmetry_ratio": "전송 비대칭 배수", "long_flow_seconds": "장기 세션 기간", "scan_window_seconds": "탐색 창",
 "beacon_min_connections": "주기성 최소 새 연결 수", "beacon_max_cv": "간격 변동 계수",
 "deny_allow_window_seconds": "거부 후 허용 기간"}


def _descriptor(key, value):
    kind = "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "number"
    unit = ("boolean" if kind == "boolean" else "seconds" if key.endswith("_seconds") else
            "bytes" if key.endswith("_bytes") else "ratio" if "ratio" in key or key.endswith("_cv") else
            "characters" if key == "long_domain_length" else "profile_rate_unit" if key == "rate_min_value" else "count")
    low, high = (0, 1) if "ratio" in key and key not in {"burst_ratio", "asymmetry_ratio"} or key.endswith("_cv") else (1, 1000000)
    if kind == "boolean":
        return {"key": key, "label": _LABELS[key], "type": kind, "default": value, "unit": unit}
    if key.endswith("_seconds"):
        low, high = 1, 31_536_000
    if key == "deny_allow_window_seconds":
        low = 0
    if key in {"transfer_min_bytes", "rate_min_value"}:
        low, high = 0, 9_007_199_254_740_991
    if key in {"beacon_min_connections", "baseline_min_intervals"}:
        low = 3
    return {"key": key, "label": _LABELS[key], "type": kind, "default": value, "unit": unit,
            "minimum": low, "maximum": high}


def _signature_spec(detector_id, engine_version):
    from dataclasses import fields

    from saw.detectors.signatures import by_id

    signature = by_id().get(detector_id.removeprefix("signature:"))
    if signature is None or engine_version not in (None, "1.1.0"):
        raise ValueError("unsupported signature spec")
    payload = {row.name: deepcopy(getattr(signature, row.name)) for row in fields(signature)
               if row.name not in {"rx", "rx_not"}}
    payload = json.loads(json.dumps(payload, ensure_ascii=False))
    sha = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    result = {"schema": "detector-spec/1", "id": detector_id, "version": "1",
        "engine": {"id": "sig.match", "version": "1.1.0"}, "title": signature.title,
        "data_sources": ["web", "waf", "zeek_http"], "defaults": {"enabled": True},
        "parameters": [_descriptor("enabled", True)], "grouping": ["source_investigation", "signature_id"],
        "window": {"kind": "selected_input", "boundary": "event", "parameter": None},
        "supported_units": ["event", "window", "entity"], "payload": payload,
        "payload_sha256": sha(payload), "prerequisites": ["대상 필드와 요청 방법·성공 응답 조건을 실제 요청에서 평가"],
        "limits": {"max_records": 1000000, "max_results": 100, "max_event_refs_per_result": 20},
        "examples": list(signature.examples), "benign_examples": list(signature.benign),
        "follow_up": list(signature.checks), "limitations": ["2xx 응답은 침해 성공을 의미하지 않습니다."],
        "provenance": {"kind": "signature_pack", "source": "saw/detectors/packs", "signature_id": signature.id}}
    result["sha256"] = sha(result)
    return result


def get_spec(detector_id: str, engine_version=None) -> dict:
    if detector_id.startswith("signature:"):
        return _signature_spec(detector_id, engine_version)
    device = detector_id.removesuffix(".observation")
    if device not in DEVICE_DEFAULTS or detector_id not in {device + ".observation", "sigma"}:
        raise ValueError("unsupported detector spec")
    engine = "firewall-observation/1" if device == "fw" else "sigma-eval/1" if device == "sigma" else device + "-observation/1"
    if engine_version is not None and engine_version != engine:
        raise ValueError("unsupported engine version")
    defaults = deepcopy(DEVICE_DEFAULTS[device])
    result = {"schema": "detector-spec/1", "id": detector_id, "version": "1",
        "engine": {"id": detector_id, "version": engine}, "title": _TITLES[device], "data_sources": _SOURCES[device][:],
        "defaults": defaults, "parameters": [_descriptor(key, value) for key, value in defaults.items()],
        "grouping": ["org_unit_id", "network", "device_id", "device_profile_version_id", "virtual_domain",
                     "service_or_target", "measurement_semantics"],
        "window": {"kind": "inclusive_sliding" if device == "sigma" else "session_then_fixed_utc" if device in {"fw", "ndr"} else "fixed_utc",
                   "boundary": "closed" if device == "sigma" else "[start,end)",
                   "parameter": None if device == "sigma" else "scan_window_seconds" if device == "fw" else "window_seconds"},
        "prerequisites": ["검증된 원천 관계사·장비·망과 장비 해석 기준", "검증된 시각·정밀도",
                          "계산별 필수 필드와 측정 단위; 미수집은 정상 0건이 아님"],
        "limits": {"max_records": 1_000_000, "max_results": 100, "max_event_refs_per_result": 20},
        "examples": [{"interpretation": "candidate", "description": "같은 맥락·단위의 반복·확산·변화가 명시 기준을 충족함"}],
        "benign_examples": [{"interpretation": "approved_activity", "description": "관측 적중과 승인 업무 여부는 별개이며 승인 근거를 확인함"},
                            {"interpretation": "insufficient_data", "description": "단위·수집 범위·필수 의미가 없어 실행할 수 없음"}],
        "follow_up": ["원문·장비 정책과 수집 범위를 확인하세요.", "담당자에게 정상 업무·실제 처리·영향 근거를 요청하세요."],
        "limitations": ["관측만으로 성공·침해·영향을 확정하지 않습니다.",
                        "신규·희소 관계는 승인된 비교 가능 기준선이 필요합니다."],
        "supported_units": ["event", "window", "entity"] if device == "sigma" else ["window"],
        "provenance": "shipped_defaults"}
    result["sha256"] = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return result


def validate_values(spec: dict, values: dict) -> dict:
    if not isinstance(values, dict):
        raise ValueError("policy values must be an object")  # noqa: TRY004 - public validation contract
    descriptors = {row["key"]: row for row in spec["parameters"]}
    if set(values) - set(descriptors):
        raise ValueError("unknown policy parameter")
    result = {**deepcopy(spec["defaults"]), **deepcopy(values)}
    for key, value in result.items():
        row = descriptors[key]
        expected = row["type"]
        if expected == "boolean":
            valid = isinstance(value, bool)
        else:
            valid = (not isinstance(value, bool) and isinstance(value, int if expected == "integer" else (int, float))
                     and math.isfinite(value) and row["minimum"] <= value <= row["maximum"])
        if not valid:
            raise ValueError("invalid policy parameter: " + key)
    return result
