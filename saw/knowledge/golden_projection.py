"""Bounded Golden projections and release-scoped private identity transformation."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from copy import deepcopy
from datetime import datetime
from time import monotonic

BUILD_FAILURE_REASONS = frozenset({
    "analysis_run_not_complete", "single_fw_scope_required", "analysis_scope_seal_invalid",
    "analysis_run_after_cutoff", "supported_execution_required", "unsupported_truth_unit",
    "runtime_pin_seal_invalid", "unsupported_fw_partition_count", "policy_seal_invalid",
    "engine_spec_changed", "unsupported_policy_semantics", "truth_case_pin_missing",
    "truth_case_seal_invalid", "truth_case_scope_not_complete", "source_manifest_changed",
    "source_processing_not_complete", "source_epoch_changed", "known_at_unavailable",
    "source_not_available_at_cutoff", "complete_scope_invalid", "native_count_invalid",
    "record_limit_exceeded", "record_limit_lookahead", "stable_timestamp_required",
    "native_enumeration_not_stable", "unsupported_scope_records", "record_byte_limit",
    "case_byte_limit", "native_truth_membership_invalid", "native_count_mismatch",
    "source_changed_during_capture", "empty_scope", "original_parts_changed",
    "transformed_case_byte_limit", "transformed_input_count_or_mapping_invalid",
    "event_order_or_identity_changed", "event_time_changed", "saved_limits_invalid",
    "engine_result_incomplete", "saved_engine_result_changed", "transformed_engine_semantics_changed",
    "truth_input_not_complete", "truth_unit_pin_changed", "unsupported_truth_selector",
    "native_truth_membership_changed", "truth_window_empty", "unsupported_transformed_truth_selector",
    "truth_selector_membership_changed", "truth_window_semantics_changed", "complete_capture_missing",
    "truth_event_reference_unavailable", "build_failed",
})


def safe_failure_reasons(values):
    """Never treat arbitrary exception text or persisted JSON as public reason codes."""
    if not isinstance(values, (list, tuple)):
        return []
    return list(dict.fromkeys(value for value in values[:8]
        if isinstance(value, str) and value in BUILD_FAILURE_REASONS))


class GoldenBuildFailure(ValueError):
    """Small typed carrier shared by pure validation and the Job persistence boundary."""
    def __init__(self, reasons):
        self.reasons = tuple(safe_failure_reasons(reasons) or ["build_failed"])
        super().__init__("golden_build_failed:" + ",".join(self.reasons))


def failure_message(reasons):
    messages = {
        "unsupported_truth_unit": "전체 재계산은 이벤트 ID를 지정하지 않은 창 정답만 지원합니다. 해석 전용 반출을 요청하세요.",
        "truth_window_empty": "정답 창에 선택된 기록이 없습니다. 범위를 확인하거나 해석 전용 반출을 요청하세요.",
        "record_limit_exceeded": "전체 재계산의 기록 10,000건 한도를 넘었습니다. 범위를 줄이거나 해석 전용 반출을 요청하세요.",
        "record_limit_lookahead": "열거 결과가 기록 10,000건 한도를 넘었습니다. 범위를 줄이거나 해석 전용 반출을 요청하세요.",
        "single_fw_scope_required": "완료된 단일 FW 분석 범위가 필요합니다. 지원되는 분석을 고정하거나 해석 전용 반출을 요청하세요.",
        "analysis_run_not_complete": "고정된 분석이 완료되지 않았습니다. 완료된 분석으로 새 반출을 요청하세요.",
        "source_not_available_at_cutoff": "기준시점에 자료가 준비되지 않았습니다. 당시 자료를 확인하고 새 반출을 요청하세요.",
        "known_at_unavailable": "자료의 준비 시점을 확인할 수 없습니다. 수집·처리 이력을 확인하세요.",
        "source_processing_not_complete": "자료 처리가 끝나지 않았습니다. 완료 후 새 반출을 요청하세요.",
        "truth_event_reference_unavailable": "정답 이벤트가 고정된 반출 근거에 없습니다. 근거를 포함한 새 골든 예제를 준비하세요.",
    }
    safe = safe_failure_reasons(reasons)
    return " ".join(messages.get(reason, "전체 재계산 검증에 실패했습니다. 고정된 자료·정책·정답 범위를 확인하거나 해석 전용 반출을 요청하세요.")
                    for reason in safe) or "골든셋 파일 생성을 중단했습니다. 권한·승인·자료 범위와 입력 저장 상태를 확인하세요."

MAX_CASE = 4 * 1024 * 1024
MAX_BLOB = 256 * 1024
MAX_TOTAL = 20 * 1024 * 1024
MAX_EXAMPLES = 100
HEX = re.compile(r"^[a-f0-9]{64}$")
CONTEXT_KEYS = {"org_unit_id", "network", "device_id", "device_profile_version_id", "virtual_domain", "resolved", "status"}
COUNTERS = {"src_to_dst_bytes", "dst_to_src_bytes", "src_to_dst_packets", "dst_to_src_packets"}
EVENT_KEYS_V2 = {"event_id", "investigation_id", "evidence_id", "file_id", "timestamp",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "transport", "data_source",
    "bytes_in", "bytes_out", "bytes_sent", "bytes_received", "duration", "status_code",
    "http_status", "method", "http_method", "enforcement_action"}
OBS_KEYS = {"producer", "version", "profile_version", "record_kind", "session_id", "start_time", "end_time",
    "action", "duration_seconds", "timestamp", "timestamp_precision", "ces_timestamp",
    "ces_timestamp_quality", "collected_time"}
DEVICE_KEYS = {"producer", "version", "verified", "profile_version", "record_kind", "timestamp",
    "time_verified", "timestamp_precision", "observation_point", "client_ip", "src_ip", "dst_ip",
    "dst_port", "protocol", "service", "request_id", "signature_id", "action", "mode", "packet_available",
    "status", "edge_status", "origin_status", "interval_start", "interval_end", "rate", "rate_unit",
    "rate_statistic", "sampling_ratio", "sampling_version", "mitigation", "capture_kind", "bidirectional",
    "user_agent_state", "ua_class"}
IDENTITIES = {"event_id", "investigation_id", "evidence_id", "file_id", "org_unit_id", "network",
    "device_id", "device_profile_version_id", "virtual_domain", "profile_version", "session_id",
    "request_id", "signature_id", "service", "observation_point"}
IP_KEYS = {"src_ip", "dst_ip", "client_ip"}
CTX = "ext.observation.context."
REF_KEYS = {"observations", "evidence", "evidence_refs", "blob_sha256", "blob_refs"}
PSEUDONYM_PROFILE = {"schema": "saw.pseudonymization-profile.v1", "version": 1,
    "identity_scope": "org_network", "identity_mapping": "scoped_injective/1", "time_transform": "none",
    "free_text": "drop_unapproved", "metadata": "allowlist_v2"}
CONVERSIONS = {
    "golden-native/1": ("golden-native", "native-input-and-answers/1", "native-files/1"),
    "input-output-jsonl/1": ("input-output", "input-output/1", "jsonl-utf8/1"),
    "messages-jsonl/1": ("messages", "messages/1", "jsonl-utf8/1"),
}


def check_cancel(cancelled):
    if cancelled and cancelled():
        raise RuntimeError("golden_release_cancelled")


def canonical_bytes(value, limit=MAX_TOTAL, *, cancelled=None):
    """Enforce UTF-8 bounds while encoding, before joining the complete value."""
    chunks, size = [], 0
    last = monotonic()
    try:
        for index, piece in enumerate(json.JSONEncoder(ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False).iterencode(value)):
            data = piece.encode("utf-8")
            size += len(data)
            if size > limit:
                raise ValueError("golden_byte_limit")
            chunks.append(data)
            if index % 500 == 0 or monotonic() - last >= 0.05:
                check_cancel(cancelled)
                last = monotonic()
    except (TypeError, RecursionError, OverflowError) as exc:
        raise ValueError("golden_invalid_json") from exc
    return b"".join(chunks)


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _leaf(value):
    return value is None or type(value) in {str, bool, int, float}


ENUMS = {
    "protocol": {"tcp", "udp", "icmp", "icmpv6", "ip", "http", "https", "dns", "tls", "unknown"},
    "transport": {"tcp", "udp", "icmp", "icmpv6", "unknown"},
    "data_source": {"firewall", "connection", "zeek_conn", "web", "waf", "ips", "ddos", "ndr", "dns", "http", "tls"},
    "record_kind": {"session_start", "session_interim", "session_end", "request", "rule_hit", "alert", "interval_summary", "flow", "dns", "http", "tls", "unknown"},
    "action": {"allowed", "blocked", "reset", "detected", "challenged", "unknown", "conflicting"},
    "enforcement_action": {"allowed", "blocked", "reset", "detected", "challenged", "unknown", "conflicting"},
    "state": {"observed", "not_collected", "recorded_empty", "unknown_semantics", "invalid"},
    "counter_mode": {"cumulative", "delta", "total", "unknown"},
    "unit": {"bytes", "packets", "unknown"},
    "timestamp_precision": {"seconds", "subseconds", "unknown", "minutes", "days"},
    "precision": {"seconds", "subseconds", "unknown", "minutes", "days"},
    "role": {"occurred", "start", "end", "collected", "unknown"},
    "scope": {"full", "sampled", "partial", "unknown"},
    "method": {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"},
    "http_method": {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"},
    "mode": {"inline", "mirror", "unknown"},
    "rate_unit": {"bps", "pps", "rps", "bytes_per_second", "packets_per_second", "requests_per_second", "unknown"},
    "rate_statistic": {"instant", "average", "peak", "sum", "unknown"},
    "mitigation": {"before", "after", "unknown"},
    "capture_kind": {"full", "sampled", "metadata", "unknown"},
    "user_agent_state": {"observed", "not_collected", "recorded_empty", "unknown"},
    "ua_class": {"browser", "tool", "bot", "unknown"},
}
NUMERIC_FIELDS = {"src_port", "dst_port", "bytes_in", "bytes_out", "bytes_sent", "bytes_received", "duration",
    "status_code", "http_status", "duration_seconds", "value", "status", "edge_status", "origin_status", "rate", "sampling_ratio"}
TIME_FIELDS = {"timestamp", "start_time", "end_time", "ces_timestamp", "collected_time", "interval_start", "interval_end"}


def _safe_leaf(key, value):
    if value is None:
        return None
    if key in ENUMS:
        return value if isinstance(value, str) and value in ENUMS[key] else None
    if key in NUMERIC_FIELDS:
        return value if type(value) in {int, float} and value >= 0 else None
    if key in TIME_FIELDS:
        try:
            stamp = datetime.fromisoformat(str(value))
            return value if stamp.tzinfo is not None else None
        except (ValueError, TypeError):
            return None
    if key == "timezone":
        return value if value in {"UTC", "Asia/Seoul"} else None
    if key in {"verified", "resolved", "time_verified", "packet_available", "bidirectional"}:
        return value if type(value) is bool else None
    if key == "sampling_version":
        return None
    if key == "ces_timestamp_quality":
        return value if value in {"valid", "invalid", "missing", "assumed", "parsed", "unknown"} else None
    return deepcopy(value)


def _select(value, keys):
    if not isinstance(value, dict):
        return {}
    return {k: _safe_leaf(k, v) for k, v in value.items() if k in keys and _leaf(v)}


def _codes(values):
    return [v for v in values or [] if isinstance(v, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", v)][:100]


def _observation(value):
    result = _select(value, OBS_KEYS)
    result["context"] = _select(value.get("context", {}), CONTEXT_KEYS)
    if "status" in result["context"]:
        status = value.get("context", {}).get("status")
        result["context"]["status"] = status if status in {"verified", "unresolved", "conflicting", "resolved"} else None
    result["counters"] = {k: _select(v, {"value", "state", "unit", "counter_mode"})
                          for k, v in value.get("counters", {}).items() if k in COUNTERS and isinstance(v, dict)}
    result["time_profile"] = _select(value.get("time_profile", {}), {"verified", "role", "precision", "timezone"})
    result["collection"] = _select(value.get("collection", {}), {"scope", "sampling_ratio"})
    result["quality"] = _codes(value.get("quality"))
    return result


def project_event_v2(event):
    """Project producer-owned semantic leaves; identities remain private until release."""
    if not isinstance(event, dict):
        raise ValueError("golden_event_invalid")  # noqa: TRY004 - consistent public validation errors
    result = _select(event, EVENT_KEYS_V2)
    ext = event.get("ext") or {}
    output = {}
    obs = ext.get("observation")
    if isinstance(obs, dict) and obs.get("producer") == "saw" and obs.get("version") == "connection-observation/1":
        output["observation"] = _observation(obs)
    device = ext.get("device_observation")
    if isinstance(device, dict) and device.get("producer") == "saw" and device.get("version") == "device-observation/1":
        safe = _select(device, DEVICE_KEYS)
        safe["context"] = _select(device.get("context", {}), CONTEXT_KEYS)
        safe["collection"] = _select(device.get("collection", {}), {"scope", "sampling_ratio"})
        safe["quality"] = _codes(device.get("quality"))
        safe["functions"] = [v for v in device.get("functions", []) if v in {"fw", "waf", "ips", "ddos", "ndr"}]
        if isinstance(device.get("connection"), dict):
            safe["connection"] = _observation(device["connection"])
        output["device_observation"] = safe
    # Preserve only typed session-equivalence data, never unrestricted product extensions.
    product = ext.get(event.get("product"), {})
    nat = {k: v for k, v in product.items() if isinstance(k, str) and any(
        token in k.lower() for token in ("nat", "zone", "interface"))} if isinstance(product, dict) else {}
    existing = ext.get("saw_golden", {})
    if event.get("product") == "saw_golden" and "nat_scope" in existing:
        nat = existing["nat_scope"]
    if not isinstance(nat, (str, dict)) or (isinstance(nat, dict) and any(not _leaf(v) for v in nat.values())):
        raise ValueError("golden_unsupported_nat_semantics")
    canonical_bytes(nat, 16384)
    output["saw_golden"] = {"nat_scope": deepcopy(nat)}
    result["product"] = "saw_golden"
    result["ext"] = output
    canonical_bytes(result, MAX_BLOB)
    return result


def validate_profile(kind, implementation, payload):
    if kind == "pseudonymization" and implementation == "scoped-identities/1":
        expected = PSEUDONYM_PROFILE
    elif kind == "model_conversion" and implementation in CONVERSIONS:
        target, mapping, serialization = CONVERSIONS[implementation]
        expected = {"schema": "saw.model-conversion-profile.v1", "version": 1,
            "target": {"name": target, "version": "1"}, "field_mapping": mapping,
            "serialization_contract": serialization, "validation_suite": "saw-release-reference-leakage/1"}
    else:
        raise ValueError("golden_unsupported_profile")
    if type(payload) is not dict or canonical_bytes(payload, 32768) != canonical_bytes(expected):
        raise ValueError("golden_unsupported_profile_payload")
    return deepcopy(expected)


def input_blob_graph(input_value, blobs):
    selected, pending = {}, []
    def refs(value, key=None):
        if isinstance(value, dict):
            for k, v in value.items():
                refs(v, k)
        elif isinstance(value, list):
            for v in value:
                refs(v, key)
        elif key in REF_KEYS and isinstance(value, str) and HEX.fullmatch(value):
            pending.append(value)
    refs(input_value)
    while pending:
        ident = pending.pop()
        if ident in selected:
            continue
        if ident not in blobs:
            raise ValueError("golden_input_reference_missing")
        value = blobs[ident]
        if hashlib.sha256(canonical_bytes(value, MAX_BLOB)).hexdigest() != ident:
            raise ValueError("golden_blob_seal_invalid")
        selected[ident] = value
        refs(value)
    return {k: selected[k] for k in sorted(selected)}


def input_graph_sha256(input_value, blobs):
    return digest({"input": input_value, "blobs": input_blob_graph(input_value, blobs)})


def prepare_release_inputs(request, examples, profiles, *, cancelled, private_context):
    check_cancel(cancelled)
    seed = private_context.get("mapping_seed") if isinstance(private_context, dict) else None
    if not isinstance(seed, str) or not HEX.fullmatch(seed) or not private_context.get("release_id") or not private_context.get("created_at"):
        raise ValueError("golden_private_context_required")
    split = request.get("split")
    expected_kind = {"train": "train", "dev": "dev", "holdout": "holdout_input"}.get(split)
    purpose = {"train": "external_training", "dev": "external_development", "holdout": "external_evaluation"}.get(split)
    if not expected_kind or request.get("artifact_kind") != expected_kind or request.get("purpose") != purpose:
        raise ValueError("golden_split_purpose_mismatch")
    if request.get("projection") not in {"v1", "v2"}:
        raise ValueError("golden_projection_unsupported")
    mode = request.get("applicability_request", {}).get("mode")
    if mode not in {"interpretation_only", "full_recalculation"} or (mode == "full_recalculation" and request["projection"] != "v2"):
        raise ValueError("golden_applicability_unsupported")
    selected_profiles = {}
    for kind in ("pseudonymization", "model_conversion"):
        item = deepcopy(profiles[kind])
        payload = validate_profile(kind, item["implementation"], item["payload"])
        if item.get("sha256") != digest(payload):
            raise ValueError("golden_profile_seal_invalid")
        selected_profiles[kind] = item
    if split == "holdout" and selected_profiles["model_conversion"]["implementation"] != "golden-native/1":
        raise ValueError("golden_holdout_native_only")
    result = {"request": deepcopy(request), "profiles": selected_profiles, "private_context": deepcopy(private_context),
              "examples": [], "captures": {}, "source_investigation_ids": [], "contributor_ids": []}
    total = len(canonical_bytes({k:v for k,v in result.items() if k != "captures"}, cancelled=cancelled))
    seen, sources, contributors = set(), set(), set()
    for example in examples:
        check_cancel(cancelled)
        if len(result["examples"]) >= MAX_EXAMPLES:
            raise ValueError("golden_example_limit")
        data = canonical_bytes(example, MAX_CASE, cancelled=cancelled)
        total += len(data) + 1
        if total > MAX_TOTAL:
            raise ValueError("golden_total_byte_limit")
        ex = json.loads(data)
        if ex["version_id"] in seen or ex.get("split") != split:
            raise ValueError("golden_duplicate_or_split_mismatch")
        seen.add(ex["version_id"])
        payload, blobs = ex["payload"], ex["blobs"]
        if digest(payload) != ex.get("content_sha256"):
            raise ValueError("golden_combined_seal_invalid")
        for ident, blob in blobs.items():
            if hashlib.sha256(canonical_bytes(blob, MAX_BLOB)).hexdigest() != ident:
                raise ValueError("golden_blob_seal_invalid")
        if input_graph_sha256(payload["input"], blobs) != ex.get("input_sha256"):
            raise ValueError("golden_input_seal_invalid")
        cutoff_raw = payload["input"].get("cutoff", {}).get("as_of", payload.get("as_of"))
        if cutoff_raw:
            cutoff = datetime.fromisoformat(str(cutoff_raw))
            if cutoff.tzinfo is None:
                raise ValueError("golden_cutoff_invalid")
            for blob in input_blob_graph(payload["input"], blobs).values():
                for key in ("known_at", "captured_at", "as_of"):
                    if blob.get(key):
                        moment = datetime.fromisoformat(str(blob[key]))
                        if moment.tzinfo is None or moment > cutoff:
                            raise ValueError("golden_input_after_cutoff")
        if mode == "full_recalculation":
            scope = ex.get("complete_scope")
            if not scope:
                raise ValueError("golden_complete_scope_missing")
            if scope.get("golden_ref") != {"id": ex["version_id"], "content_sha256": ex["content_sha256"]}:
                raise ValueError("golden_scope_golden_mismatch")
            if scope.get("truth_units") != payload["answers"].get("detection_truth", {}).get("units"):
                raise ValueError("golden_scope_truth_mismatch")
            if scope.get("cutoff") != cutoff_raw:
                raise ValueError("golden_scope_cutoff_mismatch")
        result["examples"].append(ex)
        sources.update(ex.get("source_investigation_ids", []))
        contributors.update(ex.get("contributor_ids", []))
        if len(sources) > 1000:
            raise ValueError("golden_source_limit")
    if not result["examples"]:
        raise ValueError("golden_examples_required")
    result["source_investigation_ids"] = sorted(sources)
    result["contributor_ids"] = sorted(contributors)
    canonical_bytes({k:v for k,v in result.items() if k != "captures"}, cancelled=cancelled)
    return result


def _token_scope(context, investigation_id):
    """Identity scope for pseudonyms: the verified affiliate/network, else the single source investigation.

    Rows without a verified affiliate must never share an address token with another investigation's rows.
    """
    if context.get("org_unit_id"):
        return (context.get("org_unit_id"), context.get("network"))
    return ("investigation", str(investigation_id or ""))


class IdentityMapper:
    """Private mapping; exported values are injective within their typed identity scopes."""
    def __init__(self, seed, *, cancelled=lambda: False):
        self._cancelled = cancelled
        self._seed = bytes.fromhex(seed)
        self._values = {}
        self._reverse = {}
        self._events = {}

    def token(self, kind, value, scope=()):
        check_cancel(self._cancelled)
        key = canonical_bytes([list(scope), kind, value]).decode()
        if key not in self._values:
            code = hmac.new(self._seed, key.encode(), hashlib.sha256).hexdigest()
            value_out = kind.replace("_", "-") + "-" + code[:24]
            if kind == "ip":
                address = ipaddress.ip_address(value)
                for attempt in range(131072):
                    check_cancel(self._cancelled)
                    number = int(hmac.new(self._seed, (key+":"+str(attempt)).encode(), hashlib.sha256).hexdigest(), 16)
                    value_out = str(ipaddress.ip_address(0xC6120000 + number % 131072)) if address.version == 4 else str(
                        ipaddress.IPv6Address((0x20010DB8 << 96) | (number & ((1 << 96)-1))))
                    if value_out not in self._reverse and value_out != value:
                        break
                else:
                    raise ValueError("golden_identity_pool_exhausted")
            if value_out in self._reverse:
                raise ValueError("golden_identity_collision")
            self._values[key] = value_out
            self._reverse[value_out] = deepcopy(value)
        return self._values[key]

    def register_events(self, events):
        keys = {}
        for event in events:
            check_cancel(self._cancelled)
            key = (str(event.get("investigation_id") or ""), str(event.get("event_id") or ""))
            stamp = event.get("timestamp")
            if not key[1]:
                raise ValueError("golden_event_id_missing")
            if key in keys and keys[key] != stamp:
                raise ValueError("golden_event_identity_conflict")
            keys[key] = stamp
        def order(item):
            check_cancel(self._cancelled)
            try:
                stamp = datetime.fromisoformat(str(item[1])).timestamp()
            except (ValueError, TypeError):
                stamp = 0.0
            return stamp, item[0][1], item[0][0]
        for index, (key, _) in enumerate(sorted(keys.items(), key=order)):
            check_cancel(self._cancelled)
            token = "event-" + str(index + 1).zfill(10)
            self._events[key] = token
            self._values[canonical_bytes([list(key[:1]), "event_id", key[1]]).decode()] = token
            self._reverse[token] = key[1]

    def event_id(self, value, inv):
        if (str(inv or ""), str(value)) in self._events:
            return self._events[(str(inv or ""), str(value))]
        return self.token("event_id", value, (inv,))

    def require_event_id(self, value, inv, exported_ids):
        token = self._events.get((str(inv or ""), str(value)))
        if token is None or token not in exported_ids:
            raise GoldenBuildFailure(["truth_event_reference_unavailable"])
        return token

    def event(self, original):
        result = project_event_v2(original)
        obs = result.get("ext", {}).get("observation", {})
        context = obs.get("context") or result.get("ext", {}).get("device_observation", {}).get("context", {})
        inv = original.get("investigation_id")
        scope = _token_scope(context, inv)
        def transform(value, key=None):
            if isinstance(value, dict):
                return {k: transform(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [transform(v, key) for v in value]
            if value is None:
                return None
            if key == "event_id":
                return self.event_id(value, inv)
            if key in IP_KEYS:
                return self.token("ip", value, scope)
            if key in IDENTITIES:
                return self.token(key, value, (inv,) if key in {"investigation_id", "evidence_id", "file_id"} else scope)
            return value
        nat = result["ext"]["saw_golden"].pop("nat_scope")
        result = transform(result)
        result["ext"]["saw_golden"]["nat_scope"] = self.token("nat", nat, scope)
        return result

    def filters(self, filters, events):
        contexts = sorted({canonical_bytes(list(_token_scope(((e.get("ext") or {}).get("observation") or {}).get("context") or {},
                                                             e.get("investigation_id")))).decode() for e in events})
        contexts = [tuple(json.loads(v)) for v in contexts]
        inv = events[0].get("investigation_id") if events else None
        allowed = EVENT_KEYS_V2 | {CTX + k for k in CONTEXT_KEYS} | {
            "ext.observation.action", "ext.observation.record_kind", "ext.observation.duration_seconds"}
        output = []
        for item in filters or []:
            field, op, value = item.get("field"), item.get("op", "is"), item.get("value")
            if field not in allowed or op not in {"is", "is_not", "in", "not_in", "exists", "not_exists", "range"}:
                raise ValueError("golden_unsupported_selector")
            key = field.split(".")[-1]
            if op in {"exists", "not_exists"}:
                output.append({"field": field, "op": op, "value": None})
                continue
            if key in IDENTITIES | IP_KEYS:
                if not contexts or op == "range":
                    raise ValueError("golden_unsupported_identity_selector")
                values = value if op in {"in", "not_in"} and isinstance(value, list) else [value]
                converted = []
                for original in values:
                    for context in contexts:
                        if key == "event_id":
                            token = self.event_id(original, inv)
                        elif key in IP_KEYS:
                            token = self.token("ip", original, context)
                        else:
                            token = self.token(key, original, (inv,) if key in {"investigation_id", "evidence_id", "file_id"} else context)
                        if token not in converted:
                            converted.append(token)
                converted.sort(key=str)
                if op in {"is", "is_not"} and len(converted) == 1:
                    value = converted[0]
                else:
                    value = converted
                    op = {"is": "in", "is_not": "not_in"}.get(op, op)
            elif op == "range":
                if key not in NUMERIC_FIELDS or not isinstance(value, dict) or set(value) - {"gt", "gte", "lt", "lte"} or any(type(v) not in {int, float} for v in value.values()):
                    raise ValueError("golden_unsupported_selector")
            else:
                values = value if op in {"in", "not_in"} and isinstance(value, list) else [value]
                if any(_safe_leaf(key, v) != v for v in values):
                    raise ValueError("golden_unsupported_selector")
            output.append({"field": field, "op": op, "value": value})
        return output

    def reverse(self, value):
        check_cancel(self._cancelled)
        if isinstance(value, dict):
            return {k:self.reverse(v) for k,v in value.items()}
        if isinstance(value, list):
            return [self.reverse(v) for v in value]
        return self._reverse.get(value, value) if isinstance(value, str) else value

    def private_content(self):
        entries = []
        for key, value in sorted(self._values.items()):
            check_cancel(self._cancelled)
            entries.append({"scope_type_value": json.loads(key), "pseudonym": value})
        return {"schema": "saw.golden.private-mapping.v1", "entries": entries}
