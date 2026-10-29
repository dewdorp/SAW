"""Producer-owned device metadata and public calculator dispatch."""
from __future__ import annotations

import ipaddress
import math
from copy import deepcopy

from saw.analyzers.http.useragent import classify_ua
from saw.analyzers.log.normalize import parse_time
from saw.analyzers.patterns import pattern_tags
from saw.observation.connection import _lookup, _original_time, connection_observation

DEVICE_VERSION = "device-observation/1"


def _number(value):
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else None
    except (ValueError, TypeError, OverflowError):
        return None


def device_observation(event, *, context_snapshot=None):
    """Only a server-validated immutable source profile supplies device meanings."""
    snapshot = deepcopy(context_snapshot) if context_snapshot is not None else {}
    profile = snapshot.get("profile") or {}
    semantics = profile.get("device_semantics") or {}
    mapping = profile.get("source_fields") or {}
    safe = {**event, "ext": {k: v for k, v in (event.get("ext") or {}).items() if k != "device_observation"}}
    base = connection_observation(safe, context_snapshot=snapshot)
    verified = semantics.get("verified") is True and bool(semantics.get("basis"))
    def value(key, fallback=None):
        return _lookup(safe, mapping.get(key, fallback))[1]
    def time_value(key):
        raw = _original_time(safe, mapping.get(key))
        return parse_time(str(raw), (profile.get("time") or {}).get("timezone") or "Asia/Seoul")[0] if raw not in (None, "", "-") else None
    kind_raw = value("record_kind")
    kind = (profile.get("record_kind_map") or {}).get(str(kind_raw), kind_raw)
    if kind in {"session_start", "session_interim", "session_end"}:
        kind = "flow"
    if kind not in {"request", "rule_hit", "alert", "interval_summary", "flow", "dns", "http", "tls"}:
        kind = semantics.get("record_kind", "unknown")
    ua = value("user_agent", "user_agent")
    ua_state = ((safe.get("ext") or {}).get("saw_observation") or {}).get("user_agent", "not_collected")
    if ua_state == "present":
        ua_state = "observed"
    if mapping.get("user_agent") and _lookup(safe, mapping["user_agent"])[0]:
        ua_state = "observed" if isinstance(ua, str) and ua else "recorded_empty" if ua == "" else "not_collected"
    client = event.get("src_ip")
    quality = [q for q in base["quality"] if q in {"unresolved_context", "conflicting_row_attribution",
                                                "unverified_row_attribution", "timestamp_context_conflict"}]
    if semantics.get("trusted_forwarded") is True and verified and semantics.get("forwarded_basis"):
        forwarded = value("forwarded_ip")
        try:
            client = str(ipaddress.ip_address(forwarded))
        except (ValueError, TypeError):
            quality.append("invalid_trusted_forwarded_ip")
    uri = value("uri", "uri")
    status = _number(value("http_status", "status_code"))
    edge, origin = _number(value("edge_status")), _number(value("origin_status"))
    if semantics.get("response_location") == "edge" and edge is None:
        edge = status
    if semantics.get("response_location") == "origin" and origin is None:
        origin = status
    mode = value("mode") or semantics.get("mode", "unknown")
    mode = mode if mode in {"inline", "mirror"} else "unknown"
    return {"producer": "saw", "version": DEVICE_VERSION, "verified": verified,
            "context": deepcopy(base["context"]), "connection": base, "functions": (snapshot.get("observer") or {}).get("functions") or profile.get("functions") or [],
            "profile_version": (snapshot.get("observer") or {}).get("device_profile_version_id"),
            "record_kind": kind, "timestamp": base["timestamp"], "timestamp_raw": base["timestamp_raw"],
            "time_verified": (profile.get("time") or {}).get("verified") is True,
            "timestamp_precision": base.get("timestamp_precision"), "collection": snapshot.get("collection") or {},
            "observation_point": (snapshot.get("observer") or {}).get("observation_point") or profile.get("observation_point"),
            "client_ip": client, "src_ip": event.get("src_ip"), "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"), "protocol": event.get("protocol"),
            "service": event.get("hostname") or event.get("dst_ip"), "request_id": value("request_id", "request_id"),
            "signature_id": value("signature_id"), "action": base["action"], "mode": mode,
            "packet_available": semantics.get("packet_available"), "severity": value("severity", "severity"),
            "uri": uri, "path": str(uri or "").split("?", 1)[0],
            "user_agent_state": ua_state, "ua_class": classify_ua(ua)["class"] if isinstance(ua, str) and ua else "unknown",
            "attack_patterns": pattern_tags(str(uri or "")[:8192]), "status": status,
            "edge_status": edge, "origin_status": origin, "domain": value("domain", "domain"),
            "tls_version": value("tls_version"), "target": value("target") or event.get("dst_ip"),
            "attack_type": value("attack_type"), "interval_start": time_value("interval_start"),
            "interval_end": time_value("interval_end"), "rate": _number(value("rate")),
            "rate_unit": semantics.get("rate_unit", "unknown"), "rate_statistic": semantics.get("rate_statistic", "unknown"),
            "sampling_ratio": (_number(value("sampling_ratio")) if mapping.get("sampling_ratio")
                               else semantics.get("sampling_ratio")), "sampling_version": semantics.get("sampling_version", "unknown"),
            "mitigation": value("mitigation") if value("mitigation") in {"before", "after"} else "unknown",
            "capture_kind": semantics.get("capture_kind", "unknown"), "bidirectional": semantics.get("bidirectional"),
            "quality": quality}


def analyze_device(detector_id, events, *, policy=None, context_snapshot=None, max_records=1_000_000,
                   max_results=100, cancelled=None, runtime_pin=None, profile_lookup=None):
    from saw.detection.specs import get_spec, validate_values
    from saw.observation import device_calculators
    from saw.observation.result import DeviceRun

    aliases = {"fw": "fw.observation", "waf": "waf.observation", "ips": "ips.observation",
               "ddos": "ddos.observation", "ndr": "ndr.observation"}
    detector_id = aliases.get(str(detector_id).lower(), detector_id)
    spec = get_spec(detector_id)
    pinned_values = ((runtime_pin or {}).get("policy") or {}).get("values", {})
    effective = validate_values(spec, policy if policy is not None else pinned_values)
    if detector_id == "fw.observation":
        from saw.observation.firewall import analyze_firewall
        if not effective["enabled"]:
            return {"engine_version": spec["engine"]["version"], "status": "disabled", "counts": {"records": 0, "candidates": 0},
                    "candidates": [], "quality": {}, "timeline": [], "limits": {"coverage_complete": False}, "policy": effective}
        return analyze_firewall(events, policy={k: v for k, v in effective.items() if k != "enabled"},
                                context_snapshot=context_snapshot, max_records=max_records, max_results=max_results, cancelled=cancelled)
    with DeviceRun(spec, effective, events, context_snapshot=context_snapshot, max_records=max_records,
                   max_results=max_results, cancelled=cancelled, profile_lookup=profile_lookup) as run:
        if effective["enabled"] and not run.was_cancelled:
            try:
                getattr(device_calculators, detector_id.split(".")[0])(run, runtime_pin=runtime_pin)
            except __import__("sqlite3").OperationalError:
                if not run.was_cancelled:
                    raise
        return run.finish()
