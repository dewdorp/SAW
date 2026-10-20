"""Producer-owned connection observations; raw extensions never establish semantics."""
from __future__ import annotations

import math
import re
from copy import deepcopy
from typing import TypedDict

VERSION = "connection-observation/1"


class ConnectionObservation(TypedDict):
    producer: str
    version: str
    context: dict
    counters: dict
    quality: list


def _lookup(event, field):
    if not field:
        return False, None
    if field in event:
        return True, event[field]
    ext = event.get("ext") or {}
    for product, values in ext.items():
        if product in {"observation", "saw_observation"} or not isinstance(values, dict):
            continue
        if field in values:
            return True, values[field]
    from saw.parsers.structured import alias_for

    canonical = alias_for(field)
    if canonical and canonical in event:
        return True, event[canonical]
    return False, None


def _original_time(event, field):
    """Read a mapped source timestamp before its CES alias was normalized."""
    if not field:
        return None
    for key, values in (event.get("ext") or {}).items():
        if key not in {"observation", "saw_observation"} and isinstance(values, dict) and field in values:
            return values[field]
    from saw.parsers.structured import alias_for

    if alias_for(field) == "timestamp_raw" or field == "timestamp_raw":
        return event.get("timestamp_raw")
    return _lookup(event, field)[1]


def _counter(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        return int(value)
    return None


def _number(value):
    try:
        number = float(value)
        return number if math.isfinite(number) and number >= 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


_CONTEXT_HINTS = {
    "org_unit_id": {"orgunitid", "orgunit", "recordorg", "affiliateid", "affiliate", "company", "tenantid"},
    "device_id": {"deviceid", "device", "devicename", "observerid"},
    "device_profile_version_id": {"deviceprofileversionid"},
    "network": {"network", "networkid"},
    "virtual_domain": {"virtualdomain", "vdom", "vsys"},
}


def _row_context(event, context, mapping):
    """A raw hint can corroborate explicit file attribution, never replace it."""
    from saw.parsers.structured import compact_key

    raw_sources = [event] + [values for key, values in (event.get("ext") or {}).items()
                             if key not in {"observation", "saw_observation"} and isinstance(values, dict)]
    attribution, flags = {}, set()
    for semantic, aliases in _CONTEXT_HINTS.items():
        declared = mapping.get(semantic)
        hints = []
        if declared:
            present, raw = _lookup(event, declared)
            hints.append((declared, raw, present, True))
        for source in raw_sources:
            for field, raw in source.items():
                if compact_key(str(field)) in aliases and field != declared:
                    hints.append((field, raw, True, False))
        if not hints:
            continue
        expected = context.get(semantic)
        states = []
        for field, raw, present, explicitly_mapped in hints:
            if not explicitly_mapped:
                state = "unmapped"
            elif not present:
                state = "not_collected"
            elif raw in (None, "", "-", "(empty)"):
                state = "recorded_empty"
            elif not isinstance(raw, str) or expected in (None, ""):
                state = "unresolved"
            else:
                state = "matches" if raw.strip() == str(expected) else "conflicting"
            states.append({"source_field": field, "raw_value": raw, "state": state})
        attribution[semantic] = {**states[0], "expected": expected, "hints": states}
        if any(item["state"] == "conflicting" for item in states):
            flags.add("conflicting_row_attribution")
        if any(item["state"] not in {"matches", "conflicting"} for item in states):
            flags.add("unverified_row_attribution")
    if attribution:
        context["file_context"] = {field: context.get(field) for field in _CONTEXT_HINTS}
        context["row_attribution"] = attribution
    if flags:
        for field in _CONTEXT_HINTS:
            context[field] = None
        context["resolved"] = False
        context["status"] = "conflicting" if "conflicting_row_attribution" in flags else "unresolved"
    return sorted(flags)


def connection_observation(event: dict, *, context_snapshot: dict | None = None) -> ConnectionObservation:
    """Adapt normalized CES using an explicit server-validated immutable context.

    Callers must not pass uploaded dictionaries as context_snapshot. Persisted observations
    are created by finalize; profile/semantic claims inside uploaded ext are ignored.
    """
    snapshot = deepcopy(context_snapshot) if context_snapshot is not None else {}
    profile = snapshot.get("profile") or {}
    subject = snapshot.get("subject") or {}
    observer = snapshot.get("observer") or {}
    mapping = profile.get("source_fields") or snapshot.get("source_fields") or {}
    measurement = profile.get("measurement_profile") or snapshot.get("measurement_profile") or {}
    org = subject.get("org_unit_id") if subject.get("status") == "verified" else snapshot.get("org_unit_id")
    if subject and subject.get("status") != "verified":
        org = None
    context = {key: observer.get(key, snapshot.get(key)) for key in
               ("device_id", "device_profile_version_id", "network", "virtual_domain")}
    context["org_unit_id"] = org
    context["resolved"] = bool(org and context["device_id"] and context["device_profile_version_id"]
                               and context["network"])
    row_quality = _row_context(event, context, mapping)
    mode = measurement.get("counter_semantics", "unknown")
    verified = measurement.get("verified") is True
    direction = measurement.get("direction", "unknown")
    unit = measurement.get("unit", "unknown")
    counters = {}
    zeek = event.get("product") == "zeek" and event.get("parser", "").startswith("zeek")
    specs = (("src_to_dst_bytes", "src_bytes", "bytes_out", "orig_bytes", "bytes"),
             ("dst_to_src_bytes", "dst_bytes", "bytes_in", "resp_bytes", "bytes"),
             ("src_to_dst_packets", "src_packets", "orig_pkts" if zeek else "src_packets", None, "packets"),
             ("dst_to_src_packets", "dst_packets", "resp_pkts" if zeek else "dst_packets", None, "packets"))
    for name, semantic, legacy, ambiguous, expected_unit in specs:
        if direction == "dst_to_src":
            semantic = semantic.replace("src_", "dst_", 1) if semantic.startswith("src_") else semantic.replace("dst_", "src_", 1)
        field = mapping.get(semantic)
        present, raw = _lookup(event, field)
        counter_mode, counter_unit = mode, unit
        understood = (bool(field) and verified and direction in {"src_to_dst", "dst_to_src"} and unit == expected_unit
                      and mode in {"cumulative", "delta", "total"})
        if zeek and not field:
            field, counter_mode, counter_unit, understood = legacy, "total", expected_unit, True
            present, raw = _lookup(event, legacy)
        if not field:
            field = legacy
            present, raw = _lookup(event, legacy)
            if not present and ambiguous:
                present, raw = _lookup(event, ambiguous)
                if present:
                    field = ambiguous
        state = ("not_collected" if not present else "recorded_empty" if raw in (None, "", "-", "(empty)")
                 else "unknown_semantics" if not understood else "observed")
        number = _counter(raw) if state == "observed" else None
        if state == "observed" and number is None:
            state = "invalid"
        counters[name] = {"value": number, "raw_value": raw, "state": state, "unit": counter_unit,
                          "counter_mode": counter_mode, "source_field": field}
    def value(semantic, default=None):
        return _lookup(event, mapping.get(semantic, default))[1]
    raw_kind = value("record_kind", "record_kind")
    kind = (profile.get("record_kind_map") or {}).get(str(raw_kind), raw_kind)
    if kind not in {"session_start", "session_interim", "session_end"}:
        kind = "session_end" if zeek else "unknown"
    action_raw = value("action", "action")
    action_map = profile.get("action_map") or snapshot.get("action_map") or {}
    action = action_map.get(str(action_raw), "unknown") if profile.get("action_verified") is True else "unknown"
    if action not in {"allowed", "blocked", "reset", "detected", "challenged", "unknown", "conflicting"}:
        action = "unknown"
    quality = ([] if context["resolved"] else ["unresolved_context"]) + row_quality
    if not event.get("src_ip") or not event.get("dst_ip"):
        quality.append("missing_endpoints")
    if action in {"unknown", "conflicting"}:
        quality.append("unverified_action")
    if kind == "unknown":
        quality.append("unknown_record_kind")
    from saw.analyzers.log.normalize import parse_time

    from saw.behavior.observation import bounded_timestamp_precision

    time_profile = profile.get("time") or {}
    def normalized_time(raw):
        if raw in (None, "", "-", "(empty)"):
            return None
        return parse_time(str(raw), time_profile.get("timezone") or "Asia/Seoul")[0]

    raw_timestamp = (_original_time(event, mapping["timestamp"]) if mapping.get("timestamp")
                     else event.get("timestamp_raw"))
    timestamp = normalized_time(raw_timestamp) if mapping.get("timestamp") else event.get("timestamp")
    start_time = normalized_time(_original_time(event, mapping.get("start_time")))
    end_time = normalized_time(_original_time(event, mapping.get("end_time")))
    collected_time_raw = _original_time(event, mapping.get("collected_time"))
    collected_time = normalized_time(collected_time_raw)
    if timestamp is not None and event.get("timestamp") is not None and timestamp != event["timestamp"]:
        quality.append("timestamp_context_conflict")
    duration_unit = measurement.get("duration_unit", "unknown")
    duration = _number(value("duration")) if verified and duration_unit in {"seconds", "milliseconds"} else None
    if duration is not None and duration_unit == "milliseconds":
        duration /= 1000
    return {"producer": "saw", "version": VERSION, "context": context, "counters": counters,
            "profile_version": context["device_profile_version_id"], "record_kind": kind, "raw_record_kind": raw_kind,
            "session_id": value("session_id", "session_id"),
            "start_time": start_time or (event.get("timestamp") if zeek else None),
            "end_time": end_time, "raw_action": action_raw, "action": action,
            "duration_seconds": duration,
            "timestamp": timestamp, "timestamp_raw": raw_timestamp, "time_profile": time_profile,
            "timestamp_precision": bounded_timestamp_precision(raw_timestamp, time_profile.get("precision")),
            "ces_timestamp": event.get("timestamp"), "ces_timestamp_quality": event.get("timestamp_quality"),
            "collected_time": collected_time, "collected_time_raw": collected_time_raw,
            "collection": snapshot.get("collection") or {"scope": "unknown"},
            "quality": quality}
