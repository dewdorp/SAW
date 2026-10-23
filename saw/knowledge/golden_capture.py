"""Read-only complete-scope enumeration and actual firewall semantic attestation."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic

from saw.core.schemas.query import Filter, TimeRange
from saw.knowledge.golden_projection import MAX_BLOB, MAX_CASE, canonical_bytes, check_cancel, digest
from saw.observation.firewall import ENGINE_VERSION, analyze_firewall

MAX_RECORDS = 10_000
CAPTURE_TOKEN = object()
CTX = "ext.observation.context."


@dataclass
class Capture:
    status: str
    reasons: list[str]
    scope: dict
    original_parts: tuple[bytes, ...] = ()
    size_bytes: int = 0
    native_count: int = 0
    source_state: dict = field(default_factory=dict)
    native_memberships: dict = field(default_factory=dict)
    identity_mapper: object = None
    _token: object = field(default=None, repr=False)


def _time(value):
    try:
        parsed = datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed
    except (ValueError, TypeError):
        raise ValueError("golden_known_at_unavailable") from None


def _key(event):
    return _time(event.get("timestamp")).timestamp(), str(event.get("event_id") or "")


def _rows(parts, cancelled):
    for part in parts:
        for line in part.splitlines():
            check_cancel(cancelled)
            if line:
                yield json.loads(line)


def _scope_checks(scope):
    run = scope.get("analysis_run") or {}
    request = run.get("scope") or {}
    if run.get("status") != "complete" or not run.get("finished_at"):
        return ["analysis_run_not_complete"]
    if request.get("detector_id") != "fw.observation":
        return ["single_fw_scope_required"]
    if digest(request) != scope.get("scope_sha256") or digest(run.get("input_manifest")) != run.get("input_sha256"):
        return ["analysis_scope_seal_invalid"]
    if _time(run["finished_at"]) > _time(scope.get("cutoff")):
        return ["analysis_run_after_cutoff"]
    executions = run.get("executions") or []
    if len(executions) != 1 or executions[0].get("detector_id") != "fw.observation" or executions[0].get("status") != "complete" or executions[0].get("detector_version") != ENGINE_VERSION:
        return ["supported_execution_required"]
    units = scope.get("truth_units") or []
    if not units or any(u.get("unit_kind") != "window" or u.get("event_ids") for u in units):
        return ["unsupported_truth_unit"]
    pinset = run["input_manifest"].get("runtime_pin") or {}
    if pinset.get("sha256") != digest({k:v for k,v in pinset.items() if k != "sha256"}):
        return ["runtime_pin_seal_invalid"]
    pins = [p for p in pinset.get("devices", []) if p.get("detector_id") == "fw.observation" and
        (not request.get("org_unit_id") or p["context_scope"].get("org_unit_id") == request["org_unit_id"]) and
        (not request.get("device_id") or p["context_scope"].get("device_id") == request["device_id"])]
    if len(pins) != 1:
        return ["unsupported_fw_partition_count"]
    policy = pins[0].get("policy") or {}
    if policy.get("policy_sha256") != digest({k:v for k,v in policy.items() if k != "policy_sha256"}):
        return ["policy_seal_invalid"]
    from saw.detection.specs import get_spec, validate_values
    spec = get_spec("fw.observation")
    if policy.get("spec_sha256") != spec["sha256"]:
        return ["engine_spec_changed"]
    validate_values(spec, policy.get("values", {}))
    if policy.get("values", {}).get("enabled") is not True or policy.get("exclusions"):
        return ["unsupported_policy_semantics"]
    if not scope.get("truth_cases"):
        return ["truth_case_pin_missing"]
    for case in scope["truth_cases"]:
        payload = case["payload"]
        if digest(payload) != case.get("sha256"):
            return ["truth_case_seal_invalid"]
        if payload.get("investigation_id") != run.get("investigation_id") or any(
                (payload.get(k) or ([] if k == "filters" else None)) !=
                (request.get(k) or ([] if k == "filters" else None))
                for k in ("filters", "time", "org_unit_id", "device_id")):
            return ["truth_case_scope_not_complete"]
    return []


def _policy(scope):
    run = scope["analysis_run"]
    request = run["scope"]
    return next(p["policy"] for p in run["input_manifest"]["runtime_pin"]["devices"]
        if p["detector_id"] == "fw.observation" and
        (not request.get("org_unit_id") or p["context_scope"].get("org_unit_id") == request["org_unit_id"]) and
        (not request.get("device_id") or p["context_scope"].get("device_id") == request["device_id"]))


def _state_checks(scope, state):
    run = scope["analysis_run"]
    expected = {k:v for k,v in run["input_manifest"].items() if k != "runtime_pin"}
    if state.get("source_manifest") != expected:
        return ["source_manifest_changed"]
    if state.get("processing_complete") is not True:
        return ["source_processing_not_complete"]
    if state.get("source_epochs", {}).get(run["investigation_id"]) != expected.get("data_epoch"):
        return ["source_epoch_changed"]
    known = state.get("known_at") or {}
    if known.get("basis") != "server_records":
        return ["known_at_unavailable"]
    keys = ["acquired_at", "processed_at", "profile_available_at"]
    if _policy(scope).get("layers"):
        keys.append("policy_available_at")
    cutoff = _time(scope["cutoff"])
    for key in keys:
        dates = known.get(key)
        if not isinstance(dates, list) or not dates or any(_time(value) > cutoff for value in dates):
            return ["source_not_available_at_cutoff"]
    return []


def capture_complete_scope(store, frozen_scope, *, source_state, cancelled):
    """Only this reader can create a trusted capture; JSON parts are never an authority."""
    check_cancel(cancelled)
    scope = deepcopy(frozen_scope)
    capture = Capture("ineligible", [], scope, _token=CAPTURE_TOKEN)
    try:
        capture.reasons = _scope_checks(scope)
    except (ValueError, KeyError, TypeError):
        capture.reasons = ["complete_scope_invalid"]
    if capture.reasons:
        return capture
    before = source_state()
    try:
        capture.reasons = _state_checks(scope, before)
    except (ValueError, KeyError, TypeError):
        capture.reasons = ["known_at_unavailable"]
    if capture.reasons:
        return capture
    run = scope["analysis_run"]
    request = run["scope"]
    filters = [Filter.model_validate(f) for f in request.get("filters", [])]
    for key in ("org_unit_id", "device_id"):
        if request.get(key):
            filters.append(Filter(field=CTX + key, value=request[key]))
    time = TimeRange.model_validate(request["time"]) if request.get("time") else None
    inv = run["investigation_id"]
    count = store.count(inv, filters, time=time)
    if type(count) is not int or count < 0:
        capture.reasons = ["native_count_invalid"]
        return capture
    capture.native_count = count
    if count > MAX_RECORDS:
        capture.reasons = ["record_limit_exceeded"]
        return capture
    parts, part, total, seen, previous = [], bytearray(), 0, set(), None
    started = monotonic()
    for index, event in enumerate(store.iterate(inv, filters, time=time, batch=500)):
        check_cancel(cancelled)
        if monotonic() - started > 120:
            raise TimeoutError("golden_capture_time_limit")
        if index >= MAX_RECORDS:
            capture.reasons = ["record_limit_lookahead"]
            return capture
        try:
            key = _key(event)
        except ValueError:
            capture.reasons = ["stable_timestamp_required"]
            return capture
        if not key[1] or key[1] in seen or (previous is not None and key <= previous):
            capture.reasons = ["native_enumeration_not_stable"]
            return capture
        if event.get("investigation_id") != inv or event.get("data_source") not in {"firewall", "connection", "zeek_conn"}:
            capture.reasons = ["unsupported_scope_records"]
            return capture
        previous = key
        seen.add(key[1])
        try:
            encoded = canonical_bytes(event, MAX_BLOB, cancelled=cancelled) + b"\n"
        except ValueError:
            capture.reasons = ["record_byte_limit"]
            return capture
        total += len(encoded)
        if total > MAX_CASE:
            capture.reasons = ["case_byte_limit"]
            return capture
        if part and len(part) + len(encoded) > MAX_BLOB:
            parts.append(bytes(part))
            part.clear()
        part.extend(encoded)
    if part:
        parts.append(bytes(part))
    check_cancel(cancelled)
    # Use the same time intersection and native query path as authoritative P2.
    from saw.detection.testing import _filters, _intersect_time
    cases = {case["id"]: case for case in scope["truth_cases"]}
    for unit in scope["truth_units"]:
        case = cases.get(unit.get("case_version_id"))
        if case is None:
            capture.reasons = ["truth_case_pin_missing"]
            return capture
        payload = case["payload"]
        window, empty = _intersect_time(payload.get("time"), unit.get("time"))
        selected = set()
        if not empty:
            unit_filters = _filters(payload) + [Filter.model_validate(f) for f in unit.get("filters", [])]
            for index, row in enumerate(store.iterate(inv, unit_filters, time=window, fields=["event_id"], batch=500)):
                check_cancel(cancelled)
                if monotonic() - started > 120:
                    raise TimeoutError("golden_capture_time_limit")
                ident = row.get("event_id")
                if index >= MAX_RECORDS or ident in selected or ident not in seen:
                    capture.reasons = ["native_truth_membership_invalid"]
                    return capture
                selected.add(ident)
        capture.native_memberships[(case["id"], unit["unit_id"])] = {
            "sha256": digest(sorted(selected)), "count": len(selected)}
    after_count = store.count(inv, filters, time=time)
    after = source_state()
    if len(seen) != count or after_count != count:
        capture.reasons = ["native_count_mismatch"]
        return capture
    if before != after:
        capture.reasons = ["source_changed_during_capture"]
        return capture
    if not seen:
        capture.reasons = ["empty_scope"]
        return capture
    capture.status = "passed"
    capture.original_parts = tuple(parts)
    capture.size_bytes = total
    capture.source_state = deepcopy(before)
    return capture


def _part_manifest(parts, cancelled):
    manifest = []
    for part in parts:
        values = list(_rows([part], cancelled))
        manifest.append({"sha256": hashlib.sha256(part).hexdigest(), "size_bytes": len(part),
            "records": len(values), "first_key": list(_key(values[0])) if values else None,
            "last_key": list(_key(values[-1])) if values else None})
    return manifest


def _core(result, mapper=None):
    """Compare observable semantics, excluding declared internal identifier remapping."""
    if mapper:
        result = mapper.reverse(result)
    out = {k:deepcopy(result.get(k)) for k in ("engine_version", "observation_version", "status", "counts", "quality", "policy")}
    sessions = []
    for session in result.get("sessions", []):
        safe = {k:deepcopy(v) for k,v in session.items() if k not in {"session_key", "event_refs", "context"}}
        safe["context"] = {k:v for k,v in session.get("context", {}).items() if k in {
            "org_unit_id", "network", "device_id", "device_profile_version_id", "virtual_domain", "resolved", "status"}}
        safe["event_ids"] = [r.get("event_id") for r in session.get("event_refs", [])]
        sessions.append(safe)
    out["sessions"] = sorted(sessions, key=lambda v: canonical_bytes(v))
    candidates = []
    for candidate in result.get("candidates", []):
        candidates.append({"kind": candidate.get("kind"), "metrics": deepcopy(candidate.get("metrics", {})),
            "event_ids": [r.get("event_id") for r in candidate.get("event_refs", [])]})
    out["candidates"] = sorted(candidates, key=lambda v: canonical_bytes(v))
    out["coverage_complete"] = result.get("limits", {}).get("coverage_complete")
    return out


def _field(event, field):
    result = event
    for part in field.split("."):
        if not isinstance(result, dict):
            return None
        result = result.get(part)
    return result


def _matches(event, filters):
    for f in filters:
        field, op, value = f.get("field"), f.get("op", "is"), f.get("value")
        actual = _field(event, field)
        if op == "is":
            accepted = actual == value
        elif op == "is_not":
            accepted = actual is None or actual != value
        elif op == "in" and isinstance(value, list):
            accepted = actual in value
        elif op == "not_in" and isinstance(value, list):
            accepted = actual is None or actual not in value
        elif op == "exists":
            accepted = actual is not None
        elif op == "not_exists":
            accepted = actual is None
        elif op == "range" and isinstance(value, dict) and set(value) <= {"gt", "gte", "lt", "lte"}:
            accepted = actual is not None and all(
                (actual > v if k == "gt" else actual >= v if k == "gte" else actual < v if k == "lt" else actual <= v)
                for k,v in value.items())
        else:
            raise ValueError("unsupported_truth_selector")
        if not accepted:
            return False
    return True


def _within(event, ranges):
    from saw.detection.testing import _intersect_time
    window = None
    for selected in ranges:
        window, empty = _intersect_time(window, selected)
        if empty:
            return False
    stamp = _time(event.get("timestamp"))
    return ((not window or not window.start or stamp >= _time(window.start)) and
            (not window or not window.end or stamp <= _time(window.end)))


def verify_complete_scope(capture, original_parts, transformed_parts, *, cancelled):
    if not isinstance(capture, Capture) or capture._token is not CAPTURE_TOKEN or capture.status != "passed":
        raise ValueError("golden_trusted_capture_required")
    check_cancel(cancelled)
    scope, run = capture.scope, capture.scope["analysis_run"]
    result = {"schema": "saw.golden.validation.v1", "validator_version": "fw-complete/1", "status": "failed",
        "reasons": [], "golden_ref": scope["golden_ref"],
        "analysis_run_ref": {"id": run["id"], "input_sha256": run["input_sha256"]},
        "scope_sha256": scope["scope_sha256"], "source_manifest_sha256": digest(capture.source_state["source_manifest"]),
        "source_epochs": capture.source_state["source_epochs"], "input_count": capture.native_count,
        "observed_count": 0, "engine": {"id": "fw.observation", "version": ENGINE_VERSION},
        "policy_sha256": _policy(scope)["policy_sha256"], "checks": [], "known_at": {
            "basis": "server_records", "cutoff": scope["cutoff"], "passed": True},
        "truth_preserved": False, "references_resolve": False, "leakage_passed": False}
    def fail(code):
        result["reasons"].append(code)
        return result
    if tuple(original_parts) != capture.original_parts:
        return fail("original_parts_changed")
    if sum(map(len, transformed_parts)) > MAX_CASE:
        return fail("transformed_case_byte_limit")
    original = list(_rows(original_parts, cancelled))
    transformed = list(_rows(transformed_parts, cancelled))
    if len(original) != len(transformed) or len(original) != capture.native_count or capture.identity_mapper is None:
        return fail("transformed_input_count_or_mapping_invalid")
    mapper = capture.identity_mapper
    expected_ids = [e["event_id"] for e in original]
    if [mapper.reverse(e.get("event_id")) for e in transformed] != expected_ids or len({e.get("event_id") for e in transformed}) != len(transformed):
        return fail("event_order_or_identity_changed")
    if any(_key(a)[0] != _key(b)[0] for a,b in zip(original, transformed, strict=True)):
        return fail("event_time_changed")
    policy = {k:v for k,v in _policy(scope)["values"].items() if k != "enabled"}
    limits = run["executions"][0].get("detail", {}).get("limits", {})
    max_results = limits.get("max_results", 100)
    if type(max_results) is not int or not 1 <= max_results <= 1000:
        return fail("saved_limits_invalid")
    original_result = analyze_firewall(iter(original), policy=policy, max_records=MAX_RECORDS,
                                       max_results=max_results, cancelled=cancelled)
    transformed_result = analyze_firewall(iter(transformed), policy=policy, max_records=MAX_RECORDS,
                                          max_results=max_results, cancelled=cancelled)
    check_cancel(cancelled)
    for report in (original_result, transformed_result):
        if report["status"] not in {"completed_match", "completed_no_match"} or not report["limits"]["coverage_complete"] or any(
                report["counts"].get(k) for k in ("omitted_sessions", "omitted_candidates", "unresolved_records")):
            return fail("engine_result_incomplete")
    # Saved results use the existing metadata masker. Compare both through that exact representation.
    from saw.knowledge.golden import masked
    original_core = _core(original_result)
    saved_core = _core(run["executions"][0]["detail"])
    if masked(original_core) != saved_core and original_core != saved_core:
        return fail("saved_engine_result_changed")
    transformed_core = _core(transformed_result, mapper)
    if original_core != transformed_core:
        return fail("transformed_engine_semantics_changed")
    cases = {c["id"]: c for c in scope["truth_cases"]}
    raw_hash = digest(sorted(digest(e) for e in original))
    outcomes = []
    membership_checks = []
    for unit in scope["truth_units"]:
        check_cancel(cancelled)
        case = cases.get(unit.get("case_version_id"))
        if case is None or case.get("input_sha256") != raw_hash or case.get("input_count") != len(original):
            return fail("truth_input_not_complete")
        pinned = next((u for u in case["payload"]["units"] if u["unit_id"] == unit["unit_id"]), None)
        if pinned is None or pinned != {k:v for k,v in unit.items() if k != "case_version_id"}:
            return fail("truth_unit_pin_changed")
        try:
            members = [index for index,e in enumerate(original) if _within(e, [case["payload"].get("time"), unit.get("time")]) and _matches(e, unit.get("filters", []))]
        except (ValueError, TypeError, KeyError):
            return fail("unsupported_truth_selector")
        authority = capture.native_memberships.get((case["id"], unit["unit_id"]))
        member_sha = digest(sorted(original[i]["event_id"] for i in members))
        if not authority or authority != {"sha256": member_sha, "count": len(members)}:
            return fail("native_truth_membership_changed")
        membership_checks.append({"code": "native_truth_membership", "state": "passed",
            "expected_sha256": authority["sha256"], "actual_sha256": member_sha, "input_count": len(members)})
        if not members:
            return fail("truth_window_empty")
        try:
            transformed_filters = mapper.filters(unit.get("filters", []), original)
            transformed_members = [index for index,e in enumerate(transformed)
                if _within(e, [case["payload"].get("time"), unit.get("time")]) and _matches(e, transformed_filters)]
        except (ValueError, TypeError, KeyError):
            return fail("unsupported_transformed_truth_selector")
        if members != transformed_members:
            return fail("truth_selector_membership_changed")
        # Membership/order is complete, independent of the detector's representative evidence refs.
        left = analyze_firewall((original[i] for i in members), policy=policy, max_records=MAX_RECORDS,
                                max_results=max_results, cancelled=cancelled)
        right = analyze_firewall((transformed[i] for i in members), policy=policy, max_records=MAX_RECORDS,
                                 max_results=max_results, cancelled=cancelled)
        if left["status"] not in {"completed_match", "completed_no_match"} or _core(left) != _core(right, mapper):
            return fail("truth_window_semantics_changed")
        outcomes.append({"case_version_id": unit["case_version_id"], "unit_id": unit["unit_id"],
            "event_ids": [original[i]["event_id"] for i in members], "prediction": bool(left["counts"]["candidates"]),
            "detection_truth": unit["detection_truth"], "investigation_truth": unit["investigation_truth"]})
    result.update(status="passed", complete=True, observed_count=len(original), truth_preserved=True,
                  references_resolve=True, leakage_passed=True,
                  original_parts=_part_manifest(original_parts, cancelled),
                  transformed_parts=_part_manifest(transformed_parts, cancelled))
    result["checks"] = membership_checks + [
        {"code": "saved_engine_result", "state": "passed", "expected_sha256": digest(saved_core), "actual_sha256": digest(masked(original_core))},
        {"code": "transformed_engine_result", "state": "passed", "expected_sha256": digest(original_core), "actual_sha256": digest(transformed_core)},
        {"code": "complete_window_outcomes", "state": "passed", "expected_sha256": digest(outcomes), "actual_sha256": digest(outcomes)}]
    return result
