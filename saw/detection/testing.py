"""Bounded, exact-version evaluation against explicit selected detection truth."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from time import monotonic
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from saw import container
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, list_for, require
from saw.core.application.provenance import canonical, digest
from saw.core.schemas.query import Filter, TimeRange
from saw.core.security.authz import can
from saw.detection.truth_models import DetectionCase, DetectionCaseVersion
from saw.storage.db import utcnow
from saw.storage.models import User, UserSession

MAX_RECORDS = 50000
MAX_HITS = 20000
MAX_SELECTED_IDS = 100000
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_SECONDS = 30


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TruthUnit(Strict):
    unit_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    unit_kind: Literal["event", "window", "entity", "sequence"]
    event_ids: list[str] = Field(default_factory=list, max_length=1000)
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    time: TimeRange | None = None
    detection_truth: Literal["expected_match", "expected_no_match", "unlabeled"]
    investigation_truth: Literal["attack", "attempt", "approved_activity", "normal", "false_positive",
                                "undetermined", "insufficient_data"]
    basis: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def selected(self):
        if self.unit_kind in {"event", "sequence"} and not self.event_ids:
            raise ValueError("event_ids_required")
        if self.unit_kind == "entity" and not self.filters:
            raise ValueError("entity_filters_required")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("duplicate_event_ids")
        _time(self.time)
        return self


class CaseInput(Strict):
    title: str = Field(min_length=1, max_length=256)
    investigation_id: str = Field(min_length=1, max_length=36)
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    time: TimeRange | None = None
    org_unit_id: str | None = Field(None, min_length=1, max_length=36)
    device_id: str | None = Field(None, min_length=1, max_length=36)
    units: list[TruthUnit] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def bounded(self):
        if len({u.unit_id for u in self.units}) != len(self.units):
            raise ValueError("duplicate_unit_ids")
        if len(canonical(self.model_dump()).encode()) > 131072:
            raise ValueError("truth_request_too_large")
        _time(self.time)
        return self


class UnitRef(Strict):
    case_version_id: str = Field(min_length=1, max_length=36)
    unit_id: str = Field(min_length=1, max_length=80)


class SelectedTestInput(Strict):
    method: Literal["selected_truth_v1"]
    version_id: str = Field(min_length=1, max_length=36)
    payload_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    reference_version_id: str | None = Field(None, min_length=1, max_length=36)
    units: list[UnitRef] = Field(min_length=1, max_length=100)
    context_scope: dict = Field(default_factory=lambda: {"kind": "group"})

    @model_validator(mode="after")
    def bounded(self):
        pairs = {(u.case_version_id, u.unit_id) for u in self.units}
        if len(pairs) != len(self.units) or len({p[0] for p in pairs}) > 20:
            raise ValueError("selected_truth_scope_limit")
        if len(canonical(self.context_scope).encode()) > 2048:
            raise ValueError("context_scope_too_large")
        return self


def _time(value):
    if value is None:
        return None
    value = TimeRange.model_validate(value) if isinstance(value, dict) else value
    dates = []
    for raw in (value.start, value.end):
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00")) if raw else None
        if dt is not None and dt.tzinfo is None:
            raise ValueError("truth_time_timezone_required")
        dates.append(dt)
    if all(dates) and dates[0] >= dates[1]:
        raise ValueError("truth_time_range_invalid")
    return value


def _manifest(s, inv_id):
    from saw.analysis_runs.scoped import _idle
    from saw.analysis_runs.scoped import _manifest as source_manifest
    _idle(s, inv_id)
    return source_manifest(s, inv_id)


def _filters(payload):
    filters = [Filter.model_validate(f) for f in payload.get("filters", [])]
    for name in ("org_unit_id", "device_id"):
        if payload.get(name):
            filters.append(Filter(field="ext.observation.context." + name, value=payload[name]))
    return filters


def _stream(payload, extra=None, time=None, fields=None):
    return container.get().events.iterate(payload["investigation_id"], _filters(payload) + (extra or []),
        _time(time if time is not None else payload.get("time")), fields=fields, batch=500)


def _fingerprint(payload, deadline):
    hashes = []
    for ev in _stream(payload):
        if len(hashes) >= MAX_RECORDS or monotonic() >= deadline:
            raise HTTPException(409, "selected_truth_input_limit")
        encoded = canonical(ev)
        if len(encoded.encode()) > 1024 * 1024:
            raise HTTPException(409, "selected_truth_record_limit")
        hashes.append(digest(ev))
    return {"count": len(hashes), "sha256": digest(sorted(hashes))}


def _current_principal(s, p, session_id=None, permission="detection.write"):
    s.expire_all()
    user = s.get(User, p.user_id)
    if user is None or user.status != "active":
        raise Forbidden("selected_truth_user_unavailable")
    current = principal_of(user)
    if not can(current, permission):
        raise Forbidden(permission)
    if session_id:
        login = s.get(UserSession, session_id)
        if (login is None or login.user_id != p.user_id or login.revoked_at is not None
                or not login.mfa_passed or login.expires_at.replace(tzinfo=UTC) <= utcnow()):
            raise Forbidden("selected_truth_session_changed")
    return current


def case_dict(row):
    if digest(row.payload) != row.sha256:
        raise HTTPException(409, "selected_truth_corrupt")
    payload = deepcopy(row.payload)
    return {"id": row.id, "case_id": row.case_id, "version": row.version, "sha256": row.sha256,
            "investigation_id": row.investigation_id, "title": payload["title"],
            "scope": {k: v for k, v in payload.items() if k not in {"title", "units"}},
            "units": payload["units"], "input_count": row.input_count}


def get_case(s, p, version_id, *, current=False):
    row = s.get(DetectionCaseVersion, version_id)
    if row is None:
        raise NotFound("detection case not found")
    require(s, p, "investigation.read", row.investigation_id)
    case_dict(row)
    case = s.get(DetectionCase, row.case_id)
    if case is None or (current and case.current_version != row.version):
        raise HTTPException(409, "selected_truth_version_changed")
    return row


def create_case(s, p, raw, case_id=None, *, session_id=None):
    body = CaseInput.model_validate(raw)
    payload = body.model_dump()
    if not can(p, "detection.write"):
        raise Forbidden("detection.write")
    require(s, p, "investigation.write", body.investigation_id)
    if body.org_unit_id:
        from saw.source_context.service import org_by_id
        org_by_id(s, body.org_unit_id)
    if body.device_id:
        from saw.source_context.models import Device
        device = s.get(Device, body.device_id)
        if device is None or device.investigation_id != body.investigation_id:
            raise ValueError("truth_device_outside_investigation")
    case = s.get(DetectionCase, case_id) if case_id else None
    if case_id and (case is None or case.investigation_id != body.investigation_id):
        raise NotFound("detection case not found")
    expected_version = case.current_version if case else 0
    manifest = _manifest(s, body.investigation_id)
    s.commit()
    fingerprint = _fingerprint(payload, monotonic() + MAX_SECONDS)
    current = _current_principal(s, p, session_id)
    # No source lock is held during native search.
    audit._head(s)
    lock_investigation(s, body.investigation_id)
    require(s, current, "investigation.write", body.investigation_id)
    if _manifest(s, body.investigation_id) != manifest:
        raise HTTPException(409, "selected_truth_input_changed")
    if case_id:
        case = s.get(DetectionCase, case_id, populate_existing=True)
        if case is None or case.current_version != expected_version:
            raise HTTPException(409, "selected_truth_version_changed")
        previous = s.scalar(select(DetectionCaseVersion).where(DetectionCaseVersion.case_id == case_id,
                                                               DetectionCaseVersion.version == expected_version))
        contributors = set(previous.contributor_ids)
    else:
        case = DetectionCase(investigation_id=body.investigation_id, created_by=p.user_id, current_version=0)
        s.add(case)
        s.flush()
        contributors = set()
    contributors.add(p.user_id)
    case.current_version += 1
    row = DetectionCaseVersion(case_id=case.id, version=case.current_version, investigation_id=body.investigation_id,
        payload=payload, sha256=digest(payload), source_manifest=manifest, input_sha256=fingerprint["sha256"],
        input_count=fingerprint["count"], contributor_ids=sorted(contributors), created_by=p.user_id)
    s.add(row)
    s.flush()
    audit.record(s, "detection.truth_version", actor_id=p.user_id, actor_name=p.username,
        target_type="detection_case", target_id=case.id, investigation_id=body.investigation_id,
        detail={"version": row.version, "sha256": row.sha256})
    return row


def list_cases(s, p, investigation_id=None, limit=50, before=None):
    limit = max(1, min(100, limit))
    if investigation_id:
        require(s, p, "investigation.read", investigation_id)
        ids = [investigation_id]
    else:
        ids = [i.id for i in list_for(s, p, 500)]
    query = select(DetectionCaseVersion).join(DetectionCase, DetectionCase.id == DetectionCaseVersion.case_id).where(
        DetectionCaseVersion.investigation_id.in_(ids), DetectionCase.current_version == DetectionCaseVersion.version)
    if before:
        query = query.where(DetectionCaseVersion.id < before)
    rows = list(s.scalars(query.order_by(DetectionCaseVersion.id.desc()).limit(limit + 1)))
    return {"items": [case_dict(row) for row in rows[:limit]], "next_cursor": rows[limit - 1].id if len(rows) > limit else None}


def metrics(units):
    out = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "labeled": 0, "unlabeled": 0}
    for u in units:
        if u["detection_truth"] == "unlabeled":
            out["unlabeled"] += 1
            continue
        if u["status"] != "complete" or u["prediction"] is None:
            continue
        expected, predicted = u["detection_truth"] == "expected_match", u["prediction"]
        out["tp" if expected and predicted else "fn" if expected else "fp" if predicted else "tn"] += 1
        out["labeled"] += 1
    for name, denominator in (("precision", out["tp"] + out["fp"]), ("recall", out["tp"] + out["fn"])):
        out[name] = {"numerator": out["tp"], "denominator": denominator,
                     "value": out["tp"] / denominator if denominator else None}
    return out


def _intersect_time(case_time, unit_time):
    a, b = _time(case_time), _time(unit_time)
    starts = [x.start for x in (a, b) if x and x.start]
    ends = [x.end for x in (a, b) if x and x.end]
    key = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))
    start = max(starts, key=key) if starts else None
    end = min(ends, key=key) if ends else None
    if start and end and key(start) >= key(end):
        return None, True
    return TimeRange(start=start, end=end), False


def _members(payload, units, deadline):
    sets, total = {}, 0
    for u in units:
        extra = [Filter.model_validate(f) for f in u["filters"]]
        if u["event_ids"]:
            extra.append(Filter(field="event_id", op="in", value=u["event_ids"]))
        window, empty = _intersect_time(payload.get("time"), u.get("time"))
        ids = set()
        if not empty:
            for ev in _stream(payload, extra, window, ["event_id"]):
                total += 1
                if total > MAX_SELECTED_IDS or monotonic() >= deadline:
                    raise HTTPException(409, "selected_truth_unit_limit")
                ids.add(ev["event_id"])
        sets[u["unit_id"]] = ids
    return sets


def _sigma_case(pin, payload, units, deadline):
    from saw.detection.auto import _project_metadata
    from saw.detection.sigma_eval import (
        SigmaError,
        _get,
        apply_threshold,
        compile_rule,
        evaluate,
        local_field,
    )
    data = pin["rule"]["payload"]
    if data["format"] != "sigma":
        return {u["unit_id"]: {"status": "unsupported_unit", "prediction": None, "input_count": 0,
                              "matching_event_ids": []} for u in units}
    rule = compile_rule(data["logic"])
    threshold = data.get("threshold") or {}
    policy = pin.get("policy") or {}
    excluded = set()
    for exceptions in (data.get("exceptions") or [], policy.get("exclusions") or []):
        if not exceptions:
            continue
        for ev in _stream(payload, [Filter.model_validate(x) for x in exceptions], fields=["event_id"]):
            if len(excluded) >= MAX_RECORDS or monotonic() >= deadline:
                raise HTTPException(409, "selected_truth_exception_limit")
            excluded.add(ev["event_id"])
    members = _members(payload, units, deadline)
    required = {local_field(field) for groups in rule.detections.values() for group in groups for field, mods, values in group
                if "exists" not in mods and None not in values}
    fields = {"event_id", "timestamp", *[local_field(f) for f in threshold.get("group_by", [])]}
    if threshold.get("distinct_field"):
        fields.add(local_field(threshold["distinct_field"]))
    hits, known, unknown = [], set(), set()
    scanned, bytes_used, execution = 0, 0, "complete"
    for ev in _stream(payload):
        if scanned >= MAX_RECORDS or monotonic() >= deadline:
            execution = "partial"
            break
        scanned += 1
        eid = ev["event_id"]
        if (rule.data_sources and ev.get("data_source") not in rule.data_sources) or any(_get(ev, f) is None for f in required):
            unknown.add(eid)
            continue
        if threshold and any(_get(ev, f) is None for f in fields):
            unknown.add(eid)
            continue
        known.add(eid)
        if eid in excluded or policy.get("values", {}).get("enabled") is False:
            continue
        try:
            if evaluate(rule, ev):
                metadata, size = _project_metadata(ev, fields)
                bytes_used += size
                if len(hits) >= MAX_HITS or bytes_used > MAX_METADATA_BYTES:
                    execution = "partial"
                    break
                hits.append(metadata)
        except SigmaError:
            execution = "failed"
            break
    try:
        matched = {e["event_id"] for e in apply_threshold(hits, threshold)} if execution == "complete" else set()
    except SigmaError:
        execution, matched = "failed", set()
    out = {}
    for u in units:
        ids = members[u["unit_id"]]
        if u["unit_kind"] == "sequence":
            status = "unsupported_unit"
        elif execution != "complete":
            status = execution
        elif (not ids or not ids.issubset(known) or (u["event_ids"] and set(u["event_ids"]) != ids)
              or (threshold and unknown)):
            status = "insufficient_data"
        else:
            status = "complete"
        match_ids = sorted(ids & matched) if status == "complete" else []
        out[u["unit_id"]] = {"status": status, "prediction": bool(match_ids) if status == "complete" else None,
            "input_count": len(ids), "matching_event_ids": match_ids[:1000], "matching_count": len(match_ids),
            "evidence_truncated": len(match_ids) > 1000}
    return out


def _policy_case(pin, payload, units, deadline):
    from saw.observation.device import analyze_device
    out = {}
    for unit in units:
        # Candidate event_refs are a bounded representative sample, not full membership.
        # Only a complete window computation can supply a device policy truth decision.
        if unit["unit_kind"] != "window" or unit["event_ids"]:
            out[unit["unit_id"]] = {"status": "unsupported_unit", "prediction": None,
                                    "input_count": 0, "matching_event_ids": []}
            continue
        window, empty = _intersect_time(payload.get("time"), unit.get("time"))
        if empty:
            out[unit["unit_id"]] = {"status": "insufficient_data", "prediction": None,
                                    "input_count": 0, "matching_event_ids": []}
            continue
        extra = [Filter.model_validate(f) for f in unit["filters"]]
        excluded = set()
        exceptions = pin["policy"].get("exclusions") or []
        if exceptions:
            for ev in _stream(payload, extra + [Filter.model_validate(f) for f in exceptions], window, ["event_id"]):
                if len(excluded) >= MAX_RECORDS or monotonic() >= deadline:
                    raise HTTPException(409, "selected_truth_exception_limit")
                excluded.add(ev["event_id"])
        events = (e for e in _stream(payload, extra, window) if e["event_id"] not in excluded)
        # Count input independently when an explicitly disabled policy doesn't scan.
        count = 0
        def bounded():
            nonlocal count
            for ev in events:
                if count >= MAX_RECORDS or monotonic() >= deadline:
                    raise HTTPException(409, "selected_truth_input_limit")
                count += 1
                yield ev
        if pin["policy"]["values"].get("enabled") is False:
            for _ in bounded():
                pass
            result = {"status": "completed_no_match", "counts": {"records": count, "candidates": 0},
                      "candidates": [], "limits": {"coverage_complete": True}}
        else:
            result = analyze_device(pin["spec"]["id"], bounded(), policy=pin["policy"]["values"],
                runtime_pin=pin, max_records=MAX_RECORDS, cancelled=lambda: monotonic() >= deadline)
        state = result["status"]
        complete = state in {"completed_match", "completed_no_match"} and count > 0 and result["limits"]["coverage_complete"]
        ids = sorted({r["event_id"] for c in result.get("candidates", []) for r in c.get("event_refs", []) if r.get("event_id")})
        out[unit["unit_id"]] = {"status": "complete" if complete else
            "partial" if state in {"partial", "cancelled"} else "failed" if state == "failed" else "insufficient_data",
            "prediction": bool(result["counts"].get("candidates", 0)) if complete else None,
            "input_count": count, "matching_event_ids": ids[:1000], "evidence_scope": "representative",
            "engine_result": result}
    return out


def _signature_case(pin, payload, units, deadline):
    from saw.detectors.signatures import by_id, sig_ids, texts_of
    sid = pin["spec"]["id"].split(":", 1)[1]
    signature = by_id()[sid]
    members = _members(payload, units, deadline)
    exceptions = pin["policy"].get("exclusions") or []
    excluded = set()
    if exceptions:
        for ev in _stream(payload, [Filter.model_validate(f) for f in exceptions], fields=["event_id"]):
            if len(excluded) >= MAX_RECORDS or monotonic() >= deadline:
                raise HTTPException(409, "selected_truth_exception_limit")
            excluded.add(ev["event_id"])
    known, hits, successful = set(), set(), set()
    scanned = 0
    for ev in _stream(payload):
        if scanned >= MAX_RECORDS or monotonic() >= deadline:
            raise HTTPException(409, "selected_truth_input_limit")
        scanned += 1
        eid = ev["event_id"]
        tx = texts_of(ev)
        method = ev.get("method")
        method_known = isinstance(method, str) and bool(__import__("re").fullmatch(r"[!#$%&'*+.^_|~0-9A-Za-z-]+", method))
        status_value = ev.get("status_code")
        status_known = (not isinstance(status_value, bool) and isinstance(status_value, int) and 100 <= status_value <= 599)
        if (signature.where not in tx or (signature.methods and not method_known)
                or (signature.success == "only" and not status_known)):
            continue
        known.add(eid)
        if eid not in excluded and pin["policy"]["values"].get("enabled", True) and sid in sig_ids(ev):
            hits.add(eid)
            if 200 <= int(ev.get("status_code") or 0) < 300:
                successful.add(eid)
    if signature.success == "only" and not successful:
        hits = set()
    out = {}
    for unit in units:
        ids = members[unit["unit_id"]]
        status = "unsupported_unit" if unit["unit_kind"] == "sequence" else (
            "complete" if ids and ids.issubset(known) and (not unit["event_ids"] or ids == set(unit["event_ids"])) else "insufficient_data")
        matched = sorted(hits & ids) if status == "complete" else []
        out[unit["unit_id"]] = {"status": status, "prediction": bool(matched) if status == "complete" else None,
            "input_count": len(ids), "matching_event_ids": matched[:1000],
            "matching_count": len(matched), "evidence_truncated": len(matched) > 1000}
    return out

def _check_sources(s, p, scope, *, read_inputs=False):
    for ref in scope["units"]:
        row = get_case(s, p, ref["case_version_id"], current=True)
        if _manifest(s, row.investigation_id) != row.source_manifest:
            raise HTTPException(409, "selected_truth_input_changed")
    if read_inputs:
        snapshots = {}
        for ref in scope["units"]:
            row = get_case(s, p, ref["case_version_id"], current=True)
            snapshots[row.id] = (deepcopy(row.payload), row.input_count, row.input_sha256)
        # This path is called only by the preflight verifier, before approval/activation
        # mutates any pointers. Release source locks while the native store is scanned.
        s.commit()
        deadline = monotonic() + MAX_SECONDS
        for payload, count, sha in snapshots.values():
            if _fingerprint(payload, deadline) != {"count": count, "sha256": sha}:
                raise HTTPException(409, "selected_truth_input_changed")
        current = _current_principal(s, p, permission="knowledge.read")
        for iid in scope["source_investigation_ids"]:
            require(s, current, "investigation.read", iid)
        _check_sources(s, current, scope, read_inputs=False)


def _pin(s, p, kind, subject_id, version_id, context_scope):
    from saw.detection import governance
    return governance.pin_rule(s, p, subject_id, version_id, context_scope) if kind == "rule" else governance.pin_policy(s, p, subject_id, version_id)


def run_selected(s, p, subject_id, raw, *, subject_kind="rule", session_id=None):
    from saw.detection import governance
    from saw.detection.service import TestRun
    body = SelectedTestInput.model_validate(raw)
    if not can(p, "detection.write"):
        raise Forbidden("detection.write")
    pin = _pin(s, p, subject_kind, subject_id, body.version_id, body.context_scope)
    if pin["subject"]["payload_sha256"] != body.payload_sha256:
        raise HTTPException(409, "selected_truth_payload_changed")
    reference = _pin(s, p, subject_kind, subject_id, body.reference_version_id, body.context_scope) if body.reference_version_id else None
    cases, selected, contributors = {}, [], set(pin.get("contributors", {}).get("ids", []))
    for ref in body.units:
        row = get_case(s, p, ref.case_version_id, current=True)
        unit = next((u for u in row.payload["units"] if u["unit_id"] == ref.unit_id), None)
        if unit is None:
            raise ValueError("selected_truth_unit_not_found")
        if _manifest(s, row.investigation_id) != row.source_manifest:
            raise HTTPException(409, "selected_truth_input_changed")
        cases[row.id] = {"payload": deepcopy(row.payload), "input_sha256": row.input_sha256,
            "input_count": row.input_count, "sha256": row.sha256, "source_manifest": deepcopy(row.source_manifest)}
        contributors.update(row.contributor_ids)
        selected.append({**ref.model_dump(), "unit_kind": unit["unit_kind"]})
    if len({u["unit_kind"] for u in selected}) != 1:
        raise HTTPException(422, "selected_truth_unit_kind_mismatch")
    context_scope = pin.get("context_scope") or body.context_scope
    if context_scope.get("kind") != "group":
        for case in cases.values():
            for key in ("org_unit_id", "device_id"):
                if context_scope.get(key) and case["payload"].get(key) != context_scope[key]:
                    raise HTTPException(422, "selected_truth_context_scope_mismatch")
    scope = {"method": body.method, "subject": deepcopy(pin["subject"]), "pin": pin, "reference_pin": reference,
        "context_scope": deepcopy(context_scope), "units": selected,
        "rule_policy_sha256": governance.rule_policy_digest(pin),
        "truth_sha256": digest([{"id": k, "sha256": v["sha256"]} for k, v in sorted(cases.items())]),
        "input_sha256": digest([{"id": k, "sha256": v["input_sha256"]} for k, v in sorted(cases.items())]),
        "source_investigation_ids": sorted({v["payload"]["investigation_id"] for v in cases.values()} |
                                          set(pin.get("source_investigation_ids", []))),
        "source_epochs": {v["payload"]["investigation_id"]: v["source_manifest"]["data_epoch"] for v in cases.values()},
        "contributors": {"ids": sorted(contributors), "legacy_names": pin.get("contributors", {}).get("legacy_names", [])}}
    s.commit()
    deadline = monotonic() + MAX_SECONDS
    results = []
    for case_id, case in cases.items():
        actual = _fingerprint(case["payload"], deadline)
        if actual != {"count": case["input_count"], "sha256": case["input_sha256"]}:
            raise HTTPException(409, "selected_truth_input_changed")
        selected_ids = {u["unit_id"] for u in selected if u["case_version_id"] == case_id}
        units = [u for u in case["payload"]["units"] if u["unit_id"] in selected_ids]
        evaluate_case = (_sigma_case if pin.get("rule") else
                         _signature_case if pin["spec"]["id"].startswith("signature:") else _policy_case)
        current = evaluate_case(pin, case["payload"], units, deadline)
        old = evaluate_case(reference, case["payload"], units, deadline) if reference else {}
        for unit in units:
            result = current[unit["unit_id"]]
            results.append({"case_version_id": case_id, "unit_id": unit["unit_id"], "unit_kind": unit["unit_kind"],
                "detection_truth": unit["detection_truth"], "investigation_truth": unit["investigation_truth"], **result,
                "reference_prediction": old.get(unit["unit_id"], {}).get("prediction"),
                "reference_status": old.get(unit["unit_id"], {}).get("status")})
    # A final read catches content mutation even when a caller changed the event store
    # outside the normal epoch-fenced ingestion path.
    for case in cases.values():
        if _fingerprint(case["payload"], deadline) != {"count": case["input_count"], "sha256": case["input_sha256"]}:
            raise HTTPException(409, "selected_truth_input_changed")
    counts = metrics(results)
    execution = "complete" if all(u["status"] == "complete" for u in results) else (
        "failed" if any(u["status"] == "failed" for u in results) else
        "partial" if any(u["status"] == "partial" for u in results) else "insufficient_data")
    comparison = {"reference_version_id": body.reference_version_id,
        "changed_units": sum(u["prediction"] != u["reference_prediction"] for u in results
                             if reference and u["status"] == u["reference_status"] == "complete"),
        "comparable_units": sum(u["status"] == u["reference_status"] == "complete" for u in results) if reference else 0}
    passed = (execution == "complete" and counts["labeled"] > 0 and counts["fp"] == counts["fn"] == 0
              and (reference is None or comparison["comparable_units"] == len(results)))
    result = {"execution": execution, "units": results, "metrics": counts, "comparison": comparison,
        "limits": {"records_per_case": MAX_RECORDS, "matching_metadata_bytes": MAX_METADATA_BYTES,
                   "matching_records": MAX_HITS, "units": 100, "case_versions": 20, "seconds": MAX_SECONDS}}
    scope["result_sha256"] = digest(result)
    current = _current_principal(s, p, session_id)
    audit._head(s)
    for inv_id in scope["source_investigation_ids"]:
        lock_investigation(s, inv_id)
        require(s, current, "investigation.read", inv_id)
    _check_sources(s, current, scope)
    now_pin = _pin(s, current, subject_kind, subject_id, body.version_id, body.context_scope)
    if governance.rule_policy_digest(now_pin) != scope["rule_policy_sha256"]:
        raise HTTPException(409, "selected_truth_policy_changed")
    version = pin.get("rule", {}).get("version") if pin.get("rule") else None
    if version is None:
        from saw.detection.policy_models import PolicyVersion
        version = s.get(PolicyVersion, body.version_id).version
    test = TestRun(detection_id=subject_id, version=version, scope=scope, result=result, passed=passed, ran_by=p.username)
    s.add(test)
    s.flush()
    audit.record(s, "detection.selected_test", actor_id=p.user_id, actor_name=p.username,
        target_type=subject_kind, target_id=subject_id, detail={"version_id": body.version_id,
            "test_run_id": test.id, "execution": execution, "passed": passed})
    return test


def verify_selected_proof(s, p, *, test_run_id, subject_kind, subject_version_id,
                          payload_sha256, rule_policy_sha256, _read_inputs=True):
    from saw.detection import governance
    from saw.detection.service import TestRun
    test = s.get(TestRun, test_run_id)
    if test is None:
        raise NotFound("detection test not found")
    scope = test.scope or {}
    subject = scope.get("subject") or {}
    if (scope.get("method") != "selected_truth_v1" or not test.passed or test.result.get("execution") != "complete"
            or digest(test.result) != scope.get("result_sha256")
            or subject.get("kind") != subject_kind or subject.get("version_id") != subject_version_id
            or subject.get("payload_sha256") != payload_sha256 or scope.get("rule_policy_sha256") != rule_policy_sha256):
        raise HTTPException(409, "exact_test_proof_required")
    current = _current_principal(s, p, permission="knowledge.read")
    for inv_id in scope["source_investigation_ids"]:
        require(s, current, "investigation.read", inv_id)
    _check_sources(s, current, scope, read_inputs=_read_inputs)
    pin = _pin(s, current, subject_kind, subject["id"], subject_version_id, scope.get("context_scope") or {"kind": "group"})
    if governance.rule_policy_digest(pin) != rule_policy_sha256:
        raise HTTPException(409, "selected_truth_policy_changed")
    proof = {"method": "selected_truth_v1", "status": "complete", "test_run_id": test.id, "subject": subject,
        "payload_sha256": payload_sha256, "rule_policy_sha256": rule_policy_sha256,
        "truth_sha256": scope["truth_sha256"], "input_sha256": scope["input_sha256"],
        "engine": scope["pin"]["engine"], "spec": scope["pin"]["spec"],
        "source_investigation_ids": scope["source_investigation_ids"], "contributors": scope["contributors"],
        "context_scope": scope.get("context_scope", {"kind": "group"}),
        "reference": (scope.get("reference_pin") or {}).get("subject"),
        "reference_rule_policy_sha256": governance.rule_policy_digest(scope["reference_pin"]) if scope.get("reference_pin") else None,
        "result_sha256": scope["result_sha256"], "comparison_sha256": digest(test.result["comparison"])}
    proof["proof_sha256"] = digest(proof)
    return proof


def serialized_test(s, p, test):
    # Recheck transitive ACL before returning even a historical result.
    scope = test.scope or {}
    try:
        for inv_id in scope.get("source_investigation_ids", scope.get("investigations", [])):
            require(s, p, "investigation.read", inv_id)
    except (Forbidden, NotFound):
        return None
    proof = None
    if scope.get("method") == "selected_truth_v1":
        subject = scope["subject"]
        try:
            proof = verify_selected_proof(s, p, test_run_id=test.id, subject_kind=subject["kind"],
                subject_version_id=subject["version_id"], payload_sha256=subject["payload_sha256"],
                rule_policy_sha256=scope["rule_policy_sha256"], _read_inputs=False)
        except (HTTPException, ValueError, NotFound):
            proof = None
    return {"id": test.id, "version": test.version, "passed": test.passed, "scope": deepcopy(scope),
            "result": deepcopy(test.result), "proof": proof}
