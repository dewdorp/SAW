"""Read-only runtime partitions bound to immutable policy pins and producer context."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from saw.core.application.provenance import digest
from saw.core.schemas.query import Filter, TimeRange
from saw.detection.specs import get_spec, validate_values
from saw.detectors.base import DetectorContext
from saw.storage.eventstore import SQLiteEventStore, ts_epoch

CTX = "ext.observation.context."


def _filters(values):
    return [value if isinstance(value, Filter) else Filter.model_validate(value) for value in values or []]


def scope_filters(scope):
    if scope.get("kind") == "group":
        return [Filter(field=CTX+"resolved", op="is_not", value=True)]
    result = [Filter(field=CTX+"resolved", value=True),
              Filter(field=CTX+"org_unit_id", value=scope["org_unit_id"])]
    if scope.get("kind") == "device":
        result.append(Filter(field=CTX+"device_id", value=scope["device_id"]))
    return result


def discover_context_scopes(store, inv_id, filters=None, time=None, max_scopes=100):
    filters = _filters(filters)
    fields = [CTX+"org_unit_id", CTX+"device_id"]
    known = filters+[Filter(field=CTX+"resolved", value=True)]+[Filter(field=f, op="exists") for f in fields]
    groups = store.group_by(inv_id, known, fields, [], size=max_scopes+1, time=time)
    scopes = [{"kind": "device", "org_unit_id": row["key"][fields[0]],
               "device_id": row["key"][fields[1]]} for row in groups]
    if not scopes or sum(row["count"] for row in groups) < store.count(inv_id, filters, time=time):
        scopes.append({"kind": "group"})
    if len(scopes) > max_scopes:
        raise ValueError("runtime_context_limit")
    return scopes


class ScopedEventStore:
    """Materialize only the allowed query into bounded disk storage, never memory lists."""
    def __init__(self, store, inv_id, filters=None, time=None, *, branches=None,
                 exclude_groups=None, cancelled=None, max_records=1_000_000):
        self._store, self._inv = store, inv_id
        self._filters, self._time = _filters(filters), TimeRange.model_validate(time) if isinstance(time, dict) else time
        self._branches = [_filters(v) for v in branches] if branches is not None else [[]]
        self._excludes = [_filters(v) for v in exclude_groups or [] if v]
        self._cancelled, self._max = cancelled, max_records
        self._temp = self._view = None
        self.truncated = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self._view is not None:
            self._view._conn().close()
            self._view = None
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None

    def _check(self, inv):
        if inv != self._inv:
            raise ValueError("runtime_investigation_scope")
        if self._cancelled and self._cancelled():
            raise RuntimeError("runtime_cancelled")

    def _backend(self, inv):
        self._check(inv)
        if self._view is not None:
            return self._view
        self._temp = TemporaryDirectory(prefix="saw-runtime-")
        self._view = SQLiteEventStore(Path(self._temp.name)/"events.sqlite")
        sql = self._view._conn()
        sql.execute("PRAGMA cache_size=-2048")
        sql.execute("PRAGMA temp_store=FILE")
        sql.execute("CREATE TABLE excluded(event_id TEXT PRIMARY KEY)")
        try:
            seen = 0
            for branch in self._branches:
                for exclusion in self._excludes:
                    for event in self._store.iterate(inv, self._filters+branch+exclusion, time=self._time, batch=500):
                        self._check(inv)
                        seen += 1
                        if seen > self._max:
                            raise ValueError("runtime_record_limit")
                        sql.execute("INSERT OR IGNORE INTO excluded VALUES (?)", (event["event_id"],))
            sql.commit()
            seen, batch = 0, []
            for branch in self._branches:
                for event in self._store.iterate(inv, self._filters+branch, time=self._time, batch=500):
                    self._check(inv)
                    seen += 1
                    if not sql.execute("SELECT 1 FROM excluded WHERE event_id=?", (event["event_id"],)).fetchone():
                        batch.append(event)
                    if len(batch) >= 500:
                        self._view.index(batch)
                        batch.clear()
                    if seen >= self._max+1:
                        self.truncated = True
                        break
                if self.truncated:
                    break
            if batch:
                self._view.index(batch)
            return self._view
        except BaseException:
            self.__exit__()
            raise

    def _direct(self, inv, filters=None, time=None):
        self._check(inv)
        if self._excludes or len(self._branches) != 1:
            return None
        bound = TimeRange.model_validate(time) if isinstance(time, dict) else time
        starts = [v for v in (getattr(self._time, "start", None), getattr(bound, "start", None)) if v]
        ends = [v for v in (getattr(self._time, "end", None), getattr(bound, "end", None)) if v]
        clipped = TimeRange(start=max(starts, key=ts_epoch) if starts else None,
                            end=min(ends, key=ts_epoch) if ends else None)
        return self._filters+self._branches[0]+_filters(filters), clipped

    def get(self, investigation_id, event_id):
        filters = [Filter(field="event_id", value=event_id)]
        result = self.search(investigation_id, filters, limit=1)
        return next(iter(result["events"]), None)

    def search(self, investigation_id, filters, time=None, sort="asc", limit=100, cursor=None):
        direct = self._direct(investigation_id, filters, time)
        if direct is not None:
            return self._store.search(investigation_id, direct[0], direct[1], sort, limit, cursor)
        return self._backend(investigation_id).search(investigation_id, _filters(filters), time, sort, limit, cursor)

    def iterate(self, investigation_id, filters, time=None, fields=None, batch=5000):
        direct = self._direct(investigation_id, filters, time)
        source = (self._store.iterate(investigation_id, direct[0], direct[1], fields, batch) if direct is not None
                  else self._backend(investigation_id).iterate(investigation_id, _filters(filters), time, fields, batch))
        for index, row in enumerate(source):
            self._check(investigation_id)
            if index >= self._max+1:
                raise ValueError("runtime_record_limit")
            yield row

    def count(self, investigation_id, filters=None, time=None):
        direct = self._direct(investigation_id, filters, time)
        if direct is not None:
            return self._store.count(investigation_id, direct[0], direct[1])
        return self._backend(investigation_id).count(investigation_id, _filters(filters), time)

    def aggregate(self, investigation_id, filters, agg, time=None):
        direct = self._direct(investigation_id, filters, time)
        if direct is not None:
            return self._store.aggregate(investigation_id, direct[0], agg, direct[1])
        return self._backend(investigation_id).aggregate(investigation_id, _filters(filters), agg, time)

    def group_by(self, investigation_id, filters, fields, metrics, size=100, time=None, order_by=None):
        direct = self._direct(investigation_id, filters, time)
        if direct is not None:
            return self._store.group_by(investigation_id, direct[0], fields, metrics, size, direct[1], order_by)
        return self._backend(investigation_id).group_by(investigation_id, _filters(filters), fields, metrics, size, time, order_by)

    def time_bounds(self, investigation_id, filters=None):
        selected = _filters(filters)+[Filter(field="timestamp", op="exists")]
        first = self.search(investigation_id, selected, sort="asc", limit=1)["events"]
        last = self.search(investigation_id, selected, sort="desc", limit=1)["events"]
        return (first[0]["timestamp"] if first else None, last[0]["timestamp"] if last else None)


def _empty(detector_id, reason, status="insufficient_data"):
    return {"schema": "device-observation/1", "detector_id": detector_id,
            "engine": get_spec(detector_id)["engine"], "status": status,
            "counts": {"records": 0, "eligible_records": 0, "candidates": 0,
                       "omitted_candidates": 0, "omitted_timeline": 0},
            "quality": {reason: 1}, "limits": {"max_records": 1_000_000, "max_results": 100,
            "max_event_refs_per_result": 20, "coverage_complete": False},
            "limitations": [reason], "candidates": [], "timeline": [], "sessions": []}


def _exclusions(policy):
    # Filters within one policy are a conjunction; inherited policy groups are a union.
    values = policy.get("exclusions") or []
    if values and isinstance(values[0], list):
        return values
    return [values] if values else []


def _request_scope(scope, request):
    return (not request.get("org_unit_id") or scope.get("org_unit_id") == request["org_unit_id"]) and (
        not request.get("device_id") or scope.get("device_id") == request["device_id"])


def _branches(store, inv_id, scope, ips):
    primary = scope_filters(scope)
    branches = [primary]
    if ips and scope.get("kind") == "device":
        fields = [CTX+"network", CTX+"virtual_domain"]
        rows = store.group_by(inv_id, primary, fields, [], size=101)
        if len(rows) > 100:
            raise ValueError("runtime_network_limit")
        for row in rows:
            branch = [Filter(field=CTX+"resolved", value=True),
                      Filter(field=CTX+"org_unit_id", value=scope["org_unit_id"]),
                      Filter(field=CTX+"device_id", op="is_not", value=scope["device_id"]),
                      Filter(field="ext.device_observation.record_kind", value="flow")]
            for field in fields:
                value = row["key"][field]
                branch.append(Filter(field=field, op="not_exists") if value is None else Filter(field=field, value=value))
            branches.append(branch)
    return branches


def _aggregate(detector_id, reports, pins, max_results):
    partitions = [{"context_scope": pin["context_scope"], "status": row["status"],
                   "counts": row["counts"], "quality": row.get("quality", {}),
                   "policy_sha256": pin["policy"].get("policy_sha256")} for row, pin in zip(reports, pins, strict=True)]
    if len(reports) == 1:
        result = deepcopy(reports[0])
    elif not reports:
        result = _empty(detector_id, "no_records_in_scope")
    else:
        result = _empty(detector_id, "partitioned_execution")
        result["quality"] = dict(sum((Counter(row.get("quality", {})) for row in reports), Counter()))
        keys = set().union(*(row["counts"] for row in reports))
        result["counts"] = {key: None if any(row["counts"].get(key) is None for row in reports)
                            else sum(row["counts"][key] for row in reports) for key in keys}
        applicable = [row for row in reports if row["status"] not in {"disabled", "not_applicable"}]
        result["limits"]["coverage_complete"] = bool(applicable) and all(
            row["status"] in {"completed_match", "completed_no_match"} and row.get("limits", {}).get("coverage_complete", False)
            for row in applicable)
        for key in ("candidates", "timeline", "sessions"):
            result[key] = []
            total = 0
            for row in reports:
                entries = row.get(key, [])
                total += len(entries)
                result[key].extend(entries[:max(0, max_results-len(result[key]))])
            omitted = "omitted_"+key
            result["counts"][omitted] = (result["counts"].get(omitted) or 0)+total-len(result[key])
        statuses = {row["status"] for row in reports}
        result["status"] = ("partial" if "partial" in statuses or not result["limits"]["coverage_complete"]
                            else "completed_match" if result["counts"]["candidates"] else "completed_no_match")
        result["limitations"] = list(dict.fromkeys(str(v) for row in reports for v in row.get("limitations", [])))
        if statuses == {"disabled"}:
            result["status"] = "disabled"
        elif statuses == {"not_applicable"}:
            result["status"] = "not_applicable"
        elif statuses == {"insufficient_data"}:
            result["status"] = "insufficient_data"
    if result["status"] not in {"completed_match", "completed_no_match"}:
        result["limits"]["coverage_complete"] = False
    result["partitions"], result["effective_pins"] = partitions, deepcopy(pins)
    return result


def _signature_scopes(det, ctx, pinset):
    defaults = pinset.get("signature_defaults") or {}
    if not defaults.get("available") or defaults.get("engine_version") != det.version:
        ctx.params.setdefault("execution_reports", {})[det.id] = {"status": "partial", "reason": "signature_pin_unavailable"}
        return []
    from saw.detectors.signatures import by_id
    if defaults.get("pack_sha256") != digest([{"id": ident, "payload_sha256": get_spec("signature:"+ident)["payload_sha256"]}
                                             for ident in sorted(by_id())]):
        raise ValueError("runtime_signature_pack_changed")
    scopes = {digest(pin["context_scope"]): pin["context_scope"] for pin in pinset.get("devices", [])}
    findings, partitions = [], []
    for scope in scopes.values():
        with ExitStack() as stack:
            base = stack.enter_context(ScopedEventStore(ctx.events, ctx.investigation_id, scope_filters(scope),
                                                        cancelled=ctx.params.get("cancelled")))
            views, disabled = {}, []
            for pin in pinset.get("signatures", []):
                if pin["context_scope"] != scope:
                    continue
                ident = pin["detector_id"].removeprefix("signature:")
                if not pin["policy"]["values"]["enabled"]:
                    disabled.append(ident)
                if _exclusions(pin["policy"]):
                    views[ident] = stack.enter_context(ScopedEventStore(base, ctx.investigation_id,
                        exclude_groups=_exclusions(pin["policy"]), cancelled=ctx.params.get("cancelled")))
            params = {**ctx.params, "signature_policy_views": views, "sig_disabled": disabled}
            child = DetectorContext(ctx.investigation_id, base, assets=getattr(ctx, "assets", None), params=params,
                                    data_sources=getattr(ctx, "data_sources", set()))
            found = det.run(child)
            for draft in found:
                draft.evidence_query = {"filters": [{"field": "event_id", "op": "in", "value": draft.sample_event_ids}],
                                        "reference_scope": "bounded_representative", "runtime_scope": scope}
                draft.dedup_key += ":"+digest(scope)[:16]
            findings.extend(found)
            partitions.append({"context_scope": scope, "status": "completed_match" if found else "completed_no_match",
                               "counts": {"records": base.count(ctx.investigation_id), "candidates": len(found)}})
    ctx.params.setdefault("execution_reports", {})[det.id] = {
        "status": "completed_match" if findings else "completed_no_match", "partitions": partitions,
        "counts": {"records": sum(row["counts"]["records"] for row in partitions), "candidates": len(findings)},
        "signature_defaults": deepcopy(defaults), "effective_pins": deepcopy(pinset.get("signatures", [])),
        "limits": {"coverage_complete": True, "max_event_refs_per_result": 20}}
    return findings


# Records outside any registered device context cannot be read by the WAF/IPS/DDoS/NDR observers: each one is
# counted as missing or unverified and skipped. Counting them is enough, instead of copying and reading every row.
COUNT_UNRESOLVED_DEVICE_SCOPES = True


def _unresolved_device_report(det, ctx, scope, pin, max_records, max_results):
    """The exact report a full pass over an unregistered (group) scope would produce, from counts; None if unsure."""
    from saw.observation.device import DEVICE_VERSION, analyze_device

    if det.id == "fw.observation" or scope.get("kind") != "group" or _exclusions(pin["policy"]):
        return None
    store, inv = ctx.events, ctx.investigation_id
    base = [Filter(field="data_source", op="in", value=sorted(det.data_sources))] + scope_filters(scope)
    total = store.count(inv, base)
    if total > max_records or store.count(inv, base + [Filter(field="ext.device_observation.context.resolved", value=True)]):
        return None
    current = store.count(inv, base + [Filter(field="ext.device_observation.producer", value="saw"),
                                       Filter(field="ext.device_observation.version", value=DEVICE_VERSION)])
    report = analyze_device(det.id, iter(()), runtime_pin=pin, max_records=max_records, max_results=max_results,
                            cancelled=ctx.params.get("cancelled"))
    report["counts"]["records"] = total
    quality = Counter(report.get("quality") or {})
    if total - current:
        quality["missing_device_observation"] += total - current
    if current:
        quality["unverified_device_context"] += current
    report["quality"] = dict(sorted(quality.items()))
    if total and report["status"] in {"completed_no_match", "partial", "insufficient_data"}:
        report["status"] = "insufficient_data"
        report["limits"]["coverage_complete"] = False
    return report


def run_device_scopes(det, ctx, pinset):
    """Execute each exact pinned context once; callers cannot supply live policy values."""
    pinset = deepcopy(pinset)
    if pinset.get("sha256") and pinset["sha256"] != digest({k: v for k, v in pinset.items() if k != "sha256"}):
        raise ValueError("runtime_pin_digest")
    if det.id == "sig.match":
        return _signature_scopes(det, ctx, pinset)
    request = ctx.params.get("runtime_request") or {}
    pins = [pin for pin in pinset.get("devices", []) if pin["detector_id"] == det.id
            and _request_scope(pin["context_scope"], request)]
    keys = [digest(pin["context_scope"]) for pin in pins]
    if len(keys) != len(set(keys)):
        raise ValueError("runtime_duplicate_policy_pin")
    actual = discover_context_scopes(ctx.events, ctx.investigation_id)
    selected = [scope for scope in actual if _request_scope(scope, request)]
    for scope in selected:
        if (scope not in [pin["context_scope"] for pin in pins]
                and ctx.events.count(ctx.investigation_id, scope_filters(scope))):
            raise ValueError("runtime_policy_pin_missing")
    reports, used, findings = [], [], []
    max_results = ctx.params.get("device_max_results", 100)
    for pin in pins:
        scope = pin["context_scope"]
        spec = get_spec(det.id)
        if pin["policy"].get("spec_sha256") not in (None, spec["sha256"]):
            raise ValueError("runtime_spec_changed")
        values = validate_values(spec, pin["policy"].get("values", {}))
        quick = (_unresolved_device_report(det, ctx, scope, pin, ctx.params.get("device_max_records", 1_000_000), max_results)
                 if COUNT_UNRESOLVED_DEVICE_SCOPES and values["enabled"] else None)
        if quick is not None:
            reports.append(quick)
            used.append(pin)
            continue
        with ScopedEventStore(ctx.events, ctx.investigation_id,
                branches=_branches(ctx.events, ctx.investigation_id, scope, det.id == "ips.observation"),
                exclude_groups=_exclusions(pin["policy"]), cancelled=ctx.params.get("cancelled"),
                max_records=ctx.params.get("device_max_records", 1_000_000)) as view:
            params = {**ctx.params, "device_runtime_pins": {det.id: pin}, "execution_reports": {}}
            if det.id == "fw.observation":
                params["firewall_policy"] = {k: v for k, v in values.items() if k != "enabled"}
            child = DetectorContext(ctx.investigation_id, view, assets=getattr(ctx, "assets", None), params=params,
                                    data_sources=getattr(ctx, "data_sources", set()))
            try:
                found = det.run(child) if values["enabled"] else []
                report = params["execution_reports"].get(det.id) if values["enabled"] else _empty(det.id, "policy_disabled", "disabled")
            except ValueError as exc:
                if str(exc) != "runtime_record_limit":
                    raise
                found, report = [], _empty(det.id, "runtime_record_limit", "partial")
            if view.truncated:
                report["status"] = "partial"
                report["limits"]["coverage_complete"] = False
                report["quality"]["runtime_record_limit"] = 1
            for draft in found:
                draft.evidence_query = {"filters": [{"field": "event_id", "op": "in", "value": draft.sample_event_ids}],
                                        "reference_scope": "bounded_representative", "runtime_scope": scope}
            findings.extend(found)
            reports.append(report)
            used.append(pin)
    ctx.params.setdefault("execution_reports", {})[det.id] = _aggregate(det.id, reports, used, max_results)
    return findings[:max_results]


def run_for_request(store, inv_id, request, pinset, *, max_records=1_000_000, max_results=100, cancelled=None):
    from saw.detectors.device_observation import (
        DdosObservation,
        IpsObservation,
        NdrObservation,
        WafObservation,
    )
    from saw.detectors.firewall_observation import FirewallObservation
    request = request.model_dump(exclude_none=True) if hasattr(request, "model_dump") else dict(request)
    detector_id = request.get("detector_id") or "fw.observation"
    classes = {"fw.observation": FirewallObservation, "waf.observation": WafObservation,
               "ips.observation": IpsObservation, "ddos.observation": DdosObservation, "ndr.observation": NdrObservation}
    if detector_id not in classes:
        raise ValueError("unsupported detector request")
    filters = _filters(request.get("filters"))
    if request.get("org_unit_id"):
        filters.append(Filter(field=CTX+"org_unit_id", value=request["org_unit_id"]))
    with ScopedEventStore(store, inv_id, filters, request.get("time"), cancelled=cancelled, max_records=max_records) as view:
        ctx = DetectorContext(inv_id, view, params={"runtime_request": request, "cancelled": cancelled,
                              "device_max_records": max_records, "device_max_results": max_results})
        run_device_scopes(classes[detector_id](), ctx, pinset)
        return ctx.params["execution_reports"][detector_id]
