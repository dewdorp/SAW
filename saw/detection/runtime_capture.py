"""Capture runtime authority and enforce transitive source access at publication/read."""
from copy import deepcopy

from saw import container
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, require
from saw.core.application.provenance import digest
from saw.core.schemas.query import Filter, TimeRange
from saw.core.security.authz import can
from saw.detection import governance
from saw.detection.runtime import discover_context_scopes
from saw.storage.models import User


def sources(pinset):
    result = set()
    for key in ("rules", "devices", "signatures"):
        for pin in pinset.get(key, []):
            result.update(pin.get("source_investigation_ids", []))
            result.update((pin.get("policy") or {}).get("source_investigation_ids", []))
    return result


def capture(s, p, inv_id, request=None):
    request = request or {}
    filters = [Filter.model_validate(f) for f in request.get("filters", [])]
    for key in ("org_unit_id", "device_id"):
        if request.get(key):
            filters.append(Filter(field="ext.observation.context." + key, value=request[key]))
    time = TimeRange.model_validate(request["time"]) if request.get("time") else None
    scopes = discover_context_scopes(container.get().events, inv_id, filters, time)
    return governance.pin_runtime(s, p, inv_id, scopes)


def authorize(s, p, inv_id, pinset, *, writing=False):
    if pinset.get("sha256") != digest({k: v for k, v in pinset.items() if k != "sha256"}):
        raise ValueError("runtime_pin_digest")
    user = s.get(User, p.user_id, populate_existing=True)
    if user is None or user.status != "active":
        raise Forbidden("runtime_actor_unavailable")
    actual = principal_of(user)
    if writing and not can(actual, "analyze.run"):
        raise Forbidden("analyze.run")
    require(s, actual, "investigation.write" if writing else "investigation.read", inv_id)
    for source in sources(pinset):
        require(s, actual, "investigation.read", source)


def pin_run(s, run, inv):
    user = s.get(User, run.created_by or inv.owner_id)
    if user is None or user.status != "active":
        raise Forbidden("runtime_actor_unavailable")
    p = principal_of(user)
    existing = run.input_manifest.get("runtime_pin")
    if existing is None:
        pin = capture(s, p, inv.id)
        run.input_manifest = {**run.input_manifest, "runtime_pin": deepcopy(pin)}
        run.input_sha256 = digest(run.input_manifest)
    else:
        pin = deepcopy(existing)
    authorize(s, p, inv.id, pin, writing=True)
    return p, pin
