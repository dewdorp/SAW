"""Exact Check snapshots with transitive source access and internal lifecycle hooks."""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC

from sqlalchemy import select, update

from saw.core.application import checks
from saw.core.application.identity import principal_of
from saw.core.application.investigations import Forbidden, NotFound, access_of
from saw.core.application.provenance import canonical, digest
from saw.core.security.authz import can
from saw.detection.derived_access import source_ids
from saw.followups.models import CheckRevision
from saw.storage.db import utcnow
from saw.storage.models import Check, Finding, Investigation, User

MAX_BYTES = 256 * 1024


class Conflict(ValueError):
    """A source or current revision changed before the operation completed."""


def authorize(s, p, ids, *, write_target=None):
    """Resolve all permissions before ordered locks; report capture may pre-pin the lock scope."""
    ids = set(ids)
    if not ids or len(ids) > 500:
        raise ValueError("followup_source_scope_limit")
    pinned = s.info.get("snapshot_source_ids")
    if pinned is not None and not ids <= set(pinned):
        raise Conflict("followup_source_scope_changed")
    user = s.get(User, p.user_id) if p else None
    if user is None or user.status != "active":
        raise Forbidden("active_user_required")
    actor = principal_of(user)
    for iid in sorted(ids):
        inv = s.get(Investigation, iid)
        if inv is None:
            raise NotFound("source investigation not found")
        permission = "investigation.write" if iid == write_target else "investigation.read"
        if not can(actor, permission, access_of(s, actor, iid)):
            raise Forbidden(permission)
        if (inv.settings or {}).get("data_deletion"):
            raise Conflict("followup_source_deleting")
    from saw.core.application.data_deletion import lock_investigation
    for iid in sorted(ids):
        lock_investigation(s, iid)
    return actor


def collect_check_sources(s, check):
    """Internal preflight only: no DTO, no authorization grant and no native store access."""
    from saw.behavior.models import BehaviorResult
    from saw.analysis_runs.models import AnalysisRun, DetectorExecution, FindingSnapshot

    found, visited, pending = set(), set(), [check]
    while pending:
        row = pending.pop()
        if row.id in visited:
            raise ValueError("check_source_cycle")
        visited.add(row.id)
        if len(visited) > 100:
            raise ValueError("check_source_depth_limit")
        found.add(row.investigation_id)
        found |= source_ids([row.scope, row.context])
        if row.target_type == "finding":
            finding = s.get(Finding, row.target_key)
            if finding is None or finding.investigation_id != row.investigation_id:
                raise NotFound("check finding not found")
            found |= source_ids(finding)
        attachment = (row.scope or {}).get("behavior") or {}
        if attachment:
            result = s.get(BehaviorResult, attachment.get("result_id", ""))
            if result is None or result.investigation_id != row.investigation_id:
                raise NotFound("check behavior result not found")
            if result.result_sha256 != attachment.get("result_sha256"):
                raise Conflict("check_behavior_result_changed")
            found |= source_ids(result.result)
        for value in (row.scope or {}, row.context or {}):
            run_id = value.get("analysis_run_id")
            if run_id:
                run = s.get(AnalysisRun, run_id)
                if run is None or run.investigation_id != row.investigation_id:
                    raise NotFound("check analysis run not found")
                found |= source_ids([run.input_manifest, run.scope, run.summary])
                for snapshot in s.scalars(select(FindingSnapshot).where(FindingSnapshot.run_id == run_id)):
                    found |= source_ids(snapshot.payload)
                for execution in s.scalars(select(DetectorExecution).where(DetectorExecution.run_id == run_id)):
                    found |= source_ids([execution.effective_config, execution.detail])
        if row.kind == "cited":
            source = s.get(Check, row.source_check_id) if row.source_check_id else None
            if source is None:
                raise NotFound("source check not found")
            pending.append(source)
    if len(found) > 500:
        raise ValueError("followup_source_scope_limit")
    return found


def verify_revision(row):
    if digest(row.payload) != row.payload_sha256:
        raise Conflict("check_revision_corrupt")
    if sorted(source_ids(row.payload)) != sorted(row.source_investigation_ids):
        raise Conflict("check_revision_source_corrupt")
    return row



def _verify_revision_tree(s, row):
    pending, seen, sources = [row], set(), set()
    while pending:
        current = pending.pop()
        if current.id in seen or len(seen) >= 100:
            raise Conflict("check_revision_chain_corrupt")
        seen.add(current.id)
        verify_revision(current)
        sources |= set(current.source_investigation_ids)
        ref = current.payload.get("source_check_revision")
        if ref:
            source = s.get(CheckRevision, ref.get("revision_id"))
            if (source is None or source.check_id != ref.get("check_id")
                    or source.revision != ref.get("revision")
                    or source.payload_sha256 != ref.get("payload_sha256")
                    or not set(source.source_investigation_ids) <= set(current.source_investigation_ids)):
                raise Conflict("check_revision_reference_corrupt")
            pending.append(source)
    return sources


def check_revision_dict(row):
    verify_revision(row)
    return {"check_id": row.check_id, "revision_id": row.id, "revision": row.revision,
            "payload_sha256": row.payload_sha256, "payload": deepcopy(row.payload),
            "created_at": row.created_at, "origin": row.origin}


def _payload(check):
    value = checks._snapshot_payload(check)
    value["scope"] = deepcopy(check.scope or {})
    value.pop("expired", None)
    # Explicit UTC normalization makes SQLite and PostgreSQL snapshots equivalent.
    for key in ("created_at", "valid_until"):
        val = value.get(key)
        if val is not None and hasattr(val, "isoformat"):
            value[key] = (val if val.tzinfo else val.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    return json.loads(canonical(value))


def _capture(s, p, check, *, reason, origin=None, visiting=None):
    visiting = set(visiting or ())
    if check.id in visiting or len(visiting) >= 100:
        raise ValueError("check_source_cycle")
    visiting.add(check.id)
    # Serialize the per-row revision allocator without discarding a pending lifecycle change.
    with s.no_autoflush:
        s.execute(update(Check).where(Check.id == check.id).values(id=check.id)
                  .execution_options(synchronize_session=False))
    payload = _payload(check)
    sources = collect_check_sources(s, check)
    source_ref = None
    if check.kind == "cited":
        source = s.get(Check, check.source_check_id)
        version = _capture(s, p, source, reason="citation_source", visiting=visiting)
        source_ref = {"check_id": source.id, "revision_id": version.id,
                      "revision": version.revision, "payload_sha256": version.payload_sha256}
        sources |= set(version.source_investigation_ids)
    payload.update(source_investigation_ids=sorted(sources), source_check_revision=source_ref)
    last = s.scalar(select(CheckRevision).where(CheckRevision.check_id == check.id)
                    .order_by(CheckRevision.revision.desc()).limit(1))
    if last:
        verify_revision(last)
        prior = {k: v for k, v in last.payload.items() if k not in {"evaluated_at", "expired_at_capture"}}
        if prior == payload:
            return last
    now = utcnow()
    payload.update(evaluated_at=now.isoformat(), expired_at_capture=checks._expired(check, now))
    if len(canonical(payload).encode("utf-8")) > MAX_BYTES:
        raise ValueError("check_snapshot_too_large")
    row = CheckRevision(check_id=check.id, investigation_id=check.investigation_id,
        revision=(last.revision + 1 if last else 1), payload=payload, payload_sha256=digest(payload),
        source_investigation_ids=sorted(sources), created_by=p.user_id if p else None,
        capture_reason=reason, origin=origin or ("transition" if last else "legacy_capture"))
    s.add(row)
    s.flush()
    return row


def _capture_transition(s, p, check, *, reason, new=False):
    """Private hook for an already-authorized Check mutation; never returns a public DTO."""
    _capture(s, p, check, reason=reason, origin="transition" if new else None)


def capture_check(s, p, check, *, reason="report"):
    ids = collect_check_sources(s, check)
    authorize(s, p, ids)
    # A concurrent citation change must not introduce a new lower-order lock.
    if not collect_check_sources(s, check) <= ids:
        raise Conflict("followup_source_scope_changed")
    return _capture(s, p, check, reason=reason)


def get_check_revision(s, p, inv_id, revision_id):
    row = s.get(CheckRevision, revision_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("check revision not found")
    sources = _verify_revision_tree(s, row)
    authorize(s, p, {inv_id, *sources})
    return row


def snapshot_checks(s, p, inv_id, *, check_ids=None):
    explicit = check_ids is not None
    ids = list(dict.fromkeys(check_ids or []))
    if len(ids) > 100:
        raise ValueError("check_snapshot_selection_limit")
    q = select(Check).where(Check.investigation_id == inv_id).order_by(Check.created_at, Check.id)
    q = q.where(Check.id.in_(ids)) if explicit else q.where(Check.state == "active")
    rows = list(s.scalars(q.limit(2001)))
    if len(rows) > 2000:
        raise ValueError("check_snapshot_limit")
    if explicit and {r.id for r in rows} != set(ids):
        raise NotFound("selected check not found")
    sources = {inv_id}
    for row in rows:
        sources |= collect_check_sources(s, row)
    authorize(s, p, sources)
    result = [check_revision_dict(capture_check(s, p, row)) for row in rows]
    return {"checks": result, "source_investigation_ids": sorted(sources)}
