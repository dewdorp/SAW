"""Transitive source access for published derived findings and immutable projections."""
from __future__ import annotations

from sqlalchemy import select

from saw.core.application.investigations import Forbidden, NotFound, require


def source_ids(value):
    if hasattr(value, "evidence_refs"):
        value = value.evidence_refs
    pending, result, visited = [value], set(), 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > 20000:
            raise Forbidden("derived_source_scope_limit")
        if hasattr(item, "evidence_refs"):
            pending.append(item.evidence_refs)
            continue
        if isinstance(item, dict):
            for key, child in item.items():
                if key in {"source_investigation_ids", "_source_investigation_ids"}:
                    if not isinstance(child, (list, tuple, set)) or any(not isinstance(v, str) for v in child):
                        raise Forbidden("derived_source_scope_invalid")
                    result.update(child)
                elif isinstance(child, (dict, list, tuple)):
                    pending.append(child)
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        if len(result) > 500:
            raise Forbidden("derived_source_scope_limit")
    return result


def require_snapshot(s, p, payload):
    ids = source_ids(payload)
    if ids and p is None:
        raise Forbidden("derived_source_principal_required")
    for ident in sorted(ids):
        require(s, p, "investigation.read", ident)
    return payload


def require_finding(s, p, finding):
    if p is not None:
        require(s, p, "investigation.read", finding.investigation_id)
    require_snapshot(s, p, finding.evidence_refs or {})
    return finding


def visible_findings(s, p, rows):
    out = []
    for finding in rows:
        try:
            require_finding(s, p, finding)
        except (Forbidden, NotFound):
            continue
        out.append(finding)
    return out


def require_investigation_results(s, p, inv_id):
    """Fence a dependent aggregate when its components cannot be safely filtered."""
    from saw.storage.models import Finding
    for finding in s.scalars(select(Finding).where(Finding.investigation_id == inv_id)):
        require_finding(s, p, finding)


def visible_snapshot(s, p, payload):
    try:
        require_snapshot(s, p, payload)
    except (Forbidden, NotFound):
        return False
    return True
