"""Create immutable reports and recheck every original source when serving them."""
from __future__ import annotations
import json
from copy import deepcopy
from sqlalchemy import func, select
from saw.analysis_runs import service as runs
from saw.core.application import audit, checks
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.investigations import NotFound, require
from saw.core.application.provenance import canonical, digest
from saw.reports.models import ReportVersion
from saw.storage.models import Investigation, Check


def create(s, p, inv_id, *, analysis_run_id):
    inv = require(s, p, "investigation.write", inv_id)
    lock_investigation(s, inv_id)
    run = runs.get(s, p, inv_id, analysis_run_id)
    if run.status not in {"complete", "partial", "insufficient_data"}:
        raise ValueError("report_requires_finished_analysis")
    records, source_ids = [], checks.source_investigation_ids(s, p, inv_id)
    from saw.detection.runtime_capture import sources
    source_ids.update(sources(run.input_manifest.get("runtime_pin") or {}))
    for check in checks.list_checks(s, inv_id, principal=p):
        if check.source_check_id:
            source = s.get(Check, check.source_check_id)
            if source is None:
                raise ValueError("report_check_source_missing")
            require(s, p, "investigation.read", source.investigation_id)
            source_ids.add(source.investigation_id)
        records.append(checks.to_dict(check))
    content = json.loads(canonical({"schema_version": "saw.report.v1",
        "investigation": {"id": inv.id, "display_id": inv.display_id, "title": inv.title,
            "org_unit": inv.org_unit, "org_unit_id": getattr(inv, "org_unit_id", None)},
        "analysis": runs.run_dict(s, run), "checks": records,
        "masking_policy": "authenticated-source-acl-v1",
        "limits": ["기록된 관측 결과와 분석가 확인을 구분합니다. 허용·응답은 정상 또는 침해 성공의 증명이 아닙니다."]}))
    from saw.detection.derived_access import source_ids as derived_sources
    source_ids.update(derived_sources(content))
    number = (s.scalar(select(func.max(ReportVersion.version)).where(
        ReportVersion.investigation_id == inv_id)) or 0) + 1
    row = ReportVersion(investigation_id=inv_id, version=number, created_by=p.user_id,
        source_investigation_ids=sorted(source_ids), content=content, content_sha256=digest(content))
    s.add(row)
    s.flush()
    audit.record(s, "report.version_created", actor_id=p.user_id, actor_name=p.username,
        target_type="report_version", target_id=row.id, investigation_id=inv_id,
        detail={"version": number, "content_sha256": row.content_sha256, "analysis_run_id": run.id})
    return row


def get(s, p, inv_id, report_id):
    require(s, p, "investigation.read", inv_id)
    row = s.get(ReportVersion, report_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("report version not found")
    from saw.detection.derived_access import source_ids as derived_sources
    for source_id in set(row.source_investigation_ids) | derived_sources(row.content):
        require(s, p, "investigation.read", source_id)
    if digest(row.content) != row.content_sha256:
        raise ValueError("report_content_corrupt")
    return row


def to_dict(row):
    return {"id": row.id, "version": row.version, "created_at": row.created_at,
        "created_by": row.created_by, "content_sha256": row.content_sha256,
        "content": deepcopy(row.content)}
