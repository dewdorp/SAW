"""Freeze exact report revisions and retain every original source authority."""
from __future__ import annotations

import json
from copy import deepcopy

from fastapi import HTTPException
from sqlalchemy import func, select

from saw.analysis_runs import service as runs
from saw.analysis_runs.models import AnalysisRun
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.investigations import NotFound, require
from saw.core.application.provenance import canonical, digest
from saw.reports.models import ReportSourceInvestigation, ReportVersion
from saw.reports.schemas import ReportScope
from saw.reports.source_scope import MAX_SNAPSHOT_BYTES, MAX_SOURCES, content_source_ids
from saw.storage.db import utcnow
from saw.storage.models import Check


def collect_sources(s, scope):
    """Internal preflight only; no caller may expose these unauthorised identifiers."""
    from saw.detection.derived_access import source_ids
    from saw.detection.runtime_capture import sources
    from saw.followups.check_revisions import collect_check_sources
    from saw.followups.service import collect_followup_sources
    ids = set()
    for choice in scope.selections:
        inv_id = choice.investigation_id
        ids.add(inv_id)
        run = s.get(AnalysisRun, choice.analysis_run_id)
        if run is None or run.investigation_id != inv_id:
            raise NotFound("analysis run not found")
        ids.update(sources(run.input_manifest.get("runtime_pin") or {}))
        ids.update(runs._derived_sources(s, run))
        ids.update(source_ids(run.input_manifest))
        ids.update(collect_followup_sources(s, inv_id, version_ids=choice.followup_version_ids))
        if choice.followup_version_ids is None:
            rows = list(s.scalars(select(Check).where(
                Check.investigation_id == inv_id, Check.state == "active").limit(2001)))
            if len(rows) > 2000:
                raise ValueError("report_check_limit_select_followups")
            for row in rows:
                ids.update(collect_check_sources(s, row))
    if len(ids) > MAX_SOURCES:
        raise ValueError("report_source_limit_split_selection")
    return ids


def lock_sources(s, p, ids, *, writers=()):
    """Use the same deterministic lock order for all selected and inherited sources."""
    for inv_id in sorted(set(ids)):
        lock_investigation(s, inv_id)
    write_ids = set(writers)
    for inv_id in sorted(set(ids)):
        require(s, p, "investigation.write" if inv_id in write_ids else "investigation.read", inv_id)


def create_scoped(s, p, raw_scope):
    from saw.followups.check_revisions import Conflict
    try:
        return _create_scoped(s, p, raw_scope)
    except Conflict as exc:
        raise HTTPException(409, str(exc)) from exc


def _create_scoped(s, p, raw_scope):
    scope = ReportScope.model_validate(raw_scope)
    ids = collect_sources(s, scope)
    writers = {x.investigation_id for x in scope.selections}
    lock_sources(s, p, ids, writers=writers)
    previous = s.info.get("snapshot_source_ids")
    s.info["snapshot_source_ids"] = set(ids)
    try:
        return _capture_scoped(s, p, scope, ids)
    finally:
        if previous is None:
            s.info.pop("snapshot_source_ids", None)
        else:
            s.info["snapshot_source_ids"] = previous


def _capture_scoped(s, p, scope, ids):
    from saw.followups.check_revisions import snapshot_checks
    from saw.followups.service import snapshot_followups

    # A newly added citation can change closure between preflight and locking.
    if not collect_sources(s, scope) <= ids:
        raise HTTPException(409, "report_source_scope_changed_retry")
    items, all_sources = [], set(ids)
    total_followups = 0
    for choice in scope.selections:
        inv = require(s, p, "investigation.write", choice.investigation_id)
        run = runs.get(s, p, inv.id, choice.analysis_run_id)
        if run.status not in {"complete", "partial", "insufficient_data"}:
            raise ValueError("report_requires_finished_analysis")
        follow = snapshot_followups(s, p, inv.id, version_ids=choice.followup_version_ids)
        records = (snapshot_checks(s, p, inv.id) if choice.followup_version_ids is None else
                   {"checks": follow["checks"], "source_investigation_ids": follow["source_investigation_ids"]})
        all_sources.update(records["source_investigation_ids"])
        all_sources.update(follow["source_investigation_ids"])
        total_followups += len(follow["followups"])
        if total_followups > 100:
            raise ValueError("report_followup_limit_select_fewer_investigations")
        items.append({
            "investigation": {"id": inv.id, "display_id": inv.display_id, "title": inv.title,
                              "org_unit": inv.org_unit, "org_unit_id": inv.org_unit_id},
            "analysis": runs.run_dict(s, run), "checks": records["checks"],
            "followups": follow["followups"],
        })
    content = json.loads(canonical({
        "schema_version": "saw.report.v2", "created_at": utcnow().isoformat(),
        "masking_policy": "authenticated-source-acl-v1", "scope": scope.model_dump(),
        "items": items, "limits": [
            "기록된 관측 결과와 분석가 확인을 구분합니다. 허용·응답은 정상 또는 침해 성공의 증명이 아닙니다.",
            "저장한 분석 실행과 확인 기록의 정확한 버전을 사용합니다. 원문 전체 반출 파일이 아닙니다.",
        ],
        "schema_limits": {"max_investigations": 20, "max_followups": 100,
                          "max_snapshot_bytes": MAX_SNAPSHOT_BYTES},
    }))
    all_sources = content_source_ids(content, base_sources=all_sources)
    if not all_sources <= ids:
        raise HTTPException(409, "report_source_scope_changed_retry")
    if len(canonical(content).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("report_snapshot_limit_split_selection")
    anchor = scope.selections[0].investigation_id
    number = (s.scalar(select(func.max(ReportVersion.version)).where(
        ReportVersion.investigation_id == anchor)) or 0) + 1
    row = ReportVersion(investigation_id=anchor, version=number, created_by=p.user_id,
                        source_investigation_ids=sorted(all_sources), content=content,
                        content_sha256=digest(content))
    s.add(row)
    s.flush()
    s.add_all(ReportSourceInvestigation(report_id=row.id, investigation_id=x) for x in sorted(all_sources))
    audit.record(s, "report.version_created", actor_id=p.user_id, actor_name=p.username,
                 target_type="report_version", target_id=row.id, investigation_id=anchor,
                 detail={"version": number, "content_sha256": row.content_sha256,
                         "scope_kind": scope.kind, "investigations": len(items)})
    return row


def create(s, p, inv_id, *, analysis_run_id, followup_version_ids=None):
    return create_scoped(s, p, {
        "kind": "selected_followups" if followup_version_ids is not None else "investigation",
        "selections": [{"investigation_id": inv_id, "analysis_run_id": analysis_run_id,
                        "followup_version_ids": followup_version_ids}],
    })


def source_ids(row):
    return content_source_ids(row.content, base_sources={
        row.investigation_id, *(row.source_investigation_ids or [])})


def get(s, p, inv_id, report_id):
    row = s.get(ReportVersion, report_id)
    if row is None or row.investigation_id != inv_id:
        # The caller still needs target access before a missing resource response.
        require(s, p, "investigation.read", inv_id)
        raise NotFound("report version not found")
    lock_sources(s, p, source_ids(row))
    if digest(row.content) != row.content_sha256:
        raise ValueError("report_content_corrupt")
    return row


def to_dict(row):
    return {"id": row.id, "version": row.version, "created_at": row.created_at,
            "created_by": row.created_by, "content_sha256": row.content_sha256,
            "content": deepcopy(row.content)}
