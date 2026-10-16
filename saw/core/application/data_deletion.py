"""Explicit, retryable cleanup of active local data; audit and approved records are not erased."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from saw import container
from saw.core.application import audit
from saw.core.application.investigations import NotFound
from saw.core.schemas.query import Filter
from saw.core.security.authz import Principal
from saw.storage.db import new_id, utcnow
from saw.storage.models import (AttackStory, Briefing, Case, CaseItem, Check, Correlation, CustodyLog, DataDeletion,
    Entity, Evidence, EvidenceFile, Finding, FindingFeedback, Investigation, InvestigationMember, Job, Note,
    ParameterProfile, Pattern, ProcessingRun, Relation, Review, SavedView, Support, UploadSession)
from saw.storage.objectstore import LocalFSObjectStore

TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")
RETAINED = ["감사·증거 인계·처리 이력", "폐기 케이스의 스냅샷·리비전", "별도 보관된 백업·내보낸 파일"]
BLOCKERS = {
    "legal_hold": "법적 보존 중인 증거가 있습니다. 보존 책임자가 정책에 따라 해제해야 합니다.",
    "active_jobs": "조사 작업이 대기·처리·입력 대기 중입니다. 작업 화면에서 취소하고 종료를 확인하세요.",
    "open_uploads": "업로드가 진행 중입니다. 업로드를 완료하거나 별도로 중단한 뒤 다시 확인하세요.",
    "shared_pcap_artifact": "PCAP 추출 파일이 조사 안에서 공유됩니다. 증거 일부 대신 조사 전체 정리를 검토하세요.",
    "shared_object": "다른 증거가 같은 저장 객체를 참조합니다. 관리자 점검이 필요합니다.",
    "unsafe_object": "저장 경로 또는 파일의 안전성을 확인할 수 없습니다. 관리자 점검이 필요합니다.",
    "unsupported_store": "현재 삭제는 로컬 파일 저장소와 SQLite/OpenSearch 이벤트 저장소만 지원합니다.",
    "deletion_in_progress": "이 조사에 미완료 삭제 작업이 있습니다. 해당 영수증에서 재시도하세요.",
    "case_reference": "활성 케이스가 참조합니다. 케이스를 먼저 폐기한 뒤 다시 확인하세요.",
    "knowledge_reference": "Experience 지식이 원본 조사를 참조합니다. 보존 계약 검토가 필요합니다.",
    "detection_reference": "탐지 룰 출처·과거 자료 시험이 참조합니다. 보존 계약 검토가 필요합니다.",
    "hunt_reference": "헌팅 기록이 이 자료를 참조합니다. 기록 보존 검토가 필요합니다.",
    "shared_check": "다른 조사에서 공유 확인 기록을 인용합니다. 인용 관계를 먼저 검토하세요.",
    "analyst_records": "증거 일부 삭제가 분석가 판단·노트에 영향을 줍니다. 조사 전체 정리 또는 보존 검토가 필요합니다.",
    "too_many_objects": "한 번에 10000개 파일까지 안전 점검할 수 있습니다. 관리자 별도 정리가 필요합니다.",
}


def lock_investigation(s: Session, inv_id: str, *, allow_deleting: bool = False) -> Investigation:
    # A no-op UPDATE serializes both PostgreSQL writers and SQLite writers before their read.
    txn = s.get_transaction()
    marker = (inv_id, txn)
    if marker not in s.info.setdefault("data_locks", set()):
        s.execute(update(Investigation).where(Investigation.id == inv_id).values(id=inv_id)
                  .execution_options(synchronize_session=False))
        s.info["data_locks"].add((inv_id, s.get_transaction()))
    inv = s.scalar(select(Investigation).where(Investigation.id == inv_id).execution_options(populate_existing=True))
    if inv is None:
        raise NotFound("investigation not found")
    if not allow_deleting and (inv.settings or {}).get("data_deletion"):
        raise HTTPException(409, "이 조사에 미완료 삭제 작업이 있어 접근이 중단되었습니다.")
    return inv


def epoch(inv: Investigation) -> int:
    return int((inv.settings or {}).get("data_epoch", 0))


def _count(s: Session, model, *where) -> int:
    return s.scalar(select(func.count()).select_from(model).where(*where)) or 0


def listing(s: Session, target_type: str | None = None, offset: int = 0, limit: int = 50) -> dict:
    rows = []
    for kind, model in (("case", Case), ("investigation", Investigation), ("evidence", Evidence)):
        if target_type and target_type != kind:
            continue
        q = select(model).order_by(model.id).offset(offset).limit(limit + 1)
        if kind == "case":
            q = q.where(Case.status.notin_(["deleted", "deleting"]))
        for obj in s.scalars(q):
            row = {"target_type": kind, "target_id": obj.id, "display_id": getattr(obj, "display_id", obj.id),
                   "status": obj.status, "created_at": getattr(obj, "created_at", getattr(obj, "uploaded_at", None))}
            if kind == "evidence":
                row.update(investigation_id=obj.investigation_id, files=obj.file_count, bytes=obj.total_size,
                           legal_hold=obj.legal_hold)
            rows.append(row)
    # Each category is independently paged. The UI selects a category.
    receipts = s.scalars(select(DataDeletion).order_by(DataDeletion.created_at.desc()).limit(30))
    return {"items": rows[:limit], "has_more": len(rows) > limit, "offset": offset, "limit": limit,
            "deletions": [receipt(x) for x in receipts], "scope": "활성 데이터 정리이며 완전 소거가 아닙니다."}


def _has_ref(value, ids: set[str]) -> bool:
    if isinstance(value, str):
        return value in ids
    if isinstance(value, dict):
        return any(_has_ref(v, ids) for v in value.values())
    if isinstance(value, list):
        return any(_has_ref(v, ids) for v in value)
    return False


def _plan(s: Session, kind: str, target_id: str) -> dict:
    if kind not in ("case", "investigation", "evidence"):
        raise ValueError("unsupported deletion target")
    blockers: set[str] = set()
    if kind == "case":
        s.execute(update(Case).where(Case.id == target_id).values(id=target_id).execution_options(synchronize_session=False))
        obj = s.scalar(select(Case).where(Case.id == target_id).execution_options(populate_existing=True))
        if obj is None or obj.status in ("deleted", "deleting"):
            raise NotFound("case not found")
        return {"target_type": kind, "target_id": obj.id, "confirmation": obj.display_id, "investigation_id": None,
                "counts": {"cases": 1, "retained_snapshots": _count(s, CaseItem, CaseItem.case_id == obj.id)},
                "blockers": [], "objects": [], "evidence_ids": [], "retained": RETAINED,
                "revision": {"status": obj.status, "updated": obj.summary_md, "items":
                             list(s.scalars(select(CaseItem.id).where(CaseItem.case_id == obj.id)))}}
    evidence = s.get(Evidence, target_id) if kind == "evidence" else None
    if kind == "evidence" and evidence is None:
        raise NotFound("evidence not found")
    inv_id = evidence.investigation_id if evidence else target_id
    inv = lock_investigation(s, inv_id, allow_deleting=True)
    if (inv.settings or {}).get("data_deletion"):
        blockers.add("deletion_in_progress")
    evs = list(s.scalars(select(Evidence).where(Evidence.investigation_id == inv_id).execution_options(populate_existing=True)))
    targets = [e for e in evs if kind == "investigation" or e.id == target_id]
    ids = [e.id for e in targets]
    if any(e.legal_hold for e in targets):
        blockers.add("legal_hold")
    if _count(s, Job, Job.investigation_id == inv_id, Job.state.notin_(TERMINAL)):
        blockers.add("active_jobs")
    if _count(s, UploadSession, UploadSession.evidence_id.in_([e.id for e in evs]), UploadSession.status == "open"):
        blockers.add("open_uploads")
    files = list(s.scalars(select(EvidenceFile).where(EvidenceFile.evidence_id.in_(ids))))
    if len(files) > 10000:
        blockers.add("too_many_objects")
    es, store = container.get().events, container.get().objects
    from saw.storage.eventstore import SQLiteEventStore
    from saw.storage.opensearch_store import OpenSearchEventStore
    if not isinstance(store, LocalFSObjectStore) or not isinstance(es, (SQLiteEventStore, OpenSearchEventStore)):
        blockers.add("unsupported_store")
    objects = []
    for f in files[:10000]:
        bucket = "saw-evidence-extracted" if f.parent_file_id else "saw-evidence-original"
        if _count(s, EvidenceFile, EvidenceFile.object_key == f.object_key, EvidenceFile.id != f.id,
                  EvidenceFile.evidence_id.notin_(ids)):
            blockers.add("shared_object")
        try:
            if isinstance(store, LocalFSObjectStore):
                store.safe_delete_path(bucket, f.object_key)
            # Root uploads and extracted children have different established storage keys.
            # Require the exact generated key and a parent in the same evidence bundle.
            if f.parent_file_id:
                parent = next((candidate for candidate in files if candidate.id == f.parent_file_id), None)
                if parent is None or parent.evidence_id != f.evidence_id:
                    raise ValueError("foreign extracted parent")
                expected_key = f"{inv_id}/{f.id}"
            else:
                expected_key = f"{inv_id}/{f.evidence_id}/{f.id}"
            if f.object_key != expected_key:
                raise ValueError("foreign object key")
        except (OSError, ValueError):
            blockers.add("unsafe_object")
        objects.append({"bucket": bucket, "key": f.object_key, "file_id": f.id, "sha256": f.sha256, "size": f.size})
    if isinstance(store, LocalFSObjectStore):
        known = {(o["bucket"], o["key"]) for o in objects}
        try:
            if kind == "evidence" and store.cleanup_keys("saw-artifacts", f"{inv_id}/extracted-files"):
                blockers.add("shared_pcap_artifact")
            prefixes = [inv_id] if kind == "investigation" else [f"{inv_id}/{eid}" for eid in ids]
            for bucket in ("saw-evidence-original", "saw-evidence-extracted", "saw-artifacts"):
                for prefix in prefixes:
                    for key in store.cleanup_keys(bucket, prefix):
                        if (bucket, key) in known:
                            continue
                        if _count(s, EvidenceFile, EvidenceFile.object_key == key, EvidenceFile.evidence_id.notin_(ids)):
                            blockers.add("shared_object")
                        path = store.safe_delete_path(bucket, key)
                        objects.append({"bucket": bucket, "key": key, "size": path.stat().st_size})
                        known.add((bucket, key))
                        if len(objects) > 10000:
                            raise ValueError("too many cleanup objects")
        except (ValueError, OSError):
            blockers.add("unsafe_object")
    objects.sort(key=lambda o: (o["bucket"], o["key"]))
    findings = list(s.scalars(select(Finding).where(Finding.investigation_id == inv_id)))
    finding_ids = [f.id for f in findings]
    related_ids = {inv_id, *ids, *(f.id for f in files), *finding_ids}
    for c in s.scalars(select(Case).where(Case.status != "deleted")):
        if inv_id in (c.investigation_ids or []):
            blockers.add("case_reference")
        for item in s.scalars(select(CaseItem).where(CaseItem.case_id == c.id)):
            if item.ref_id in related_ids or _has_ref(item.snapshot, related_ids):
                blockers.add("case_reference")
    from saw.knowledge.models import Experience
    from saw.detection.service import Detection, TestRun
    from saw.hunting.service import HuntSession, HuntStep
    if _count(s, Experience, Experience.source_investigation_id == inv_id):
        blockers.add("knowledge_reference")
    if any(_has_ref(d.source, related_ids) for d in s.scalars(select(Detection))):
        blockers.add("detection_reference")
    if any(_has_ref(t.scope, related_ids) or _has_ref(t.result, related_ids) for t in s.scalars(select(TestRun))):
        blockers.add("detection_reference")
    if (_count(s, HuntSession, HuntSession.investigation_id == inv_id)
            or any(_has_ref(t.result_summary, related_ids) for t in s.scalars(select(HuntStep)))):
        blockers.add("hunt_reference")
    check_ids = list(s.scalars(select(Check.id).where(Check.investigation_id == inv_id)))
    if (_count(s, Check, Check.investigation_id != inv_id, Check.source_check_id.in_(check_ids))
            or _count(s, Check, Check.investigation_id == inv_id, Check.shared.is_(True))):
        blockers.add("shared_check")
    if kind == "evidence":
        human = (any(f.status != "new" or f.detector_id == "hunt.manual" for f in findings)
                 or _count(s, FindingFeedback, FindingFeedback.finding_id.in_(finding_ids))
                 or any(_count(s, m, m.investigation_id == inv_id) for m in (Note, Check, Review, Support, Briefing))
                 or _count(s, AttackStory, AttackStory.investigation_id == inv_id, AttackStory.origin != "auto")
                 or any((e.attrs or {}).get("ioc") or (e.attrs or {}).get("source") in ("ioc_list", "paste")
                        for e in s.scalars(select(Entity).where(Entity.investigation_id == inv_id))))
        if human:
            blockers.add("analyst_records")
    counts = {"investigations": int(kind == "investigation"), "evidence_bundles": len(targets), "files": len(files),
              "bytes": sum(o["size"] for o in objects), "objects": len(objects), "events": es.count(inv_id) if kind == "investigation" else sum(es.count(inv_id, [Filter(field="evidence_id", value=e.id)]) for e in targets),
              "invalidated_findings": len(findings), "notes": _count(s, Note, Note.investigation_id == inv_id),
              "retained_custody": _count(s, CustodyLog, CustodyLog.evidence_id.in_(ids)),
              "retained_processing_runs": _count(s, ProcessingRun, ProcessingRun.investigation_id == inv_id)}
    return {"target_type": kind, "target_id": target_id, "investigation_id": inv_id,
            "confirmation": inv.display_id if kind == "investigation" else target_id,
            "counts": counts, "blockers": sorted(blockers), "objects": objects, "evidence_ids": ids,
            "retained": RETAINED, "revision": {"epoch": epoch(inv), "findings": sorted(finding_ids),
            "jobs": [(j.id, j.state, j.attempt) for j in s.scalars(select(Job).where(Job.investigation_id == inv_id))]}}


def _fingerprint(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def preview(s: Session, kind: str, target_id: str) -> dict:
    p = _plan(s, kind, target_id)
    return {k: p[k] for k in ("target_type", "target_id", "confirmation", "counts", "blockers", "retained")} | {
        "fingerprint": _fingerprint(p), "blocker_details": [{"code": code, "message": BLOCKERS[code]} for code in p["blockers"]],
        "scope_note": "증거 묶음은 포함 파일 전체입니다. 증거 삭제 시 이 조사의 자동 분석 결과를 무효화하며 남은 자료는 재분석해야 합니다."}


def receipt(op: DataDeletion) -> dict:
    return {"id": op.id, "target_type": op.target_type, "target_id": op.target_id, "state": op.state,
            "step": op.step, "counts": op.plan.get("counts", {}), "retained": op.plan.get("retained", RETAINED),
            "error_code": op.error_code, "created_at": op.created_at, "updated_at": op.updated_at}


def start(s: Session, p: Principal, kind: str, tid: str, confirmation: str, fingerprint: str, reason: str) -> DataDeletion:
    plan = _plan(s, kind, tid)
    if confirmation != plan["confirmation"] or fingerprint != _fingerprint(plan):
        raise HTTPException(409, "대상 또는 영향 범위가 변경되었습니다. 미리보기를 다시 확인하세요.")
    if plan["blockers"]:
        raise HTTPException(409, "삭제를 막는 조건을 먼저 해결하세요.")
    op = DataDeletion(id=new_id(), target_type=kind, target_id=tid, investigation_id=plan["investigation_id"],
                      plan=plan, reason=reason, actor_id=p.user_id, actor_name=p.username, state="PENDING", step="planned")
    s.add(op)
    if op.target_type == "case":
        s.get(Case, tid).status = "deleting"
    if op.investigation_id:
        inv = s.get(Investigation, op.investigation_id)
        inv.settings = {**(inv.settings or {}), "data_deletion": op.id, "data_epoch": epoch(inv) + 1}
    audit.record(s, "data.delete_requested", actor_id=p.user_id, actor_name=p.username, target_type=kind,
                 target_id=tid, investigation_id=op.investigation_id,
                 detail={"receipt_id": op.id, "reason": reason, "counts": plan["counts"], "retained": RETAINED})
    s.commit()  # Barrier and receipt must survive any external-store failure.
    return resume(s, op.id)


def _finish_relational(s: Session, op: DataDeletion) -> None:
    iid, ids = op.investigation_id, op.plan["evidence_ids"]
    if op.target_type == "case":
        c = s.get(Case, op.target_id)
        c.status = "deleted"
        return
    from saw.knowledge.similar import KnowledgeDoc
    from saw.llm.service import LlmInteraction
    from saw.behavior.models import BehaviorResult
    s.execute(delete(BehaviorResult).where(BehaviorResult.investigation_id == iid))
    fids = select(Finding.id).where(Finding.investigation_id == iid)
    s.execute(delete(FindingFeedback).where(FindingFeedback.finding_id.in_(fids)))
    for model in (Finding, Pattern, ParameterProfile, Entity, Relation, AttackStory, Correlation, LlmInteraction):
        s.execute(delete(model).where(model.investigation_id == iid))
    s.execute(delete(KnowledgeDoc).where(KnowledgeDoc.ref_type == "investigation", KnowledgeDoc.ref_id == iid))
    for model in (UploadSession, EvidenceFile):
        s.execute(delete(model).where(model.evidence_id.in_(ids)))
    s.execute(delete(Evidence).where(Evidence.id.in_(ids)))
    s.execute(delete(Job).where(Job.investigation_id == iid if op.target_type == "investigation" else Job.evidence_id.in_(ids)))
    inv = s.get(Investigation, iid)
    if op.target_type == "investigation":
        for model in (Note, SavedView, Briefing, Check, Review, Support, InvestigationMember):
            s.execute(delete(model).where(model.investigation_id == iid))
        s.delete(inv)
    else:
        settings = dict(inv.settings or {})
        settings.pop("data_deletion", None)
        settings["analysis_invalidated_by_deletion"] = op.id
        inv.settings = settings
        inv.risk_score, inv.risk_level, inv.risk_override = 0, "info", None
        inv.time_start, inv.time_end = None, None


def resume(s: Session, deletion_id: str, *, requested_by: Principal | None = None) -> DataDeletion:
    # Lock the receipt to prevent concurrent retries from racing external deletion with finalization.
    s.execute(update(DataDeletion).where(DataDeletion.id == deletion_id).values(id=deletion_id)
              .execution_options(synchronize_session=False))
    op = s.scalar(select(DataDeletion).where(DataDeletion.id == deletion_id).execution_options(populate_existing=True))
    if op is None:
        raise NotFound("deletion receipt not found")
    if requested_by is not None:
        # Keep the original requester on the receipt; record each retry caller separately.
        # Persist the request before external work while preserving database lock order.
        if op.state != "COMPLETED" and op.investigation_id:
            lock_investigation(s, op.investigation_id, allow_deleting=True)
        audit.record(s, "data.delete_retry_requested", actor_id=requested_by.user_id,
                     actor_name=requested_by.username, target_type=op.target_type,
                     target_id=op.target_id, investigation_id=op.investigation_id,
                     detail={"receipt_id": op.id, "previous_state": op.state, "previous_step": op.step})
        s.commit()
        # Reacquire the receipt and barrier after committing the durable audit request.
        return resume(s, deletion_id)
    if op.state == "COMPLETED":
        return op
    phase = op.step
    try:
        if op.investigation_id:
            inv = lock_investigation(s, op.investigation_id, allow_deleting=True)
            if (inv.settings or {}).get("data_deletion") != op.id:
                raise ValueError("barrier changed")
            if _count(s, Evidence, Evidence.id.in_(op.plan["evidence_ids"]), Evidence.legal_hold.is_(True)):
                raise ValueError("legal hold changed")
            if _count(s, Job, Job.investigation_id == op.investigation_id, Job.state.notin_(TERMINAL)):
                raise ValueError("active job changed")
        if phase == "planned":
            if op.investigation_id:
                es = container.get().events
                if op.target_type == "investigation":
                    es.delete_by_investigation(op.investigation_id)
                    if es.count(op.investigation_id):
                        raise ValueError("remaining events")
                else:
                    for eid in op.plan["evidence_ids"]:
                        es.delete_by_evidence(op.investigation_id, eid)
                        if es.count(op.investigation_id, [Filter(field="evidence_id", value=eid)]):
                            raise ValueError("remaining events")
            op.step = phase = "events_removed"
            s.flush()
        if phase == "events_removed":
            store = container.get().objects
            for obj in op.plan["objects"]:
                if not isinstance(store, LocalFSObjectStore):
                    raise ValueError("unsupported store")
                store.safe_delete_path(obj["bucket"], obj["key"])
                store.delete(obj["bucket"], obj["key"])
                if store.exists(obj["bucket"], obj["key"]):
                    raise ValueError("remaining object")
            op.step = phase = "objects_removed"
            s.flush()
        # External stores are not part of this transaction. Recheck even after a saved
        # checkpoint so a failed attempt cannot certify a recreated event as removed.
        if op.investigation_id:
            es = container.get().events
            if op.target_type == "investigation":
                es.delete_by_investigation(op.investigation_id)
                if es.count(op.investigation_id):
                    raise ValueError("remaining events")
            else:
                for eid in op.plan["evidence_ids"]:
                    es.delete_by_evidence(op.investigation_id, eid)
                    if es.count(op.investigation_id, [Filter(field="evidence_id", value=eid)]):
                        raise ValueError("remaining events")
        _finish_relational(s, op)
        op.state, op.step, op.error_code, op.updated_at = "COMPLETED", "completed", "", utcnow()
        audit.record(s, "data.delete_completed", actor_id=op.actor_id, actor_name=op.actor_name,
                     target_type=op.target_type, target_id=op.target_id, investigation_id=op.investigation_id,
                     detail={"receipt_id": op.id, "counts": op.plan["counts"], "retained": RETAINED})
        s.commit()
    except Exception:
        s.rollback()
        op = s.get(DataDeletion, deletion_id)
        op.state, op.error_code, op.updated_at = "FAILED", f"{phase}_failed", utcnow()
        # Keep the last externally verified checkpoint. Repeated deletes are idempotent.
        op.step = phase
        audit.record(s, "data.delete_failed", actor_id=op.actor_id, actor_name=op.actor_name,
                     target_type=op.target_type, target_id=op.target_id, investigation_id=op.investigation_id,
                     outcome="failure", detail={"receipt_id": op.id, "error_code": op.error_code})
        s.commit()
    return op
