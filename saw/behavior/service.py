"""Immutable behavior results and validated references from analyst records."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from saw.behavior.models import BehaviorResult
from saw.core.application import audit
from saw.core.application.data_deletion import lock_investigation
from saw.core.application.investigations import NotFound, require
from saw.core.application.provenance import canonical, digest
from saw.core.schemas.query import Filter, TimeRange
from saw.knowledge.golden import masked
from saw.storage.models import Check, Job

MAX_RESULT_BYTES = 3 * 1024 * 1024
TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")

class BehaviorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    time: TimeRange | None = None
    ips: list[str] = Field(default_factory=list, max_length=16)
    role: Literal["src", "dst", "either"] = "src"
    profile: dict[str, Any] | None = None
    idempotency_key: str | None = Field(None, min_length=1, max_length=128)

    @field_validator("ips")
    @classmethod
    def valid_ips(cls, values):
        return sorted({str(ip_address(v)) for v in values})

    @model_validator(mode="after")
    def bounded_request(self):
        if len(canonical(self.model_dump()).encode()) > 32768:
            raise ValueError("behavior_request_too_large")
        if self.time:
            values = []
            for raw in (self.time.start, self.time.end):
                if raw is None:
                    values.append(None)
                    continue
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError("behavior_time_timezone_required")
                values.append(dt)
            if all(values) and values[0] >= values[1]:
                raise ValueError("behavior_time_range_invalid")
        return self

class BehaviorAttachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result_id: str = Field(min_length=1, max_length=36)
    result_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    metric_ids: list[str] = Field(default_factory=list, max_length=5)
    follow_up: dict[str, Any] = Field(default_factory=dict)
    answer_status: Literal["answered", "follow_up", "not_applicable"] = "answered"

    @model_validator(mode="after")
    def bounded_follow_up(self):
        if len(canonical(self.follow_up).encode()) > 8192:
            raise ValueError("behavior_follow_up_too_large")
        if self.answer_status == "follow_up" and not self.follow_up:
            raise ValueError("behavior_follow_up_required")
        return self

def ensure_source_idle(s, inv_id):
    active = s.scalar(select(Job.id).where(Job.investigation_id == inv_id,
        Job.kind != "behavior", Job.state.notin_(TERMINAL)).limit(1))
    if active:
        raise HTTPException(409, "behavior_source_processing_active")

def source_manifest(s, inv_id):
    from saw.core.application.guidance import _manifest
    from saw.storage.models import Investigation
    inv = s.get(Investigation, inv_id)
    if inv is None or (inv.settings or {}).get("data_deletion"):
        raise ValueError("behavior_source_unavailable")
    evidence = _manifest(s, inv_id, None)
    from saw.storage.models import EvidenceFile, Evidence
    details = {f.id: f for f in s.scalars(select(EvidenceFile).join(Evidence, EvidenceFile.evidence_id == Evidence.id)
                                       .where(Evidence.investigation_id == inv_id))}
    sources = {e.id: e for e in s.scalars(select(Evidence).where(Evidence.investigation_id == inv_id))}
    for item in evidence:
        original = sources[item["evidence_id"]]
        item.update(title=original.title, kind=original.kind, tz_assumed=original.tz_assumed)
        for file in item["files"]:
            row = details[file["id"]]
            file.update(events_parsed=row.events_parsed, size_bytes=row.size, display_name=row.display_name)
        item["files"].sort(key=lambda f: f["id"])
    evidence.sort(key=lambda x: x["evidence_id"])
    source_jobs = [{"id": j.id, "attempt": j.attempt, "state": j.state,
                    "finished_at": str(j.finished_at) if j.finished_at else None}
                   for j in s.scalars(select(Job).where(Job.investigation_id == inv_id,
                       Job.kind != "behavior").order_by(Job.id))]
    return masked({"data_epoch": int((inv.settings or {}).get("data_epoch", 0)),
                   "evidence": evidence, "source_jobs": source_jobs})

def submit(s, p, inv_id, raw):
    require(s, p, "investigation.write", inv_id)
    body = BehaviorRequest.model_validate(raw)
    from saw.behavior.definitions import resolve_profile
    profile = resolve_profile(body.profile)
    request = body.model_dump(exclude={"idempotency_key"})
    request["profile"] = profile
    lock_investigation(s, inv_id)
    if body.idempotency_key:
        old = s.scalar(select(Job).where(Job.requested_by == p.user_id,
                                         Job.idempotency_key == body.idempotency_key))
        if old:
            if old.kind != "behavior" or old.investigation_id != inv_id or (old.stages or {}).get("behavior_request") != request:
                raise HTTPException(409, "behavior_idempotency_conflict")
            return old, False
    ensure_source_idle(s, inv_id)
    job = Job(investigation_id=inv_id, kind="behavior", requested_by=p.user_id,
              idempotency_key=body.idempotency_key, stages={"behavior_request": request,
                  "requested": {"by": p.user_id, "name": p.username, "action": "behavior"}})
    s.add(job)
    s.flush()
    audit.record(s, "behavior.submit", actor_id=p.user_id, actor_name=p.username, target_type="job",
                 target_id=job.id, investigation_id=inv_id, detail={"scope_sha256": digest(request)})
    return job, True

def verify(row):
    if digest(row.result) != row.result_sha256:
        raise ValueError("behavior_result_corrupt")
    return row

def get(s, p, inv_id, result_id):
    require(s, p, "investigation.read", inv_id)
    row = s.get(BehaviorResult, result_id)
    if row is None or row.investigation_id != inv_id:
        raise NotFound("behavior result not found")
    return verify(row)

def to_dict(row, full=True):
    verify(row)
    out = {"id": row.id, "version": row.version, "job_id": row.job_id,
           "created_at": row.created_at, "created_by": row.created_by, "result_sha256": row.result_sha256}
    if full:
        out["result"] = deepcopy(row.result)
    else:
        out.update({k: deepcopy(row.result["observations"].get(k)) for k in ("summary", "execution")})
        out["scope"] = deepcopy(row.result["scope"])
    return out

def list_results(s, p, inv_id):
    require(s, p, "investigation.read", inv_id)
    return {"results": [to_dict(r, False) for r in s.scalars(select(BehaviorResult)
        .where(BehaviorResult.investigation_id == inv_id).order_by(BehaviorResult.version.desc()).limit(200))]}

def prepare_check(s, p, inv_id, data):
    raw = deepcopy(data)
    attach = BehaviorAttachment.model_validate(raw["behavior"])
    row = get(s, p, inv_id, attach.result_id)
    if attach.result_sha256 != row.result_sha256:
        raise ValueError("behavior_result_hash_mismatch")
    if not set(attach.metric_ids).issubset({m["id"] for m in row.result["observations"]["metrics"]}):
        raise ValueError("behavior_metric_outside_result")
    saved = row.result["scope"]
    existing = raw.get("scope") or {}
    if existing.get("query") is not None and existing["query"] != saved:
        raise ValueError("behavior_check_scope_mismatch")
    raw["scope"] = {"coverage": "selected", **existing, "query": deepcopy(saved)}
    raw.setdefault("target_type", "set")
    raw.setdefault("target_label", "행위 분석 결과 v" + str(row.version))
    raw["questions"] = raw.get("questions") or ["nature"]
    raw["behavior"] = masked(attach.model_dump())
    return raw

def attach_check(s, p, inv_id, check, raw, previous=None):
    attachment = raw.get("behavior")
    if attachment is None and previous:
        attachment = (previous.scope or {}).get("behavior")
    if attachment is None:
        return
    validated = prepare_check(s, p, inv_id, {"behavior": attachment, "scope": check.scope})
    row = get(s, p, inv_id, attachment["result_id"])
    ids = set(check.evidence or []) | set((check.scope or {}).get("event_ids") or [])
    if check.target_type == "event":
        ids.add(check.target_key)
    if not ids.issubset({e["event_id"] for e in row.result["selected_evidence"]}):
        raise ValueError("behavior_evidence_outside_saved_result")
    if check.target_type == "entity":
        kind, _, value = check.target_key.partition(":")
        if kind != "ip" or value not in row.result["scope"]["ips"]:
            raise ValueError("behavior_target_outside_saved_scope")
    if check.target_type == "set":
        check.target_key = "behavior:" + row.id
    check.scope = {**check.scope, "behavior": validated["behavior"]}
    check.context = {**(check.context or {}), "behavior": {"result_id": row.id, "result_sha256": row.result_sha256}}

def closure_references(s, inv_id):
    refs = []
    for check in s.scalars(select(Check).where(Check.investigation_id == inv_id, Check.state == "active")
                           .order_by(Check.created_at)):
        attachment = (check.scope or {}).get("behavior")
        if not attachment:
            continue
        row = s.get(BehaviorResult, attachment["result_id"])
        if row is None or row.investigation_id != inv_id or verify(row).result_sha256 != attachment["result_sha256"]:
            raise ValueError("behavior_closure_result_missing")
        refs.append({"check_id": check.id, "result_id": row.id, "result_sha256": row.result_sha256,
                     "version": row.version, "created_by": row.created_by, "check_author_id": check.author_id})
    return refs

def golden_capture(s, inv_id, check):
    """Project computed observations only; analyst interpretation is never an input blob."""
    attachment = (check.scope or {}).get("behavior") or {}
    row = s.get(BehaviorResult, attachment.get("result_id", ""))
    if row is None or row.investigation_id != inv_id or verify(row).result_sha256 != attachment.get("result_sha256"):
        raise ValueError("golden_behavior_result_missing")
    ensure_source_idle(s, inv_id)
    if source_manifest(s, inv_id) != row.result["source_manifest"]:
        raise ValueError("golden_source_evidence_changed")
    data = row.result
    safe = {"schema": "saw.golden.behavior-observation.v1", "result_id": row.id,
            "result_sha256": row.result_sha256, "captured_at": data["captured_at"],
            "methodology": deepcopy(data["methodology"]), "profile": deepcopy(data["profile"]),
            "request": deepcopy(data["scope"]), "source_manifest": deepcopy(data["source_manifest"]),
            "observations": deepcopy(data["observations"])}
    for item in data["selected_evidence"]:
        if digest(item["event"]) != item["sha256"]:
            raise ValueError("golden_selected_snapshot_corrupt")
    return row, safe, deepcopy(data["selected_evidence"])


def verify_golden_reference(s, inv_id, observation):
    """Recheck retained source hashes without replacing a historical frozen observation."""
    from saw.storage.models import Evidence, EvidenceFile, ProcessingRun
    row = s.get(BehaviorResult, observation.get("result_id"))
    if (row is None or row.investigation_id != inv_id or
            verify(row).result_sha256 != observation.get("result_sha256")):
        raise ValueError("golden_behavior_result_missing")
    for source in observation.get("source_manifest", {}).get("evidence", []):
        evidence = s.get(Evidence, source.get("evidence_id"))
        if evidence is None or evidence.investigation_id != inv_id:
            raise ValueError("golden_source_evidence_changed")
        for item in source.get("files", []):
            file = s.get(EvidenceFile, item.get("id"))
            if file is None or file.evidence_id != evidence.id or file.sha256 != item.get("sha256"):
                raise ValueError("golden_source_evidence_changed")
            original = item.get("processing_run")
            if original:
                processing = s.get(ProcessingRun, original.get("id"))
                if (processing is None or processing.file_id != file.id or
                    processing.input_sha256 != file.sha256 or processing.run_digest != original.get("run_digest")):
                    raise ValueError("golden_source_processing_changed")
