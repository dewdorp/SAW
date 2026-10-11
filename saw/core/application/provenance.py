"""Processing provenance: every parse of an evidence file leaves a content-free record of who processed which
input (SHA-256) with which parser and settings (fingerprints) and what came out (result fingerprint).

The same record is written to the hash-chained audit log, so a later change of the table is detectable. Analysts
see the runs of their investigations; the SOC manager and auditors see all of them (auditors without content).
"""
from __future__ import annotations

import hashlib
import inspect
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.storage.models import EvidenceFile, Job, ProcessingRun, User

PIPELINE = "saw.ingest/2"  # bump when the pipeline itself changes how text becomes events


def canonical(v) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def digest(v) -> str:
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()


@lru_cache(maxsize=64)
def _source_digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parser_digest(parser) -> str:
    """Analyst parsers: fingerprint of their spec. Built-ins: fingerprint of their source module, so a code change
    shows up as a different parser even when the version string was not bumped."""
    spec = getattr(parser, "spec", None)
    if spec is not None and hasattr(spec, "model_dump"):
        return digest(spec.model_dump())
    try:
        return _source_digest(inspect.getsourcefile(type(parser)) or "")
    except (OSError, TypeError):
        return ""


@lru_cache(maxsize=1)
def pcap_engine_digest() -> str:
    import saw.integrations.pcapkit as kit

    h = hashlib.sha256()
    for f in sorted(Path(kit.__file__).parent.glob("*.py")):
        h.update(f.name.encode() + f.read_bytes())
    return h.hexdigest()


def actor_of(s: Session, job: Job | None) -> tuple[str, str]:
    req = ((job.stages or {}).get("requested") or {}) if job else {}
    uid = req.get("by") or (job.requested_by if job else "") or ""
    name = req.get("name") or (s.execute(select(User.username).where(User.id == uid)).scalar_one_or_none() if uid else "")
    return uid, name or ""


def record_run(s: Session, *, job: Job | None, f: EvidenceFile, investigation_id: str, parser_id: str,
               parser_version: str, parser_fp: str, settings: dict, events: int, failed: int, coverage: dict,
               status: str, started_at: datetime | None) -> ProcessingRun:
    settings = {"pipeline": PIPELINE, "parser": parser_id, "parser_version": parser_version, "parser_digest": parser_fp,
                **settings}
    sdig = digest(settings)
    rdig = digest({"input_sha256": f.sha256 or "", "settings_digest": sdig, "events": events, "failed": failed,
                   "coverage": coverage})
    uid, name = actor_of(s, job)
    run = ProcessingRun(investigation_id=investigation_id, evidence_id=f.evidence_id, file_id=f.id,
                        job_id=job.id if job else None, actor_id=uid, actor_name=name[:64], file_name=f.display_name[:512],
                        input_sha256=f.sha256 or "", input_size=f.size or 0, parser_id=parser_id[:64],
                        parser_version=str(parser_version)[:16], parser_digest=parser_fp, settings=settings, settings_digest=sdig,
                        events=events, failed=failed, coverage=coverage, status=status, run_digest=rdig,
                        started_at=started_at)
    s.add(run)
    s.flush()
    audit.record(s, "evidence.processed", actor_id=uid or None, actor_name=name, target_type="evidence_file",
                 target_id=f.id, investigation_id=investigation_id,
                 detail={"run_id": run.id, "input_sha256": run.input_sha256, "parser": parser_id,
                         "parser_version": parser_version, "settings_digest": sdig, "run_digest": rdig,
                         "events": events, "failed": failed})
    return run
