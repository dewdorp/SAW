"""Bounded SQL selection and exhaustive durable Job routing.

This cursor coordinates one local dispatcher, not distributed task execution.
Task leases and domain publication fences remain owned by task implementations.
"""
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from saw.storage.models import Job
from saw.workers.queue_models import QueueCursor

TASK_BY_KIND = {
    "ingest": "ingest.run", "reanalyze": "analyze.run", "behavior": "behavior.run",
    "device_analysis": "device_analysis.run", "report_export": "report_export.run",
    "golden_export": "golden_export.run", "reprocess": "reprocess.run",
}
KNOWN_KINDS = tuple(TASK_BY_KIND)
RECOVERABLE_STATES = ("QUEUED", "PARSING", "INDEXING", "ANALYZING")
QUIESCENT_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED", "WAITING_INPUT"})


class PrepareContractError(RuntimeError):
    """The captured preparer did not honor the durable admission contract."""


def validate_route(job: Job, route: str) -> str:
    allowed = ({"ingest.run", "ingest.resume", "analyze.run"} if job.kind == "ingest"
               else {TASK_BY_KIND.get(job.kind)})
    if not isinstance(route, str) or route not in allowed:
        raise PrepareContractError("invalid durable route")
    return route


def resolve_task(job: Job) -> str | None:
    """Resolve pure routing only; root owns recovery and cancellation bookkeeping."""
    if job.kind not in TASK_BY_KIND:
        return None
    if job.kind == "golden_export" and (job.stages or {}).get("input_state") != "input_ready":
        return None
    route = (job.stages or {}).get("_queue_task")
    if route is None:
        route = "analyze.run" if job.kind == "ingest" and job.state == "ANALYZING" else TASK_BY_KIND[job.kind]
    return validate_route(job, route)


def is_due(job: Job) -> bool:
    return (job.kind in TASK_BY_KIND and job.state == "QUEUED" and not job.cancel_requested
            and (job.kind != "golden_export" or (job.stages or {}).get("input_state") == "input_ready"))


def due_predicates(active_ids: Collection[str] = ()) -> tuple:
    predicates = (Job.kind.in_(KNOWN_KINDS), Job.state == "QUEUED", Job.cancel_requested.is_(False),
                  or_(Job.kind != "golden_export", Job.stages["input_state"].as_string() == "input_ready"))
    return predicates + ((Job.id.not_in(tuple(active_ids)),) if active_ids else ())


@dataclass(frozen=True)
class Candidate:
    job_id: str
    requester: str
    revision: int


def choose_candidate(session: Session, active_ids: Collection[str] = ()) -> Candidate | None:
    cursor = session.get(QueueCursor, "heavy")
    if cursor is None:
        raise RuntimeError("queue cursor is not initialized")
    predicates = due_predicates(active_ids)
    requester = None
    if cursor.last_requester is not None:
        requester = session.scalar(select(func.min(Job.requested_by)).where(
            *predicates, Job.requested_by > cursor.last_requester))
    if requester is None:
        requester = session.scalar(select(func.min(Job.requested_by)).where(*predicates))
    if requester is None:
        return None
    job_id = session.scalar(select(Job.id).where(*predicates, Job.requested_by == requester)
                            .order_by(Job.created_at, Job.id).limit(1))
    return Candidate(job_id, requester, cursor.revision) if job_id is not None else None
