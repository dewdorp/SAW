"""Composition root: builds adapters from settings (local fallbacks by default)."""
from __future__ import annotations

from dataclasses import dataclass

from saw.config import Settings, get_settings
from saw.storage.db import init_db
from saw.storage.eventstore import EventStorePort, SQLiteEventStore
from saw.storage.objectstore import LocalFSObjectStore, ObjectStorePort
from saw.workers.runner import InProcessRunner, JobRunnerPort


@dataclass
class Container:
    settings: Settings
    events: EventStorePort
    objects: ObjectStorePort
    runner: JobRunnerPort


_container: Container | None = None


def build(settings: Settings | None = None, synchronous_jobs: bool = False) -> Container:
    global _container
    s = settings or get_settings()
    init_db(s.database_url, s.schema_mode)
    if s.event_store == "opensearch":  # ADR-0016 / ENV-03
        from saw.storage.opensearch_store import OpenSearchEventStore

        auth = (s.opensearch_user, s.opensearch_password) if s.opensearch_user else None
        events: EventStorePort = OpenSearchEventStore(
            s.opensearch_url, prefix=s.opensearch_index_prefix, durability=s.opensearch_durability, http_auth=auth,
            verify_certs=s.opensearch_verify_certs, ca_certs=s.opensearch_ca_certs or None)
    else:
        events = SQLiteEventStore(s.event_store_path)
    if s.object_store == "s3":  # ENV-04
        from saw.storage.objectstore import S3ObjectStore

        objects: ObjectStorePort = S3ObjectStore(s.s3_endpoint, s.s3_access_key, s.s3_secret_key,
                                                 s.data_dir / "scratch")
    else:
        objects = LocalFSObjectStore(s.object_store_root)
    from saw.analysis_runs import scoped  # noqa: F401
    from saw.reports import export_jobs  # noqa: F401

    if s.job_runner == "celery":  # ENV-05
        from saw.workers.runner import CeleryRunner

        runner: JobRunnerPort = CeleryRunner(s.broker_url)
    else:
        runner = InProcessRunner(workers=max(1, s.job_workers), synchronous=synchronous_jobs)
    _container = Container(s, events, objects, runner)
    # register task implementations
    from saw.workers import tasks  # noqa: F401

    from saw.parsers.library import active_parsers, parser_by_id
    from saw.parsers.registry import set_user_parser_provider

    set_user_parser_provider(active_parsers, parser_by_id)  # analyst-defined parsers join detection and get_parser
    if isinstance(runner, InProcessRunner) and not synchronous_jobs:
        _recover_orphaned_jobs(runner)
    return _container


def _recover_orphaned_jobs(runner: InProcessRunner) -> None:
    """In-process jobs die with the process: re-queue them on startup (tasks are idempotent)."""
    from sqlalchemy import select

    from saw.storage.db import session_scope
    from saw.storage.models import Job

    with session_scope() as s:
        orphans = s.execute(select(Job).where(Job.state.in_(["QUEUED", "PARSING", "INDEXING", "ANALYZING"]))).scalars().all()
        todo = [(j.id, "report_export.run" if j.kind == "report_export" else
                 "device_analysis.run" if j.kind == "device_analysis" else
                 "behavior.run" if j.kind == "behavior" else
                 "analyze.run" if j.kind == "reanalyze" or j.state == "ANALYZING" else "ingest.run") for j in orphans]
        for j in orphans:
            j.current_item = "recovered after restart"
    for job_id, name in todo:
        runner.submit(name, job_id=job_id)


def get() -> Container:
    if _container is None:
        return build()
    return _container
