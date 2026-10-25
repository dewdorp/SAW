"""Composition root: builds adapters from settings (local fallbacks by default)."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saw.config import Settings, get_settings
from saw.storage.db import get_sessionmaker, init_db
from saw.storage.eventstore import EventStorePort, SQLiteEventStore
from saw.storage.objectstore import LocalFSObjectStore, ObjectStorePort
from saw.workers.runner import InProcessRunner, JobRunnerPort


@dataclass
class Container:
    settings: Settings
    events: EventStorePort
    objects: ObjectStorePort
    runner: JobRunnerPort
    session_factory: sessionmaker[Session] | None = None
    generations: object = None
    legacy_events: EventStorePort | None = None
    _engine: Engine | None = field(default=None, repr=False)
    _owned_clients: tuple[object, ...] = field(default=(), repr=False)
    _closed: bool = field(default=False, init=False, repr=False)


_container: Container | None = None
_active: ContextVar[Container | None] = ContextVar("saw_container", default=None)


def build(settings: Settings | None = None, synchronous_jobs: bool = False) -> Container:
    global _container
    s = settings or get_settings()
    previous = _container
    if previous is not None:
        # Changing defaults is not shutdown: captured apps still serve reads.
        _drain(previous.runner)
        if previous._engine is not None:
            previous._engine.dispose()
    engine = init_db(s.database_url, s.schema_mode)
    clients: list[object] = []
    runner: JobRunnerPort | None = None

    def own(client: object) -> None:
        if client is not None and callable(getattr(client, "close", None)) and not any(
                client is existing for existing in clients):
            clients.append(client)

    try:
        factory = get_sessionmaker()
        if s.event_store == "opensearch":  # ADR-0016 / ENV-03
            from saw.storage.opensearch_store import OpenSearchEventStore

            auth = (s.opensearch_user, s.opensearch_password) if s.opensearch_user else None
            events: EventStorePort = OpenSearchEventStore(
                s.opensearch_url, ensure=False, prefix=s.opensearch_index_prefix, durability=s.opensearch_durability, http_auth=auth,
                verify_certs=s.opensearch_verify_certs, ca_certs=s.opensearch_ca_certs or None)
            own(events.client)
            events._wait_ready()
            events.ensure_template()
        else:
            events = SQLiteEventStore(s.event_store_path)
            own(getattr(events, "_anchor", None))
        if s.object_store == "s3":  # ENV-04
            from saw.storage.objectstore import S3ObjectStore

            objects: ObjectStorePort = S3ObjectStore(s.s3_endpoint, s.s3_access_key, s.s3_secret_key,
                                                     s.data_dir / "scratch")
            own(objects.s3)
        else:
            objects = LocalFSObjectStore(s.object_store_root)
        from saw.analysis_runs import scoped  # noqa: F401
        from saw.knowledge import golden_jobs  # noqa: F401
        from saw.reports import export_jobs  # noqa: F401

        # Register before the runner takes its immutable task snapshot.
        from saw.workers import tasks  # noqa: F401
        from saw.workers.preparation import prepare_job

        if s.job_runner == "celery":  # ENV-05
            from saw.workers.runner import CeleryRunner

            runner = CeleryRunner(s.broker_url)
            own(runner.app)
        else:
            runner = InProcessRunner(workers=max(1, s.job_workers), synchronous=synchronous_jobs,
                                     session_factory=factory,
                                     context_factory=lambda: activate(captured, factory),
                                     prepare_job=prepare_job)
        from saw.event_generations.reads import EventFacade

        facade = EventFacade(events, objects=objects, session_factory=factory, settings=s)
        captured = Container(s, facade, objects, runner, factory, facade.generations, events,
                             _engine=engine, _owned_clients=tuple(clients))
        _container = captured

        from saw.parsers.library import active_parsers, parser_by_id
        from saw.parsers.registry import set_user_parser_provider

        set_user_parser_provider(active_parsers, parser_by_id)  # analyst-defined parsers join detection and get_parser
        if isinstance(runner, InProcessRunner):
            runner.start()
        return captured
    except BaseException:
        _container = previous
        _drain(runner)
        _dispose(engine, clients)
        raise


def _drain(runner: JobRunnerPort | None) -> None:
    stop = getattr(runner, "close", None)
    if stop is not None:
        stop(wait=True)


def _dispose(engine: Engine | None, clients: tuple[object, ...] | list[object]) -> None:
    # ExitStack attempts every owned close even if one client raises.
    with ExitStack() as cleanup:
        if engine is not None:
            cleanup.callback(engine.dispose)
        seen: set[int] = set()
        for client in clients:
            if id(client) not in seen:
                seen.add(id(client))
                cleanup.callback(client.close)


def close(captured: Container) -> None:
    """Final app shutdown; drain before releasing only this app's owned resources."""
    if captured._closed:
        return
    _drain(captured.runner)
    captured._closed = True
    _dispose(captured._engine, captured._owned_clients)


@contextmanager
def activate(captured: Container, session_factory: sessionmaker[Session]) -> Iterator[None]:
    """Keep nested tasks on their owning app even if process defaults change."""
    from saw.storage.db import bind_sessionmaker

    if captured is None:
        raise ValueError("captured container is required")
    token = _active.set(captured)
    try:
        with bind_sessionmaker(session_factory):
            yield
    finally:
        _active.reset(token)


def get() -> Container:
    captured = _active.get()
    if captured is not None:
        return captured
    if _container is None:
        return build()
    return _container
