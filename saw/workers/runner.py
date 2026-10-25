"""Job runner port. InProcessRunner (local, verified) / CeleryRunner (ENV-05).

Task functions are registered by name and must be idempotent (docs/10 §1).
"""
from __future__ import annotations

import contextvars
import inspect
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from functools import wraps
from typing import Any, ClassVar, Literal, Protocol

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from saw.storage.models import Job
from saw.workers import durable_queue as queue
from saw.workers.queue_models import QueueCursor

log = logging.getLogger("saw.jobs")

TASKS: dict[str, Callable[..., Any]] = {}


def task(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(fn)
        @wraps(fn)
        def bound_task(*args, **kwargs):
            if "job_id" not in signature.parameters:
                return fn(*args, **kwargs)
            from saw.event_generations.reads import task_read_scope
            job_id = signature.bind(*args, **kwargs).arguments.get("job_id")
            with task_read_scope(job_id):
                return fn(*args, **kwargs)
        TASKS[name] = bound_task
        return bound_task

    return deco


class JobRunnerPort(Protocol):
    def submit(self, name: str, **kwargs: Any) -> None: ...


class PrepareJob(Protocol):
    def __call__(self, session: Session, job: Job, *, recovering: bool) -> str | None: ...


@dataclass(frozen=True)
class RunnerStatus:
    state: Literal["new", "running", "stopping", "closed", "failed"]
    fatal_code: str | None
    active_count: int


class RunnerError(RuntimeError):
    """Safe queue failure: contains only an allowlisted diagnostic code."""


_WORKER: contextvars.ContextVar[object | None] = contextvars.ContextVar("saw_runner_worker", default=None)
_FATAL_CODES = frozenset({"startup_recovery_failed", "sql_refill_failed", "prepare_contract_failed",
                          "executor_submit_failed", "task_unhandled_error", "task_incomplete_return"})


def _deleted(session: Session, job: Job) -> bool:
    return job in session.deleted or sa_inspect(job).deleted


class InProcessRunner:
    def __init__(self, workers: int = 1, synchronous: bool = False, *,
                 session_factory: sessionmaker[Session] | None = None,
                 context_factory: Callable[[], AbstractContextManager[None]] | None = None,
                 prepare_job: PrepareJob | None = None, poll_interval: float = 0.5,
                 recovery_batch_size: int = 64):
        if workers < 1 or poll_interval <= 0 or recovery_batch_size < 1:
            raise ValueError("invalid runner limits")
        if not synchronous and (not isinstance(session_factory, sessionmaker)
                                or context_factory is None or prepare_job is None):
            raise ValueError("async runner requires captured session, context and preparation dependencies")
        self.synchronous = synchronous
        self.workers = workers
        self.session_factory = session_factory
        self.context_factory = context_factory or nullcontext
        self.prepare_job = prepare_job
        self.poll_interval = poll_interval
        self.recovery_batch_size = recovery_batch_size
        self.pool: ThreadPoolExecutor | None = None
        self.futures: set[Future] = set()
        self._active_ids: set[str] = set()
        self._condition = threading.Condition()
        self._lifecycle = threading.Lock()
        self._wake = threading.Event()
        self._dispatcher: threading.Thread | None = None
        self._tasks: dict[str, Callable[..., Any]] = {}
        self._status = RunnerStatus("new", None, 0)
        self._requested_scan = 0
        self._empty_scan = -1

    def status(self) -> RunnerStatus:
        # Publishing one immutable object keeps this snapshot constant-size and I/O-free.
        return self._status

    def _publish(self, state=None, fatal_code=None) -> None:
        previous = self._status
        self._status = RunnerStatus(state or previous.state, previous.fatal_code or fatal_code,
                                    len(self._active_ids))
        self._condition.notify_all()

    def _fatal(self, code: str) -> None:
        assert code in _FATAL_CODES
        with self._condition:
            self._publish("failed", code)
        self._wake.set()

    def _raise_failure(self) -> None:
        if self._status.fatal_code:
            raise RunnerError(self._status.fatal_code) from None

    def _in_context(self, fn, *args, **kwargs):
        def invoke():
            with self.context_factory():
                return fn(*args, **kwargs)
        return contextvars.Context().run(invoke)

    def _prepare(self, session: Session, job: Job, *, recovering: bool) -> str | None:
        try:
            route = self._in_context(self.prepare_job, session, job, recovering=recovering)
        except SQLAlchemyError:
            raise
        except Exception:  # noqa: BLE001 - convert arbitrary captured callbacks to one safe failure
            raise queue.PrepareContractError("preparation failed") from None
        if route is None:
            if not _deleted(session, job) and queue.is_due(job):
                raise queue.PrepareContractError("eligible job left without a route")
            return None
        queue.validate_route(job, route)
        if route not in self._tasks:
            raise queue.PrepareContractError("durable task is not registered")
        if _deleted(session, job) or not queue.is_due(job):
            raise queue.PrepareContractError("preparation returned an ineligible job")
        job.stages = {**(job.stages or {}), "_queue_task": route}
        return route

    def _recover(self) -> None:
        last_id = None
        while True:
            with self.session_factory.begin() as session:
                statement = select(Job).where(Job.kind.in_(queue.KNOWN_KINDS),
                                              Job.state.in_(queue.RECOVERABLE_STATES))
                if last_id is not None:
                    statement = statement.where(Job.id > last_id)
                jobs = list(session.scalars(statement.order_by(Job.id).limit(min(64, self.recovery_batch_size))))
                if not jobs:
                    return
                for job in jobs:
                    self._prepare(session, job, recovering=True)
                last_id = jobs[-1].id

    def start(self) -> None:
        with self._lifecycle:
            with self._condition:
                if self._status.state == "running":
                    return
                if self._status.state != "new":
                    self._raise_failure()
                    raise RuntimeError("runner cannot restart after close")
            self._tasks = dict(TASKS)
            if not self.synchronous:
                try:
                    for fn in self._tasks.values():
                        inspect.signature(fn).bind(job_id="synthetic")
                    self._recover()
                except Exception:
                    log.exception("queue startup recovery failed")
                    self._fatal("startup_recovery_failed")
                    self._raise_failure()
                self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="saw-job")
            with self._condition:
                self._publish("running")
            if not self.synchronous:
                self._dispatcher = threading.Thread(target=self._dispatch, name="saw-dispatch", daemon=True)
                self._dispatcher.start()

    def submit(self, name: str, **kwargs: Any) -> None:
        registry = self._tasks if self._status.state != "new" else TASKS
        fn = registry[name]
        if not self.synchronous and (set(kwargs) != {"job_id"} or not isinstance(kwargs["job_id"], str)):
            raise ValueError("async submit requires exactly job_id: str")
        with self._condition:
            self._raise_failure()
            if self._status.state in {"stopping", "closed"}:
                raise RuntimeError("runner is closed")
            if not self.synchronous and self._status.state != "running":
                raise RuntimeError("runner has not started")
        if self.synchronous:
            self._in_context(fn, **kwargs)
            return
        self._wake.set()

    def _cancel_queued(self) -> None:
        with self._condition:
            active = tuple(self._active_ids)
        with self.session_factory.begin() as session:
            jobs = list(session.scalars(select(Job).where(
                Job.kind.in_(queue.KNOWN_KINDS), Job.state == "QUEUED", Job.cancel_requested.is_(True),
                Job.id.not_in(active)).order_by(Job.id).limit(self.recovery_batch_size)))
            for job in jobs:
                self._prepare(session, job, recovering=False)
                if not _deleted(session, job) and job.state == "QUEUED" and job.cancel_requested:
                    raise queue.PrepareContractError("queued cancellation was not cleaned up")

    def _refill(self) -> bool:
        self._cancel_queued()
        for _ in range(self.recovery_batch_size):
            with self._condition:
                if self._status.state != "running" or len(self._active_ids) >= self.workers:
                    return False
                active = tuple(self._active_ids)
            with self.session_factory() as session:
                candidate = queue.choose_candidate(session, active)
            if candidate is None:
                return True
            route = None
            with self.session_factory.begin() as session:
                # Domain preparation establishes source/investigation fencing before Job locks.
                job = session.get(Job, candidate.job_id)
                if job is None or job.requested_by != candidate.requester:
                    continue
                if job.cancel_requested and job.state == "QUEUED":
                    self._prepare(session, job, recovering=False)
                    if not _deleted(session, job) and job.state == "QUEUED" and job.cancel_requested:
                        raise queue.PrepareContractError("queued cancellation was not cleaned up")
                    continue
                if not queue.is_due(job):
                    continue
                route = self._prepare(session, job, recovering=False)
                session.flush()
                if route is None:
                    continue
                advanced = session.execute(update(QueueCursor).where(
                    QueueCursor.id == "heavy", QueueCursor.revision == candidate.revision).values(
                        last_requester=job.requested_by, revision=candidate.revision + 1)).rowcount
                if advanced != 1:
                    session.rollback()
                    return False
            # The SQL transaction is released before handing work to the executor.
            with self._condition:
                if self._status.state != "running":
                    return False
                self._active_ids.add(candidate.job_id)
                self._publish()
                try:
                    future = self.pool.submit(self._execute, route, candidate.job_id)
                except Exception:
                    self._active_ids.discard(candidate.job_id)
                    self._fatal("executor_submit_failed")
                    log.exception("queue executor admission failed")
                    return False
                self.futures.add(future)
                future.add_done_callback(lambda done, job_id=candidate.job_id: self._done(job_id, done))
        return False

    def _dispatch(self) -> None:
        try:
            while self._status.state == "running":
                # A notification arriving during refill remains set for the next pass.
                self._wake.clear()
                with self._condition:
                    requested_scan = self._requested_scan
                try:
                    empty = self._refill()
                except queue.PrepareContractError:
                    self._fatal("prepare_contract_failed")
                    log.exception("queue preparation contract failed")
                    break
                except Exception:
                    self._fatal("sql_refill_failed")
                    log.exception("queue SQL refill failed")
                    break
                with self._condition:
                    if empty and not self._active_ids:
                        self._empty_scan = requested_scan
                    self._condition.notify_all()
                if self._status.state == "running":
                    self._wake.wait(self.poll_interval)
        finally:
            with self._condition:
                if self._status.state == "stopping" and not self._active_ids:
                    self._publish("closed")

    def _execute(self, name: str, job_id: str) -> None:
        def run():
            token = _WORKER.set(self)
            try:
                self._tasks[name](job_id=job_id)
                with self.session_factory() as session:
                    job = session.get(Job, job_id)
                    if job is not None and job.state not in queue.QUIESCENT_STATES:
                        self._fatal("task_incomplete_return")
            except BaseException:
                self._fatal("task_unhandled_error")
                log.exception("queue task escaped its failure handler")
            finally:
                _WORKER.reset(token)
        self._in_context(run)

    def _done(self, job_id: str, future: Future) -> None:
        with self._condition:
            self.futures.discard(future)
            self._active_ids.discard(job_id)
            # context_factory failures happen outside the inner task wrapper.
            if future.exception() is not None:
                self._fatal("task_unhandled_error")
            state = self._status.state
            self._publish("closed" if state == "stopping" and not self._active_ids else state)
        self._wake.set()

    def wait_all(self, timeout: float | None = None) -> None:
        if _WORKER.get() is self:
            raise RuntimeError("a runner worker cannot wait for its own slot")
        if self.synchronous:
            return
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._condition:
            self._raise_failure()
            if self._status.state != "running":
                raise RuntimeError("runner is not running")
            self._requested_scan += 1
            target = self._requested_scan
            self._wake.set()
            while True:
                self._raise_failure()
                if not self._active_ids and self._empty_scan >= target:
                    return
                if self._status.state != "running":
                    raise RuntimeError("runner stopped while waiting")
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("runner wait timed out")
                self._condition.wait(remaining)

    def close(self, *, wait: bool = True) -> None:
        if wait and _WORKER.get() is self:
            raise RuntimeError("a runner worker cannot join its own slot")
        with self._lifecycle:
            with self._condition:
                if self._status.state != "closed":
                    self._publish("stopping")
            self._wake.set()
            dispatcher, pool = self._dispatcher, self.pool
        if dispatcher is not None and dispatcher is not threading.current_thread():
            dispatcher.join()
        if pool is not None:
            pool.shutdown(wait=wait)
        with self._condition:
            if not self._active_ids:
                self._publish("closed")

    def shutdown(self, *, wait: bool = True) -> None:
        self.close(wait=wait)


class CeleryRunner:  # pragma: no cover - ENV-05
    QUEUE_BY_TASK: ClassVar[dict[str, str]] = {
        "ingest": "q.ingest", "parse": "q.parse", "pcap": "q.pcap", "analyze": "q.analyze"}

    def __init__(self, broker_url: str):
        from celery import Celery

        self.app = Celery("saw", broker=broker_url, backend=broker_url)
        self.app.conf.update(task_acks_late=True, worker_prefetch_multiplier=1,
                             task_reject_on_worker_lost=True, task_serializer="json",
                             accept_content=["json"], broker_transport_options={"visibility_timeout": 6 * 3600})
        for name, fn in TASKS.items():
            self.app.task(name=name)(fn)

    def submit(self, name: str, **kwargs: Any) -> None:
        queue = self.QUEUE_BY_TASK.get(name.split(".")[0], "q.analyze")
        self.app.send_task(name, kwargs=kwargs, queue=queue)
