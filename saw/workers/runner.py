"""Job runner port. InProcessRunner (local, verified) / CeleryRunner (ENV-05).

Task functions are registered by name and must be idempotent (docs/10 §1).
"""
from __future__ import annotations

import logging
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Protocol

log = logging.getLogger("saw.jobs")

TASKS: dict[str, Callable[..., Any]] = {}


def task(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        TASKS[name] = fn
        return fn

    return deco


class JobRunnerPort(Protocol):
    def submit(self, name: str, **kwargs: Any) -> None: ...


class InProcessRunner:
    def __init__(self, workers: int = 2, synchronous: bool = False):
        self.synchronous = synchronous
        self.pool = None if synchronous else ThreadPoolExecutor(max_workers=workers, thread_name_prefix="saw-job")
        self.futures: list[Future] = []

    def submit(self, name: str, **kwargs: Any) -> None:
        fn = TASKS[name]
        if self.synchronous:
            fn(**kwargs)
            return

        def run() -> None:
            try:
                fn(**kwargs)
            except Exception:  # task functions record failures themselves; this is a last resort
                log.error("task %s crashed: %s", name, traceback.format_exc())

        self.futures.append(self.pool.submit(run))  # type: ignore[union-attr]

    def wait_all(self, timeout: float | None = None) -> None:
        for f in list(self.futures):
            f.result(timeout=timeout)


class CeleryRunner:  # pragma: no cover - ENV-05
    QUEUE_BY_TASK = {"ingest": "q.ingest", "parse": "q.parse", "pcap": "q.pcap", "analyze": "q.analyze"}

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
