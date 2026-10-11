"""SecurityDataConnector abstraction (docs/01 FR-CONN, ADR-0012). Read-only by contract.

Connectors speak the SAW Query Model and return CES events, so the workbench/analyzers never see vendor syntax.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from saw.core.schemas.query import AggRequest, Filter, TimeRange


@dataclass
class Health:
    ok: bool
    detail: str
    latency_ms: float | None = None


class SecurityDataConnector(Protocol):
    id: str
    kind: str
    read_only: bool

    def search(self, filters: list[Filter], time: TimeRange | None = None, limit: int = 100,
               cursor: str | None = None) -> dict: ...
    def get_event(self, event_id: str) -> dict | None: ...
    def get_events(self, event_ids: list[str]) -> list[dict]: ...
    def aggregate(self, filters: list[Filter], agg: AggRequest, time: TimeRange | None = None) -> dict: ...
    def get_context(self, observable_type: str, value: str) -> dict: ...
    def health_check(self) -> Health: ...


class ConnectorNotImplemented(Exception):
    pass


class LogpressoConnector:  # pragma: no cover - ENV-11
    """Real Logpresso connector intentionally NOT implemented: no official API documentation available.

    Per ADR-0012 we do not invent vendor APIs. Implement once docs + a read-only test account are provided.
    """

    kind = "logpresso"
    read_only = True

    def __init__(self, cid: str, settings: dict[str, Any], secret: str | None):
        self.id = cid

    def _na(self, *_a, **_k):
        raise ConnectorNotImplemented("Logpresso connector requires the official API documentation (ENV-11)")

    search = get_event = get_events = aggregate = get_context = _na

    def health_check(self) -> Health:
        return Health(False, "not implemented: official Logpresso API documentation required (ENV-11)")
