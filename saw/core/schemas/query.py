"""SAW Query Model (docs/08 §6, docs/30 §2): structured filters only, never raw query strings."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_\-]+){0,4}$")

Op = Literal["is", "is_not", "in", "not_in", "range", "exists", "not_exists", "prefix", "contains"]


class Filter(BaseModel):
    field: str
    op: Op = "is"
    value: Any = None

    @field_validator("field")
    @classmethod
    def _field_ok(cls, v: str) -> str:
        if not FIELD_RE.match(v):
            raise ValueError(f"invalid field name: {v!r}")
        return v


class TimeRange(BaseModel):
    start: str | None = None  # ISO8601
    end: str | None = None


class SearchRequest(BaseModel):
    filters: list[Filter] = Field(default_factory=list)
    time: TimeRange | None = None
    sort: Literal["asc", "desc"] = "asc"
    limit: int = Field(100, ge=1, le=500)
    cursor: str | None = None
    fields: list[str] | None = None


AggType = Literal["terms", "cardinality", "date_histogram", "stats", "count", "percentiles"]


class AggRequest(BaseModel):
    type: AggType
    field: str | None = None
    size: int = Field(10, ge=1, le=1000)
    interval_sec: int | None = Field(None, ge=1)
    percents: list[float] = Field(default_factory=lambda: [50.0, 95.0])

    @field_validator("field")
    @classmethod
    def _field_ok(cls, v: str | None) -> str | None:
        if v is not None and not FIELD_RE.match(v):
            raise ValueError(f"invalid field name: {v!r}")
        return v


class AggregateRequest(BaseModel):
    filters: list[Filter] = Field(default_factory=list)
    time: TimeRange | None = None
    agg: AggRequest


class GroupMetric(BaseModel):
    type: Literal["count", "cardinality", "min", "max", "sum", "avg", "min_ts", "max_ts"]
    field: str | None = None
    name: str


class GroupByRequest(BaseModel):
    filters: list[Filter] = Field(default_factory=list)
    time: TimeRange | None = None
    fields: list[str]
    metrics: list[GroupMetric] = Field(default_factory=list)
    size: int = Field(100, ge=1, le=10000)
