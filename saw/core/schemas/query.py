"""SAW Query Model (docs/08 §6, docs/30 §2): structured filters only, never raw query strings."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_serializer, model_validator

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
    end_exclusive: bool = False  # [start, end) — used for whole-day periods so no instant of the last day is lost

    @model_serializer(mode="wrap")
    def _omit_default_bound(self, handler):
        # Stored queries and their digests from before half-open ranges existed must stay byte-identical.
        data = handler(self)
        if isinstance(data, dict) and not data.get("end_exclusive"):
            data.pop("end_exclusive", None)
        return data


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
    type: Literal["count", "value_count", "cardinality", "min", "max", "sum", "avg", "min_ts", "max_ts"]
    field: str | None = None
    name: str
    filters: list[Filter] = Field(default_factory=list, max_length=30)
    preserve_timestamp: bool = False

    @field_validator("field")
    @classmethod
    def valid_field(cls, value):
        if value is not None and not FIELD_RE.fullmatch(value):
            raise ValueError("invalid metric field")
        return value

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value) or value in {"key", "count"}:
            raise ValueError("invalid metric name")
        return value

    @model_validator(mode="after")
    def require_field(self):
        if self.type not in {"count", "min_ts", "max_ts"} and not self.field:
            raise ValueError("metric field required")
        if self.preserve_timestamp and self.type not in {"min_ts", "max_ts"}:
            raise ValueError("source timestamp only supports timestamp bounds")
        return self


class GroupByRequest(BaseModel):
    filters: list[Filter] = Field(default_factory=list)
    time: TimeRange | None = None
    fields: list[str]
    metrics: list[GroupMetric] = Field(default_factory=list)
    size: int = Field(100, ge=1, le=10000)
    order_by: str | None = None

    @model_validator(mode="after")
    def valid_group(self):
        if not self.fields or any(not FIELD_RE.fullmatch(f) for f in self.fields):
            raise ValueError("invalid grouping fields")
        names = [m.name for m in self.metrics]
        if len(set(names)) != len(names):
            raise ValueError("duplicate metric names")
        if self.order_by not in (None, "count") and self.order_by not in names:
            raise ValueError("unknown group order")
        if any(m.name == self.order_by and m.type in {"min_ts", "max_ts"} for m in self.metrics):
            raise ValueError("timestamp bounds cannot order groups")
        return self
