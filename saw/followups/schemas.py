"""Strict user-action contracts; absence and explicit null retain different meanings."""
from __future__ import annotations
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Text = Annotated[str, Field(min_length=1, max_length=8000)]
Short = Annotated[str, Field(min_length=1, max_length=1000)]
Ident = Annotated[str, Field(min_length=1, max_length=64)]
Priority = Literal["low", "normal", "high", "urgent"]


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Owner(StrictIn):
    org_unit_id: Ident | None = None
    department: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    user_id: Ident | None = None


Address = Annotated[str, Field(min_length=1, max_length=64)]


def _aware(value):
    if value is not None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("시각에는 시간대를 포함하세요.")
        value = value.astimezone(UTC)
    return value


class Target(StrictIn):
    """Who and what the question is about; a reply is compared with exactly this."""
    org_unit_id: Ident | None = None
    src_ips: list[Address] = Field(default_factory=list, max_length=50)
    dst_ips: list[Address] = Field(default_factory=list, max_length=50)
    dst_ports: list[Annotated[int, Field(ge=0, le=65535)]] = Field(default_factory=list, max_length=50)
    behavior: Annotated[str, Field(min_length=1, max_length=1000)] | None = None


class Period(StrictIn):
    start: datetime
    end: datetime

    @field_validator("start")
    @classmethod
    def aware_start(cls, value):
        return _aware(value)

    @field_validator("end")
    @classmethod
    def aware_ordered_end(cls, value, info):
        value = _aware(value)
        start = info.data.get("start")
        if start is not None and value < start:
            raise ValueError("기간의 끝이 시작보다 앞섭니다.")
        return value


class ReplyScope(StrictIn):
    """What the reply itself says it covers (from the work record or the answer)."""
    org_unit_id: Ident | None = None
    src_ips: list[Address] = Field(default_factory=list, max_length=50)
    dst_ips: list[Address] = Field(default_factory=list, max_length=50)
    dst_ports: list[Annotated[int, Field(ge=0, le=65535)]] = Field(default_factory=list, max_length=50)
    start: datetime | None = None
    end: datetime | None = None

    @field_validator("start", "end")
    @classmethod
    def aware_bounds(cls, value):
        return _aware(value)


class Fields(StrictIn):
    question: Short
    reason: Text
    needed_data: list[Short] = Field(default_factory=list, max_length=50)
    items: list[Short] = Field(default_factory=list, max_length=50)
    priority: Priority = "normal"
    owner: Owner = Field(default_factory=Owner)
    due_at: datetime | None = None
    target: Target | None = None
    period: Period | None = None

    @field_validator("due_at")
    @classmethod
    def aware_due(cls, value):
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("기한에는 시간대를 포함하세요.")
            value = value.astimezone(UTC)
        return value


class CreateIn(Fields):
    check_id: Ident
    check_revision_id: Ident | None = None
    origin_kind: Literal["analyst", "legacy_check_followup"] = "analyst"


class PatchFields(StrictIn):
    question: Short | None = None
    reason: Text | None = None
    needed_data: list[Short] | None = Field(default=None, max_length=50)
    items: list[Short] | None = Field(default=None, max_length=50)
    priority: Priority | None = None
    owner: Owner | None = None
    due_at: datetime | None = None
    target: Target | None = None
    period: Period | None = None

    @field_validator("question", "reason", "needed_data", "items", "priority", "owner")
    @classmethod
    def not_null(cls, value):
        if value is None:
            raise ValueError("이 항목은 null로 지울 수 없습니다.")
        return value

    _due = field_validator("due_at")(Fields.aware_due.__func__)


class PatchIn(StrictIn):
    expected_version_id: Ident
    patch: PatchFields


class ActionIn(StrictIn):
    expected_version_id: Ident
    reason: Text


class EvidenceRef(StrictIn):
    investigation_id: Ident
    event_id: Ident


class ReplyIn(ActionIn):
    note: Text
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=200)
    scope: ReplyScope | None = None


class VerifyIn(ActionIn):
    outcome: Literal["confirmed", "not_confirmed", "insufficient_data"]
    basis: Text
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=200)
