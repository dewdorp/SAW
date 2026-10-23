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


class Fields(StrictIn):
    question: Short
    reason: Text
    needed_data: list[Short] = Field(default_factory=list, max_length=50)
    items: list[Short] = Field(default_factory=list, max_length=50)
    priority: Priority = "normal"
    owner: Owner = Field(default_factory=Owner)
    due_at: datetime | None = None

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


class VerifyIn(ActionIn):
    outcome: Literal["confirmed", "not_confirmed", "insufficient_data"]
    basis: Text
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=200)
