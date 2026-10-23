"""Explicit, bounded selections for immutable report exports."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str = Field(min_length=1, max_length=36)
    analysis_run_id: str = Field(min_length=1, max_length=36)
    followup_version_ids: list[str] | None = Field(None, max_length=100)

    @model_validator(mode="after")
    def exact_versions(self):
        ids = self.followup_version_ids
        if ids is not None and (not ids or len(set(ids)) != len(ids) or
                                any(not x or len(x) > 36 for x in ids)):
            raise ValueError("report_followup_versions_must_be_nonempty_unique_ids")
        return self


class ReportScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["investigation", "selected_followups", "investigations"]
    selections: list[Selection] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def consistent(self):
        ids = [x.investigation_id for x in self.selections]
        if len(set(ids)) != len(ids):
            raise ValueError("report_duplicate_investigation")
        if self.kind != "investigations" and len(ids) != 1:
            raise ValueError("report_single_scope_requires_one_investigation")
        if self.kind == "selected_followups":
            if self.selections[0].followup_version_ids is None:
                raise ValueError("report_selected_followups_required")
        elif any(x.followup_version_ids is not None for x in self.selections):
            raise ValueError("report_followup_selection_requires_selected_scope")
        if sum(len(x.followup_version_ids or []) for x in self.selections) > 100:
            raise ValueError("report_followup_limit")
        return self


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: ReportScope
    format: Literal["html", "xlsx"]
    idempotency_key: str = Field(min_length=1, max_length=128)
