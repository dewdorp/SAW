"""Strict, bounded Golden governance wire requests."""
from __future__ import annotations
from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128)]
Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Reason = Annotated[str, Field(min_length=1, max_length=2000)]
Split = Literal["train", "dev", "holdout"]


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Ref(StrictIn):
    id: Identifier
    sha256: Sha256


class PrepareIn(StrictIn):
    expected_experience_rev: Annotated[StrictInt, Field(ge=1)]
    schema_version: Literal["saw.golden.v1", "saw.golden.v2"] | None = None
    check_ids: list[Identifier] | None = Field(default=None, max_length=100)
    check_revision_ids: list[Identifier] | None = Field(default=None, max_length=100)
    analysis_run_id: Identifier | None = None
    truth_case_version_ids: list[Identifier] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def selectors(self):
        if self.check_ids is not None and self.check_revision_ids is not None:
            raise ValueError("golden_check_selectors_mutually_exclusive")
        for rows in (self.check_ids, self.check_revision_ids, self.truth_case_version_ids):
            if rows is not None and len(set(rows)) != len(rows):
                raise ValueError("golden_duplicate_selection")
        if self.schema_version != "saw.golden.v2" and (
                self.check_revision_ids is not None or self.analysis_run_id or self.truth_case_version_ids):
            raise ValueError("golden_v2_required")
        return self


class ProfileIn(StrictIn):
    kind: Literal["pseudonymization", "model_conversion"]
    profile_key: Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,99}$")]
    expected_latest_id: Identifier | None
    implementation: Annotated[str, Field(min_length=1, max_length=100)]
    payload: dict


class ExampleRef(StrictIn):
    version_id: Identifier
    content_sha256: Sha256 | None = None
    input_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def one_digest(self):
        if (self.content_sha256 is None) == (self.input_sha256 is None):
            raise ValueError("golden_exact_selection_digest_required")
        return self


class Recipient(StrictIn):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    organization: Annotated[str, Field(min_length=1, max_length=200)]


class Redistribution(StrictIn):
    confirmed: StrictBool
    basis: Reason


class CompleteScope(StrictIn):
    golden_version_id: Identifier
    analysis_run_id: Identifier
    scope_sha256: Sha256


class ApplicabilityRequest(StrictIn):
    mode: Literal["interpretation_only", "full_recalculation"]
    complete_scopes: list[CompleteScope] = Field(max_length=100)


class ReleaseRequest(StrictIn):
    schema_version: Literal["saw.golden.release.v2"]
    expected_current_version_id: Identifier | None
    idempotency_key: Identifier
    purpose: Literal["external_training", "external_development", "external_evaluation"]
    purpose_text: Annotated[str, Field(min_length=1, max_length=1000)]
    recipient: Recipient
    usage_conditions: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(min_length=1, max_length=20)
    expires_at: datetime
    examples: list[ExampleRef] = Field(min_length=1, max_length=100)
    split: Split
    artifact_kind: Literal["train", "dev", "holdout_input"]
    projection: Literal["v1", "v2"]
    pseudonymization_profile: Ref
    model_conversion_profile: Ref
    redistribution: Redistribution
    applicability_request: ApplicabilityRequest

    @model_validator(mode="after")
    def consistent(self):
        if self.expires_at.tzinfo is None:
            raise ValueError("golden_expiry_timezone_required")
        ids = [e.version_id for e in self.examples]
        if len(set(ids)) != len(ids):
            raise ValueError("golden_duplicate_selection")
        purpose = {"train": "external_training", "dev": "external_development", "holdout": "external_evaluation"}[self.split]
        if self.purpose != purpose or self.artifact_kind != ("holdout_input" if self.split == "holdout" else self.split):
            raise ValueError("golden_release_purpose_split_mismatch")
        if any((e.input_sha256 is not None) != (self.split == "holdout") for e in self.examples):
            raise ValueError("golden_selection_digest_kind_mismatch")
        if not self.redistribution.confirmed:
            raise ValueError("golden_redistribution_confirmation_required")
        scopes = [x.golden_version_id for x in self.applicability_request.complete_scopes]
        full = self.applicability_request.mode == "full_recalculation"
        if (full and (self.projection != "v2" or sorted(scopes) != sorted(ids))) or (not full and scopes):
            raise ValueError("golden_complete_scope_selection_mismatch")
        return self


class ApprovalConfirmations(StrictIn):
    preview_reviewed: StrictBool = False
    redistribution_rights: StrictBool = False
    recipient_and_purpose: StrictBool = False
    limits_accepted: StrictBool = False


class ApprovalIn(StrictIn):
    expected_current_version_id: Identifier
    expected_payload_sha256: Sha256
    expected_artifact_sha256: Sha256
    expected_decision_id: Identifier | None
    decision: Literal["approve", "decline"]
    reason: Reason
    confirmations: ApprovalConfirmations


class RevokeIn(StrictIn):
    expected_decision_id: Identifier
    reason: Reason


class Target(StrictIn):
    kind: Literal["model", "detector", "application"]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    version: Annotated[str, Field(min_length=1, max_length=200)]
    artifact_sha256: Sha256


class AttemptIn(StrictIn):
    release_version_id: Identifier
    expected_artifact_sha256: Sha256
    target: Target
    purpose_text: Annotated[str, Field(min_length=1, max_length=1000)]
    idempotency_key: Identifier


class ResultIn(StrictIn):
    expected_result_sha256: Sha256 | None
    artifact_sha256: Sha256
    summary: Annotated[str, Field(min_length=1, max_length=4000)]
