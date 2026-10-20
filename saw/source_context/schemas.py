"""Validated, conservative source semantics used by upload and normalization."""
from __future__ import annotations

from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OrgUnitInput(StrictModel):
    display_name: str = Field(min_length=1, max_length=64)


class DeviceInput(StrictModel):
    display_name: str = Field(min_length=1, max_length=128)


class MeasurementProfile(StrictModel):
    counter_semantics: Literal["cumulative", "delta", "total", "unknown"] = "unknown"
    direction: Literal["src_to_dst", "dst_to_src", "unknown"] = "unknown"
    unit: Literal["bytes", "packets", "unknown"] = "unknown"
    duration_unit: Literal["seconds", "milliseconds", "unknown"] = "unknown"
    verified: bool = False
    basis: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def verified_semantics(self):
        if self.verified and ("unknown" in (self.counter_semantics, self.direction, self.unit) or not self.basis):
            raise ValueError("verified measurement requires known semantics, direction, unit and basis")
        return self


class TimeProfile(StrictModel):
    role: Literal["occurred", "start", "end", "collected", "unknown"] = "unknown"
    timezone: str | None = Field(default=None, max_length=64)
    precision: str = Field(default="unknown", max_length=64)
    verified: bool = False
    basis: str = Field(default="", max_length=1000)

    @field_validator("timezone")
    @classmethod
    def timezone_name(cls, value):
        if value is not None:
            try:
                ZoneInfo(value)
            except (ZoneInfoNotFoundError, ValueError) as exc:
                raise ValueError("unknown timezone") from exc
        return value

    @model_validator(mode="after")
    def verified_time(self):
        if self.verified and (self.role == "unknown" or not self.timezone or self.precision in {"", "unknown"} or not self.basis):
            raise ValueError("verified time requires role, timezone, precision and basis")
        return self


Action = Literal["allowed", "blocked", "reset", "detected", "challenged", "unknown", "conflicting"]


class DeviceSemantics(StrictModel):
    verified: bool = False
    basis: str = Field(default="", max_length=1000)
    record_kind: Literal["request", "rule_hit", "alert", "interval_summary", "flow", "dns", "http", "tls", "unknown"] = "unknown"
    mode: Literal["inline", "mirror", "unknown"] = "unknown"
    packet_available: bool | None = None
    response_location: Literal["edge", "origin", "unknown"] = "unknown"
    trusted_forwarded: bool = False
    forwarded_basis: str = Field(default="", max_length=1000)
    rate_unit: Literal["bps", "pps", "rps", "unknown"] = "unknown"
    rate_statistic: Literal["mean", "peak", "unknown"] = "unknown"
    sampling_ratio: float | None = Field(default=None, gt=0, le=1, allow_inf_nan=False)
    sampling_version: str = Field(default="unknown", max_length=128)
    bidirectional: bool | None = None
    capture_kind: Literal["flows", "alerts_only", "pcap", "mixed", "unknown"] = "unknown"

    @model_validator(mode="after")
    def verify_source(self):
        if self.verified and not self.basis:
            raise ValueError("verified device semantics require a source basis")
        if self.trusted_forwarded and (not self.verified or not self.forwarded_basis):
            raise ValueError("trusted forwarding requires verified source and basis")
        return self


class DeviceProfileInput(StrictModel):
    owner_org_unit_id: str | None = Field(default=None, max_length=36)
    operator_org_unit_id: str | None = Field(default=None, max_length=36)
    vendor: str = Field(default="", max_length=128)
    product: str = Field(default="", max_length=128)
    product_version: str = Field(default="", max_length=128)
    functions: list[Literal["FW", "WAF", "IPS", "DDoS", "NDR"]] = Field(default_factory=list, max_length=5)
    network: str = Field(default="", max_length=128)
    virtual_domain: str = Field(default="", max_length=128)
    observation_point: str = Field(default="", max_length=256)
    collection_path: str = Field(default="", max_length=256)
    source_fields: dict[str, str] = Field(default_factory=dict, max_length=64)
    record_kind_map: dict[str, Literal["session_start", "session_interim", "session_end", "request", "rule_hit", "alert",
                                  "interval_summary", "flow", "dns", "http", "tls", "unknown"]] = Field(default_factory=dict, max_length=128)
    action_map: dict[str, Action] = Field(default_factory=dict, max_length=128)
    action_verified: bool = False
    action_basis: str = Field(default="", max_length=1000)
    measurement_profile: MeasurementProfile = Field(default_factory=MeasurementProfile)
    time: TimeProfile = Field(default_factory=TimeProfile)
    device_semantics: DeviceSemantics = Field(default_factory=DeviceSemantics)

    @field_validator("source_fields", "action_map", "record_kind_map")
    @classmethod
    def bounded_fields(cls, value):
        if any(not k or len(k) > 128 or not v or len(v) > 128 for k, v in value.items()):
            raise ValueError("mapping names and values must contain 1 to 128 characters")
        return value

    @field_validator("source_fields")
    @classmethod
    def supported_semantics(cls, value):
        supported = {"org_unit_id", "device_id", "device_profile_version_id", "network", "virtual_domain",
                     "timestamp", "start_time", "end_time", "collected_time", "record_kind", "session_id",
                     "action", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "duration",
                     "request_id", "signature_id", "origin_status", "edge_status", "mode", "forwarded_ip",
                     "interval_start", "interval_end", "rate", "target", "attack_type", "mitigation",
                     "sampling_ratio", "tls_version", "domain", "http_status", "uri", "user_agent", "severity"}
        if set(value) - supported:
            raise ValueError("unsupported source semantics")
        return value

    @model_validator(mode="after")
    def verified_fields(self):
        if self.action_verified and (not self.action_basis or not self.source_fields.get("action") or not self.action_map
                                     or any(v in {"unknown", "conflicting"} for v in self.action_map.values())):
            raise ValueError("verified actions require explicit source field, known mapping and basis")
        if self.measurement_profile.verified and not any(k in self.source_fields for k in ("src_bytes", "dst_bytes", "src_packets", "dst_packets")):
            raise ValueError("verified measurements require explicit source counter fields")
        if self.time.verified and not any(k in self.source_fields for k in ("timestamp", "start_time", "end_time", "collected_time")):
            raise ValueError("verified time requires explicit source time field")
        return self


class SubjectInput(StrictModel):
    org_unit_id: str | None = Field(default=None, max_length=36)
    status: Literal["verified", "unknown", "conflicting"] = "unknown"
    basis: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def verified_subject(self):
        if self.status == "verified" and (not self.org_unit_id or not self.basis):
            raise ValueError("verified subject requires an organization and evidence basis")
        return self


class CollectionInput(StrictModel):
    scope: Literal["full", "alerts_only", "blocked_only", "sampled", "filtered", "unknown"] = "unknown"
    filter: str = Field(default="", max_length=1000)
    loss: Literal["known", "unknown"] = "unknown"


class ContextInput(StrictModel):
    device_profile_version_id: str | None = Field(default=None, max_length=36)
    subject: SubjectInput = Field(default_factory=SubjectInput)
    collection: CollectionInput = Field(default_factory=CollectionInput)