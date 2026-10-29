"""Meanings of device alert names / signature IDs, confirmed by analysts and versioned.

Lookup is exact: vendor + product + signature ID when the ID is known, otherwise the original name. A name that
is merely similar is never treated as registered, and the device's original wording is never replaced.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound, require
from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.core.security.authz import can
from saw.internal_kb.models import DeviceSignature, DeviceSignatureVersion
from saw.storage.db import utcnow

Line = Annotated[str, Field(max_length=4000)]
Short = Annotated[str, Field(max_length=512)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SignatureIn(Strict):
    vendor: Annotated[str, Field(max_length=128)] = ""
    product: Annotated[str, Field(max_length=128)] = ""
    original_name: Annotated[str, Field(min_length=1, max_length=512)]
    signature_id: Annotated[str, Field(max_length=128)] = ""
    rule_version: Short = ""
    valid_from: Short = ""
    valid_to: Short = ""
    status: Literal["confirmed", "needs_confirmation"] = "confirmed"
    meaning: Line = ""
    description: Line = ""
    example_logs: list[Line] = Field(default_factory=list, max_length=20)
    benign_cases: list[Line] = Field(default_factory=list, max_length=50)
    false_positive_cases: list[Line] = Field(default_factory=list, max_length=50)
    checks: list[Line] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def confirmed_has_meaning(self):
        if self.status == "confirmed" and not self.meaning:
            raise ValueError("확인한 의미를 적거나 상태를 '확인 필요'로 두세요.")
        return self


class UpdateIn(SignatureIn):
    expected_version: int


def match_key(vendor: str, product: str, signature_id: str, original_name: str) -> str:
    """Exact identity. Case and surrounding spaces of vendor/product are ignored; the alert name is not normalised."""
    v, pr = vendor.strip().casefold(), product.strip().casefold()
    if signature_id.strip():
        return f"id|{v}|{pr}|{signature_id.strip()}"
    return f"name|{v}|{pr}|{original_name.strip()}"


def _manage(p):
    if not can(p, "signature.manage"):
        raise Forbidden("signature.manage")


def _out(row: DeviceSignature) -> dict:
    return {"id": row.id, "vendor": row.vendor, "product": row.product, "original_name": row.original_name,
            "signature_id": row.signature_id, "status": row.status, "version": row.current_version,
            **{k: v for k, v in (row.content or {}).items() if k not in {"vendor", "product", "original_name",
                                                                           "signature_id", "status"}},
            "updated_at": row.updated_at}


def _version(s, row, body: SignatureIn, p):
    row.current_version += 1
    row.content = body.model_dump(exclude={"expected_version"})
    row.status, row.updated_by, row.updated_at = body.status, p.user_id, utcnow()
    s.add(DeviceSignatureVersion(signature_id_ref=row.id, version=row.current_version, content=row.content,
                                 changed_by=p.user_id))


def create(s, p, body: SignatureIn | dict) -> dict:
    _manage(p)
    body = SignatureIn.model_validate(body)
    key = match_key(body.vendor, body.product, body.signature_id, body.original_name)
    if s.scalar(select(DeviceSignature.id).where(DeviceSignature.match_key == key)):
        raise ValueError("같은 장비·시그니처가 이미 등록되어 있습니다. 기존 항목을 수정하세요.")
    row = DeviceSignature(match_key=key, vendor=body.vendor, product=body.product, original_name=body.original_name,
                          signature_id=body.signature_id, created_by=p.user_id, updated_by=p.user_id, current_version=0)
    s.add(row)
    s.flush()
    _version(s, row, body, p)
    s.flush()
    audit.record(s, "signature.create", actor_id=p.user_id, actor_name=p.username, target_type="signature",
                 target_id=row.id, detail={"version": row.current_version})
    return _out(row)


def update(s, p, sid: str, body: UpdateIn | dict) -> dict:
    _manage(p)
    body = UpdateIn.model_validate(body)
    row = s.get(DeviceSignature, sid)
    if row is None:
        raise NotFound("signature not found")
    if body.expected_version != row.current_version:
        raise ValueError("다른 사람이 먼저 수정했습니다. 다시 불러온 뒤 저장하세요.")
    # The identity (and the device's own wording) is fixed: a different name or ID is a different entry.
    if match_key(body.vendor, body.product, body.signature_id, body.original_name) != row.match_key:
        raise ValueError("장비·시그니처 ID·원래 이름은 바꿀 수 없습니다. 다른 항목이면 새로 등록하세요.")
    _version(s, row, body, p)
    s.flush()
    audit.record(s, "signature.update", actor_id=p.user_id, actor_name=p.username, target_type="signature",
                 target_id=row.id, detail={"version": row.current_version})
    return _out(row)


def list_all(s, p, *, q: str = "", limit: int = 200) -> list[dict]:
    if not (can(p, "knowledge.read") or can(p, "signature.manage")):
        raise Forbidden("knowledge.read")
    rows = s.scalars(select(DeviceSignature).order_by(DeviceSignature.updated_at.desc()).limit(min(max(limit, 1), 1000)))
    needle = q.strip().casefold()
    return [_out(r) for r in rows if not needle or needle in (r.original_name + " " + r.signature_id + " " +
                                                             r.vendor + " " + r.product).casefold()]


def history(s, p, sid: str) -> list[dict]:
    if not (can(p, "knowledge.read") or can(p, "signature.manage")):
        raise Forbidden("knowledge.read")
    if s.get(DeviceSignature, sid) is None:
        raise NotFound("signature not found")
    return [{"version": v.version, "content": v.content, "changed_by": v.changed_by, "created_at": v.created_at}
            for v in s.scalars(select(DeviceSignatureVersion).where(DeviceSignatureVersion.signature_id_ref == sid)
                               .order_by(DeviceSignatureVersion.version.desc()))]


def investigation_alerts(s, p, inv_id: str, limit: int = 50) -> dict:
    """Device alert names seen in one investigation, each with its registered meaning or 'needs confirmation'."""
    from saw import container

    require(s, p, "investigation.read", inv_id)
    es = container.get().events
    groups = es.group_by(inv_id, [Filter(field="alert_name", op="exists")], ["alert_name"],
                         [GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last"),
                          GroupMetric(type="cardinality", field="src_ip", name="sources"),
                          GroupMetric(type="cardinality", field="dst_ip", name="destinations")], size=limit)
    total = es.aggregate(inv_id, [Filter(field="alert_name", op="exists")], AggRequest(type="count", field="alert_name"))
    by_name: dict[str, list[DeviceSignature]] = {}
    for row in s.scalars(select(DeviceSignature)):
        by_name.setdefault(row.original_name, []).append(row)
    items = []
    for g in groups:
        name = str(g["key"]["alert_name"])
        matches = by_name.get(name, [])  # exact original name only
        confirmed = [m for m in matches if m.status == "confirmed"]
        items.append({"alert_name": name, "count": g["count"], "first": g.get("first"), "last": g.get("last"),
                      "sources": g.get("sources"), "destinations": g.get("destinations"),
                      "registry": ("confirmed" if len(confirmed) == 1 else "ambiguous" if len(confirmed) > 1
                                   else "needs_confirmation"),
                      "entries": [_out(m) for m in matches]})
    return {"items": items, "events_with_alert": total.get("value", 0),
            "note": "장비가 붙인 공격명은 장비의 주장입니다. 등록된 의미는 정확히 같은 원래 이름에만 연결하며, 미등록 이름은 "
                    "의미 확인이 필요합니다. 공격명만으로 공격 성공이나 침해를 판단하지 않습니다."}
