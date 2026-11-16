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
    # What the alert observes and cannot prove, the device's own action values, the follow-up data it calls for
    # and the investigation questions it feeds (Q01..Q10). An empty list means "not written yet", not "none".
    log_source: Short = ""
    action_values: list[Annotated[str, Field(max_length=128)]] = Field(default_factory=list, max_length=20)
    observes: list[Line] = Field(default_factory=list, max_length=30)
    cannot_prove: list[Line] = Field(default_factory=list, max_length=30)
    followup_data: list[Line] = Field(default_factory=list, max_length=30)
    linked_questions: list[Annotated[str, Field(pattern=r"^Q(0[1-9]|10)$")]] = Field(default_factory=list, max_length=10)
    scope_note: Line = ""  # an affiliate-specific exception, kept apart from the common meaning

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


CTX = "ext.observation.context."


def _day(value):
    from datetime import datetime

    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return "invalid"
    return parsed.date()


def _applies(row: DeviceSignature, name: str, vendor: str, product: str, sig: str, first, last) -> tuple[bool, str]:
    """Whether a registered meaning may be applied to these records, and why not when it may not."""
    content = row.content or {}
    if row.signature_id:
        if not sig:
            return False, "로그에 시그니처 ID가 없어 같은 규칙인지 확인할 수 없습니다."
        if sig != row.signature_id:
            return False, "시그니처 ID가 다릅니다."
    elif row.original_name != name:
        return False, "원래 이름이 다릅니다."
    for label, wanted, seen in (("제조사", row.vendor, vendor), ("제품", row.product, product)):
        if wanted.strip():
            if not seen:
                return False, f"로그의 {label} 정보가 없어 등록된 장비({wanted})의 규칙인지 확인할 수 없습니다."
            if wanted.strip().casefold() != seen.strip().casefold():
                return False, f"등록된 {label}({wanted})와 로그의 {label}({seen})가 다릅니다."
    if content.get("rule_version"):
        return False, f"등록은 규칙 버전 {content['rule_version']}에 대한 것이지만 로그에서 규칙 버전을 확인할 수 없습니다."
    valid_from, valid_to = _day(content.get("valid_from")), _day(content.get("valid_to"))
    if "invalid" in (valid_from, valid_to):
        return False, "등록된 유효기간을 해석할 수 없습니다."
    seen_first, seen_last = _day(first), _day(last)
    if (valid_from or valid_to) and not (seen_first and seen_last):
        return False, "로그 시각이 없어 유효기간 안인지 확인할 수 없습니다."
    if valid_from and seen_first < valid_from or valid_to and seen_last > valid_to:
        return False, f"로그 시각이 등록의 유효기간({content.get('valid_from') or '…'} ~ {content.get('valid_to') or '…'}) 밖입니다."
    return True, ""


def investigation_alerts(s, p, inv_id: str, limit: int = 50) -> dict:
    """Device alert names seen in one investigation, each with the meaning that applies to it or 'needs confirmation'.

    A registered meaning applies only to records from the same vendor/product (and signature ID when registered)
    within its validity period; a meaning registered without any device is shown as a name-only match.
    """
    from saw import container
    from saw.source_context.models import DeviceProfileVersion

    require(s, p, "investigation.read", inv_id)
    es = container.get().events
    fields = ["alert_name", "ext.signature_id", "ext.cef_vendor", "ext.cef_product", CTX + "device_profile_version_id"]
    groups = es.group_by(inv_id, [Filter(field="alert_name", op="exists")], fields,
                         [GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last"),
                          GroupMetric(type="cardinality", field="src_ip", name="sources"),
                          GroupMetric(type="cardinality", field="dst_ip", name="destinations")], size=limit * 4)
    total = es.aggregate(inv_id, [Filter(field="alert_name", op="exists")], AggRequest(type="count", field="alert_name"))
    rows = list(s.scalars(select(DeviceSignature)))
    profiles: dict[str, dict] = {}
    items: dict[tuple, dict] = {}
    for g in groups:
        key = g["key"]
        name = str(key["alert_name"])
        sig = str(key.get("ext.signature_id") or "")
        vendor, product = str(key.get("ext.cef_vendor") or ""), str(key.get("ext.cef_product") or "")
        profile_id = key.get(CTX + "device_profile_version_id")
        if profile_id and not (vendor and product):
            if profile_id not in profiles:
                row = s.get(DeviceProfileVersion, profile_id)
                profiles[profile_id] = (row.payload or {}) if row else {}
            vendor = vendor or str(profiles[profile_id].get("vendor") or "")
            product = product or str(profiles[profile_id].get("product") or "")
        ident = (name, sig, vendor, product)
        item = items.setdefault(ident, {"alert_name": name, "signature_id": sig, "vendor": vendor, "product": product,
                                        "count": 0, "first": None, "last": None, "sources": 0, "destinations": 0})
        item["count"] += g["count"]
        item["first"] = min(x for x in (item["first"], g.get("first")) if x) if g.get("first") or item["first"] else None
        item["last"] = max(x for x in (item["last"], g.get("last")) if x) if g.get("last") or item["last"] else None
        item["sources"] = max(item["sources"], g.get("sources") or 0)
        item["destinations"] = max(item["destinations"], g.get("destinations") or 0)
    out = []
    for item in sorted(items.values(), key=lambda x: -x["count"])[:limit]:
        entries, applied = [], []
        for row in rows:
            if row.original_name != item["alert_name"] and not (row.signature_id and row.signature_id == item["signature_id"]):
                continue
            ok, reason = _applies(row, item["alert_name"], item["vendor"], item["product"], item["signature_id"],
                                  item["first"], item["last"])
            entries.append({**_out(row), "applies": ok, "not_applied_reason": reason})
            if ok and row.status == "confirmed":
                applied.append(row)
        scoped = [r for r in applied if r.vendor.strip() or r.product.strip() or r.signature_id.strip()]
        chosen = scoped or applied
        registry = ("ambiguous" if len(chosen) > 1 else "needs_confirmation" if not chosen
                    else "confirmed" if scoped else "name_only")
        out.append({**item, "registry": registry, "entries": entries,
                    "applied": ({**_out(chosen[0]), "basis": "장비·시그니처·유효기간 일치" if scoped else
                                 "이름만 일치(등록에 장비 정보 없음)"} if len(chosen) == 1 else None)})
    return {"items": out, "events_with_alert": total.get("value", 0),
            "note": "장비가 붙인 공격명은 장비의 주장입니다. 등록된 의미는 같은 장비·시그니처·유효기간에만 적용하고, 출처·버전·"
                    "유효기간을 확인할 수 없으면 '확인 필요'로 둡니다. 공격명만으로 공격 성공이나 침해를 판단하지 않습니다."}
