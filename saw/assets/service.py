"""Asset and business knowledge on top of the existing asset store (same table, same revisions).

What this adds:
- register with a name and one identifier; everything else can be filled in later,
- addresses with a validity period and a source, so an event is matched with what was true at its time,
- a file refresh that shows new / changed / unchanged / conflict / error before anything is applied,
  never overwrites by IP alone, keeps existing values for blank cells and never deletes what the file omits,
- a "to review" list (address conflicts, unconfirmed owners, stale information),
- registration candidates from what a hunt observed (never registered automatically).
An asset never hides an activity: it is shown next to it as a possible explanation, with how fresh it is.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from datetime import date, datetime, timezone

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from saw.core.application.investigations import require
from saw.core.security.authz import can
from saw.core.application.investigations import Forbidden
from saw.knowledge import asset as store
from saw.knowledge.models import Asset, KnowledgeRevision

EXTRA = ["name", "external_id", "addresses", "info_source", "last_confirmed", "next_review", "review_days", "state",
         "regular_work", "business", "operating_hours"]
for _name in EXTRA:
    if _name not in store.FIELDS:
        store.FIELDS.append(_name)

COLUMNS = {  # header (lower-cased, spaces removed) -> field
    "asset_id": "asset_id", "자산id": "asset_id", "자산번호": "asset_id", "관리번호": "asset_id", "external_id": "external_id", "외부관리id": "external_id",
    "name": "name", "이름": "name", "자산명": "name", "service": "service", "서비스": "service", "업무": "business", "business": "business",
    "ip": "ip", "ip주소": "ip", "주소": "ip", "hostname": "hostname", "호스트": "hostname", "호스트명": "hostname", "domain": "domain", "도메인": "domain",
    "cidr": "cidr", "대역": "cidr", "owner": "owner", "담당자": "owner", "department": "department", "부서": "department",
    "criticality": "criticality", "중요도": "criticality", "network": "network", "망": "network", "notes": "notes", "비고": "notes",
    "valid_from": "valid_from", "유효시작": "valid_from", "valid_to": "valid_to", "유효종료": "valid_to", "info_source": "info_source", "출처": "info_source",
    "last_confirmed": "last_confirmed", "마지막확인일": "last_confirmed", "next_review": "next_review", "다음확인일": "next_review",
    "state": "state", "상태": "state", "operating_hours": "operating_hours", "운영시간": "operating_hours",
}
CRIT_KO = {"매우높음": "critical", "높음": "high", "보통": "medium", "낮음": "low"}
SIMPLE = ("name", "service", "business", "hostname", "owner", "department", "network", "notes", "info_source", "last_confirmed",
          "next_review", "state", "operating_hours", "external_id")


class QuickIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)
    identifier: str = Field(min_length=1, max_length=255)  # one of IP, CIDR, domain or host name
    org_unit_id: str | None = Field(None, max_length=36)
    asset_id: str | None = Field(None, max_length=64)


class UpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_rev: int
    criticality: str | None = None
    data: dict = Field(default_factory=dict)


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=5_000_000)
    org_unit_id: str | None = Field(None, max_length=36)
    clear_blank: bool = False  # a blank cell keeps the existing value unless this is chosen


def _kind(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return "cidr"
    except ValueError:
        pass
    return "domain" if "." in value else "host"


def _today() -> str:
    return date.today().isoformat()


def _valid(addr: dict, at: str | None) -> bool:
    """Whether an address assignment was in force at a moment (ISO date or datetime). Open ends are open."""
    day = (at or _today())[:10]
    return (not addr.get("valid_from") or addr["valid_from"][:10] <= day) and (not addr.get("valid_to") or day <= addr["valid_to"][:10])


def _sync(data: dict) -> dict:
    """Keep the plain ip/cidr/domain lists (used by the existing matching) equal to the addresses valid today."""
    addrs = data.get("addresses") or []
    if addrs:
        now = [a for a in addrs if _valid(a, None)]
        data["ip"] = sorted({a["value"] for a in now if a["kind"] == "ip"})
        data["cidr"] = sorted({a["value"] for a in now if a["kind"] == "cidr"})
        data["domain"] = sorted({a["value"] for a in now if a["kind"] == "domain"})
        hosts = [a["value"] for a in now if a["kind"] == "host"]
        if hosts and not data.get("hostname"):
            data["hostname"] = hosts[0]
    return data


def _addresses(existing: list[dict], values: list[str], *, valid_from: str = "", valid_to: str = "", source: str = "") -> list[dict]:
    out = [dict(a) for a in existing]
    for value in values:
        value = value.strip()
        if not value:
            continue
        kind = _kind(value)
        hit = next((a for a in out if a["value"] == value and a["kind"] == kind and _valid(a, valid_from or None)), None)
        if hit:
            if valid_to:
                hit["valid_to"] = valid_to
            continue
        out.append({"value": value, "kind": kind, "valid_from": valid_from, "valid_to": valid_to, "source": source or "수동 등록"})
    return out


def out(a: Asset) -> dict:
    d = store.to_dict(a)
    d["name"] = d.get("name") or a.service
    d["addresses"] = d.get("addresses") or [{"value": v, "kind": k, "valid_from": "", "valid_to": "", "source": "이전 등록"}
                                            for k in ("ip", "cidr", "domain") for v in (d.get(k) or [])]
    d["review"] = _review_flags(d)
    return d


def _review_flags(d: dict) -> list[str]:
    flags = []
    if not d.get("owner"):
        flags.append("담당자 미확인")
    if d.get("next_review") and d["next_review"][:10] < _today():
        flags.append(f"확인 기한 지남({d['next_review'][:10]})")
    elif not d.get("last_confirmed"):
        flags.append("확인한 날짜 없음")
    if not d.get("business") and not d.get("notes"):
        flags.append("업무 설명 없음")
    if d.get("state") == "retired":
        flags.append("폐기 상태")
    return flags


def listing(s, p, *, org_unit_id: str | None = None, q: str = "") -> dict:
    if not can(p, "knowledge.read"):
        raise Forbidden("knowledge.read")
    rows = [out(a) for a in store.all_assets(s)]
    if org_unit_id:
        rows = [r for r in rows if r.get("org_unit_id") in (org_unit_id, None)]
    needle = q.strip().casefold()
    if needle:
        rows = [r for r in rows if needle in f"{r['asset_id']} {r['name']} {r.get('hostname') or ''} {' '.join(a['value'] for a in r['addresses'])}".casefold()]
    rows.sort(key=lambda r: (r.get("state") == "retired", r["name"]))
    return {"items": rows, "to_review": review_list(rows)}


def review_list(rows: list[dict]) -> list[dict]:
    """What needs a human: the same address on two assets of one affiliate at the same time, and stale information."""
    items, seen = [], {}
    for r in rows:
        if r.get("state") == "retired":
            continue
        for a in r["addresses"]:
            if a["kind"] != "ip" or not _valid(a, None):
                continue
            key = (r.get("org_unit_id"), r.get("network") or "", a["value"])
            if key in seen and seen[key]["id"] != r["id"]:
                items.append({"kind": "address_conflict", "asset_ids": [seen[key]["id"], r["id"]],
                              "text": f"{a['value']}이(가) '{seen[key]['name']}'와 '{r['name']}'에 동시에 배정되어 있습니다. 재배정이면 앞 자산의 유효 종료일을 적어 주세요."})
            seen.setdefault(key, r)
        for flag in r["review"]:
            items.append({"kind": "stale", "asset_ids": [r["id"]], "text": f"{r['name']}: {flag}"})
    return items[:500]


def quick_create(s, p, body: QuickIn | dict) -> dict:
    """Register with a name and one identifier. The affiliate comes from where the analyst is working."""
    body = QuickIn.model_validate(body)
    asset_id = body.asset_id or _new_id(s, body.name)
    if s.scalar(select(Asset.id).where(Asset.asset_id == asset_id)):
        raise ValueError("같은 자산 ID가 이미 있습니다. 기존 자산을 고치거나 다른 ID를 쓰세요.")
    data = _sync({"name": body.name, "org_unit_id": body.org_unit_id, "state": "active",
                  "addresses": _addresses([], [body.identifier], source="수동 등록")})
    return out(store.upsert(s, p, asset_id, body.name, "medium", data, "manual"))


def _new_id(s, name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()[:24] or "ASSET"
    n = 1
    while s.scalar(select(Asset.id).where(Asset.asset_id == f"{base}-{n:03d}")):
        n += 1
    return f"{base}-{n:03d}"


def _get(s, asset_pk: str) -> Asset:
    from saw.core.application.investigations import NotFound

    a = s.get(Asset, asset_pk)
    if a is None:
        raise NotFound("asset not found")
    return a


def update(s, p, asset_pk: str, body: UpdateIn | dict) -> dict:
    body = UpdateIn.model_validate(body)
    a = _get(s, asset_pk)
    if body.expected_rev != a.rev:
        raise ValueError(f"다른 사람이 먼저 고쳤습니다(현재 rev {a.rev}). 다시 불러온 뒤 저장하세요.")
    data = dict(body.data)
    if "addresses" in data:
        for addr in data["addresses"]:
            addr["kind"] = _kind(addr["value"])
            if addr.get("valid_from") and addr.get("valid_to") and addr["valid_to"] < addr["valid_from"]:
                raise ValueError("주소의 유효 종료일이 시작일보다 앞섭니다.")
    merged = _sync({**(a.data or {}), **data})
    service = merged.get("name") or a.service
    return out(store.upsert(s, p, a.asset_id, service, body.criticality or a.criticality, merged, a.source))


def history(s, p, asset_pk: str) -> list[dict]:
    if not can(p, "knowledge.read"):
        raise Forbidden("knowledge.read")
    a = _get(s, asset_pk)
    rows = s.scalars(select(KnowledgeRevision).where(KnowledgeRevision.kind == "asset", KnowledgeRevision.ref_id == a.id)
                     .order_by(KnowledgeRevision.rev.desc()).limit(100))
    return [{"rev": r.rev, "actor": r.actor, "data": r.data, "at": getattr(r, "created_at", None)} for r in rows]


# ---------------------------------------------------------------------------------------------------------------
# File refresh

def _parse(text: str) -> tuple[list[str], list[dict], list[str]]:
    sample = text.lstrip("﻿")
    delim = "\t" if sample.split("\n", 1)[0].count("\t") > sample.split("\n", 1)[0].count(",") else ","
    reader = csv.reader(io.StringIO(sample), delimiter=delim)
    header = next(reader, [])
    mapping, unknown = [], []
    for name in header:
        field = COLUMNS.get(re.sub(r"\s+", "", name).casefold())
        mapping.append(field)
        if field is None and name.strip():
            unknown.append(name.strip())
    rows = []
    for n, cells in enumerate(reader, 2):
        if not any(c.strip() for c in cells):
            continue
        row = {"_line": n}
        for field, cell in zip(mapping, cells):
            if field:
                row[field] = cell.strip()
        rows.append(row)
    return [m for m in mapping if m], rows, unknown


def _plan(s, body: ImportIn) -> dict:
    mapped, rows, unknown = _parse(body.text)
    existing = {a.asset_id: a for a in store.all_assets(s)}
    by_external = {(a.data or {}).get("external_id"): a for a in existing.values() if (a.data or {}).get("external_id")}
    owners_of_ip: dict[tuple, str] = {}
    for a in existing.values():
        d = a.data or {}
        for addr in out(a)["addresses"]:
            if addr["kind"] == "ip" and _valid(addr, None):
                owners_of_ip[(d.get("org_unit_id"), d.get("network") or "", addr["value"])] = a.asset_id
    plan, seen_keys = [], set()
    for row in rows:
        line, key = row["_line"], row.get("asset_id") or ""
        target = existing.get(key) if key else by_external.get(row.get("external_id") or "")
        entry = {"line": line, "asset_id": key or (target.asset_id if target else ""), "name": row.get("name") or row.get("service") or "", "changes": [], "action": "new"}
        try:
            ips = [x.strip() for x in re.split(r"[;\s]+", row.get("ip") or "") if x.strip()]
            for ip in ips:
                ipaddress.ip_address(ip)
            for c in [x.strip() for x in re.split(r"[;\s]+", row.get("cidr") or "") if x.strip()]:
                ipaddress.ip_network(c, strict=False)
            crit = CRIT_KO.get(row.get("criticality") or "", row.get("criticality") or "")
            if crit and crit not in store.CRIT:
                raise ValueError(f"중요도 값 '{row.get('criticality')}'를 알 수 없습니다(critical/high/medium/low).")
            if not key and target is None:
                # Never update by IP alone: a row without a key that names an address already owned is a conflict.
                owner = next((owners_of_ip.get((body.org_unit_id, row.get("network") or "", ip)) for ip in ips), None)
                if owner:
                    entry.update(action="conflict", reason=f"자산 ID가 없고 주소가 이미 '{owner}'에 배정되어 있습니다. IP만으로는 덮어쓰지 않습니다. 자산 ID를 적어 주세요.")
                    plan.append(entry)
                    continue
                if not entry["name"]:
                    raise ValueError("자산 ID도 이름도 없습니다.")
            if entry["asset_id"] and entry["asset_id"] in seen_keys:
                entry.update(action="conflict", reason="같은 자산 ID가 파일에 두 번 있습니다.")
                plan.append(entry)
                continue
            seen_keys.add(entry["asset_id"])
            if target is not None:
                d = target.data or {}
                if body.org_unit_id and d.get("org_unit_id") not in (None, body.org_unit_id):
                    entry.update(action="conflict", reason="같은 자산 ID가 다른 관계사에 등록되어 있습니다.")
                    plan.append(entry)
                    continue
                for field in SIMPLE:
                    if field not in row:
                        continue
                    old = (target.service if field in ("service",) else d.get(field)) or ""
                    new = row[field]
                    if new == "" and not body.clear_blank:
                        continue  # a blank cell keeps what is there
                    if str(old) != new:
                        entry["changes"].append({"field": field, "from": str(old), "to": new})
                if crit and crit != target.criticality:
                    entry["changes"].append({"field": "criticality", "from": target.criticality, "to": crit})
                current = {a["value"] for a in out(target)["addresses"] if _valid(a, None)}
                added = [v for v in ips + ([row["domain"]] if row.get("domain") else []) if v not in current]
                for value in added:
                    other = owners_of_ip.get((d.get("org_unit_id"), d.get("network") or "", value))
                    if other and other != target.asset_id:
                        entry.update(action="conflict", reason=f"{value}은(는) 이미 '{other}'에 배정되어 있습니다. 재배정이면 그 자산의 유효 종료일을 먼저 적어 주세요.")
                        break
                    entry["changes"].append({"field": "주소 추가", "from": "", "to": value})
                if entry["action"] != "conflict":
                    entry["action"] = "changed" if entry["changes"] else "unchanged"
            else:
                clash = next((owners_of_ip.get((body.org_unit_id, row.get("network") or "", ip)) for ip in ips), None)
                if clash:
                    entry.update(action="conflict", reason=f"주소가 이미 '{clash}'에 배정되어 있습니다.")
            entry["_row"] = row
        except ValueError as exc:
            entry.update(action="error", reason=str(exc)[:200])
        plan.append(entry)
    counts = {k: sum(1 for e in plan if e["action"] == k) for k in ("new", "changed", "unchanged", "conflict", "error")}
    return {"columns": mapped, "unknown_columns": unknown, "rows": plan, "counts": counts,
            "notes": ["빈 칸은 기존 값을 유지합니다." if not body.clear_blank else "빈 칸은 기존 값을 비웁니다.",
                      "파일에 없는 자산은 지우지 않습니다.", "자산 ID가 같으면 같은 자산으로 갱신합니다. IP만으로는 덮어쓰지 않습니다."]}


def import_preview(s, p, body: ImportIn | dict) -> dict:
    if not can(p, "asset.write"):
        raise Forbidden("asset.write")
    plan = _plan(s, ImportIn.model_validate(body))
    for e in plan["rows"]:
        e.pop("_row", None)
    return plan


def import_apply(s, p, body: ImportIn | dict) -> dict:
    """Apply what the preview showed: new and changed rows only. Conflicts and errors are left for the analyst."""
    body = ImportIn.model_validate(body)
    if not can(p, "asset.write"):
        raise Forbidden("asset.write")
    plan = _plan(s, body)
    applied = {"new": 0, "changed": 0}
    for e in plan["rows"]:
        if e["action"] not in ("new", "changed"):
            continue
        row = e["_row"]
        key = e["asset_id"] or _new_id(s, e["name"])
        target = s.scalar(select(Asset).where(Asset.asset_id == key))
        d = dict(target.data or {}) if target else {"org_unit_id": body.org_unit_id, "state": "active"}
        for field in SIMPLE:
            if field in row and (row[field] != "" or body.clear_blank) and field != "service":
                d[field] = row[field]
        values = [x.strip() for x in re.split(r"[;\s]+", row.get("ip") or "") if x.strip()] + ([row["domain"]] if row.get("domain") else []) \
            + [x.strip() for x in re.split(r"[;\s]+", row.get("cidr") or "") if x.strip()]
        d["addresses"] = _addresses(out(target)["addresses"] if target else [], values, valid_from=row.get("valid_from") or "",
                                    valid_to=row.get("valid_to") or "", source=row.get("info_source") or "파일 갱신")
        crit = CRIT_KO.get(row.get("criticality") or "", row.get("criticality") or "") or (target.criticality if target else "medium")
        service = row.get("service") or row.get("name") or (target.service if target else key)
        d.setdefault("name", row.get("name") or service)
        store.upsert(s, p, key, service, crit, _sync(d), "csv")
        applied[e["action"]] += 1
    return {"applied": applied, "skipped": {k: plan["counts"][k] for k in ("unchanged", "conflict", "error")}}


# ---------------------------------------------------------------------------------------------------------------
# Use in a hunt

def match_at(rows: list[dict], *, org_unit_id: str | None, value: str, at: str | None) -> dict | None:
    """The asset an address or host belonged to at the time of the event, inside one affiliate."""
    kind = _kind(value)
    best = None
    for r in rows:
        if r.get("org_unit_id") not in (org_unit_id, None) or r.get("state") == "retired" and not at:
            continue
        for a in r["addresses"]:
            if not _valid(a, at):
                continue
            if a["value"] == value and a["kind"] == kind:
                return r
            if kind == "ip" and a["kind"] == "cidr":
                try:
                    if ipaddress.ip_address(value) in ipaddress.ip_network(a["value"], strict=False):
                        best = best or r
                except ValueError:
                    pass
        if kind in ("domain", "host") and value == (r.get("hostname") or ""):
            best = best or r
    return best


def context_lines(rows: list[dict], *, org_unit_id: str | None, entities: list[str], at: str | None) -> list[dict]:
    """What is registered about the addresses of an activity: shown next to it, never used to hide it."""
    found, seen = [], set()
    for value in entities:
        r = match_at(rows, org_unit_id=org_unit_id, value=str(value), at=at)
        if r is None or r["id"] in seen:
            continue
        seen.add(r["id"])
        stale = [f for f in r["review"] if "기한" in f or "없음" in f or "미확인" in f]
        found.append({"asset_id": r["asset_id"], "id": r["id"], "name": r["name"], "value": value, "criticality": r["criticality"],
                      "business": r.get("business") or r.get("notes") or "", "operating_hours": r.get("operating_hours") or "",
                      "stale": stale,
                      "text": f"{value}은(는) 등록 자산 '{r['name']}'입니다" + (f"(업무: {r.get('business')})" if r.get("business") else "")
                              + (f". 등록 정보가 약합니다: {', '.join(stale)}" if stale else ".")
                              + " 등록된 업무와 이 활동의 대상·시간·방향이 실제로 맞는지 비교해야 합니다."})
    return found


def candidates(s, p, inv_id: str, *, limit: int = 30) -> dict:
    """Internal addresses and services seen in a hunt that no asset covers: proposals, never registered by themselves."""
    from saw import container
    from saw.core.schemas.query import AggRequest

    inv = require(s, p, "investigation.read", inv_id)
    rows = [out(a) for a in store.all_assets(s)]
    es = container.get().events
    out_rows = []
    for field, label in (("dst_ip", "목적지 주소"), ("hostname", "서비스 호스트")):
        agg = es.aggregate(inv_id, [], AggRequest(type="terms", field=field, size=200), None)
        for b in agg.get("buckets") or []:
            value = str(b["key"])
            if field == "dst_ip":
                try:
                    if not ipaddress.ip_address(value).is_private:
                        continue
                except ValueError:
                    continue
            if match_at(rows, org_unit_id=inv.org_unit_id, value=value, at=None) is None:
                out_rows.append({"value": value, "kind": label, "records": b["count"]})
    out_rows.sort(key=lambda r: -r["records"])
    return {"items": out_rows[:limit], "org_unit_id": inv.org_unit_id,
            "note": "이 헌팅에서 관측됐지만 등록되지 않은 대상입니다. 등록 후보일 뿐이며 자동으로 자산이 되지 않습니다."}
