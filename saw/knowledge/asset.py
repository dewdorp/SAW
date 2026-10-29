"""Asset Knowledge (docs/27): CRUD, CSV import, matching, detector baseline port, context comparisons."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from saw.core.application import audit
from saw.core.application.investigations import Forbidden, NotFound
from saw.core.security.authz import Principal, can
from saw.knowledge.models import Asset, KnowledgeRevision
from saw.storage.db import utcnow

KST = timezone(timedelta(hours=9))
CRIT = {"critical", "high", "medium", "low"}
LIST_FIELDS = {"ip", "cidr", "domain", "expected_country", "expected_asn", "expected_uri"}
JSON_FIELDS = {"expected_user_agent", "expected_access_time", "expected_request_rate", "batch_schedule", "known_exception"}
FIELDS = ["org_unit_id", "network", "company", "hostname", "domain", "ip", "cidr", "owner", "department", "environment", "internet_exposed",
          "data_classification", "expected_country", "expected_asn", "expected_user_agent", "expected_access_time",
          "expected_request_rate", "expected_uri", "batch_schedule", "known_exception", "authentication", "notes"]


def _validate(data: dict) -> dict:
    d = {k: data[k] for k in FIELDS if k in data}
    org_id = d.get("org_unit_id")
    if org_id is not None:
        if not isinstance(org_id, str) or len(org_id) > 36:
            raise ValueError("asset org_unit_id must be a registry identity")
        d["org_unit_id"] = org_id.strip() or None
    network = d.get("network")
    if network is not None:
        if not isinstance(network, str) or len(network) > 128:
            raise ValueError("asset network must be a string of at most 128 characters")
        d["network"] = network.strip()
    for k in ("ip",):
        for v in d.get(k) or []:
            ipaddress.ip_address(v)
    for v in d.get("cidr") or []:
        ipaddress.ip_network(v, strict=False)
    for ex in d.get("known_exception") or []:
        if not ex.get("expires_at"):
            raise ValueError("known_exception requires expires_at")
    return d


def to_dict(a: Asset) -> dict:
    d = {"id": a.id, "asset_id": a.asset_id, "service": a.service, "criticality": a.criticality, "source": a.source,
         "rev": a.rev, "updated_at": a.updated_at, **(a.data or {})}
    if d.get("owner"):
        d["owner_masked"] = d["owner"][0] + "*" * max(1, len(d["owner"]) - 1)  # contact info is sensitive (docs/27 §6)
    return d


def upsert(s: Session, p: Principal, asset_id: str, service: str, criticality: str, data: dict, source: str = "manual") -> Asset:
    if not can(p, "asset.write"):
        raise Forbidden("asset.write")
    if criticality not in CRIT:
        raise ValueError(f"criticality must be one of {sorted(CRIT)}")
    clean = _validate(data)
    a = s.execute(select(Asset).where(Asset.asset_id == asset_id)).scalar_one_or_none()
    scoped_data = {**(a.data or {}), **clean} if a is not None else clean
    if scoped_data.get("org_unit_id"):
        from saw.source_context.service import org_by_id

        org_by_id(s, scoped_data["org_unit_id"])
    if a is None:
        a = Asset(asset_id=asset_id, service=service, criticality=criticality, data=clean, source=source)
        s.add(a)
    else:
        a.service, a.criticality, a.data, a.source = service, criticality, {**a.data, **clean}, source
        a.rev += 1
        a.updated_at = utcnow()
    s.flush()
    s.add(KnowledgeRevision(kind="asset", ref_id=a.id, rev=a.rev, status="approved", data=to_dict(a) | {"updated_at": None},
                            actor=p.username))
    audit.record(s, "asset.upsert", actor_id=p.user_id, actor_name=p.username, target_type="asset", target_id=asset_id)
    return a


def import_csv(s: Session, p: Principal, text: str) -> dict:
    """CSV columns: asset_id,service,criticality + any FIELDS. List fields use ';', JSON fields contain JSON."""
    ok, errors = 0, []
    for i, row in enumerate(csv.DictReader(io.StringIO(text)), 2):
        try:
            data = {}
            for k, v in row.items():
                if k in ("asset_id", "service", "criticality") or v in (None, ""):
                    continue
                if k in LIST_FIELDS:
                    data[k] = [x.strip() for x in v.split(";") if x.strip()]
                elif k in JSON_FIELDS:
                    data[k] = json.loads(v)
                elif k == "internet_exposed":
                    data[k] = v.strip().lower() in ("1", "true", "y", "yes")
                else:
                    data[k] = v
            upsert(s, p, row["asset_id"].strip(), row["service"].strip(), (row.get("criticality") or "medium").strip(), data, "csv")
            ok += 1
        except Exception as e:  # noqa: BLE001 - report per-row validation errors
            errors.append({"line": i, "error": str(e)[:200]})
    return {"imported": ok, "errors": errors}


def all_assets(s: Session) -> list[Asset]:
    return list(s.execute(select(Asset)).scalars())


def match(assets: list[Asset], ip: str | None = None, host: str | None = None, path: str | None = None) -> Asset | None:
    """Most specific rule wins: exact IP > CIDR > hostname/domain > URI prefix."""
    best, score = None, 0
    for a in assets:
        d = a.data or {}
        if ip:
            if ip in (d.get("ip") or []):
                return a
            try:
                addr = ipaddress.ip_address(ip)
                for c in d.get("cidr") or []:
                    if addr in ipaddress.ip_network(c, strict=False) and score < 3:
                        best, score = a, 3
            except ValueError:
                pass
        if host and (host == d.get("hostname") or host in (d.get("domain") or [])) and score < 2:
            best, score = a, 2
        if path:
            for pre in d.get("expected_uri") or []:
                if path.startswith(pre) and score < 1:
                    best, score = a, 1
    return best


def _hours(spec: str | None) -> tuple[int, int] | None:
    m = re.match(r"(\d{1,2}):\d{2}-(\d{1,2}):\d{2}", spec or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def _scope_assets(s: Session, org_unit_id: str | None, network: str | None):
    """Separate explicit registry scope from references without resolving names to IDs."""
    from saw.source_context.models import OrgUnit

    org = s.get(OrgUnit, org_unit_id) if isinstance(org_unit_id, str) and org_unit_id else None
    if org is not None and org.state != "active":
        org = None
    scoped, references = [], []
    for item in all_assets(s):
        data = item.data or {}
        asset_org, asset_network = data.get("org_unit_id"), data.get("network")
        if asset_org:
            if org is None or asset_org != org.id:
                continue
            if asset_network:
                if not network:
                    references.append((item, "network_unknown"))
                    continue
                if asset_network != network:
                    continue
            scoped.append(item)
        elif not data.get("company"):
            references.append((item, "legacy_unscoped"))
        elif org is not None and data["company"] == org.display_name:
            references.append((item, "legacy_company_only"))
    # Prefer the explicit network policy over an organization-wide policy.
    scoped.sort(key=lambda item: not bool((item.data or {}).get("network")))
    return scoped, references


class AssetPortImpl:
    """Only explicit active organization/network scope may affect detector baselines."""

    def __init__(self, s: Session, org_unit_id: str | None = None, network: str | None = None):
        self.assets, _ = _scope_assets(s, org_unit_id, network)
        if not self.assets:
            raise ImportError("no scoped assets")  # detectors fall back to relative comparison

    def match_path(self, path: str) -> dict | None:
        a = match(self.assets, path=path)
        return to_dict(a) if a else None

    def off_hours_findings(self, ctx, det) -> list:
        from saw.core.schemas.query import Filter
        from saw.detectors.base import AttackMap, FindingDraft, check, metric

        out = []
        for a in self.assets:
            d = a.data or {}
            hrs = _hours((d.get("expected_access_time") or {}).get("weekday"))
            if not hrs or not d.get("expected_uri"):
                continue
            flt = [Filter(field="data_source", op="in", value=["web", "waf"]),
                   Filter(field="url_path", op="prefix", value=d["expected_uri"][0])]
            total, off, first = 0, 0, None
            for e in ctx.events.iterate(ctx.investigation_id, flt, fields=["timestamp", "event_id"]):
                total += 1
                h = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).astimezone(KST).hour
                if not (hrs[0] <= h < hrs[1]):
                    off += 1
                    first = first or e["timestamp"]
            if total and off / total >= 0.5 and off >= 50:
                out.append(FindingDraft(det.id, det.version, f"Possible Off-hours Access to {a.service}", det.category,
                                        det.stage, 0.6, "medium",
                                        [metric("off_hours_requests", off, label="Off-hours requests"),
                                         metric("share", round(off / total, 3), label="Off-hours share")],
                                        [check("Outside expected access time", True, f"expected {hrs[0]:02d}-{hrs[1]:02d} KST"),
                                         check("Asset criticality", a.criticality in ("critical", "high"), a.criticality)],
                                        [f"asset:{a.asset_id}"], {"filters": [f.model_dump() for f in flt]}, first, None,
                                        f"{det.id}:{a.asset_id}", asset_criticality=a.criticality,
                                        attack_unmapped_reason="time-of-day deviation is context, not a technique",
                                        explanation=f"{a.service} 요청의 {off / total:.0%}가 업무시간 외 발생."))
        return out


def context_for(s: Session, finding: dict | None, inv_entities: dict,
                org_unit_id: str | None = None, network: str | None = None) -> list[dict]:
    """Stable-ID comparisons; ambiguous legacy and unknown-network matches are references."""
    scoped, references = _scope_assets(s, org_unit_id, network)
    reference_status = {a.asset_id: status for a, status in references}
    assets = scoped + [a for a, _ in references]
    if not assets:
        return []
    hits: dict[str, Asset] = {}
    paths = [e.split(":", 1)[1].split("?")[0].replace("<NUM>", "0") for e in (finding or {}).get("entities", []) if e.startswith("uri_template:")]
    ips = [e.split(":", 1)[1] for e in (finding or {}).get("entities", []) if e.startswith("ip:")] + inv_entities.get("dst_ips", [])
    # Reference matches cannot shadow an eligible stable-ID baseline or each other.
    groups = [scoped] + [[a for a, state in references if state == status]
                         for status in ("network_unknown", "legacy_company_only", "legacy_unscoped")]
    for candidates in groups:
        for pth in paths + inv_entities.get("paths", []):
            a = match(candidates, path=pth)
            if a:
                hits[a.asset_id] = a
        for ip in ips:
            a = match(candidates, ip=ip)
            if a:
                hits[a.asset_id] = a
        for h in inv_entities.get("hosts", []):
            a = match(candidates, host=h)
            if a:
                hits[a.asset_id] = a
    out = []
    for a in list(hits.values())[:3]:
        d = to_dict(a)
        if a.asset_id in reference_status:
            out.append({**d, "reference_only": True, "scope_status": reference_status[a.asset_id], "comparisons": [],
                        "batch_schedule": [{**b, "matches": False} for b in d.get("batch_schedule") or []]})
            continue
        comps = []
        rate = (d.get("expected_request_rate") or {}).get("per_min")
        if finding and rate:
            m = next((m for m in finding.get("metrics", []) if m.get("name") == "request_rate_per_min"), None)
            if m:
                comps.append({"label": "Request rate", "normal": f"{rate.get('min')}–{rate.get('max')}/min",
                              "current": f"{m['observed']}/min", "deviates": m["observed"] > (rate.get("max") or 0)})
        hrs = _hours((d.get("expected_access_time") or {}).get("weekday"))
        if finding and hrs and finding.get("time_start"):
            ts = finding["time_start"]
            dt = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            h = dt.astimezone(KST)
            comps.append({"label": "Access time", "normal": d["expected_access_time"]["weekday"], "current": h.strftime("%H:%M"),
                          "deviates": not (hrs[0] <= h.hour < hrs[1])})
        if d.get("expected_country") and inv_entities.get("countries"):
            cur = inv_entities["countries"]
            comps.append({"label": "Country", "normal": ",".join(d["expected_country"]), "current": ",".join(cur[:3]),
                          "deviates": any(c not in d["expected_country"] for c in cur[:3])})
        batches = []
        for b in d.get("batch_schedule") or []:
            matches = bool(finding and any(e == f"ip:{b.get('src')}" for e in finding.get("entities", []))
                           or (b.get("uri") and any(p.startswith(b["uri"]) for p in paths)))
            batches.append({**b, "matches": matches})
        out.append({**d, "reference_only": False, "scope_status": "matched", "comparisons": comps, "batch_schedule": batches})
    return out


def get(s: Session, asset_id: str) -> Asset:
    a = s.execute(select(Asset).where(Asset.asset_id == asset_id)).scalar_one_or_none()
    if a is None:
        raise NotFound("asset not found")
    return a
