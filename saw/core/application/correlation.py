"""Cross-source correlation (docs/32 §2, docs/28 §5): shared entity + time window across data-source families.

Strength: strong = same entity (IP/domain/session/account) seen in ≥2 source families within the window;
weak = only the same asset/host and time proximity. Results feed Timeline/Story; nothing is auto-concluded.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from saw import container
from saw.core.schemas.query import Filter, GroupMetric
from saw.detection.derived_access import source_ids
from saw.storage.models import Correlation, Finding, Investigation

FAMILY = {"web": "web", "waf": "waf", "zeek_conn": "network", "zeek_dns": "network", "zeek_ssl": "network",
          "zeek_http": "network", "suricata": "ids", "linux": "auth", "windows": "auth", "vpn": "auth",
          "db_audit": "db", "firewall": "network"}
WINDOW_SEC = 2 * 3600


def _ep(ts) -> float | None:
    if not ts:
        return None
    if isinstance(ts, datetime):
        return ts.timestamp()
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def _valid_ip(value) -> bool:
    try:
        ip_address(str(value))
        return True
    except ValueError:
        return False


def _identity_entities(finding) -> set[str]:
    return {value for value in finding.entities
            if value.startswith("domain:") or (value.startswith("ip:") and _valid_ip(value[3:]))}


def _skew(s: Session, inv_id: str) -> dict[str, float]:
    inv = s.get(Investigation, inv_id)
    return {k: float(v) for k, v in ((inv.settings or {}).get("clock_skew") or {}).items()}


def run_correlation(s: Session, inv_id: str) -> list[Correlation]:
    es = container.get().events
    skew = _skew(s, inv_id)
    s.execute(delete(Correlation).where(Correlation.investigation_id == inv_id))
    out: list[Correlation] = []
    # 1) same IP across source families (as src or dst)
    per_ip: dict[str, dict[str, dict]] = {}
    for field in ("src_ip", "dst_ip"):
        rows = es.group_by(inv_id, [Filter(field=field, op="exists")], [field, "data_source"],
                           [GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=20000)
        for r in rows:
            ip, ds = r["key"][field], r["key"]["data_source"]
            if not _valid_ip(ip):
                continue
            fam = FAMILY.get(ds, ds)
            d = per_ip.setdefault(ip, {}).setdefault(fam, {"count": 0, "first": None, "last": None, "sources": set(), "as": set()})
            d["count"] += r["count"]
            d["sources"].add(ds)
            d["as"].add(field)
            sk = skew.get(ds, 0.0)
            f, l = _ep(r["first"]), _ep(r["last"])
            if f is not None:
                f += sk
                d["first"] = f if d["first"] is None or f < d["first"] else d["first"]
            if l is not None:
                l += sk
                d["last"] = l if d["last"] is None or l > d["last"] else d["last"]
    for ip, fams in per_ip.items():
        if len(fams) < 2:
            continue
        spans = sorted(((fam, v) for fam, v in fams.items() if v["first"] is not None), key=lambda x: x[1]["first"])
        if len(spans) < 2:
            continue
        # time window: consecutive families must start within WINDOW_SEC of the previous family's activity
        gap_ok = all(b[1]["first"] - a[1]["last"] <= WINDOW_SEC for a, b in zip(spans, spans[1:], strict=False))
        steps = [{"family": fam, "sources": sorted(v["sources"]), "role": sorted(v["as"]), "count": v["count"],
                  "first": datetime.fromtimestamp(v["first"]).astimezone().isoformat(),
                  "last": datetime.fromtimestamp(v["last"]).astimezone().isoformat()} for fam, v in spans]
        c = Correlation(investigation_id=inv_id, kind="same_ip_cross_source", strength="strong" if gap_ok else "weak",
                        entity_keys=[f"ip:{ip}"], steps=steps,
                        explanation=f"{ip} 가 {' → '.join(f for f, _ in spans)} 에서 관찰"
                                    + ("" if gap_ok else f" (단계 간 간격 > {WINDOW_SEC // 3600}h, 약한 연결)"))
        s.add(c)
        out.append(c)
    # 2) finding-level chains: findings from different families sharing an entity within the window
    fs = s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars().all()
    fam_of = {f.id: ("network" if f.category.startswith("net.") else "web") for f in fs}
    for i, a in enumerate(fs):
        for b in fs[i + 1:]:
            if fam_of[a.id] == fam_of[b.id]:
                continue
            shared = sorted(_identity_entities(a) & _identity_entities(b))
            ta, tb = _ep(a.time_start), _ep(b.time_start)
            if not shared or ta is None or tb is None or abs(tb - ta) > WINDOW_SEC:
                continue
            first, second = (a, b) if ta <= tb else (b, a)
            c = Correlation(investigation_id=inv_id, kind="finding_chain", strength="strong", entity_keys=shared,
                            steps=[{"finding_id": x.id, "display_id": x.display_id, "title": x.title, "family": fam_of[x.id],
                                    "time": x.time_start.isoformat() if x.time_start else None,
                                    "_source_investigation_ids": sorted(source_ids(x))} for x in (first, second)],
                            explanation=f"{first.display_id} → {second.display_id}: 공통 {', '.join(shared)}")
            s.add(c)
            out.append(c)
    s.flush()
    return out
