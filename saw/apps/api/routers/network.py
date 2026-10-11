"""Network (PCAP-derived) overview + visual network story (docs/20 §3-4)."""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from saw import container
from saw.apps.api.deps import AuthContext, auth, client_ip, db
from saw.core.application import audit
from saw.core.application.investigations import require
from saw.core.schemas.query import AggRequest, Filter, GroupMetric, TimeRange
from saw.core.security.masking import mask_text
from saw.integrations.pcap import ARTIFACTS, tools_available
from saw.integrations.pcapkit.extract import extract_session
from saw.integrations.pcapkit.reader import PcapError
from saw.storage.models import Evidence, EvidenceFile, Finding

router = APIRouter(prefix="/investigations/{inv_id}/network", tags=["network"])
CONN = Filter(field="data_source", value="zeek_conn")


@router.get("/overview")
def overview(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    es = container.get().events
    conns = es.count(inv_id, [CONN])
    if not conns and not es.count(inv_id, [Filter(field="data_source", op="prefix", value="zeek")]):
        return {"available": False, "tools": tools_available()}
    lo, hi = es.time_bounds(inv_id, [CONN])
    hosts = es.aggregate(inv_id, [CONN], AggRequest(type="cardinality", field="src_ip"))["value"]
    domains = es.aggregate(inv_id, [Filter(field="data_source", value="zeek_dns")], AggRequest(type="cardinality", field="domain"))["value"]
    proto = es.group_by(inv_id, [CONN], ["protocol"], [GroupMetric(type="sum", field="bytes_out", name="out"),
                                                       GroupMetric(type="sum", field="bytes_in", name="in")], size=15)
    talkers = es.group_by(inv_id, [CONN], ["src_ip"], [GroupMetric(type="sum", field="bytes_out", name="out"),
                                                       GroupMetric(type="sum", field="bytes_in", name="in")], size=200)
    dsts = es.group_by(inv_id, [CONN, Filter(field="dst_ip_scope", value="external")], ["dst_ip"],
                       [GroupMetric(type="sum", field="bytes_out", name="out")], size=200)
    doms = es.aggregate(inv_id, [Filter(field="data_source", value="zeek_dns")], AggRequest(type="terms", field="domain", size=10))
    edges = es.group_by(inv_id, [CONN], ["src_ip", "dst_ip", "protocol"], [GroupMetric(type="sum", field="bytes_out", name="out"),
                                                                          GroupMetric(type="sum", field="bytes_in", name="in")], size=3000)
    dns_edges = es.group_by(inv_id, [Filter(field="data_source", value="zeek_dns")], ["src_ip", "domain"], [], size=2000)
    nf = [f for f in s.execute(select(Finding).where(Finding.investigation_id == inv_id,
                                                     Finding.category.like("net.%"))).scalars()]
    flagged: dict[tuple, list[str]] = {}
    for f in nf:
        ips = [e.split(":", 1)[1] for e in f.entities if e.startswith("ip:")]
        if len(ips) >= 2:
            flagged.setdefault((ips[0], ips[1]), []).append(f.title.replace("Potential ", ""))
        for e in f.entities:
            if e.startswith("domain:") and ips:
                flagged.setdefault((ips[0], e.split(":", 1)[1]), []).append(f.title.replace("Potential ", ""))
    # story: top edges by volume + every flagged edge
    top = sorted(edges, key=lambda r: -((r["out"] or 0) + (r["in"] or 0)))[:20]
    keyset = {(r["key"]["src_ip"], r["key"]["dst_ip"]) for r in top}
    for r in edges:
        k = (r["key"]["src_ip"], r["key"]["dst_ip"])
        if k in flagged and k not in keyset:
            top.append(r)
            keyset.add(k)
    story = [{"src": r["key"]["src_ip"], "dst": r["key"]["dst_ip"], "protocol": r["key"]["protocol"], "conns": r["count"],
              "bytes_out": r["out"] or 0, "bytes_in": r["in"] or 0, "flags": flagged.get((r["key"]["src_ip"], r["key"]["dst_ip"]), [])}
             for r in top]
    top_dns = sorted(dns_edges, key=lambda r: -r["count"])[:6]
    story += [{"src": r["key"]["src_ip"], "dst": r["key"]["domain"], "protocol": "dns", "conns": r["count"], "bytes_out": 0,
               "bytes_in": 0, "flags": flagged.get((r["key"]["src_ip"], r["key"]["domain"]), [])} for r in top_dns]
    return {
        "available": True, "tools": tools_available(),
        "summary": {"time_range": [lo, hi], "connections": conns, "hosts": hosts, "domains": domains},
        "protocols": [{"protocol": r["key"]["protocol"] or "other", "bytes": (r["out"] or 0) + (r["in"] or 0), "conns": r["count"]} for r in proto],
        "top_talkers": sorted(({"ip": r["key"]["src_ip"], "bytes": (r["out"] or 0) + (r["in"] or 0)} for r in talkers), key=lambda x: -x["bytes"])[:10],
        "top_destinations": sorted(({"ip": r["key"]["dst_ip"], "bytes": r["out"] or 0} for r in dsts), key=lambda x: -x["bytes"])[:10],
        "top_domains": doms["buckets"],
        "findings": [{"id": f.id, "display_id": f.display_id, "title": f.title, "risk_level": f.risk_level} for f in
                     sorted(nf, key=lambda x: -x.risk_score)],
        "story": story,
    }


@router.get("/sessions/{event_id}/pcap")
def session_pcap(inv_id: str, event_id: str, request: Request, ctx: AuthContext = Depends(auth),
                 s: Session = Depends(db, scope="function")):
    """Download the packets of one session (the event's IP/port pair) from the original PCAP (built-in extractor)."""
    require(s, ctx.principal, "investigation.read", inv_id)
    ev, f, src, t0, t1 = resolve_session(s, inv_id, event_id)
    tmp = tempfile.NamedTemporaryFile(prefix="saw-sess-", suffix=".pcap", delete=False,
                                      dir=str(container.get().settings.data_dir))
    try:
        with open(src, "rb") as fh, tmp:
            left_out: dict = {}
            n = extract_session(fh, tmp, (ev["src_ip"], int(ev["src_port"])), (ev["dst_ip"], int(ev["dst_port"])), t0, t1,
                                proto=PROTO_NUMBER.get(str(ev.get("protocol") or "").lower()), info=left_out)
    except PcapError as x:
        Path(tmp.name).unlink(missing_ok=True)
        raise HTTPException(422, f"PCAP 읽기 실패: {x}") from None
    audit.record(s, "network.session_pcap", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="event", target_id=event_id, investigation_id=inv_id,
                 detail={"evidence_file": f.id, "packets": n, **{k: v for k, v in left_out.items() if v}})
    name = f"session_{ev['src_ip']}_{ev['src_port']}-{ev['dst_ip']}_{ev['dst_port']}.pcap".replace(":", "-")
    return FileResponse(tmp.name, media_type="application/vnd.tcpdump.pcap", filename=name,
                        headers={"X-SAW-Packets": str(n)}, background=BackgroundTask(Path(tmp.name).unlink, missing_ok=True))


PROTO_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132}
LINK_WINDOW_SEC = 300  # same IP/port pair within ±5 min = same session (ephemeral ports recycle slowly)
REQUEST_WINDOW_SEC = 5  # same client + path within ±5 s = same HTTP request seen by two sensors
TUPLE = ("src_ip", "src_port", "dst_ip", "dst_port")


def _pcap_file(s: Session, inv_id: str, ev: dict) -> EvidenceFile | None:
    parts = ((ev.get("raw_ref") or {}).get("object_key") or "").split("/")
    fid = parts[3] if len(parts) > 4 and parts[0] == ARTIFACTS else None
    f = s.get(EvidenceFile, fid) if fid else None
    e = s.get(Evidence, f.evidence_id) if f else None
    if f is None or e is None or e.investigation_id != inv_id or not (f.parser_id or "").startswith("pcap"):
        return None
    return f


def _window(ev: dict, seconds: int) -> TimeRange | None:
    if not ev.get("timestamp"):
        return None
    t = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
    return TimeRange(start=(t - timedelta(seconds=seconds)).isoformat(), end=(t + timedelta(seconds=seconds)).isoformat())


def _same_tuple(inv_id: str, ev: dict, extra: list[Filter], limit: int = 50) -> list[dict]:
    """Events with the same IP/port pair in either direction around the event's time."""
    if not all(ev.get(k) is not None for k in TUPLE):
        return []
    win = _window(ev, LINK_WINDOW_SEC)
    out: dict[str, dict] = {}
    for a, ap, b, bp in ((ev["src_ip"], ev["src_port"], ev["dst_ip"], ev["dst_port"]),
                         (ev["dst_ip"], ev["dst_port"], ev["src_ip"], ev["src_port"])):
        try:
            ports = (int(ap), int(bp))
        except (TypeError, ValueError):
            return []
        flt = [Filter(field="src_ip", value=a), Filter(field="src_port", value=ports[0]),
               Filter(field="dst_ip", value=b), Filter(field="dst_port", value=ports[1])] + extra
        for x in container.get().events.search(inv_id, flt, win, limit=limit)["events"]:
            out.setdefault(x["event_id"], x)
    return [x for x in out.values() if x["event_id"] != ev["event_id"]]


def linked_pcap_conn(s: Session, inv_id: str, ev: dict) -> tuple[dict, EvidenceFile] | None:
    """A PCAP-derived connection for the same session as `ev` (an NDR / log / IDS event), if a capture covers it."""
    for c in _same_tuple(inv_id, ev, [CONN], limit=10):
        f = _pcap_file(s, inv_id, c)
        if f is not None:
            return c, f
    return None


def resolve_session(s: Session, inv_id: str, event_id: str):
    """Event → (session event, pcap EvidenceFile, local pcap path, t0, t1).

    Events from other sources (NDR meta, firewall/web logs, Zeek logs) resolve through the PCAP-derived connection
    with the same IP/port pair and time window, so an NDR alert opens straight into the captured packets.
    """
    es = container.get().events
    ev = es.get(inv_id, event_id)
    if ev is None:
        raise HTTPException(404, "event not found")
    if not all(ev.get(k) is not None for k in TUPLE):
        raise HTTPException(400, "event has no IP/port pair")
    f = _pcap_file(s, inv_id, ev)
    if f is None:
        linked = linked_pcap_conn(s, inv_id, ev)
        if linked is None:
            raise HTTPException(409, "이 세션의 원본 패킷이 없습니다 — 같은 시간대의 PCAP을 이 조사에 올리면 연결됩니다")
        ev, f = linked
    t0 = t1 = None
    anchor = ev
    if ev.get("session_id") and ev.get("data_source") != "zeek_conn":
        hit = es.search(inv_id, [CONN, Filter(field="session_id", value=ev["session_id"])], limit=1)["events"]
        anchor = hit[0] if hit else ev
    if anchor.get("timestamp"):
        start = datetime.fromisoformat(anchor["timestamp"].replace("Z", "+00:00")).timestamp()
        dur = ((anchor.get("ext") or {}).get("zeek") or {}).get("duration")
        if isinstance(dur, (int, float)):
            t0, t1 = start - 1, start + dur + 1
    bucket = "saw-evidence-original" if f.parent_file_id is None else "saw-evidence-extracted"
    return ev, f, container.get().objects.local_path(bucket, f.object_key), t0, t1


SUMMARY = ("event_id", "timestamp", "data_source", "event_type", "src_ip", "src_port", "dst_ip", "dst_port", "method",
           "status_code", "domain", "bytes_out", "bytes_in", "parser", "source_file")


def _summary(e: dict) -> dict:
    out = {k: e.get(k) for k in SUMMARY if e.get(k) is not None}
    if e.get("uri"):
        out["uri"] = mask_text(str(e["uri"])[:300]).text
    return out


@router.get("/linked/{event_id}")
def linked_records(inv_id: str, event_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Records of the same session / request seen by other sensors (NDR meta, web log, WAF, PCAP), plus whether the
    captured packets of the session are available for stream view and session PCAP."""
    require(s, ctx.principal, "investigation.read", inv_id)
    es = container.get().events
    ev = es.get(inv_id, event_id)
    if ev is None:
        raise HTTPException(404, "event not found")
    groups: dict[tuple[str, str], list[dict]] = {}
    seen = {event_id}
    for x in _same_tuple(inv_id, ev, [Filter(field="evidence_id", op="is_not", value=ev.get("evidence_id"))]):
        seen.add(x["event_id"])
        groups.setdefault(("same_session", x["data_source"]), []).append(x)
    path = ev.get("url_path")
    if path and ev.get("src_ip"):
        flt = [Filter(field="src_ip", value=ev["src_ip"]), Filter(field="url_path", value=path),
               Filter(field="evidence_id", op="is_not", value=ev.get("evidence_id"))]
        for x in es.search(inv_id, flt, _window(ev, REQUEST_WINDOW_SEC), limit=20)["events"]:
            if x["event_id"] not in seen:
                seen.add(x["event_id"])
                groups.setdefault(("same_request", x["data_source"]), []).append(x)
    pcap = _pcap_file(s, inv_id, ev) is not None if all(ev.get(k) is not None for k in TUPLE) else False
    if not pcap and all(ev.get(k) is not None for k in TUPLE):
        pcap = linked_pcap_conn(s, inv_id, ev) is not None
    return {"pcap_session": pcap, "groups": [
        {"relation": rel, "data_source": ds, "count": len(evs),
         "events": [_summary(x) for x in sorted(evs, key=lambda e: e.get("timestamp") or "")[:20]]}
        for (rel, ds), evs in sorted(groups.items())]}
