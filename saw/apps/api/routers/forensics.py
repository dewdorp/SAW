"""PCAP forensic workspace API: capture summary, extracted files, cleartext-auth records, session stream view,
self-contained HTML report and CSV exports. All reads are scoped to the investigation; downloads are audited.
"""
from __future__ import annotations

import csv
import html
import io
import re
from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from saw import container
from saw.apps.api.deps import AuthContext, auth, client_ip, db
from saw.apps.api.routers.network import resolve_session
from saw.core.application import audit
from saw.core.application.analysis import finding_dict
from saw.core.application.investigations import require
from saw.core.schemas.query import AggRequest, Filter
from saw.core.security.masking import mask_text
from saw.integrations.pcap import ARTIFACTS, files_key
from saw.integrations.pcapkit.extract import session_streams
from saw.integrations.pcapkit.reader import PcapError
from saw.storage.models import Evidence, EvidenceFile, Finding, Investigation

router = APIRouter(prefix="/investigations/{inv_id}/forensics", tags=["forensics"])
FILES = Filter(field="data_source", value="zeek_files")
AUTH = Filter(field="data_source", value="pcap_auth")
NET_CATS = ("pcap.", "net.", "ioc.")
RISKY = {"executable", "script", "exploit_content", "archive", "unknown"}
SEV = ["critical", "high", "medium", "low", "info"]


def _ext(e: dict) -> dict:
    return (e.get("ext") or {}).get("zeek") or {}


def _net_findings(s: Session, inv_id: str) -> list[Finding]:
    rows = s.execute(select(Finding).where(Finding.investigation_id == inv_id)).scalars().all()
    return [f for f in rows if f.category.startswith(NET_CATS) and f.status not in ("false_positive", "duplicate")]


def _captures(s: Session, inv_id: str) -> list[dict]:
    out = []
    q = select(EvidenceFile, Evidence).join(Evidence, Evidence.id == EvidenceFile.evidence_id).where(
        Evidence.investigation_id == inv_id, EvidenceFile.parser_id.like("pcap%"))
    for f, e in s.execute(q).all():
        summ = next((x.get("pcap_summary") for x in (f.error_samples or []) if isinstance(x, dict) and "pcap_summary" in x), None)
        out.append({"evidence_id": e.id, "file_id": f.id, "name": f.display_name, "size": f.size, "sha256": f.sha256,
                    "engine": f.parser_id, "status": f.parse_status, "events": f.events_parsed, "note": f.message,
                    "summary": summ})
    return out


def _verdict(sev: Counter) -> dict:
    if sev["critical"] or sev["high"]:
        return {"level": "high", "text": "침해 정황 의심 — 높음 이상 탐지가 있습니다. 근거를 확인하고 판단하세요."}
    if sev["medium"]:
        return {"level": "medium", "text": "의심 활동 있음 — 보통 등급 탐지를 검토하세요."}
    return {"level": "low", "text": "특이 징후 낮음 — 자동 탐지 기준으로 높은 위험은 없습니다(미탐 가능성은 남음)."}


@router.get("/summary")
def summary(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    es = container.get().events
    fs = _net_findings(s, inv_id)
    sev = Counter(f.risk_level for f in fs)
    cats = es.aggregate(inv_id, [FILES], AggRequest(type="terms", field="ext.zeek.category", size=20))["buckets"]
    outcomes = es.aggregate(inv_id, [AUTH], AggRequest(type="terms", field="outcome", size=5))["buckets"]
    hist = es.aggregate(inv_id, [Filter(field="data_source", value="zeek_conn")], AggRequest(type="date_histogram", field="timestamp"))
    return {
        "captures": _captures(s, inv_id),
        "verdict": _verdict(sev),
        "severity": {k: sev.get(k, 0) for k in SEV},
        "counts": {
            "connections": es.count(inv_id, [Filter(field="data_source", value="zeek_conn")]),
            "http": es.count(inv_id, [Filter(field="data_source", value="zeek_http")]),
            "dns": es.count(inv_id, [Filter(field="data_source", value="zeek_dns")]),
            "tls": es.count(inv_id, [Filter(field="data_source", value="zeek_ssl")]),
            "files": es.count(inv_id, [FILES]),
            "masquerade": es.count(inv_id, [FILES, Filter(field="ext.zeek.masquerade", value=True)]),
            "auth": es.count(inv_id, [AUTH]),
            "ids_alerts": es.count(inv_id, [Filter(field="data_source", value="suricata"), Filter(field="event_type", value="suricata_alert")]),
        },
        "file_categories": cats,
        "auth_outcomes": outcomes,
        "traffic": hist,
        "findings": [{"id": f.id, "display_id": f.display_id, "title": f.title, "risk_level": f.risk_level,
                      "risk_score": f.risk_score, "category": f.category, "stage": f.stage, "time_start": f.time_start}
                     for f in sorted(fs, key=lambda x: -x.risk_score)],
    }


@router.get("/files")
def files(inv_id: str, category: str | None = None, masquerade: bool | None = None, limit: int = Query(500, le=5000),
          ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    flt = [FILES]
    if category:
        flt.append(Filter(field="ext.zeek.category", value=category))
    if masquerade is not None:
        flt.append(Filter(field="ext.zeek.masquerade", value=masquerade))
    evs = container.get().events.search(inv_id, flt, limit=limit)["events"]
    out = []
    for e in evs:
        x = _ext(e)
        out.append({"event_id": e["event_id"], "timestamp": e.get("timestamp"), "fuid": x.get("fuid"),
                    "session_id": e.get("session_id"), "source": x.get("source"), "direction": x.get("direction"),
                    "filename": x.get("filename"), "kind": x.get("kind"), "category": x.get("category"),
                    "mime_type": x.get("mime_type"), "declared_type": x.get("declared_type"),
                    "declared_category": x.get("declared_category"), "masquerade": bool(x.get("masquerade")),
                    "size": x.get("seen_bytes"), "missing_bytes": x.get("missing_bytes"), "entropy": x.get("entropy"),
                    "md5": x.get("md5"), "sha1": x.get("sha1"), "sha256": x.get("sha256"),
                    "tx": (x.get("tx_hosts") or [None])[0], "rx": (x.get("rx_hosts") or [None])[0],
                    "http_uri": x.get("http_uri"), "http_host": x.get("http_host"), "referrer": x.get("referrer"),
                    "extracted": bool(x.get("extracted")), "risky": x.get("category") in RISKY or bool(x.get("masquerade"))})
    return out


@router.get("/files/{sha256}/download")
def download_file(inv_id: str, sha256: str, request: Request, ctx: AuthContext = Depends(auth),
                  s: Session = Depends(db, scope="function")):
    """Extracted object as an inert attachment. Risky types get a `.infected` suffix (never served inline)."""
    require(s, ctx.principal, "investigation.write", inv_id)
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise HTTPException(400, "invalid sha256")
    es = container.get().events
    ev = es.search(inv_id, [FILES, Filter(field="hash", value=sha256)], limit=1)["events"]
    obj = container.get().objects
    if not ev or not obj.exists(ARTIFACTS, files_key(inv_id, sha256)):
        raise HTTPException(404, "extracted file not found in this investigation")
    x = _ext(ev[0])
    risky = x.get("category") in RISKY or x.get("masquerade")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", x.get("filename") or "file")[:80]
    name = f"{sha256[:16]}_{base}" + (".infected" if risky else "")
    with obj.open(ARTIFACTS, files_key(inv_id, sha256)) as fh:
        data = fh.read()
    audit.record(s, "forensics.file_download", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="file", target_id=sha256, investigation_id=inv_id,
                 detail={"filename": x.get("filename"), "category": x.get("category"), "risky": bool(risky)})
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Content-Type-Options": "nosniff"})


@router.get("/credentials")
def credentials(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Cleartext authentication attempts. Passwords are never stored — only length/weakness properties."""
    require(s, ctx.principal, "investigation.read", inv_id)
    evs = container.get().events.search(inv_id, [AUTH], limit=2000)["events"]
    return [{"event_id": e["event_id"], "timestamp": e.get("timestamp"), "protocol": e.get("protocol"), "user": e.get("user"),
             "outcome": e.get("outcome"), "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"), "dst_port": e.get("dst_port"),
             "password_length": _ext(e).get("password_length"), "password_weak": bool(_ext(e).get("password_weak")),
             "password_equals_user": bool(_ext(e).get("password_equals_user")), "session_id": e.get("session_id")}
            for e in evs]


@router.get("/certificates")
def certificates(inv_id: str, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Server certificates seen in clear (TLS <= 1.2), one row per destination + certificate, with the anomalies
    the TLS certificate detector looks at. TLS 1.3 sessions carry no visible certificate."""
    from datetime import datetime

    from saw.analyzers.ioc.observables import ip_scope

    require(s, ctx.principal, "investigation.read", inv_id)
    rows: dict[tuple, dict] = {}
    tls_sessions = 0
    for e in container.get().events.iterate(inv_id, [Filter(field="data_source", value="zeek_ssl")],
                                            fields=["timestamp", "dst_ip", "dst_port", "domain", "ext", "ja3s"]):
        tls_sessions += 1
        z = _ext(e)
        c = z.get("cert")
        if not c:
            continue
        r = rows.setdefault((e.get("dst_ip"), c.get("sha1")), {
            "dst_ip": e.get("dst_ip"), "dst_port": e.get("dst_port"), "external": ip_scope(str(e.get("dst_ip") or "")) == "external",
            "server_names": [], "subject_cn": c.get("subject_cn"), "issuer_cn": c.get("issuer_cn"), "san": c.get("san"),
            "not_before": c.get("not_before"), "not_after": c.get("not_after"), "self_signed": bool(c.get("self_signed")),
            "key": f"{c.get('key_type')}-{c.get('key_bits')}", "sha1": c.get("sha1"), "sha256": c.get("sha256"),
            "ja3s": e.get("ja3s"), "name_mismatch": False, "expired_at_use": False, "sessions": 0, "first": e.get("timestamp")})
        r["sessions"] += 1
        if e.get("domain") and e["domain"] not in r["server_names"] and len(r["server_names"]) < 10:
            r["server_names"].append(e["domain"])
        if z.get("cert_name_match") is False:
            r["name_mismatch"] = True
        try:
            if e.get("timestamp") and c.get("not_after") and datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) > datetime.fromisoformat(c["not_after"]):
                r["expired_at_use"] = True
        except ValueError:
            pass
    out = sorted(rows.values(), key=lambda r: (not r["external"], -(r["self_signed"] + r["name_mismatch"] + r["expired_at_use"]), -r["sessions"]))
    return {"tls_sessions": tls_sessions, "with_certificate": sum(r["sessions"] for r in out), "certificates": out[:500]}


def _render(b: bytes, limit: int) -> dict:
    """Printable view of untrusted bytes: masked text when mostly text, else a hex dump."""
    b = b[:limit]
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / max(1, len(b))
    if printable > 0.85:
        text = b.decode("utf-8", "replace")
        m = mask_text(text)
        return {"mode": "text", "text": m.text, "masked": m.kinds}
    rows = [f"{i:08x}  {b[i:i + 16].hex(' '):<47}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in b[i:i + 16])}"
            for i in range(0, min(len(b), 16384), 16)]
    return {"mode": "hex", "text": "\n".join(rows), "masked": []}


@router.get("/sessions/{event_id}/stream")
def stream(inv_id: str, event_id: str, request: Request, limit: int = Query(65536, le=262144),
           ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Reassembled client/server payload of the event's TCP session (masked text or hex), like 'Follow TCP Stream'."""
    require(s, ctx.principal, "investigation.read", inv_id)
    ev, _f, src, t0, t1 = resolve_session(s, inv_id, event_id)
    try:
        with open(src, "rb") as fh:
            st = session_streams(fh, (ev["src_ip"], int(ev["src_port"])), (ev["dst_ip"], int(ev["dst_port"])), t0, t1, cap=limit)
    except PcapError as x:
        raise HTTPException(422, f"PCAP 읽기 실패: {x}") from None
    audit.record(s, "forensics.stream_view", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="event", target_id=event_id, investigation_id=inv_id,
                 detail={"packets": st["packets"]})
    return {"client": st["client"], "server": st["server"], "packets": st["packets"],
            "client_view": _render(st["client_data"], limit), "server_view": _render(st["server_data"], limit),
            "client_bytes": len(st["client_data"]), "server_bytes": len(st["server_data"]),
            "missed_bytes": st["client_missed"] + st["server_missed"],
            "truncated": bool(st["client_truncated"] or st["server_truncated"])}


def _safe_cell(v) -> str:
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t  # spreadsheet formula injection


@router.get("/export/{kind}.csv")
def export_csv(inv_id: str, kind: str, request: Request, ctx: AuthContext = Depends(auth),
               s: Session = Depends(db, scope="function")):
    require(s, ctx.principal, "investigation.read", inv_id)
    if kind == "files":
        rows = files(inv_id, None, None, 5000, ctx, s)
        cols = ["timestamp", "source", "direction", "filename", "kind", "category", "declared_type", "masquerade", "size",
                "entropy", "md5", "sha1", "sha256", "tx", "rx", "http_uri", "referrer"]
    elif kind == "credentials":
        rows = credentials(inv_id, ctx, s)
        cols = ["timestamp", "protocol", "user", "outcome", "src_ip", "dst_ip", "dst_port", "password_length", "password_weak"]
    elif kind == "findings":
        rows = [finding_dict(f) for f in _net_findings(s, inv_id)]
        cols = ["display_id", "title", "risk_level", "risk_score", "confidence", "stage", "time_start", "time_end"]
    else:
        raise HTTPException(404, "unknown export (files, credentials, findings)")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([_safe_cell(r.get(c)) for c in cols])
    audit.record(s, "forensics.export", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="investigation", target_id=inv_id, investigation_id=inv_id,
                 detail={"kind": kind, "rows": len(rows)})
    return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="saw-{kind}.csv"'})


@router.get("/report.html")
def report(inv_id: str, request: Request, ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    """Self-contained forensic report (no scripts, all values escaped) for sharing or printing to PDF."""
    require(s, ctx.principal, "investigation.read", inv_id)
    inv = s.get(Investigation, inv_id)
    summ = summary(inv_id, ctx, s)
    fs = [finding_dict(f) for f in sorted(_net_findings(s, inv_id), key=lambda x: -x.risk_score)]
    fl = [f for f in files(inv_id, None, None, 2000, ctx, s) if f["risky"]]
    cr = credentials(inv_id, ctx, s)
    e = html.escape

    def table(head: list[str], rows: list[list]) -> str:
        return ("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" +
                "".join("<tr>" + "".join(f"<td>{e('' if c is None else str(c))}</td>" for c in r) + "</tr>" for r in rows) +
                "</table>")

    caps = table(["파일", "SHA-256", "패킷", "중복 제외", "추출 파일", "기간(UTC)"],
                 [[c["name"], c["sha256"], (c["summary"] or {}).get("packets"), (c["summary"] or {}).get("duplicates"),
                   (c["summary"] or {}).get("files_extracted"),
                   " ~ ".join(datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d %H:%M:%S") for t in
                              [(c["summary"] or {}).get("first_ts"), (c["summary"] or {}).get("last_ts")] if t)]
                  for c in summ["captures"]])
    finds = "".join(
        f"<section class='f {e(f['risk_level'])}'><h3>[{e(f['risk_level'].upper())}] {e(f['display_id'])} {e(f['title'])}</h3>"
        + table(["지표", "값"], [[m.get("label"), m.get("observed")] for m in f["metrics"]])
        + table(["확인 항목", "결과", "값"], [[c.get("label"), {True: "예", False: "아니오", None: "—"}[c.get("passed")], c.get("value")] for c in f["checks"]])
        + ("<p>ATT&amp;CK: " + e(", ".join(f"{a['technique_id']} {a['name']} ({a['confidence']})" for a in f["attack"])) + "</p>" if f["attack"] else "")
        + f"<pre>{e(f.get('explanation_md') or '')}</pre></section>" for f in fs)
    body = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>SAW PCAP 포렌식 보고서</title>
<style>body{{font-family:'Malgun Gothic','Segoe UI',sans-serif;margin:32px;color:#1d2330;font-size:13px}}h1{{font-size:22px}}
table{{border-collapse:collapse;margin:8px 0;width:100%}}td,th{{border:1px solid #ccd3dd;padding:4px 8px;text-align:left;vertical-align:top;word-break:break-all}}
th{{background:#eef1f5}}.f{{border-left:4px solid #999;padding:4px 12px;margin:14px 0}}.critical{{border-color:#c2185b}}.high{{border-color:#e65100}}
.medium{{border-color:#f9a825}}.low{{border-color:#1565c0}}pre{{white-space:pre-wrap;background:#f6f7f9;padding:8px}}.v{{padding:10px;background:#f6f7f9;border:1px solid #ccd3dd}}</style></head>
<body><h1>PCAP 포렌식 분석 보고서</h1>
<p>사건: {e(inv.display_id if inv else inv_id)} {e(inv.title if inv else '')} · 작성: {e(ctx.principal.username)} ·
생성: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} · SAW 자동 분석 결과이며 최종 판단은 분석가가 합니다.</p>
<div class="v"><b>요약 판단:</b> {e(summ['verdict']['text'])}<br>심각도별: {e(', '.join(f'{k} {v}' for k, v in summ['severity'].items()))}</div>
<h2>1. 분석 대상</h2>{caps}
<h2>2. 탐지 결과 ({len(fs)}건)</h2>{finds or '<p>탐지 없음</p>'}
<h2>3. 위험 파일 ({len(fl)}건)</h2>{table(['파일명', '실제 형식', '선언 형식', '위장', '크기', '엔트로피', 'SHA-256', '송신→수신'],
        [[f['filename'], f['kind'], f['declared_type'], '예' if f['masquerade'] else '', f['size'], f['entropy'], f['sha256'], f"{f['tx']} → {f['rx']}"] for f in fl])}
<h2>4. 평문 인증 ({len(cr)}건, 비밀번호 미보관)</h2>{table(['시각', '프로토콜', '계정', '결과', '출발지', '목적지', '취약 비밀번호'],
        [[c['timestamp'], c['protocol'], c['user'], c['outcome'], c['src_ip'], c['dst_ip'], '예' if c['password_weak'] else ''] for c in cr[:500]])}
</body></html>"""
    audit.record(s, "forensics.report", actor_id=ctx.principal.user_id, actor_name=ctx.principal.username,
                 actor_ip=client_ip(request), target_type="investigation", target_id=inv_id, investigation_id=inv_id)
    return HTMLResponse(body, headers={"Content-Disposition": 'attachment; filename="saw-pcap-report.html"',
                                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
