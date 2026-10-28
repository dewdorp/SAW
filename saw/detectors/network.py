"""Network detectors over Zeek/Suricata data (docs/20 §6). Wording: 'Potential …', never 'Confirmed C2'."""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from saw.analyzers.ioc.observables import registered_domain
from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

CONN = Filter(field="data_source", value="zeek_conn")
DNS = Filter(field="data_source", value="zeek_dns")
TLS = Filter(field="data_source", op="in", value=["zeek_ssl"])
INTERNAL_SRC = Filter(field="src_ip_scope", value="internal")
EXTERNAL_DST = Filter(field="dst_ip_scope", value="external")


def _ep(ts: str | None) -> float | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else None


def _q(flt: list[Filter]) -> dict:
    return {"filters": [f.model_dump() for f in flt]}


def _samples(ctx: DetectorContext, flt: list[Filter], n: int = 20) -> list[str]:
    return [e["event_id"] for e in ctx.events.search(ctx.investigation_id, flt, limit=n)["events"]]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def _gb(n: float) -> str:
    return f"{n / 1024**3:.2f} GB" if n >= 1024**3 else f"{n / 1024**2:.1f} MB"


class LargeOutbound:
    id, version, category, stage = "net.large_outbound", "1.0.0", "net.large_outbound", "OUTBOUND"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_bytes": 100 * 1024**2, **ctx.params}
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [CONN, INTERNAL_SRC, EXTERNAL_DST], ["src_ip", "dst_ip"],
                                   [GroupMetric(type="sum", field="bytes_out", name="up"),
                                    GroupMetric(type="sum", field="bytes_in", name="down"),
                                    GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")],
                                   size=2000)
        ups = sorted((r["up"] or 0) for r in rows)
        med = statistics.median(ups) if ups else 0
        out = []
        for r in sorted(rows, key=lambda x: -(x["up"] or 0))[:5]:
            up, down = r["up"] or 0, r["down"] or 0
            if up < p["min_bytes"]:
                continue
            src, dst = r["key"]["src_ip"], r["key"]["dst_ip"]
            flt = [CONN, Filter(field="src_ip", value=src), Filter(field="dst_ip", value=dst)]
            ratio = up / max(1, down)
            out.append(FindingDraft(
                self.id, self.version, "Potential Large Outbound Transfer", self.category, self.stage,
                0.75, "high" if ratio >= 10 else "medium",
                [metric("bytes_out", up, {"min": 0, "max": round(med), "source": "relative:median_pair"}, "bytes", label="Bytes sent"),
                 metric("up_down_ratio", round(ratio, 1), label="Upload/Download ratio"),
                 metric("connections", r["count"], label="Connections")],
                [check("Internal → external", True, f"{src} → {dst}"),
                 check("Upload dominates", ratio >= 10, f"×{ratio:.1f}"),
                 check("Volume ≥ threshold", True, _gb(up))],
                [f"ip:{src}", f"ip:{dst}"], _q(flt), r["first"], r["last"], f"{self.id}:{src}:{dst}",
                attack=[AttackMap("T1041", "low", "대량 송신 + 다른 의심 신호 동반 시", condition_met=False,
                                  rationale="volume alone does not prove exfiltration")],
                explanation=f"{src} → {dst} 로 {_gb(up)} 송신 (수신 대비 ×{ratio:.1f}).",
                sample_event_ids=_samples(ctx, flt), total_events=r["count"]))
        return out


class PeriodicCommunication:
    id, version, category, stage = "net.periodic", "1.0.0", "net.periodic", "OUTBOUND"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_conns": 10, "max_cv": 0.15, **ctx.params}
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [CONN, INTERNAL_SRC, EXTERNAL_DST], ["src_ip", "dst_ip", "dst_port"], [],
                                   size=3000)
        out = []
        for r in rows:
            if r["count"] < p["min_conns"]:
                continue
            k = r["key"]
            flt = [CONN, Filter(field="src_ip", value=k["src_ip"]), Filter(field="dst_ip", value=k["dst_ip"]),
                   Filter(field="dst_port", value=k["dst_port"])]
            evs = list(ctx.events.iterate(inv, flt, fields=["timestamp", "bytes_out", "event_id"]))
            ts = sorted(x for x in (_ep(e.get("timestamp")) for e in evs) if x is not None)
            iv = [b - a for a, b in zip(ts, ts[1:], strict=False) if b - a > 0.5]
            if len(iv) < p["min_conns"] - 1:
                continue
            mean = statistics.fmean(iv)
            cv = statistics.pstdev(iv) / mean if mean else 9
            sizes = [e.get("bytes_out") or 0 for e in evs]
            size_cv = statistics.pstdev(sizes) / statistics.fmean(sizes) if sizes and statistics.fmean(sizes) else 0
            if cv > p["max_cv"]:
                continue
            med = statistics.median(iv)
            out.append(FindingDraft(
                self.id, self.version, "Potential Periodic Communication", self.category, self.stage,
                0.65, "high" if cv <= 0.05 and len(iv) >= 30 else "medium",
                [metric("connections", len(ts), label="Connections"), metric("interval_median_sec", round(med, 2), unit="s", label="Interval (median)"),
                 metric("interval_cv", round(cv, 3), label="Interval CV"), metric("size_cv", round(size_cv, 3), label="Payload size CV"),
                 {"name": "intervals", "label": "Intervals", "observed": None, "series": [round(x, 2) for x in iv[:300]]}],
                [check("Regular interval", True, f"every {med:.0f}s, CV {cv:.3f}"),
                 check("Consistent payload size", size_cv < 0.3, f"CV {size_cv:.2f}"),
                 check("Enough repetitions", True, f"n={len(ts)}")],
                [f"ip:{k['src_ip']}", f"ip:{k['dst_ip']}"], _q(flt),
                datetime.fromtimestamp(ts[0]).astimezone().isoformat(), datetime.fromtimestamp(ts[-1]).astimezone().isoformat(),
                f"{self.id}:{k['src_ip']}:{k['dst_ip']}:{k['dst_port']}",
                attack=[AttackMap("T1071.001", "low", "주기성 + 외부 HTTP(S)", condition_met=k.get("dst_port") in (80, 443, 8080, 8443),
                                  rationale="periodicity is consistent with beaconing but also with updaters/health checks")],
                explanation=f"{k['src_ip']} → {k['dst_ip']}:{k['dst_port']} 연결 {len(ts)}회, 간격 중앙값 {med:.1f}s (CV {cv:.3f}). "
                            "업데이트/헬스체크 등 정상 주기 통신 가능성도 확인 필요.",
                sample_event_ids=[e["event_id"] for e in evs[:20]], total_events=len(evs)))
        return out[:10]


class LongConnection:
    id, version, category, stage = "net.long_conn", "1.0.0", "net.long_conn", "OUTBOUND"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        flt = [CONN, EXTERNAL_DST, Filter(field="ext.zeek.duration", op="range", value={"gte": 3600})]
        evs = ctx.events.search(ctx.investigation_id, flt, limit=50)["events"]
        if not evs:
            return []
        longest = max(evs, key=lambda e: (e.get("ext") or {}).get("zeek", {}).get("duration") or 0)
        d = longest["ext"]["zeek"]["duration"]
        return [FindingDraft(self.id, self.version, "Potential Long-lived Connection", self.category, self.stage, 0.4, "medium",
                             [metric("connections", len(evs), label="Connections ≥1h"), metric("max_duration_sec", round(d), unit="s", label="Longest")],
                             [check("Duration ≥ 1h to external", True, f"{d / 3600:.1f} h")],
                             [f"ip:{longest.get('src_ip')}", f"ip:{longest.get('dst_ip')}"], _q(flt), longest.get("timestamp"),
                             longest.get("timestamp"), self.id, attack_unmapped_reason="duration alone does not imply a technique",
                             explanation=f"외부로 1시간 이상 유지된 연결 {len(evs)}건 (최장 {d / 3600:.1f}h).",
                             sample_event_ids=[e["event_id"] for e in evs[:20]], total_events=len(evs))]


class Scanning:
    id, version, category, stage = "net.scan", "1.0.0", "net.scan", "DISCOVERY"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_ports": 50, "min_hosts": 30, **ctx.params}
        inv = ctx.investigation_id
        out = []
        rows = ctx.events.group_by(inv, [CONN], ["src_ip", "dst_ip"], [GroupMetric(type="cardinality", field="dst_port", name="ports"),
                                                                    GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=2000)
        for r in rows:
            if r["ports"] < p["min_ports"]:
                continue
            src, dst = r["key"]["src_ip"], r["key"]["dst_ip"]
            flt = [CONN, Filter(field="src_ip", value=src), Filter(field="dst_ip", value=dst)]
            fails = ctx.events.count(inv, flt + [Filter(field="ext.zeek.conn_state", op="in", value=["REJ", "S0", "RSTOS0", "RSTR"])])
            internal = r["key"]["src_ip"] and ctx.events.count(inv, flt + [INTERNAL_SRC]) > 0
            out.append(FindingDraft(self.id, self.version, "Potential Port Scanning", self.category, self.stage, 0.55,
                                    "high" if fails / r["count"] > 0.5 else "medium",
                                    [metric("distinct_ports", r["ports"], label="Distinct ports"), metric("connections", r["count"], label="Connections"),
                                     metric("failed_ratio", round(fails / r["count"], 3), label="Failed/rejected ratio")],
                                    [check("Many ports on one host", True, f"{r['ports']} ports"),
                                     check("Mostly failed handshakes", fails / r["count"] > 0.5, f"{fails}/{r['count']}")],
                                    [f"ip:{src}", f"ip:{dst}"], _q(flt), r["first"], r["last"], f"{self.id}:port:{src}:{dst}",
                                    attack=[AttackMap("T1046" if internal else "T1595.001", "high" if internal else "medium",
                                                      "내부 출발지면 T1046, 외부면 T1595.001")],
                                    explanation=f"{src} → {dst} 에서 {r['ports']}개 포트 접속 시도 (실패 {fails}).",
                                    sample_event_ids=_samples(ctx, flt), total_events=r["count"]))
        rows = ctx.events.group_by(inv, [CONN], ["src_ip", "dst_port"], [GroupMetric(type="cardinality", field="dst_ip", name="hosts"),
                                                                       GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=2000)
        for r in rows:
            if r["hosts"] < p["min_hosts"]:
                continue
            src, port = r["key"]["src_ip"], r["key"]["dst_port"]
            flt = [CONN, Filter(field="src_ip", value=src), Filter(field="dst_port", value=port)]
            out.append(FindingDraft(self.id, self.version, "Potential Host Scanning", self.category, self.stage, 0.5, "medium",
                                    [metric("distinct_hosts", r["hosts"], label="Distinct hosts"), metric("port", port, label="Port")],
                                    [check("Many hosts on one port", True, f"{r['hosts']} hosts : {port}")],
                                    [f"ip:{src}"], _q(flt), r["first"], r["last"], f"{self.id}:host:{src}:{port}",
                                    attack=[AttackMap("T1046", "medium", "동일 포트 다수 호스트")],
                                    explanation=f"{src} 가 포트 {port}로 {r['hosts']}개 호스트에 접속.",
                                    sample_event_ids=_samples(ctx, flt), total_events=r["count"]))
        return out


class DnsAnomaly:
    id, version, category, stage = "net.dns_anomaly", "1.0.0", "net.dns_anomaly", "OUTBOUND"
    data_sources = {"zeek_dns"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_subdomains": 50, "min_entropy": 3.3, **ctx.params}
        inv = ctx.investigation_id
        per: dict[str, dict] = defaultdict(lambda: {"subs": set(), "count": 0, "nx": 0, "txt": 0, "srcs": set(),
                                                    "first": None, "last": None})
        for e in ctx.events.iterate(inv, [DNS], fields=["domain", "src_ip", "timestamp", "ext"]):
            q = (e.get("domain") or "").lower().rstrip(".")
            if not q or "." not in q:
                continue
            rd = registered_domain(q)
            d = per[rd]
            sub = q[: -len(rd)].rstrip(".")
            if sub:
                d["subs"].add(sub)
            d["count"] += 1
            z = (e.get("ext") or {}).get("zeek", {})
            if z.get("rcode_name") == "NXDOMAIN":
                d["nx"] += 1
            if z.get("qtype_name") == "TXT":
                d["txt"] += 1
            d["srcs"].add(e.get("src_ip"))
            ts = e.get("timestamp")
            d["first"] = d["first"] or ts
            d["last"] = ts or d["last"]
        out = []
        for rd, d in sorted(per.items(), key=lambda x: -len(x[1]["subs"])):
            if len(d["subs"]) < p["min_subdomains"]:
                continue
            ent = statistics.fmean(_entropy(s.split(".")[0]) for s in d["subs"])
            avg_len = statistics.fmean(len(s) for s in d["subs"])
            if ent < p["min_entropy"] and d["txt"] / max(1, d["count"]) < 0.3:
                continue
            flt = [DNS, Filter(field="domain", op="contains", value=rd)]
            out.append(FindingDraft(
                self.id, self.version, "Potential DNS Tunneling / Anomalous Subdomains", self.category, self.stage, 0.65,
                "high" if ent >= 3.8 and len(d["subs"]) >= 200 else "medium",
                [metric("queries", d["count"], label="Queries"), metric("unique_subdomains", len(d["subs"]), label="Unique subdomains"),
                 metric("label_entropy", round(ent, 2), label="Label entropy"), metric("avg_label_length", round(avg_len, 1), label="Avg label length"),
                 metric("nxdomain_ratio", round(d["nx"] / d["count"], 3), label="NXDOMAIN ratio"),
                 metric("txt_ratio", round(d["txt"] / d["count"], 3), label="TXT ratio")],
                [check("High-entropy labels", ent >= p["min_entropy"], f"{ent:.2f} bits"),
                 check("Many unique subdomains", True, str(len(d["subs"]))),
                 check("TXT heavy", d["txt"] / d["count"] >= 0.3, f"{d['txt']}/{d['count']}")],
                [f"domain:{rd}"] + [f"ip:{s}" for s in list(d["srcs"])[:5] if s], _q(flt), d["first"], d["last"],
                f"{self.id}:{rd}",
                attack=[AttackMap("T1071.004", "medium", "고엔트로피 서브도메인 다수", condition_met=ent >= 3.5),
                        AttackMap("T1572", "low", "터널링 의심", condition_met=ent >= 3.8 and len(d["subs"]) >= 200)],
                explanation=f"{rd} 에 대해 고유 서브도메인 {len(d['subs'])}개, 평균 엔트로피 {ent:.2f}.",
                sample_event_ids=_samples(ctx, flt), total_events=d["count"]))
        return out[:5]


class TlsRarity:
    id, version, category, stage = "net.tls_rarity", "1.0.0", "net.tls_rarity", "INFRASTRUCTURE"
    data_sources = {"zeek_ssl"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [TLS, Filter(field="ja4", op="exists")], ["ja4"],
                                   [GroupMetric(type="cardinality", field="src_ip", name="hosts"),
                                    GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=500)
        if len(rows) < 3:
            return []
        out = []
        for r in rows:
            if r["hosts"] != 1:
                continue
            ja4 = r["key"]["ja4"]
            flt = [TLS, Filter(field="ja4", value=ja4)]
            dsts = ctx.events.aggregate(inv, flt, AggRequest(type="terms", field="domain", size=3))["buckets"]
            out.append(FindingDraft(self.id, self.version, "Potential Rare TLS Client Fingerprint", self.category, self.stage, 0.35, "low",
                                    [metric("hosts_using", 1, label="Hosts using JA4"), metric("handshakes", r["count"], label="Handshakes"),
                                     metric("distinct_ja4", len(rows), label="Distinct JA4 in capture")],
                                    [check("Used by a single host", True, ja4),
                                     check("Destinations", None, ", ".join(str(b["key"]) for b in dsts) or "no SNI")],
                                    [f"ja4:{ja4}"], _q(flt), r["first"], r["last"], f"{self.id}:{ja4}",
                                    attack_unmapped_reason="fingerprint rarity is a hunting lead, not a technique",
                                    explanation=f"JA4 {ja4} 는 캡처 내 단일 호스트만 사용.",
                                    sample_event_ids=_samples(ctx, flt), total_events=r["count"]))
        return out[:5]


class UnexpectedProtocol:
    id, version, category, stage = "net.unexpected_protocol", "1.0.0", "net.unexpected_protocol", "OUTBOUND"
    data_sources = {"zeek_conn"}
    EXPECT = {443: {"ssl"}, 22: {"ssh"}, 53: {"dns"}, 80: {"http"}, 25: {"smtp"}}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        out = []
        for port, ok in self.EXPECT.items():
            flt = [CONN, Filter(field="dst_port", value=port), Filter(field="ext.zeek.service", op="exists"),
                   Filter(field="ext.zeek.service", op="not_in", value=sorted(ok))]
            n = ctx.events.count(inv, flt)
            if not n:
                continue
            svc = ctx.events.aggregate(inv, flt, AggRequest(type="terms", field="ext.zeek.service", size=3))["buckets"]
            lo, hi = ctx.events.time_bounds(inv, flt)
            out.append(FindingDraft(self.id, self.version, f"Potential Unexpected Protocol on Port {port}", self.category, self.stage,
                                    0.45, "medium", [metric("connections", n, label="Connections")],
                                    [check("Service ≠ port convention", True, ", ".join(f"{b['key']} ({b['count']})" for b in svc))],
                                    [], _q(flt), lo, hi, f"{self.id}:{port}",
                                    attack=[AttackMap("T1571", "low", "비표준 포트 사용 + C2 의심 신호 동반 시", condition_met=False)],
                                    explanation=f"포트 {port}에서 예상({','.join(ok)})과 다른 서비스 감지.",
                                    sample_event_ids=_samples(ctx, flt), total_events=n))
        return out


class IdsAlerts:
    id, version, category, stage = "net.ids_alerts", "1.0.0", "net.ids_alerts", "EXPLOITATION"
    data_sources = {"suricata"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        flt0 = [Filter(field="data_source", value="suricata"), Filter(field="event_type", value="suricata_alert")]
        rows = ctx.events.group_by(inv, flt0, ["ext.suricata.alert.signature_id"],
                                   [GroupMetric(type="cardinality", field="src_ip", name="srcs"),
                                    GroupMetric(type="min_ts", name="first"), GroupMetric(type="max_ts", name="last")], size=50)
        out = []
        for r in rows:
            sid = r["key"]["ext.suricata.alert.signature_id"]
            flt = flt0 + [Filter(field="ext.suricata.alert.signature_id", value=sid)]
            ev = ctx.events.search(inv, flt, limit=1)["events"][0]
            a = (ev.get("ext") or {}).get("suricata", {}).get("alert", {})
            md = a.get("metadata") or {}
            attack = []
            for tid in (md.get("mitre_technique_id") or []):
                attack.append(AttackMap(tid, "medium", "Suricata rule metadata", rationale=f"sid {sid}", source="rule_metadata"))
            sev = {1: 0.75, 2: 0.5, 3: 0.3}.get(a.get("severity"), 0.3)
            d = FindingDraft(self.id, self.version, f"IDS Alert: {a.get('signature', sid)}", self.category,
                             "EXPLOITATION" if "exploit" in str(a.get("category", "")).lower() else "RECON" if "scan" in str(a.get("category", "")).lower() else "OUTBOUND",
                             sev, "medium", [metric("alerts", r["count"], label="Alerts"), metric("sources", r["srcs"], label="Sources")],
                             [check("Signature match (Suricata)", True, f"sid {sid}", a.get("category", "")),
                              check("Rule-provided ATT&CK metadata", bool(attack), ", ".join(md.get("mitre_technique_id") or []) or "none")],
                             [f"ip:{ev.get('src_ip')}", f"ip:{ev.get('dst_ip')}"], _q(flt), r["first"], r["last"], f"{self.id}:{sid}",
                             attack=attack, attack_unmapped_reason=None if attack else "rule has no ATT&CK metadata",
                             explanation=f"Suricata 시그니처 {sid} 경보 {r['count']}건. 시그니처 매칭은 공격 '시도'의 근거이며 성공 여부는 별도 확인 필요.",
                             # A signature match (and the device's own severity) never shows that an attack worked.
                             success_signal=False,
                             sample_event_ids=_samples(ctx, flt), total_events=r["count"])
            out.append(d)
        return out


NETWORK_DETECTORS = [LargeOutbound(), PeriodicCommunication(), LongConnection(), Scanning(), DnsAnomaly(), TlsRarity(),
                     UnexpectedProtocol(), IdsAlerts()]
