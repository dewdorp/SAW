"""Anomaly detectors (docs/28): Rule → Statistics → Baseline → (light) ML. Always explain 'compared to what'.

History baselines come from investigations closed as normal / false_positive (never from confirmed attacks — T-20).
When no history exists, comparisons are relative within the investigation and labelled as such.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

WEB = Filter(field="data_source", op="in", value=["web", "waf"])


def _ep(ts: str | None) -> float | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else None


def _q(flt: list[Filter]) -> dict:
    return {"filters": [f.model_dump() for f in flt]}


def robust_z(x: float, xs: list[float]) -> float:
    med = statistics.median(xs)
    mad = statistics.median([abs(v - med) for v in xs]) or 1e-9
    return 0.6745 * (x - med) / mad


class VolumeSpike:
    """Per-URI request rate in 5-minute buckets vs the URI's own robust baseline (median+MAD of other buckets)."""

    id, version, category, stage = "anomaly.volume", "1.0.0", "anomaly.volume", "DATA_ACCESS"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"z": 5.0, "min_buckets": 6, "bucket": 300, **ctx.params}
        inv = ctx.investigation_id
        tops = ctx.events.aggregate(inv, [WEB], AggRequest(type="terms", field="uri_template", size=15))["buckets"]
        out = []
        for t in tops:
            tpl = t["key"]
            flt = [WEB, Filter(field="uri_template", value=tpl)]
            h = ctx.events.aggregate(inv, flt, AggRequest(type="date_histogram", field="timestamp", interval_sec=p["bucket"]))
            b = h["buckets"]
            if len(b) < p["min_buckets"]:
                continue
            # fill empty buckets with 0 so quiet periods count toward the baseline
            lo, hi = b[0]["key"], b[-1]["key"]
            m = {x["key"]: x["count"] for x in b}
            series = [m.get(k, 0) for k in range(lo, hi + p["bucket"], p["bucket"])]
            peak_i = max(range(len(series)), key=lambda i: series[i])
            peak = series[peak_i]
            rest = series[:peak_i] + series[peak_i + 1:]
            if len(rest) < p["min_buckets"] - 1:
                continue
            z = robust_z(peak, rest)
            if z < p["z"] or peak < 20:
                continue
            med = statistics.median(rest)
            q = sorted(rest)
            band = [q[int(len(q) * 0.05)], q[min(len(q) - 1, int(len(q) * 0.95))]]
            per_min = round(peak / (p["bucket"] / 60), 1)
            start = datetime.fromtimestamp(lo + peak_i * p["bucket"]).astimezone().isoformat()
            out.append(FindingDraft(
                self.id, self.version, "Potential Volume Anomaly", self.category, self.stage, 0.45,
                "high" if z >= 10 else "medium",
                [metric("requests_per_min", per_min, {"min": round(band[0] / 5, 1), "max": round(band[1] / 5, 1),
                                                      "source": "relative:same_uri_other_buckets(p05-p95)"}, "req/min", label="Peak rate"),
                 metric("robust_z", round(z, 1), label="Robust z-score"), metric("median_per_bucket", med, label="Median per 5m"),
                 {"name": "rate_series", "label": "5-min series", "observed": None, "series": series[:500], "band": band, "bucket_sec": p["bucket"]}],
                [check("Peak far above own baseline", True, f"z={z:.1f}", "median + MAD (robust)"),
                 check("Baseline from history", False, "Investigation 내부 시간 구간 비교", "history baseline 없음")],
                [f"uri_template:{tpl}"], _q(flt), start, None, f"{self.id}:{tpl}",
                attack_unmapped_reason="volume deviation is a lead, not a technique",
                explanation=f"`{tpl}` 5분 구간 최대 {peak}건 (중앙값 {med}) — robust z {z:.1f}.",
                total_events=sum(series)))
        return out[:5]


class RareValue:
    """User-Agents / JA4 never seen in history (closed normal investigations); else rarity within the investigation."""

    id, version, category, stage = "anomaly.rare", "1.0.0", "anomaly.rare", "INFRASTRUCTURE"
    data_sources = {"web", "waf", "zeek_ssl"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        hist = (ctx.params or {}).get("history") or {}
        inv = ctx.investigation_id
        out = []
        for field in ("user_agent", "ja4"):
            known = set(hist.get(field, []))
            vals = ctx.events.aggregate(inv, [Filter(field=field, op="exists")], AggRequest(type="terms", field=field, size=500))
            total = vals["total"] or 1
            if not known:
                continue  # no history → skip (relative rarity is already covered by tls_rarity/scripted detectors)
            new = [b for b in vals["buckets"] if b["key"] not in known and b["count"] / total >= 0.01]
            for b in new[:3]:
                flt = [Filter(field=field, value=b["key"])]
                lo, hi = ctx.events.time_bounds(inv, flt)
                out.append(FindingDraft(self.id, self.version, f"Potential New {field.replace('_', '-').upper()} (first seen)",
                                        self.category, self.stage, 0.3, "medium",
                                        [metric("events", b["count"], label="Events"), metric("share", round(b["count"] / total, 3), label="Share"),
                                         metric("history_values", len(known), label="Known values in history")],
                                        [check("Not seen in history baseline", True, str(b["key"])[:80], "closed normal/FP investigations")],
                                        [f"{'user_agent' if field == 'user_agent' else 'ja4'}:{b['key']}"], _q(flt), lo, hi,
                                        f"{self.id}:{field}:{b['key']}"[:250], attack_unmapped_reason="novelty is context",
                                        explanation=f"{field} `{b['key']}` 는 과거(정상 종결) 데이터에 없던 값.", total_events=b["count"]))
        return out


class SequenceAnomaly:
    """1st-order Markov model of per-session URI sequences; flags sessions with very low per-step log-likelihood."""

    id, version, category, stage = "anomaly.sequence", "1.0.1", "anomaly.sequence", "DATA_ACCESS"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_len": 5, "min_sessions": 30, **ctx.params}
        inv = ctx.investigation_id
        seqs: dict[str, list[str]] = defaultdict(list)
        pending: dict[str, list[tuple]] = defaultdict(list)
        excluded: set[str] = set()
        record_ordered: Counter = Counter()
        bucket = None
        n, truncated = 0, False

        def exclude(key):
            excluded.add(key)
            seqs.pop(key, None)

        def flush():
            for key, actions in pending.items():
                if key in excluded:
                    continue
                if len({row[0] for row in actions}) > 1:
                    # File positions establish record order only within the same source.
                    source = actions[0][1]
                    positions = None
                    if source and all(row[1] == source for row in actions):
                        if all(type(row[2]) is int and row[2] >= 0 for row in actions):
                            positions = [row[2] for row in actions]
                        elif all(row[2] is None and type(row[3]) is int and row[3] > 0 for row in actions):
                            positions = [row[3] for row in actions]
                    if positions is None or len(set(positions)) != len(actions):
                        exclude(key)
                        continue
                    actions = [row for _, row in sorted(zip(positions, actions), key=lambda item: item[0])]
                    record_ordered[key] += 1
                for step, _source, _offset, _line in actions:
                    if not seqs[key] or seqs[key][-1] != step:
                        seqs[key].append(step)
            pending.clear()

        for e in ctx.events.iterate(inv, [WEB, Filter(field="url_path", op="exists")],
                                    fields=["session_id", "src_ip", "user_agent", "url_path", "uri_template",
                                            "timestamp", "raw_ref"]):
            if n >= 300_000:
                truncated = True
                # A limit inside an equal-time batch must not choose a random ID-ordered prefix.
                for key in pending:
                    exclude(key)
                pending.clear()
                break
            n += 1
            key = e.get("session_id") or f"{e.get('src_ip')}|{e.get('user_agent')}"
            try:
                dt = datetime.fromisoformat(e.get("timestamp") or "")
                timestamp = dt.timestamp() if dt.tzinfo is not None else None
                if timestamp is None or not math.isfinite(timestamp):
                    raise ValueError
            except (TypeError, ValueError, OverflowError, OSError):
                exclude(key)
                continue
            if timestamp != bucket:
                flush()
                bucket = timestamp
            if key in excluded:
                continue
            step = (e.get("uri_template") or e.get("url_path") or "").split("?")[0]
            ref = e.get("raw_ref")
            ref = ref if isinstance(ref, dict) else {}
            source = ref.get("object_key")
            pending[key].append((step, source if isinstance(source, str) else None,
                                 ref.get("offset"), ref.get("line_no")))
        flush()
        coverage = []
        if excluded or truncated:
            coverage.append(FindingDraft(
                self.id, self.version, "행동 순서 분석 범위 확인 필요", "anomaly.sequence.coverage", self.stage,
                0.1, "low",
                [metric("excluded_sessions", len(excluded), label="순서 평가에서 제외한 세션"),
                 metric("scanned_events", n, label="읽은 기록")],
                [check("행동 순서 평가 범위", False, len(excluded),
                       f"시각·같은 원문의 고유 위치 확인 불가 또는 입력 상한 도달={truncated}")],
                [], _q([WEB]), None, None, self.id + ":coverage", success_signal=False,
                attack_unmapped_reason="순서 평가 범위 안내",
                explanation=("시각이나 같은 시각의 기록 순서를 확인할 수 없는 세션은 순서 모델에서 제외했습니다. "
                             "제외는 정상 판정이 아니며 해당 세션의 순서 이상을 놓칠 수 있습니다. "
                             "원문 위치·시각 정밀도와 처리 범위를 확인하세요.")))
        sessions = [s for s in seqs.values() if len(s) >= 2]
        if len(sessions) < p["min_sessions"]:
            return coverage
        trans: dict[str, Counter] = defaultdict(Counter)
        starts = Counter()
        for s in sessions:
            starts[s[0]] += 1
            for a, b in zip(s, s[1:], strict=False):
                trans[a][b] += 1
        vocab = len({x for s in sessions for x in s}) + 1

        def ll(s: list[str]) -> float:
            v = math.log((starts[s[0]] + 1) / (len(sessions) + vocab))
            for a, b in zip(s, s[1:], strict=False):
                v += math.log((trans[a][b] + 1) / (sum(trans[a].values()) + vocab))
            return v / len(s)

        scored = sorted(((ll(s), k, s) for k, s in seqs.items() if len(s) >= p["min_len"]), key=lambda x: (x[0], x[1]))
        if not scored:
            return coverage
        all_scores = sorted(ll(s) for s in sessions)
        thr = all_scores[max(0, int(len(all_scores) * 0.001))]
        common = sorted(Counter(tuple(s[:3]) for s in sessions if len(s) >= 3).items(), key=lambda item: (-item[1], item[0]))[:1]
        out = []
        for score, key, s in scored[:3]:
            if score > thr:
                break
            rarity = sum(1 for x in all_scores if x <= score) / len(all_scores)
            src = key.split("|")[0]
            flt = [WEB, Filter(field="src_ip", value=src)] if "|" in key else [WEB, Filter(field="session_id", value=key)]
            out.append(FindingDraft(self.id, self.version, "Potential Anomalous Action Sequence", self.category, self.stage, 0.4,
                                    "medium",
                                    [metric("sequence_rarity", round(rarity, 5), label="Sequence rarity (percentile)"),
                                     metric("log_likelihood_per_step", round(score, 2), {"min": round(thr, 2), "max": round(statistics.median(all_scores), 2),
                                                                                       "source": "relative:session_markov"}, label="Log-likelihood/step"),
                                     {"name": "sequence", "label": "Sequence", "observed": None, "observed_path": s[:12],
                                      "normal_path": list(common[0][0]) if common else []}],
                                    [check("Below 0.1% likelihood threshold", True, f"{score:.2f} ≤ {thr:.2f}"),
                                     check("Long enough to judge", True, f"{len(s)} actions"),
                                     check("동일 시각의 원문 기록 순서", None, record_ordered[key],
                                           "같은 원문의 고유 위치로 복구한 기록 순서이며 실제 실행 순서·인과관계의 확정은 아닙니다.")],
                                    [f"ip:{src}"] if "|" in key else [f"session:{key}"], _q(flt), None, None,
                                    f"{self.id}:{key}"[:250], attack_unmapped_reason="sequence rarity is behavioural context",
                                    explanation=f"세션 행동 순서 {' → '.join(s[:6])} … 가 다른 세션 대비 매우 드묾 (하위 {rarity:.3%}).",
                                    total_events=len(s)))
        if coverage:
            for finding in out:
                finding.checks.append(check("전체 세션 평가", False, len(excluded), "일부 세션 제외 또는 처리 상한"))
        return out + coverage


class EntityPeerOutlier:
    """HBOS-style explainable outlier score per source IP over (requests, unique paths, 4xx ratio, bytes)."""

    id, version, category, stage = "anomaly.entity", "1.0.0", "anomaly.entity", "DATA_ACCESS"
    data_sources = {"web", "waf"}
    FEATS = ["requests", "unique_paths", "error_ratio", "bytes"]

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [WEB], ["src_ip"], [GroupMetric(type="cardinality", field="url_path", name="paths"),
                                                           GroupMetric(type="sum", field="bytes_out", name="bytes")], size=5000)
        if len(rows) < 30:
            return []
        err = {r["key"]["src_ip"]: r["count"] for r in ctx.events.group_by(
            inv, [WEB, Filter(field="status_class", value="4xx")], ["src_ip"], [], size=5000)}
        X = {r["key"]["src_ip"]: {"requests": r["count"], "unique_paths": r["paths"] or 0,
                                  "error_ratio": err.get(r["key"]["src_ip"], 0) / r["count"], "bytes": r["bytes"] or 0} for r in rows}
        bins = 10
        dens: dict[str, tuple[float, float, list[int]]] = {}
        for f in self.FEATS:
            vals = [math.log1p(v[f]) if f != "error_ratio" else v[f] for v in X.values()]
            lo, hi = min(vals), max(vals)
            w = (hi - lo) / bins or 1
            hist = [0] * bins
            for v in vals:
                hist[min(bins - 1, int((v - lo) / w))] += 1
            dens[f] = (lo, w, hist)
        scores = []
        for ip, v in X.items():
            contrib = {}
            for f in self.FEATS:
                lo, w, hist = dens[f]
                x = math.log1p(v[f]) if f != "error_ratio" else v[f]
                h = hist[min(bins - 1, int((x - lo) / w))] / len(X)
                contrib[f] = -math.log(h + 1e-6)
            scores.append((sum(contrib.values()), ip, contrib))
        scores.sort(reverse=True)
        allv = [s[0] for s in scores]
        thr = statistics.median(allv) + 3 * (statistics.pstdev(allv) or 1)
        out = []
        med = {f: statistics.median(v[f] for v in X.values()) for f in self.FEATS}
        for sc, ip, contrib in scores[:3]:
            if sc < thr:
                break
            top = sorted(contrib.items(), key=lambda x: -x[1])[:3]
            flt = [WEB, Filter(field="src_ip", value=ip)]
            out.append(FindingDraft(self.id, self.version, "Potential Entity Behaviour Outlier", self.category, self.stage, 0.4, "medium",
                                    [metric(f, round(X[ip][f], 3), {"min": 0, "max": round(med[f], 3), "source": "relative:peer_median"}, label=f)
                                     for f, _ in top] + [metric("hbos_score", round(sc, 2), label="HBOS score")],
                                    [check("Outlier vs peers (HBOS)", True, f"{sc:.1f} > {thr:.1f}"),
                                     check("Top contributing features", None, ", ".join(f for f, _ in top))],
                                    [f"ip:{ip}"], _q(flt), None, None, f"{self.id}:{ip}",
                                    attack_unmapped_reason="statistical outlier — needs analyst interpretation",
                                    explanation=f"{ip} 의 행동이 동료 출발지 대비 이례적 (기여: {', '.join(f for f, _ in top)}).",
                                    total_events=X[ip]["requests"]))
        return out


class NewRelationship:
    """Internal host ↔ external destination pairs never seen in history baselines (first-seen edges)."""

    id, version, category, stage = "anomaly.relationship", "1.0.0", "anomaly.relationship", "OUTBOUND"
    data_sources = {"zeek_conn"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        known = set(map(tuple, (ctx.params or {}).get("history", {}).get("edges", [])))
        if not known:
            return []
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [Filter(field="data_source", value="zeek_conn"), Filter(field="src_ip_scope", value="internal"),
                                         Filter(field="dst_ip_scope", value="external")], ["src_ip", "dst_ip"],
                                   [GroupMetric(type="sum", field="bytes_out", name="bytes"), GroupMetric(type="min_ts", name="first")], size=5000)
        new = [r for r in rows if (r["key"]["src_ip"], r["key"]["dst_ip"]) not in known]
        new.sort(key=lambda r: -(r["bytes"] or 0))
        out = []
        for r in new[:3]:
            s_, d_ = r["key"]["src_ip"], r["key"]["dst_ip"]
            flt = [Filter(field="data_source", value="zeek_conn"), Filter(field="src_ip", value=s_), Filter(field="dst_ip", value=d_)]
            out.append(FindingDraft(self.id, self.version, "Potential New External Relationship", self.category, self.stage, 0.35, "low",
                                    [metric("connections", r["count"], label="Connections"), metric("bytes_out", r["bytes"], unit="bytes", label="Bytes sent")],
                                    [check("Pair never seen in history", True, f"{s_} → {d_}")], [f"ip:{s_}", f"ip:{d_}"], _q(flt),
                                    r["first"], None, f"{self.id}:{s_}:{d_}",
                                    attack=[AttackMap("T1071", "low", "새 외부 통신 + 다른 신호 동반 시", condition_met=False)],
                                    explanation=f"{s_} 가 과거 기준선에 없던 외부 {d_} 와 통신.", total_events=r["count"]))
        return out


ANOMALY_DETECTORS = [VolumeSpike(), RareValue(), SequenceAnomaly(), EntityPeerOutlier(), NewRelationship()]
