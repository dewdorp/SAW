"""Web/WAF log detectors (docs/19 §7). Deterministic; thresholds are parameters (versioned)."""
from __future__ import annotations

import re
import statistics
from datetime import datetime

from saw.analyzers.parameter.profile import collect_many, profile_values
from saw.core.schemas.query import AggRequest, Filter, GroupMetric
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

WEB = ["web", "waf"]
SRC_WEB = Filter(field="data_source", op="in", value=WEB)
SENSITIVE_RX = re.compile(r"(?i)(/\.env|/\.git(/|$)|/\.svn|/\.hg|/\.DS_Store|/config(\.\w+)?$|/wp-config|"
                          r"/backup|\.bak$|\.sql$|\.old$|/phpinfo|/server-status|/actuator|/\.aws|/id_rsa|"
                          r"/web\.config|/\.htpasswd|/etc/passwd|/admin(/|$)|/console(/|$)|/manager/html)")
LOGIN_RX = re.compile(r"(?i)(login|signin|sign-in|logon|auth|session|token|oauth|password)")
STATIC_RX = re.compile(r"(?i)\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)$")


def _epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def _minutes(a: str | None, b: str | None) -> float:
    ea, eb = _epoch(a), _epoch(b)
    if ea is None or eb is None:
        return 1.0
    return max(1.0, (eb - ea) / 60)


def _cloud_breakdown(ctx: DetectorContext, flt: list[Filter]) -> dict[str, int]:
    b = ctx.events.aggregate(ctx.investigation_id, flt, AggRequest(type="terms", field="src_cloud", size=10))
    return {x["key"]: x["count"] for x in b["buckets"]}


def _src_by_cloud(ctx: DetectorContext, flt: list[Filter]) -> dict[str, int]:
    rows = ctx.events.group_by(ctx.investigation_id, flt, ["src_cloud"],
                               [GroupMetric(type="cardinality", field="src_ip", name="ips")], size=20)
    return {str(r["key"]["src_cloud"]): r["ips"] for r in rows}


def _dominant(ctx: DetectorContext, flt: list[Filter], field: str) -> tuple[str | None, float, int]:
    t = ctx.events.aggregate(ctx.investigation_id, flt, AggRequest(type="terms", field=field, size=1))
    if not t["buckets"] or not t["total"]:
        return None, 0.0, 0
    return t["buckets"][0]["key"], t["buckets"][0]["count"] / t["total"], t["total"]


def _intervals(ctx: DetectorContext, flt: list[Filter], limit: int = 20000) -> tuple[float | None, float | None]:
    ts = []
    for e in ctx.events.iterate(ctx.investigation_id, flt, fields=["timestamp"]):
        ep = _epoch(e.get("timestamp"))
        if ep is not None:
            ts.append(ep)
        if len(ts) >= limit:
            break
    d = [b - a for a, b in zip(ts, ts[1:], strict=False)]
    if len(d) < 5:
        return None, None
    med = statistics.median(d)
    mean = statistics.fmean(d)
    cv = statistics.pstdev(d) / mean if mean > 0 else 0.0
    return round(med, 3), round(cv, 3)


def _samples(ctx: DetectorContext, flt: list[Filter], n: int = 20) -> list[str]:
    return [e["event_id"] for e in ctx.events.search(ctx.investigation_id, flt, limit=n)["events"]]


def _q(flt: list[Filter]) -> dict:
    return {"filters": [f.model_dump() for f in flt]}


def _asset_baseline(ctx: DetectorContext, url_path: str | None) -> tuple[dict | None, dict | None]:
    if ctx.assets is None or not url_path:
        return None, None
    a = ctx.assets.match_path(url_path)
    if not a:
        return None, None
    rate = (a.get("expected_request_rate") or {}).get("per_min")
    return a, rate


# ---------------------------------------------------------------------------------------------- detectors
class ApiEnumeration:
    id, version, category, stage = "web.api_enumeration", "1.1.0", "web.api_enumeration", "DATA_ACCESS"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_requests": 200, "min_unique": 100, "seq_threshold": 0.8, **ctx.params}
        inv = ctx.investigation_id
        groups = ctx.events.group_by(inv, [SRC_WEB, Filter(field="uri_template", op="contains", value="<NUM>")],
                                     ["uri_template"], [GroupMetric(type="cardinality", field="src_ip", name="srcs"),
                                                        GroupMetric(type="min_ts", name="first"),
                                                        GroupMetric(type="max_ts", name="last")], size=50)
        # relative baseline: median request rate of other busy templates
        all_groups = ctx.events.group_by(inv, [SRC_WEB], ["uri_template"],
                                         [GroupMetric(type="min_ts", name="first"),
                                          GroupMetric(type="max_ts", name="last")], size=200)
        rates = [g["count"] / _minutes(g["first"], g["last"]) for g in all_groups if g["count"] >= 50]
        out = []
        for g in groups:
            tpl = g["key"]["uri_template"]
            if g["count"] < p["min_requests"]:
                continue
            flt = [SRC_WEB, Filter(field="uri_template", value=tpl)]
            num_params = [m for m in re.findall(r"([\w\[\]]+)=<NUM>", tpl)]
            path_idx = [i for i, s in enumerate(tpl.split("?")[0].split("/")) if s == "<NUM>"]
            pnames = num_params + [f"path[{i}]" for i in path_idx]
            best = None
            values = collect_many(ctx.events, inv, tpl, pnames)
            for pn in pnames:
                prof = profile_values(values[pn])
                if best is None or prof.get("sequential_ratio", 0) > best[1].get("sequential_ratio", 0):
                    best = (pn, prof)
            if best is None:
                continue
            pn, prof = best
            if prof["unique"] < p["min_unique"]:
                continue
            seq = prof.get("sequential_ratio", 0.0)
            ok = ctx.events.count(inv, flt + [Filter(field="status_class", value="2xx")])
            success = ok / g["count"]
            rate = g["count"] / _minutes(g["first"], g["last"])
            others = [r for r in rates if abs(r - rate) > 1e-9]
            med_iv, cv = _intervals(ctx, flt)
            clouds = _src_by_cloud(ctx, flt)
            cloud_ips = sum(v for k, v in clouds.items() if k not in ("none", "None"))
            ja4, ja4_share, _ = _dominant(ctx, flt, "ja4")
            ua, ua_share, _ = _dominant(ctx, flt, "user_agent")
            asset, asset_rate = _asset_baseline(ctx, tpl.split("?")[0])
            baseline = None
            if asset_rate:
                baseline = {"min": asset_rate.get("min"), "max": asset_rate.get("max"),
                            "source": f"asset:{asset['asset_id']}"}
            elif others:
                med = statistics.median(others)
                baseline = {"min": round(min(others), 1), "max": round(med, 1), "source": "relative:other_uri_median"}
            checks = [
                check("Sequential identifier", seq >= p["seq_threshold"], f"{seq:.1%}", f"param {pn}, {prof.get('increment')}"),
                check("High success ratio", success >= 0.8, f"{success:.1%} 2xx"),
                check("Automated interval", (med_iv is not None and (med_iv < 2 or (cv or 9) < 0.5)),
                      f"Δt median {med_iv}s, CV {cv}" if med_iv is not None else "n/a"),
                check("Multiple Cloud IP", cloud_ips >= 3,
                      ", ".join(f"{k} {v}" for k, v in clouds.items() if k not in ("none", "None")) or "none"),
                check("Same fingerprint", (ja4_share >= 0.9) or (ua_share >= 0.9),
                      f"JA4 {ja4} {ja4_share:.0%}" if ja4 else f"UA {ua} {ua_share:.0%}"),
            ]
            counter = []
            if asset and asset.get("batch_schedule"):
                checks.append(check("Known batch window", False, "batch 대상 여부 확인 필요",
                                    "asset batch_schedule present"))
            elif asset is None:
                checks.append(check("Known batch window", None, "Asset 정보 없음", "Asset Knowledge 미등록"))
            passed = sum(1 for c in checks if c["passed"])
            if seq < p["seq_threshold"] and passed < 3:
                continue
            conf = "high" if passed >= 4 else "medium" if passed >= 3 else "low"
            metrics = [
                metric("requests", g["count"], label="Requests"),
                metric("unique_objects", prof["unique"], label="Unique objects", approx=False),
                metric("sequential_ratio", round(seq, 4), label="Sequential ratio"),
                metric("http_2xx_ratio", round(success, 4), label="HTTP 2xx ratio"),
                metric("source_ips", g["srcs"], label="Source IPs"),
                metric("request_rate_per_min", round(rate, 1), baseline, "req/min", label="Request rate"),
            ]
            out.append(FindingDraft(
                self.id, self.version, "Possible API Enumeration", self.category, self.stage,
                severity=0.8, confidence=conf, metrics=metrics, checks=checks,
                entities=[f"uri_template:{tpl}"] + ([f"ja4:{ja4}"] if ja4 else []),
                evidence_query=_q(flt), time_start=g["first"], time_end=g["last"],
                dedup_key=f"{self.id}:{tpl}", counter_evidence=counter,
                attack=[AttackMap("T1213", "low", "대량 2xx 객체 조회", condition_met=success >= 0.8,
                                  rationale="API 객체 열거는 ATT&CK에 정확히 대응하는 기법이 없음 — 가장 가까운 후보")],
                attack_unmapped_reason="API object enumeration has no exact ATT&CK technique (candidate only)",
                asset_criticality=(asset or {}).get("criticality"), success_signal=success >= 0.5,
                explanation=(f"`{tpl}` 에 {g['count']:,}건 요청, 파라미터 `{pn}` 값 {prof['unique']:,}개 중 "
                             f"{seq:.1%}가 순차({prof.get('increment')})입니다. 2xx 비율 {success:.1%}."),
                sample_event_ids=_samples(ctx, flt), total_events=g["count"],
            ))
            out[-1].metrics.append({"name": "param_profile", "label": f"Parameter {pn}", "observed": None,
                                    "profile": {k: prof.get(k) for k in ("type", "unique", "increment",
                                                                         "numeric_range", "step_sample")}})
        return out


class Discovery:
    id, version, category, stage = "web.discovery", "1.0.0", "web.discovery", "DISCOVERY"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_404": 100, "min_paths": 50, **ctx.params}
        rows = ctx.events.group_by(ctx.investigation_id, [SRC_WEB, Filter(field="status_code", value=404)],
                                   ["src_ip"], [GroupMetric(type="cardinality", field="url_path", name="paths"),
                                                GroupMetric(type="min_ts", name="first"),
                                                GroupMetric(type="max_ts", name="last")], size=200)
        hits = [r for r in rows if r["count"] >= p["min_404"] and r["paths"] >= p["min_paths"]]
        if not hits:
            return []
        srcs = [r["key"]["src_ip"] for r in hits]
        flt = [SRC_WEB, Filter(field="src_ip", op="in", value=srcs), Filter(field="status_code", value=404)]
        total = sum(r["count"] for r in hits)
        paths = ctx.events.aggregate(ctx.investigation_id, flt, AggRequest(type="cardinality", field="url_path"))["value"]
        first = min(r["first"] for r in hits)
        last = max(r["last"] for r in hits)
        ok_after = ctx.events.count(ctx.investigation_id, [SRC_WEB, Filter(field="src_ip", op="in", value=srcs),
                                                          Filter(field="status_class", value="2xx")])
        checks = [check("404 burst", True, f"{total:,} × 404"), check("Path diversity", True, f"{paths:,} paths"),
                  check("Any success from same sources", ok_after > 0, f"{ok_after:,} × 2xx")]
        return [FindingDraft(self.id, self.version, "Possible Forced Browsing / Discovery", self.category, self.stage,
                             0.45, "high" if len(hits) >= 1 and paths >= 2 * p["min_paths"] else "medium",
                             [metric("not_found", total, label="404 responses"),
                              metric("distinct_paths", paths, label="Distinct paths"),
                              metric("sources", len(hits), label="Sources")], checks,
                             [f"ip:{s}" for s in srcs[:20]], _q(flt), first, last, f"{self.id}:{','.join(sorted(srcs))[:200]}",
                             attack=[AttackMap("T1595.003", "medium", "404 burst + 경로 다양성")],
                             success_signal=ok_after > 0,
                             explanation=f"{len(hits)}개 출발지에서 404 응답 {total:,}건, 서로 다른 경로 {paths:,}개.",
                             sample_event_ids=_samples(ctx, flt), total_events=total)]


class SensitiveFileProbe:
    id, version, category, stage = "web.sensitive_file_probe", "1.0.0", "web.sensitive_file_probe", "RECON"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        paths = ctx.events.group_by(ctx.investigation_id, [SRC_WEB], ["url_path", "status_class"], [], size=5000)
        sens = [r for r in paths if r["key"]["url_path"] and SENSITIVE_RX.search(str(r["key"]["url_path"]))]
        if not sens:
            return []
        plist = sorted({r["key"]["url_path"] for r in sens})[:500]
        flt = [SRC_WEB, Filter(field="url_path", op="in", value=plist)]
        total = sum(r["count"] for r in sens)
        succ = sum(r["count"] for r in sens if r["key"]["status_class"] == "2xx")
        srcs = ctx.events.aggregate(ctx.investigation_id, flt, AggRequest(type="cardinality", field="src_ip"))["value"]
        lo, hi = ctx.events.time_bounds(ctx.investigation_id, flt)
        succ_paths = sorted({r["key"]["url_path"] for r in sens if r["key"]["status_class"] == "2xx"})[:10]
        checks = [check("Sensitive path dictionary match", True, f"{len(plist)} paths"),
                  check("Successful response (2xx)", succ > 0, f"{succ} × 2xx", ", ".join(succ_paths))]
        return [FindingDraft(self.id, self.version, "Possible Sensitive File Probing", self.category, self.stage,
                             0.75 if succ else 0.4, "high" if len(plist) >= 3 else "medium",
                             [metric("requests", total, label="Requests"), metric("paths", len(plist), label="Paths"),
                              metric("sources", srcs, label="Sources"), metric("success_2xx", succ, label="2xx")],
                             checks, [f"url_path:{x}" for x in plist[:10]], _q(flt), lo, hi, f"{self.id}",
                             attack=[AttackMap("T1595.003", "high", "외부 출발지, 민감 경로 사전 매칭")],
                             success_signal=succ > 0,
                             explanation=f"민감 경로 {len(plist)}종에 {total:,}건 요청 (2xx {succ}건).",
                             sample_event_ids=_samples(ctx, flt), total_events=total)]


class CredentialAttack:
    id, version, category, stage = "web.credential_attack", "1.1.0", "web.credential_attack", "AUTHENTICATION"
    data_sources = {"web", "waf", "linux", "windows"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        p = {"min_attempts": 30, "min_failures": 10, "min_fail_ratio": 0.3, **ctx.params}
        inv = ctx.investigation_id
        out = []
        paths = ctx.events.group_by(inv, [SRC_WEB, Filter(field="method", value="POST")], ["url_path"], [], size=500)
        login_paths = [r["key"]["url_path"] for r in paths if r["key"]["url_path"] and LOGIN_RX.search(r["key"]["url_path"])]
        flt_web = [SRC_WEB, Filter(field="method", value="POST"), Filter(field="url_path", op="in", value=login_paths)] \
            if login_paths else None
        flt_auth = [Filter(field="event_type", value="auth")]
        for flt, label in ((flt_web, "web login"), (flt_auth, "auth log")):
            if not flt:
                continue
            rows = ctx.events.group_by(inv, flt, ["src_ip"], [GroupMetric(type="cardinality", field="user", name="users"),
                                                             GroupMetric(type="min_ts", name="first"),
                                                             GroupMetric(type="max_ts", name="last")], size=200)
            for r in rows:
                if r["count"] < p["min_attempts"] or not r["key"]["src_ip"]:
                    continue
                src = r["key"]["src_ip"]
                f2 = flt + [Filter(field="src_ip", value=src)]
                fails = ctx.events.count(inv, f2 + [Filter(field="status_code", op="in", value=[401, 403])]) + \
                    ctx.events.count(inv, f2 + [Filter(field="ext.syslog.outcome", value="failure")])
                fail_ratio = fails / r["count"]
                users = r["users"] or 0
                stuffing = users >= 10 and users / r["count"] > 0.5
                # Many logins from one address are normal (mobile carriers and offices share addresses, apps log in
                # again in the background). Guessing shows as refusals, stuffing as many different accounts: without
                # either there is nothing to report.
                if not stuffing and (fails < p["min_failures"] or fail_ratio < p["min_fail_ratio"]):
                    continue
                success = ctx.events.count(inv, f2 + [Filter(field="status_class", value="2xx")]) + \
                    ctx.events.count(inv, f2 + [Filter(field="ext.syslog.outcome", value="success")])
                tid = "T1110.004" if stuffing else "T1110.001"
                title = "Possible Credential Stuffing" if stuffing else "Possible Password Guessing / Brute Force"
                checks = [check("High attempt volume", True, f"{r['count']:,} attempts ({label})"),
                          check("High failure ratio", fail_ratio >= 0.5, f"{fail_ratio:.0%}"),
                          check("Many distinct accounts", stuffing, f"{users} accounts"),
                          check("Success after attempts", success > 0, f"{success} success")]
                out.append(FindingDraft(self.id, self.version, title, self.category, self.stage, 0.7,
                                        "high" if fail_ratio >= 0.5 else "medium",
                                        [metric("attempts", r["count"], label="Attempts"),
                                         metric("failure_ratio", round(fail_ratio, 3), label="Failure ratio"),
                                         metric("accounts", users, label="Accounts"),
                                         metric("success", success, label="Successful")], checks,
                                        [f"ip:{src}"], _q(f2), r["first"], r["last"], f"{self.id}:{label}:{src}",
                                        attack=[AttackMap(tid, "high", "계정 다양성/반복 패턴",
                                                          rationale=f"{users} accounts / {r['count']} attempts")]
                                        + ([AttackMap("T1078", "medium", "시도 후 성공", rationale="valid account use after attempts")]
                                           if success else []),
                                        success_signal=success > 0,
                                        explanation=f"{src}에서 {label} 시도 {r['count']:,}건, 실패율 {fail_ratio:.0%}, 계정 {users}개.",
                                        sample_event_ids=_samples(ctx, f2), total_events=r["count"]))
        return out


class InjectionLike:
    id, version, category, stage = "web.injection_like", "1.0.0", "web.injection_like", "EXPLOITATION"
    data_sources = {"web", "waf"}
    TAGS = ["pattern:sqli", "pattern:xss", "pattern:traversal", "pattern:cmdi", "pattern:ssti", "pattern:ssrf",
            "pattern:deser"]

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        out = []
        for tag in self.TAGS:
            flt = [SRC_WEB, Filter(field="tags", value=tag)]
            n = ctx.events.count(inv, flt)
            if not n:
                continue
            srcs = ctx.events.group_by(inv, flt, ["src_ip"], [], size=20)
            ok = ctx.events.count(inv, flt + [Filter(field="status_class", value="2xx")])
            err = ctx.events.count(inv, flt + [Filter(field="status_class", value="5xx")])
            lo, hi = ctx.events.time_bounds(inv, flt)
            kind = tag.split(":")[1]
            label = {"sqli": "SQL Injection", "xss": "XSS", "traversal": "Directory Traversal / LFI",
                     "cmdi": "Command Injection", "ssti": "SSTI / Expression Injection", "ssrf": "SSRF / RFI",
                     "deser": "Insecure Deserialization"}[kind]
            success = ok > 0 or err > 0
            checks = [check("Payload pattern in parameters", True, f"{n} requests"),
                      check("Success / error signal", success, f"2xx {ok}, 5xx {err}",
                            "2xx/5xx 응답은 공격 성공 가능성 신호 (확정 아님)"),
                      check("Blocked responses", None, f"{n - ok - err} other")]
            out.append(FindingDraft(self.id, self.version, f"Potential {label} Attempts", self.category, self.stage,
                                    0.75, "high" if n >= 10 else "medium",
                                    [metric("requests", n, label="Requests"), metric("sources", len(srcs), label="Sources"),
                                     metric("success_2xx", ok, label="2xx"), metric("errors_5xx", err, label="5xx")],
                                    checks, [f"ip:{r['key']['src_ip']}" for r in srcs[:10]], _q(flt), lo, hi,
                                    f"{self.id}:{kind}",
                                    attack=[AttackMap("T1190", "medium", "성공 신호(2xx/5xx/에러) 있을 때만",
                                                      condition_met=success)],
                                    success_signal=success,
                                    explanation=f"{label} 패턴 요청 {n}건 (2xx {ok}, 5xx {err}).",
                                    sample_event_ids=_samples(ctx, flt), total_events=n))
        return out


class ScriptedClient:
    id, version, category, stage = "web.scripted_client", "1.0.0", "web.scripted_client", "INFRASTRUCTURE"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        flt = [SRC_WEB, Filter(field="ua_class", op="in", value=["script", "scanner", "empty"])]
        n = ctx.events.count(inv, flt)
        total = ctx.events.count(inv, [SRC_WEB])
        if n < 100 or not total:
            return []
        uas = ctx.events.aggregate(inv, flt, AggRequest(type="terms", field="user_agent", size=5))["buckets"]
        scanners = ctx.events.count(inv, [SRC_WEB, Filter(field="ua_class", value="scanner")])
        lo, hi = ctx.events.time_bounds(inv, flt)
        srcs = ctx.events.aggregate(inv, flt, AggRequest(type="cardinality", field="src_ip"))["value"]
        return [FindingDraft(self.id, self.version,
                             "Possible Vulnerability Scanner Activity" if scanners else "Possible Scripted / Automated Client",
                             self.category, self.stage, 0.5 if scanners else 0.3, "medium",
                             [metric("requests", n, label="Requests"), metric("share", round(n / total, 4), label="Share of traffic"),
                              metric("sources", srcs, label="Sources")],
                             [check("Non-browser User-Agent", True, ", ".join(str(u["key"])[:40] for u in uas[:3])),
                              check("Known scanner signature", scanners > 0, f"{scanners}")],
                             [f"user_agent:{u['key']}" for u in uas[:3]], _q(flt), lo, hi, self.id,
                             attack=[AttackMap("T1595.002", "medium", "스캐너 UA", condition_met=scanners > 0)],
                             success_signal=False, explanation=f"스크립트/스캐너/빈 UA 요청 {n:,}건.",
                             sample_event_ids=_samples(ctx, flt), total_events=n)]


class LargeResponse:
    id, version, category, stage = "web.large_response", "1.0.0", "web.large_response", "DATA_ACCESS"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        rows = ctx.events.group_by(inv, [SRC_WEB], ["src_ip"], [GroupMetric(type="sum", field="bytes_out", name="bytes"),
                                                               GroupMetric(type="min_ts", name="first"),
                                                               GroupMetric(type="max_ts", name="last")], size=2000)
        vols = sorted(r["bytes"] or 0 for r in rows)
        if len(vols) < 5:
            return []
        med = statistics.median(vols)
        q3 = vols[int(len(vols) * 0.75)]
        thr = max(q3 * 10, med * 20, 50 * 1024 * 1024)
        hits = [r for r in rows if (r["bytes"] or 0) >= thr]
        out = []
        for r in hits[:5]:
            src = r["key"]["src_ip"]
            flt = [SRC_WEB, Filter(field="src_ip", value=src)]
            out.append(FindingDraft(self.id, self.version, "Possible Large Data Retrieval", self.category, self.stage,
                                    0.55, "medium",
                                    [metric("bytes_out", r["bytes"], {"min": 0, "max": round(med), "source": "relative:median_src"},
                                            "bytes", label="Bytes returned")],
                                    [check("Outlier vs other sources", True, f"≥ {thr:,.0f} B")], [f"ip:{src}"], _q(flt),
                                    r["first"], r["last"], f"{self.id}:{src}",
                                    attack=[AttackMap("T1213", "low", "대량 응답", condition_met=False)],
                                    explanation=f"{src} 누적 응답 {r['bytes']:,} bytes (중앙값 {med:,.0f}).",
                                    sample_event_ids=_samples(ctx, flt), total_events=r["count"]))
        return out


class RequestMutationSuccess:
    id, version, category, stage = "web.request_mutation_success", "1.0.0", "web.request_mutation_success", "EXPLOITATION"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        denied = ctx.events.group_by(inv, [SRC_WEB, Filter(field="status_code", op="in", value=[401, 403, 405])],
                                     ["src_ip", "url_path"], [GroupMetric(type="max_ts", name="last_denied")], size=500)
        out = []
        for d in denied:
            src, path = d["key"]["src_ip"], d["key"]["url_path"]
            if not src or not path:
                continue
            flt = [SRC_WEB, Filter(field="src_ip", value=src), Filter(field="url_path", value=path)]
            evs = ctx.events.search(inv, flt, limit=500)["events"]
            seen_fail: dict | None = None
            for e in evs:
                sc = e.get("status_code") or 0
                if sc in (401, 403, 405):
                    seen_fail = e
                elif 200 <= sc < 300 and seen_fail is not None:
                    changed = []
                    if e.get("method") != seen_fail.get("method"):
                        changed.append(f"method {seen_fail.get('method')}→{e.get('method')}")
                    if set(e.get("param_names") or []) != set(seen_fail.get("param_names") or []):
                        changed.append("parameter names changed")
                    if not changed:
                        continue
                    out.append(FindingDraft(
                        self.id, self.version, "Possible Access Control Bypass via Request Mutation", self.category,
                        self.stage, 0.8, "medium",
                        [metric("denied_before", d["count"], label="Denied attempts"),
                         metric("status_transition", f"{seen_fail.get('status_code')} → {sc}", label="Status")],
                        [check("Denied then succeeded on same path", True, f"{seen_fail.get('status_code')} → {sc}"),
                         check("Request mutated", True, "; ".join(changed))],
                        [f"ip:{src}", f"url_path:{path}"], _q(flt), seen_fail.get("timestamp"), e.get("timestamp"),
                        f"{self.id}:{src}:{path}",
                        attack=[AttackMap("T1190", "medium", "403→변형→200")],
                        explanation=f"{src}가 {path}에서 {seen_fail.get('status_code')} 이후 요청을 변형({'; '.join(changed)})해 {sc} 응답을 받음.",
                        sample_event_ids=[seen_fail["event_id"], e["event_id"]], total_events=len(evs)))
                    break
            if len(out) >= 20:
                break
        return out


class RarePathAccess:
    id, version, category, stage = "web.rare_path_access", "1.0.0", "web.rare_path_access", "DISCOVERY"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv = ctx.investigation_id
        total_src = ctx.events.aggregate(inv, [SRC_WEB], AggRequest(type="cardinality", field="src_ip"))["value"]
        if total_src < 50:
            return []  # rarity is meaningless on tiny populations
        rows = ctx.events.group_by(inv, [SRC_WEB, Filter(field="status_class", value="2xx"),
                                         Filter(field="src_ip_scope", value="external")], ["url_path"],
                                   [GroupMetric(type="cardinality", field="src_ip", name="srcs")], size=5000)
        rare = [r for r in rows if r["srcs"] == 1 and r["key"]["url_path"]
                and not STATIC_RX.search(r["key"]["url_path"]) and r["count"] <= 3]
        rare = [r for r in rare if re.search(r"(?i)(admin|internal|debug|manage|export|download|api/v\d+/\w+/)",
                                             r["key"]["url_path"])][:20]
        if not rare:
            return []
        paths = [r["key"]["url_path"] for r in rare]
        flt = [SRC_WEB, Filter(field="url_path", op="in", value=paths)]
        lo, hi = ctx.events.time_bounds(inv, flt)
        return [FindingDraft(self.id, self.version, "Possible Rare Sensitive Path Access", self.category, self.stage,
                             0.35, "low", [metric("paths", len(paths), label="Rare paths")],
                             [check("Single external source with 2xx", True, f"{len(paths)} paths"),
                              check("Administrative / export keyword", True, ", ".join(paths[:3]))],
                             [f"url_path:{p}" for p in paths[:10]], _q(flt), lo, hi, self.id,
                             attack_unmapped_reason="rarity alone does not imply a technique",
                             explanation="외부 단일 출발지만 성공적으로 접근한 관리/내보내기 성격 경로.",
                             sample_event_ids=_samples(ctx, flt), total_events=sum(r["count"] for r in rare))]


class OffHoursSensitiveAccess:
    id, version, category, stage = "web.off_hours_sensitive", "1.0.0", "web.off_hours_sensitive", "DATA_ACCESS"
    data_sources = {"web", "waf"}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        if ctx.assets is None:
            return []  # requires Asset Knowledge expected_access_time (Phase 8)
        return ctx.assets.off_hours_findings(ctx, self)


WEB_DETECTORS = [ApiEnumeration(), Discovery(), SensitiveFileProbe(), CredentialAttack(), InjectionLike(),
                 ScriptedClient(), LargeResponse(), RequestMutationSuccess(), RarePathAccess(),
                 OffHoursSensitiveAccess()]
