"""Device calculations over bounded disk-backed observations."""
from __future__ import annotations

import json
import re

from saw.observation.result import canonical, seconds


def waf(run, **_):
    run.db.execute("CREATE TABLE requests(k TEXT,b INTEGER,rid TEXT,src TEXT,path TEXT,uri TEXT,obj TEXT,"
                   "attack INTEGER,automation INTEGER,allowed INTEGER,edge REAL,origin REAL,ref TEXT)")
    for row in run.query("SELECT * FROM rows WHERE kind IN ('request','rule_hit') ORDER BY k,b,t,n"):
        obs = json.loads(row["obs"])
        if row["kind"] == "rule_hit":
            run.counts["rule_hits"] += 1
        state = obs.get("user_agent_state", "not_collected")
        if state in {"not_collected", "recorded_empty"}:
            run.quality["user_agent_" + state] += 1
        if not row["rid"]:
            run.quality["request_identity_missing"] += 1
            continue
        object_ids = re.findall(r"(?:/|[?&][^=]{1,64}=)([0-9]{1,32})(?=/|&|$|\?)", row["uri"] or "")
        run.db.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["k"], row["b"], row["rid"], row["src"], row["path"] or None, row["uri"] or None,
             canonical(object_ids) if object_ids else None, int(bool(obs.get("attack_patterns"))),
             int(obs.get("ua_class") in {"scanner", "script", "bot"}),
             None if obs.get("action") in {None, "unknown", "conflicting"} else int(obs.get("action") == "allowed"),
             obs.get("edge_status"), obs.get("origin_status"), row["ref"]))
    run.db.execute("CREATE INDEX request_group ON requests(k,b,rid)")
    # Several rule hits are one request; only independently observed request features are combined.
    conflicts = run.db.execute("SELECT count(*) FROM (SELECT k,b,rid FROM requests GROUP BY k,b,rid "
                               "HAVING count(DISTINCT edge)>1 OR count(DISTINCT origin)>1)").fetchone()[0]
    if conflicts:
        run.quality["conflicting_request_status"] += conflicts
    run.db.execute("CREATE TABLE unique_requests AS SELECT k,b,rid,src,min(path) path,min(uri) uri,min(obj) obj,"
                   "max(attack) attack,max(automation) automation,max(allowed) allowed,"
                   "CASE WHEN count(DISTINCT edge)=1 THEN max(edge) ELSE NULL END edge,"
                   "CASE WHEN count(DISTINCT origin)=1 THEN max(origin) ELSE NULL END origin,"
                   "min(ref) ref FROM requests GROUP BY k,b,rid,src")
    run.db.execute("CREATE INDEX unique_request_group ON unique_requests(k,b,rid)")
    known = run.db.execute("SELECT count(*) FROM unique_requests").fetchone()[0]
    run.counts["requests"] = None if run.quality.get("request_identity_missing") else known
    uri_known = run.db.execute("SELECT count(*) FROM unique_requests WHERE uri IS NOT NULL AND uri<>''").fetchone()[0]
    comparable = run.db.execute("SELECT count(*) FROM unique_requests WHERE edge IS NOT NULL AND origin IS NOT NULL").fetchone()[0]
    action_known = run.db.execute("SELECT count(*) FROM unique_requests WHERE allowed IS NOT NULL").fetchone()[0]
    run.counts["uri_observed_requests"] = uri_known
    run.counts["edge_origin_comparable_requests"] = comparable
    run.counts["edge_origin_disagreements"] = (run.db.execute(
        "SELECT count(*) FROM unique_requests WHERE edge IS NOT NULL AND origin IS NOT NULL AND edge<>origin").fetchone()[0]
        if comparable else None)
    run.calculation_coverage = {}
    for name, observed, reason in (("uri", uri_known, "uri_not_collected"),
                                   ("response_comparison", comparable, "response_pair_not_collected"),
                                   ("allowed_attack", action_known, "action_not_collected")):
        run.calculation_coverage[name] = {
            "status": "available" if observed == known and known else "partial" if observed else "unavailable",
            "observed_requests": observed, "missing_requests": known-observed, "requests": known}
        if known > observed:
            run.quality[reason] += known-observed
    if not known:
        run.insufficient = True
    for row in run.query("SELECT k,b,count(*) n,count(DISTINCT path) paths,count(DISTINCT uri) uris,"
                         "count(DISTINCT obj) objects,count(uri) uri_observed,sum(attack) attacks,sum(automation) automated,"
                         "sum(COALESCE(attack*allowed,0)) attack_allowed, "
                         "sum(CASE WHEN edge IS NOT NULL AND origin IS NOT NULL THEN 1 ELSE 0 END) response_comparable, "
                         "sum(CASE WHEN edge IS NOT NULL AND origin IS NOT NULL AND edge<>origin THEN 1 ELSE 0 END) response_differences "
                         "FROM unique_requests GROUP BY k,b ORDER BY k,b"):
        scope, bucket, count = row["k"], row["b"], row["n"]
        refs = [json.loads(item["ref"]) for item in run.query(
            "SELECT ref FROM unique_requests WHERE k=? AND b=? ORDER BY rid LIMIT 20", (scope, bucket))]
        metrics = {"requests": count, "denominator": count, "unique_paths": row["paths"],
                   "attack_requests": row["attacks"], "window_start_epoch": bucket * run.policy["window_seconds"]}
        if row["uri_observed"] >= run.policy["min_requests"] and row["paths"] >= run.policy["min_paths"]:
            run.add("multi_path_discovery", refs, metrics, scope=scope)
        if row["uri_observed"] >= run.policy["min_repetitions"] and row["uris"] <= 2 and row["attacks"] >= run.policy["attack_min_requests"]:
            run.add("attack_repetition", refs, metrics, scope=scope)
        if row["attacks"] >= run.policy["attack_min_requests"] and row["uris"] >= run.policy["attack_min_requests"]:
            run.add("attack_mutation", refs, metrics, scope=scope)
        if row["objects"] >= run.policy["min_object_ids"] and (row["automated"] or row["attacks"]):
            run.add("object_id_walk", refs, {**metrics, "unique_object_ids": row["objects"],
                                           "automation_requests": row["automated"]}, scope=scope)
        if row["response_differences"] >= run.policy["attack_min_requests"]:
            run.add("response_location_difference", refs, {**metrics, "denominator": row["response_comparable"], "disagreement_requests": row["response_differences"]}, scope=scope)
        if row["attack_allowed"] >= run.policy["attack_min_requests"]:
            run.add("allowed_attack", refs, {**metrics, "allowed_attack_requests": row["attack_allowed"]}, scope=scope)
        run.add_timeline({"start_epoch": bucket * run.policy["window_seconds"], "end_epoch": (bucket+1)*run.policy["window_seconds"],
                          "unit": "requests", "statistic": "count", "value": count, "denominator": count,
                          "context": json.loads(scope)})


def ips(run, **_):
    run.counts["alerts"] = run.db.execute("SELECT count(*) FROM rows WHERE kind='alert'").fetchone()[0]
    if not run.counts["alerts"]:
        run.insufficient = True
    for row in run.query("SELECT * FROM rows WHERE kind='alert' ORDER BY k,b,t,n"):
        obs = json.loads(row["obs"])
        if obs.get("packet_available") is not True:
            run.quality["packet_not_collected"] += 1
        if not row["sig"]:
            run.quality["signature_missing"] += 1
        if obs.get("mode") == "unknown" or obs.get("action") == "unknown":
            run.quality["ips_mode_or_action_unknown"] += 1
        if (str(obs.get("severity")).lower() in {"high", "critical", "1"} and
                (obs.get("mode") == "mirror" or obs.get("action") == "detected")):
            run.add("detect_only", [json.loads(row["ref"])], {"alerts": 1, "mode": obs.get("mode"),
                     "action": obs.get("action"), "denominator": run.counts["alerts"]}, scope=row["k"])
        follow = next(run.query("SELECT ref,t FROM rows WHERE kind='flow' AND net=? AND src=? AND dst=? "
                               "AND action='allowed' AND t>=? AND t<=? ORDER BY t,n LIMIT 1",
                              (row["net"], row["src"], row["dst"], row["t"], row["t"]+run.policy["followup_seconds"])), None)
        if follow:
            run.add("followup_communication", [json.loads(row["ref"]), json.loads(follow["ref"])],
                    {"elapsed_seconds": follow["t"]-row["t"], "association": "candidate", "denominator": run.counts["alerts"]},
                    scope=row["k"])
    for row in run.query("SELECT k,b,sig,count(*) n,count(DISTINCT dst) targets FROM rows "
                         "WHERE kind='alert' AND sig IS NOT NULL GROUP BY k,b,sig ORDER BY k,b,sig"):
        refs = run.refs("k=? AND b=? AND sig=? AND kind='alert'", (row["k"], row["b"], row["sig"]))
        metrics = {"alerts": row["n"], "signature_id": row["sig"], "unique_targets": row["targets"],
                   "denominator": run.counts["alerts"]}
        if row["n"] >= run.policy["repeat_count"]:
            run.add("pattern_repeat", refs, metrics, scope=row["k"])
        if row["targets"] >= run.policy["target_count"]:
            run.add("target_spread", refs, metrics, scope=row["k"])
    for row in run.query("SELECT k,b,dst,count(*) n,count(DISTINCT sig) patterns FROM rows WHERE kind='alert' "
                         "GROUP BY k,b,dst ORDER BY k,b,dst"):
        if row["patterns"] >= run.policy["pattern_count"]:
            run.add("pattern_diversity", run.refs("k=? AND b=? AND dst=? AND kind='alert'",
                    (row["k"], row["b"], row["dst"])), {"alerts": row["n"], "unique_patterns": row["patterns"],
                     "dst_ip": row["dst"], "denominator": run.counts["alerts"]}, scope=row["k"])
    for row in run.query("SELECT k,b,action,count(*) n FROM rows WHERE kind='alert' GROUP BY k,b,action ORDER BY k,b,action"):
        run.add_timeline({"start_epoch": row["b"]*run.policy["window_seconds"], "unit": "alerts",
                          "statistic": "count", "value": row["n"], "action": row["action"], "context": json.loads(row["k"])})


def ddos(run, **_):
    run.db.execute("CREATE TABLE intervals(k TEXT,c TEXT,scope TEXT,target TEXT,type TEXT,a REAL,z REAL,v REAL,unit TEXT,"
                   "stat TEXT,phase TEXT,ref TEXT)")
    for row in run.query("SELECT * FROM rows WHERE kind='interval_summary' ORDER BY k,t,n"):
        obs = json.loads(row["obs"])
        begin, end = seconds(obs.get("interval_start")), seconds(obs.get("interval_end"))
        sampling = obs.get("sampling_ratio")
        if (obs.get("rate_unit") not in {"bps", "pps", "rps"} or obs.get("rate_statistic") not in {"mean", "peak"}
                or obs.get("rate") is None or begin is None or end is None or end <= begin
                or not isinstance(sampling, (int, float)) or not 0 < sampling <= 1
                or obs.get("sampling_version") in (None, "", "unknown") or not obs.get("observation_point")
                or not obs.get("target")):
            run.quality["invalid_interval_semantics"] += 1
            continue
        identity = [row["k"], obs["target"], obs.get("attack_type"), obs["rate_unit"], obs["rate_statistic"],
                    sampling, obs["sampling_version"], obs["observation_point"], end-begin]
        run.db.execute("INSERT INTO intervals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (canonical(identity), canonical(identity[:1]+identity[2:]), row["k"], obs["target"], obs.get("attack_type"), begin, end, obs["rate"],
             obs["rate_unit"], obs["rate_statistic"], obs.get("mitigation"), row["ref"]))
    run.db.execute("CREATE INDEX interval_order ON intervals(k,a,z)")
    conflict = run.db.execute("SELECT count(*) FROM (SELECT k,a,z FROM intervals GROUP BY k,a,z "
                              "HAVING min(v)<>max(v) OR count(DISTINCT phase)>1)").fetchone()[0]
    if conflict:
        run.quality["conflicting_interval_duplicates"] += conflict
    run.db.execute("CREATE TABLE dedup_intervals AS SELECT k,c,scope,target,type,a,z,min(v) v,unit,stat,phase,min(ref) ref "
                   "FROM intervals GROUP BY k,a,z HAVING min(v)=max(v) AND count(DISTINCT phase)=1")
    run.db.execute("CREATE INDEX dedup_interval_order ON dedup_intervals(k,a,z)")
    # A sorted prefix maximum and next start detect every overlapping interval, including nesting.
    # No correlated scan of all previous intervals: sorting plus a linear window pass is bounded.
    run.db.execute("CREATE TABLE ordered_intervals AS SELECT *, "
                   "max(z) OVER (PARTITION BY k ORDER BY a,z ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) prior_end, "
                   "lead(a) OVER (PARTITION BY k ORDER BY a,z) next_start FROM dedup_intervals")
    overlap = "(prior_end>a OR next_start<z)"
    overlapping = run.db.execute("SELECT count(*) FROM ordered_intervals WHERE "+overlap).fetchone()[0]
    if overlapping:
        run.quality["overlapping_intervals"] += overlapping
    run.db.execute("CREATE TABLE unique_intervals AS SELECT * FROM ordered_intervals WHERE NOT COALESCE("+overlap+",0)")
    run.counts["intervals"] = run.db.execute("SELECT count(*) FROM unique_intervals").fetchone()[0]
    if not run.counts["intervals"]:
        run.insufficient = True
    current = None
    def finish(group):
        if not group:
            return
        refs = group["refs"]
        metrics = {"denominator": group["n"], "unit": group["unit"], "statistic": group["stat"],
                   "max_observed_rate": group["peak"], "target": group["target"], "attack_type": group["type"]}
        if group["high"] >= run.policy["repeat_min_intervals"]:
            run.add("repeated_intervals", refs, {**metrics, "high_intervals": group["high"]}, scope=group["scope"])
        if group["stat"] == "mean" and group["max_duration"] >= run.policy["sustain_seconds"]:
            run.add("sustained_rate", refs, {**metrics, "duration_seconds": group["max_duration"]}, scope=group["scope"])
    for row in run.query("SELECT * FROM unique_intervals ORDER BY k,a,z,ref"):
        if current is None or row["k"] != current["key"]:
            finish(current)
            current = {"key": row["k"], "scope": row["scope"], "target": row["target"], "type": row["type"],
                       "unit": row["unit"], "stat": row["stat"], "n": 0, "baseline_sum": 0,
                       "baseline_n": 0, "peak": 0, "high": 0, "last_end": None, "duration": 0,
                       "max_duration": 0, "before": None, "refs": []}
        ref = json.loads(row["ref"])
        current["refs"] = (current["refs"][:19] + [ref]) if len(current["refs"]) >= 20 else current["refs"] + [ref]
        current["n"] += 1
        current["peak"] = max(current["peak"], row["v"])
        if current["baseline_n"] < run.policy["baseline_min_intervals"]:
            current["baseline_sum"] += row["v"]
            current["baseline_n"] += 1
        else:
            previous = current["baseline_sum"]/current["baseline_n"]
            if previous > 0 and row["v"] >= previous*run.policy["burst_ratio"]:
                run.add("rate_burst", current["refs"], {"value": row["v"], "previous_observed_mean": previous,
                    "ratio": row["v"]/previous, "unit": row["unit"], "statistic": row["stat"],
                    "denominator": current["baseline_n"], "target": row["target"], "attack_type": row["type"]}, scope=row["scope"])
        high = row["v"] >= run.policy["rate_min_value"]
        if high:
            current["high"] += 1
            if current["last_end"] == row["a"]:
                current["duration"] += row["z"]-row["a"]
            else:
                current["duration"] = row["z"]-row["a"]
            current["max_duration"] = max(current["max_duration"], current["duration"])
        else:
            current["duration"] = 0
        current["last_end"] = row["z"] if high else None
        if row["phase"] == "before":
            current["before"] = dict(row)
        elif row["phase"] == "after" and current["before"] and current["before"]["z"] <= row["a"]:
            before = current["before"]
            run.add("mitigation_comparison", [json.loads(before["ref"]), ref],
                {"before": before["v"], "after": row["v"], "residual_observed_rate": row["v"],
                 "unit": row["unit"], "statistic": row["stat"], "denominator": 2,
                 "ratio": row["v"]/before["v"] if before["v"] else None}, scope=row["scope"])
            current["before"] = None
        run.add_timeline({"start_epoch": row["a"], "end_epoch": row["z"], "unit": row["unit"],
                          "statistic": row["stat"], "value": row["v"], "denominator": 1,
                          "target": row["target"], "attack_type": row["type"], "context": json.loads(row["scope"])})
    finish(current)
    for row in run.query("SELECT c,scope,target,count(*) n FROM unique_intervals WHERE v>=? GROUP BY c,target ORDER BY c,target",
                         (run.policy["rate_min_value"],)):
        total = run.db.execute("SELECT count(*) FROM unique_intervals WHERE c=? AND v>=?", (row["c"], run.policy["rate_min_value"])).fetchone()[0]
        if total and row["n"] >= run.policy["repeat_min_intervals"] and row["n"]/total >= run.policy["concentration_ratio"]:
            refs = [json.loads(r["ref"]) for r in run.query(
                "SELECT ref FROM unique_intervals WHERE c=? AND target=? AND v>=? ORDER BY a LIMIT 20", (row["c"], row["target"], run.policy["rate_min_value"]))]
            run.add("target_concentration", refs, {"target": row["target"], "observed_intervals": row["n"],
                    "denominator": total, "ratio": row["n"]/total, "unit": "intervals"}, scope=row["scope"])
    run.limitations.append("이전 관측 구간은 승인 정상 기준선이 아닙니다. 서로 다른 시각의 peak를 합산하지 않습니다.")


def ndr(run, **_):
    from saw.observation.firewall import DEFAULT_POLICY, analyze_firewall

    for kind in ("dns", "http", "tls", "alert", "flow"):
        run.counts[kind + "_records"] = run.db.execute("SELECT count(*) FROM rows WHERE kind=?", (kind,)).fetchone()[0]
    run.counts["alerts"] = run.counts["alert_records"]
    valid_flows = run.db.execute("SELECT count(*) FROM rows WHERE kind='flow' AND "
                                 "json_extract(obs,'$.collection.scope')<>'alerts_only' AND "
                                 "json_extract(obs,'$.capture_kind')<>'alerts_only'").fetchone()[0]
    if valid_flows:
        flow_events = (json.loads(row["event"]) for row in run.query(
            "SELECT event FROM rows WHERE kind='flow' AND json_extract(obs,'$.collection.scope')<>'alerts_only' "
            "AND json_extract(obs,'$.capture_kind')<>'alerts_only' ORDER BY t,n"))
        result = analyze_firewall(flow_events, policy={key: run.policy[key] for key in DEFAULT_POLICY},
                                  max_records=run.max_records, max_results=run.max_results, cancelled=run.cancelled)
        run.counts["sessions"] = result["counts"]["sessions"]
        run.counts["new_connections"] = result["counts"]["new_connections"]
        run.quality.update(result["quality"])
        if result["status"] == "cancelled":
            run.was_cancelled = run.partial = True
        for candidate in result["candidates"]:
            run.add(candidate["kind"], candidate["event_refs"], candidate["metrics"], scope=candidate.get("context"))
    else:
        run.counts["sessions"] = None
        run.quality["flow_coverage_unavailable"] += 1
    run.db.execute("CREATE TABLE characteristics(k TEXT,b INTEGER,name TEXT,value REAL,den INTEGER)")
    for field, kind, column in (("domain", "dns", "domain"), ("http_status", "http", "json_extract(obs,'$.status')"),
                                 ("tls_version", "tls", "json_extract(obs,'$.tls_version')")):
        observed = run.db.execute("SELECT count(*) FROM rows WHERE kind=? AND " + column + " IS NOT NULL AND " + column + "<>''", (kind,)).fetchone()[0]
        missing = run.counts[kind + "_records"] - observed
        run.counts[field + "_observed"] = observed
        if missing:
            run.quality[field + "_not_collected"] += missing
    for row in run.query("SELECT k,b,kind,count(*) n,"
                         "sum(CASE WHEN domain IS NOT NULL AND domain<>'' THEN 1 ELSE 0 END) dns_observed,"
                         "sum(CASE WHEN json_extract(obs,'$.status') IS NOT NULL THEN 1 ELSE 0 END) http_observed,"
                         "sum(CASE WHEN json_extract(obs,'$.tls_version') IS NOT NULL THEN 1 ELSE 0 END) tls_observed,"
                         "sum(CASE WHEN length(domain)>=? THEN 1 ELSE 0 END) long_dns,"
                         "sum(CASE WHEN json_extract(obs,'$.status')>=400 THEN 1 ELSE 0 END) errors,"
                         "sum(CASE WHEN json_extract(obs,'$.ua_class') IN ('script','scanner','bot') THEN 1 ELSE 0 END) automated,"
                         "sum(CASE WHEN json_array_length(json_extract(obs,'$.attack_patterns'))>0 THEN 1 ELSE 0 END) attacks,"
                         "sum(CASE WHEN json_extract(obs,'$.tls_version') IN ('TLSv1','TLSv1.0','SSLv3') THEN 1 ELSE 0 END) weak_tls "
                         "FROM rows WHERE kind IN ('dns','http','tls') GROUP BY k,b,kind ORDER BY k,b,kind",
                         (run.policy["long_domain_length"],)):
        kind, count = row["kind"], row["n"]
        refs = run.refs("k=? AND b=? AND kind=?", (row["k"], row["b"], kind))
        denominator = row[{"dns": "dns_observed", "http": "http_observed", "tls": "tls_observed"}[kind]]
        metrics = {"denominator": denominator, "records": count, "window_start_epoch": row["b"]*run.policy["window_seconds"]}
        if denominator:
            name, number = {"dns": ("dns_long_ratio", row["long_dns"]), "http": ("http_error_ratio", row["errors"]),
                            "tls": ("tls_weak_ratio", row["weak_tls"])}[kind]
            run.db.execute("INSERT INTO characteristics VALUES (?,?,?,?,?)", (row["k"], row["b"], name, number/denominator, denominator))
        if kind == "dns" and denominator >= run.policy["min_dns_queries"] and row["long_dns"]/denominator >= run.policy["long_domain_ratio"]:
            run.add("dns_characteristics", refs, {**metrics, "long_queries": row["long_dns"], "ratio": row["long_dns"]/denominator}, scope=row["k"])
        if (kind == "http" and count >= run.policy["min_http_requests"] and row["automated"] and
                (row["attacks"] or (denominator and row["errors"]/denominator >= run.policy["http_error_ratio"]))):
            run.add("http_characteristics", refs, {**metrics, "errors": row["errors"], "attack_patterns": row["attacks"],
                                                  "automation_records": row["automated"]}, scope=row["k"])
        if kind == "tls" and count >= run.policy["min_tls_records"] and row["weak_tls"]:
            run.add("tls_characteristics", refs, {**metrics, "weak_protocol_records": row["weak_tls"]}, scope=row["k"])
        run.add_timeline({"start_epoch": row["b"]*run.policy["window_seconds"], "unit": kind+"_records",
                          "statistic": "count", "value": count, "denominator": count, "context": json.loads(row["k"])})
    for row in run.query("SELECT c.k,c.b,group_concat(c.name) names,count(*) n FROM characteristics c "
                         "JOIN characteristics p ON p.k=c.k AND p.b=c.b-1 AND p.name=c.name "
                         "WHERE c.value>p.value AND c.value-p.value>=? GROUP BY c.k,c.b HAVING count(*)>=2 ORDER BY c.k,c.b",
                         (run.policy["change_ratio"],)):
        run.add("combined_change", run.refs("k=? AND b IN (?,?)", (row["k"], row["b"]-1, row["b"])),
                {"changed_characteristics": sorted(row["names"].split(",")), "denominator": row["n"],
                 "previous_window": row["b"]-1, "current_window": row["b"]}, scope=row["k"])
    if run.policy["enable_new_relationships"]:
        run.quality["approved_baseline_unavailable"] += 1
        run.insufficient = True
    run.limitations.append("신규·희소 통신의 승인 기준선 저장소가 연결되지 않아 신규 관계를 확정하지 않습니다.")
