"""Streaming firewall session analysis with disk-backed grouping and bounded output."""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import tempfile
from collections import Counter
from copy import deepcopy
from datetime import datetime

from saw.observation.connection import VERSION, connection_observation

ENGINE_VERSION = "firewall-observation/1"
DEFAULT_POLICY = {"scan_min_targets": 5, "scan_min_ports": 5, "transfer_min_bytes": 50_000_000,
                  "asymmetry_ratio": 10, "long_flow_seconds": 3600,
                  "scan_window_seconds": 300, "beacon_min_connections": 4, "beacon_max_cv": 0.1, "deny_allow_window_seconds": 3600}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _time(value):
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def analyze_firewall(events, *, context_snapshot=None, max_records=1_000_000, max_results=100,
                     policy=None, cancelled=None):
    """Analyze normalized CES once; caller supplies ACL-scoped events and trusted context.

    Start/interim/end are records, never independent periodic connections. Permission
    to pass a firewall is not evidence of handshake, compromise or data exfiltration.
    Disk state and result references are bounded independently of input cardinality.
    """
    if not 1 <= max_records <= 10_000_000 or not 1 <= max_results <= 1000:
        raise ValueError("invalid analysis limits")
    context_snapshot = deepcopy(context_snapshot)
    effective = {**DEFAULT_POLICY, **(policy or {})}
    if set(effective) != set(DEFAULT_POLICY) or any(
        isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
        for v in effective.values()
    ):
        raise ValueError("invalid firewall policy")
    if (effective["beacon_min_connections"] < 3 or effective["scan_window_seconds"] <= 0
            or effective["asymmetry_ratio"] < 1):
        raise ValueError("invalid firewall threshold")
    counts = Counter(records=0, sessions=0, deny_attempts=0, unresolved_records=0,
                     new_connections=0, candidates=0, omitted_sessions=0, omitted_candidates=0)
    quality = Counter()
    output, candidates = [], []
    partial, was_cancelled = False, False

    def stop():
        nonlocal partial, was_cancelled
        if cancelled and cancelled():
            was_cancelled = partial = True
        return was_cancelled

    def candidate(kind, refs, **metrics):
        counts["candidates"] += 1
        if len(candidates) < max_results:
            candidates.append({"kind": kind, "interpretation": "candidate", "event_refs": refs[:20],
                               "metrics": metrics, "limitations": ["No connection success or impact is established."]})
        else:
            counts["omitted_candidates"] += 1

    with tempfile.TemporaryDirectory(prefix="saw-fw-") as directory:
        db = sqlite3.connect(directory + "/sessions.sqlite")
        try:
            db.set_progress_handler(lambda: int(stop()), 10000)
            db.execute("PRAGMA temp_store=FILE")
            db.execute("PRAGMA cache_size=-2048")
            db.execute("CREATE TABLE records (n INTEGER PRIMARY KEY,k TEXT,t REAL,o TEXT,e TEXT)")
            db.execute("CREATE TABLE sessions (k TEXT,g TEXT,src TEXT,dst TEXT,port TEXT,t REAL,new INTEGER,body TEXT)")
            iterator = iter(events)
            for index in range(max_records):
                if stop():
                    break
                event = next(iterator, None)
                if event is None:
                    break
                counts["records"] += 1
                obs = (connection_observation(event, context_snapshot=context_snapshot) if context_snapshot is not None
                       else (event.get("ext") or {}).get("observation"))
                if not isinstance(obs, dict) or obs.get("producer") != "saw" or obs.get("version") != VERSION:
                    obs = connection_observation(event)
                obs = dict(obs)
                context = obs["context"]
                resolved = context.get("resolved") is True
                if not resolved:
                    counts["unresolved_records"] += 1
                base = [context.get(k) for k in ("org_unit_id", "network", "device_id",
                                                "device_profile_version_id", "virtual_domain")]
                communication = [event.get(k) for k in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol")]
                # NAT/zone/interface differences remain in the identity even when no canonical value exists.
                product = (event.get("ext") or {}).get(event.get("product"), {})
                nat = {k: v for k, v in product.items() if any(
                    word in k.lower() for word in ("nat", "zone", "interface"))} if isinstance(product, dict) else {}
                obs["endpoint"] = communication
                obs["group"] = _json(base)
                key = [base, communication, nat, obs.get("session_id"), obs.get("start_time")]
                if not resolved or not obs.get("session_id") or obs.get("action") == "blocked":
                    key.append(index)
                ref = {"event_id": event.get("event_id"), "raw_ref": event.get("raw_ref"),
                       "evidence_id": event.get("evidence_id"), "file_id": event.get("file_id")}
                db.execute("INSERT INTO records VALUES (?,?,?,?,?)",
                           (index, _json(key), _time(obs.get("timestamp")), _json(obs), _json(ref)))
            else:
                if next(iterator, None) is not None:
                    quality["record_limit_reached"] += 1
                    partial = True
            db.commit()
            db.execute("CREATE INDEX record_order ON records(k,t,n)")

            def finish(state):
                if state is None:
                    return
                obs = state["obs"]
                flags = state["quality"]
                if not state["time_verified"]:
                    flags.add("unverified_time_semantics")
                if obs["action"] == "blocked":
                    counts["deny_attempts"] += state["record_count"]
                    quality.update(flags)
                    return
                counts["sessions"] += 1
                if not state["ended"]:
                    flags.add("missing_session_end")
                totals = {}
                for name in ("src_to_dst_bytes", "dst_to_src_bytes"):
                    metric = obs["counters"][name]
                    mode = metric["counter_mode"]
                    valid = (state["valid"][name] and state["ended"] and obs["context"]["resolved"] and
                             "missing_endpoints" not in flags and
                             mode in {"cumulative", "delta", "total"} and not state["reset"][name])
                    totals[name] = state["sum"][name] if valid and mode == "delta" else (
                        state["last"][name] if valid else None)
                    if state["reset"][name]:
                        flags.add("counter_reset_or_reversal")
                    if not valid:
                        flags.add("unverified_or_incomplete_counters")
                duration = obs.get("duration_seconds") if state["time_verified"] and obs["context"]["resolved"] else None
                if (duration is None and state["time_verified"] and obs["context"]["resolved"] and
                        state["started"] is not None and state["ended_at"] is not None):
                    duration = max(0, state["ended_at"] - state["started"])
                new = bool(state["start_seen"] and obs["context"]["resolved"] and state["started"] is not None
                           and state["time_verified"] and obs["action"] == "allowed"
                           and "missing_endpoints" not in flags)
                counts["new_connections"] += int(new)
                body = {"session_key": hashlib.sha256(_json([state["key"], state["refs"][0]]).encode()).hexdigest(),
                        "context": obs["context"], "session_id": obs.get("session_id"),
                        "record_count": state["record_count"], "event_refs": state["refs"],
                        "omitted_event_refs": max(0, state["record_count"] - len(state["refs"])),
                        "new_connection_observed": new, "established_connection": None,
                        "action": obs["action"], "duration_seconds": duration, "quality": sorted(flags), **totals}
                if len(output) < max_results:
                    output.append(body)
                else:
                    counts["omitted_sessions"] += 1
                for flag in flags:
                    quality[flag] += 1
                src, _, dst, port, _ = obs["endpoint"]
                db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                           (body["session_key"], obs["group"], src, dst, str(port), state["started"],
                            int(new), _json(body)))
                if duration is not None and duration >= effective["long_flow_seconds"]:
                    candidate("long_flow", state["refs"], duration_seconds=duration)
                a, b = totals.values()
                if a is not None and b is not None and max(a, b) >= effective["transfer_min_bytes"]:
                    ratio = max(a, b) / max(1, min(a, b))
                    if ratio >= effective["asymmetry_ratio"]:
                        candidate("transfer_asymmetry", state["refs"], src_to_dst_bytes=a,
                                  dst_to_src_bytes=b, ratio=ratio)

            state = None
            for key, timestamp, raw_obs, raw_ref in db.execute("SELECT k,t,o,e FROM records ORDER BY k,t,n"):
                if stop():
                    break
                obs, ref = json.loads(raw_obs), json.loads(raw_ref)
                # ID reuse without start_time creates a fresh generation on a new start or after an end.
                split = state and (state["key"] != key or (
                    not obs.get("start_time") and (obs["record_kind"] == "session_start" or state["ended"])))
                if split:
                    finish(state)
                    state = None
                if state is None:
                    state = {"key": key, "obs": obs, "record_count": 0, "refs": [], "quality": set(),
                             "sum": {k: 0 for k in obs["counters"]},
                             "last": {k: None for k in obs["counters"]},
                             "valid": {k: True for k in obs["counters"]},
                             "reset": {k: False for k in obs["counters"]}, "start_seen": False,
                             "started": _time(obs.get("start_time")), "ended": False, "ended_at": None,
                             "time_verified": True}
                state["record_count"] += 1
                if len(state["refs"]) < 20:
                    state["refs"].append(ref)
                else:
                    state["refs"][-1] = ref
                state["obs"] = obs
                state["quality"].update(obs.get("quality") or [])
                time_profile = obs.get("time_profile") or {}
                state["time_verified"] &= (timestamp is not None and time_profile.get("verified") is True and
                                            time_profile.get("role") in {"occurred", "start", "end"} and
                                            obs.get("timestamp_precision") in {"seconds", "subseconds"})
                if obs["record_kind"] == "session_start":
                    state["start_seen"] = True
                    if state["started"] is None:
                        state["started"] = timestamp
                if obs["record_kind"] == "session_end":
                    state["ended"] = True
                    state["ended_at"] = _time(obs.get("end_time")) or timestamp
                if obs.get("whole_session"):
                    # One record is the whole connection. Its time is a start only when the profile says so;
                    # an end (or unspecified) time places the start only with a duration, and that start is
                    # an estimate. Without either, no start-to-start period can be claimed.
                    role = (obs.get("time_profile") or {}).get("role")
                    duration = obs.get("duration_seconds")
                    if timestamp is not None and role == "start":
                        state["start_seen"] = True
                        state["started"] = timestamp if state["started"] is None else state["started"]
                    elif timestamp is not None and duration is not None and role in {"end", "occurred"}:
                        state["start_seen"] = True
                        state["started"] = timestamp - duration if state["started"] is None else state["started"]
                        state["quality"].add("start_time_estimated")
                    else:
                        state["quality"].add("start_time_unknown")
                for name, metric in obs["counters"].items():
                    value = metric["value"]
                    state["valid"][name] &= metric["state"] == "observed"
                    if value is not None:
                        previous = state["last"][name]
                        if metric["counter_mode"] == "cumulative" and previous is not None and value < previous:
                            state["reset"][name] = True
                        state["last"][name] = value
                        state["sum"][name] += value
            finish(state)
            db.commit()
            if not was_cancelled:
                # Exploration includes denied attempts; it does not imply established connections.
                db.execute("CREATE TABLE attempts (g TEXT,src TEXT,dst TEXT,port TEXT,t REAL,a TEXT,r TEXT,b INTEGER)")
                for timestamp, raw_obs, ref in db.execute("SELECT t,o,e FROM records ORDER BY t,n"):
                    if stop():
                        break
                    obs = json.loads(raw_obs)
                    src, _, dst, port, _ = obs["endpoint"]
                    time_profile = obs.get("time_profile") or {}
                    if (time_profile.get("verified") is not True or
                            time_profile.get("role") not in {"occurred", "start", "end"} or
                            obs.get("timestamp_precision") not in {"seconds", "subseconds"}):
                        timestamp = None
                    if obs["context"]["resolved"]:
                        db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?)",
                                   (obs["group"], src, dst, str(port), timestamp, obs["action"], ref,
                                    int(timestamp // effective["scan_window_seconds"]) if timestamp is not None else None))
                db.execute("CREATE INDEX attempt_group ON attempts(g,src,dst,port,t)")
                for group, src, bucket, targets, ports in db.execute(
                    "SELECT g,src,b,count(DISTINCT dst),count(DISTINCT port) FROM attempts "
                    "WHERE src IS NOT NULL AND b IS NOT NULL GROUP BY g,src,b ORDER BY g,src,b"):
                    if stop():
                        break
                    if targets >= effective["scan_min_targets"] or ports >= effective["scan_min_ports"]:
                        refs = [json.loads(row[0]) for row in db.execute(
                            "SELECT r FROM attempts WHERE g=? AND src=? AND b=? ORDER BY t,r LIMIT 20",
                            (group, src, bucket))]
                        candidate("scan", refs, src_ip=src, unique_destinations=targets, unique_ports=ports,
                                  window_start_epoch=bucket * effective["scan_window_seconds"],
                                  window_seconds=effective["scan_window_seconds"])
                last_key, denied = None, None
                for group, src, dst, port, timestamp, action, ref in db.execute(
                    "SELECT g,src,dst,port,t,a,r FROM attempts ORDER BY g,src,dst,port,t,r"):
                    if stop():
                        break
                    key = (group, src, dst, port)
                    if key != last_key:
                        denied = None
                        last_key = key
                    if action == "blocked" and timestamp is not None:
                        denied = (timestamp, json.loads(ref))
                    elif (action == "allowed" and timestamp is not None and denied is not None and
                          0 <= timestamp - denied[0] <= effective["deny_allow_window_seconds"]):
                        candidate("deny_to_allow", [denied[1], json.loads(ref)], src_ip=src, dst_ip=dst)
                        denied = None
                beacon = None
                def finish_beacon(item):
                    if not item or item["n"] < effective["beacon_min_connections"] or item["sum"] <= 0:
                        return
                    count = item["n"] - 1
                    mean = item["sum"] / count
                    cv = math.sqrt(max(0, item["squares"] / count - mean * mean)) / mean
                    if cv <= effective["beacon_max_cv"]:
                        candidate("beacon", item["refs"], new_connections=item["n"], mean_interval_seconds=mean, cv=cv)
                for group, src, dst, port, timestamp, body in db.execute(
                    "SELECT g,src,dst,port,t,body FROM sessions WHERE new=1 ORDER BY g,src,dst,port,t,k"):
                    if stop():
                        break
                    key = (group, src, dst, port)
                    if beacon is None or beacon["key"] != key:
                        finish_beacon(beacon)
                        beacon = {"key": key, "n": 0, "last": timestamp, "sum": 0, "squares": 0, "refs": []}
                    if beacon["n"]:
                        delta = timestamp - beacon["last"]
                        beacon["sum"] += delta
                        beacon["squares"] += delta * delta
                    beacon["n"] += 1
                    beacon["last"] = timestamp
                    start_ref = json.loads(body)["event_refs"][0]
                    if len(beacon["refs"]) < 20:
                        beacon["refs"].append(start_ref)
                    else:
                        beacon["refs"][-1] = start_ref
                if not was_cancelled:
                    finish_beacon(beacon)
        except sqlite3.OperationalError:
            if not was_cancelled:
                raise
        finally:
            db.close()
    unresolved = counts["unresolved_records"]
    status = ("cancelled" if was_cancelled else "partial" if partial else "insufficient_data"
              if not counts["records"] or unresolved == counts["records"] else "partial"
              if unresolved or quality else "completed_match" if candidates else "completed_no_match")
    return {"engine_version": ENGINE_VERSION, "observation_version": VERSION, "status": status,
            "counts": dict(counts), "sessions": output, "candidates": candidates,
            "quality": dict(sorted(quality.items())), "policy": effective,
            "limits": {"max_records": max_records, "max_results": max_results,
                       "max_event_refs_per_result": 20, "coverage_complete": not partial},
            "limitations": ["Allowed action does not establish a successful connection or impact.",
                            "New/rare communication requires a separately approved comparable baseline.",
                            "Manufacturer mappings require validated product dictionaries.",
                            "Candidates are observations requiring analyst verification.",
                            "Scan windows are fixed half-open epoch buckets; cross-boundary attempts remain separate.",
                            "Session groups include isolated unresolved records; established connections are unverified."]}
