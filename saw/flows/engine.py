"""Deterministic flow analysis: apply analyst knowledge to time-ordered records.

Pure functions over event dictionaries, so the same records and the same knowledge always give the same result.
Nothing here knows a service, a URL or an account: every meaning comes from the knowledge passed in.

What is deliberately *not* inferred:
- an HTTP status, a cookie being present or a response size never decides an authentication or business result;
  only an analyst-declared result rule does,
- "no earlier authentication record" is not "unauthenticated" (the session may predate the collected period),
- one failed attempt does not cancel another valid session,
- the same IP is not the same actor; without a confirmed session link a flow is only a *candidate* grouping,
- a DDoS interval is a service-level aggregate and is never attached to one session as its behaviour,
- a frequent transition is not "normal" and a rare one is not "an attack".
"""
from __future__ import annotations

import re
import urllib.parse
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime, timezone

ENGINE_VERSION = "saw.flows/1"
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")
ROLES = {"auth_page": "인증 화면 접근", "auth_attempt": "인증 시도", "lookup": "조회 요청", "change": "변경 요청",
         "logout": "로그아웃", "other": "기타"}
DEFAULTS = {"idle_seconds": 1800, "join_seconds": 5, "skew_seconds": 2, "max_records": 3_000_000,
            "max_flows": 300, "max_steps": 300, "max_side_records": 300_000}


def get(e: dict, path: str):
    """A field by dotted path, from a full document or from a flat projection."""
    if path in e:
        return e[path]
    cur = e
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def ext(e: dict, name: str):
    return get(e, f"ext.security_csv.{name}")


def epoch(ts) -> float | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def norm_host(host) -> str:
    host = (host or "").strip().lower()
    if host.startswith("["):
        return host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def split_uri(uri) -> tuple[str, dict[str, str]]:
    path, _, query = (uri or "").partition("?")
    if path.startswith(("http://", "https://")):
        path = "/" + path.split("/", 3)[3] if path.count("/") >= 3 else "/"
    params = {}
    for name, value in urllib.parse.parse_qsl(query.partition("#")[0], keep_blank_values=True)[:100]:
        params.setdefault(name, value)
    return path or "/", params


# ---------------------------------------------------------------------------------------------------------------
# Knowledge compilation and matching


def _path_regex(path: str, match: str):
    if match == "exact":
        return None
    if match == "prefix":
        return None
    parts = []
    for seg in path.split("/"):
        if seg.startswith("{") and seg.endswith("}"):
            parts.append("[^/]+")
        else:
            parts.append(".*".join(re.escape(piece) for piece in seg.split("*")) if "*" in seg else re.escape(seg))
    return re.compile("/".join(parts) + r"/?\Z")


class Activity:
    __slots__ = ("id", "version", "org", "host", "method", "path", "match", "regex", "params", "meaning", "role",
                 "object_param", "outcomes", "rank")

    def __init__(self, item: dict):
        c = item["content"]
        self.id, self.version, self.org = item["id"], item["version"], item.get("org_unit_id")
        self.host, self.method = norm_host(c.get("host")), (c.get("method") or "").upper()
        self.path, self.match = c.get("path") or "/", c.get("match") or "exact"
        self.regex = _path_regex(self.path, self.match)
        self.params = [(p.get("name"), p.get("value") or "") for p in c.get("params") or [] if p.get("name")]
        self.meaning, self.role = c.get("meaning") or "", c.get("role") or "other"
        self.object_param, self.outcomes = c.get("object_param") or "", c.get("outcomes") or []
        # More specific knowledge wins: exact > template > prefix (longer first), then method, parameters, affiliate.
        base = {"exact": 3000, "pattern": 2000, "prefix": 1000}[self.match] + min(len(self.path), 900)
        self.rank = base * 10 + (4 if self.method else 0) + min(len(self.params), 3) + (0.5 if self.org else 0)

    def matches(self, method: str, path: str, params: dict) -> bool:
        if self.method and self.method != method:
            return False
        if self.match == "exact":
            if path != self.path and path.rstrip("/") != self.path.rstrip("/"):
                return False
        elif self.match == "prefix":
            if not path.startswith(self.path):
                return False
        elif not self.regex.match(path):
            return False
        return all(name in params and (not value or params[name] == value) for name, value in self.params)


class Compiled:
    """Active knowledge for one affiliate, indexed by service."""

    def __init__(self, items: list[dict]):
        self.activities: dict[str, list[Activity]] = defaultdict(list)
        self.links: dict[str, dict] = {}
        self.flows: dict[str, list[dict]] = defaultdict(list)
        self.by_id: dict[str, dict] = {}
        self.conflicts: list[dict] = []
        self.versions = {item["id"]: item["version"] for item in items}
        links: dict[str, list[dict]] = defaultdict(list)
        for item in items:
            self.by_id[item["id"]] = item
            host = norm_host(item["content"].get("host"))
            if item["kind"] == "activity":
                self.activities[host].append(Activity(item))
            elif item["kind"] == "link":
                links[host].append(item)
            elif item["kind"] == "flow":
                self.flows[host].append(item)
        for host, rows in self.activities.items():
            rows.sort(key=lambda a: -a.rank)
        for host, rows in links.items():
            # An affiliate's own link definition replaces the common one; two of the same scope conflict.
            own = [r for r in rows if r.get("org_unit_id")] or rows
            if len(own) > 1 and len({_stable(r["content"]) for r in own}) > 1:
                self.conflicts.append({"kind": "link", "host": host, "ids": [r["id"] for r in own],
                                       "text": f"{host}의 연결 기준이 서로 다르게 {len(own)}개 등록되어 있어 적용하지 않았습니다."})
            else:
                self.links[host] = own[0]

    def activity(self, host: str, method: str, path: str, params: dict) -> tuple[Activity | None, dict | None]:
        hits = [a for a in self.activities.get(host, ()) if a.matches(method, path, params)]
        if not hits:
            return None, None
        top = [a for a in hits if a.rank == hits[0].rank]
        if len({(a.meaning, a.role) for a in top}) > 1:
            return None, {"kind": "activity", "host": host, "ids": [a.id for a in top],
                          "text": f"{host} {method} {path}에 같은 범위의 정의가 서로 다르게 등록되어 있어 의미를 적용하지 않았습니다: "
                                  + " / ".join(sorted({a.meaning for a in top}))}
        return top[0], None


def _stable(value) -> str:
    import json

    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------------------------------------------
# Result rules


def _rule_value(source: dict, field: str):
    value = get(source, field)
    if value is None:
        value = ext(source, field)
    return value


def _rule_hit(rule: dict, source: dict) -> bool:
    actual, wanted, op = _rule_value(source, rule.get("field") or ""), rule.get("value"), rule.get("op") or "eq"
    if actual is None:
        return False
    a, w = str(actual).strip().casefold(), str(wanted if wanted is not None else "").strip().casefold()
    if op == "eq":
        return a == w
    if op == "ne":
        return a != w
    if op == "in":
        return a in {part.strip() for part in w.split(",")}
    if op == "contains":
        return w in a
    if op == "prefix":
        return a.startswith(w)
    try:
        return float(a) >= float(w) if op == "ge" else float(a) <= float(w) if op == "le" else False
    except ValueError:
        return False


class SideIndex:
    """Application events and device alerts, looked up by request id, session reference or source address."""

    def __init__(self, events: list[dict]):
        self.by_request: dict[str, list[dict]] = defaultdict(list)
        self.by_session: dict[str, list[dict]] = defaultdict(list)
        self.by_src: dict[tuple, list[dict]] = defaultdict(list)
        for e in events:
            e["_t"] = epoch(e.get("timestamp"))
            if e["_t"] is None:
                continue
            rid = ext(e, "request_id")
            if rid not in (None, "", "-"):
                self.by_request[str(rid)].append(e)
            ref = ext(e, "session_ref")
            if ref:
                self.by_session[ref].append(e)
            if e.get("src_ip"):
                self.by_src[(e["src_ip"], norm_host(e.get("hostname")))].append(e)
        for table in (self.by_request, self.by_session, self.by_src):
            for rows in table.values():
                rows.sort(key=lambda r: r["_t"])

    @staticmethod
    def near(rows: list[dict], t: float, window: float) -> list[dict]:
        keys = [r["_t"] for r in rows]
        start = bisect_left(keys, t - window)
        out = []
        for row in rows[start:]:
            if row["_t"] > t + window:
                break
            out.append(row)
        return out


# ---------------------------------------------------------------------------------------------------------------
# The analysis


class _Session:
    __slots__ = ("key", "host", "link", "link_text", "ref", "src_ips", "ua", "steps", "omitted", "first", "last",
                 "prev_label", "prev_t", "accounts", "attempted", "auth", "seen_pairs", "total", "unlabeled", "part")

    def __init__(self, key, host, link, link_text, ref):
        self.key, self.host, self.link, self.link_text, self.ref = key, host, link, link_text, ref
        self.src_ips, self.ua, self.steps, self.omitted = set(), None, [], 0
        self.first = self.last = None
        self.prev_label = self.prev_t = None
        self.accounts: dict[str, str] = {}
        self.attempted: set[str] = set()
        self.auth = {"state": "unknown", "success_at": None, "failures": 0, "attempts": 0, "logout_at": None}
        self.seen_pairs: set = set()
        self.total = self.unlabeled = 0
        self.part = 0


def _iso(t: float | None) -> str | None:
    return None if t is None else datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


def analyze(web_events, *, app_events: list[dict], alerts: list[dict], ddos: list[dict], compiled: Compiled,
            options: dict | None = None, history: set | None = None, signature=None) -> dict:
    """web_events: time-ordered HTTP request records. Returns the result document stored with the run."""
    opt = {**DEFAULTS, **(options or {})}
    baseline_end = epoch(opt.get("baseline_end")) if opt.get("baseline_end") else None
    apps, alert_index = SideIndex(app_events), SideIndex(alerts)
    sessions: dict[tuple, _Session] = {}
    done: list[_Session] = []
    transitions: dict[tuple, dict] = {}
    counts = {"records_read": 0, "labeled": 0, "unlabeled": 0, "static_skipped": 0, "no_time": 0, "duplicates": 0,
              "no_host": 0, "conflicting_definition": 0, "sessions_confirmed": 0, "sessions_candidate": 0}
    conflicts = {_stable(c): c for c in compiled.conflicts}
    services: dict[str, dict] = {}
    unlabeled_paths: dict[tuple, dict] = {}
    intervals = _ddos_intervals(ddos)
    last_key = None
    first_t = last_t = None
    truncated = False

    for e in web_events:
        if counts["records_read"] >= opt["max_records"]:
            truncated = True
            break
        counts["records_read"] += 1
        t = epoch(e.get("timestamp"))
        if t is None:
            counts["no_time"] += 1  # a record without a time has no place in an order; it is counted, not placed
            continue
        host = norm_host(e.get("hostname"))
        method = (e.get("method") or "").upper()
        path, params = split_uri(e.get("uri"))
        uid = ext(e, "uuid")
        # The same record delivered twice (re-export, overlapping upload) is one observation.
        dup_key = (t, e.get("src_ip"), e.get("src_port"), host, method, e.get("uri"), uid, e.get("data_source"))
        if dup_key == last_key:
            counts["duplicates"] += 1
            continue
        last_key = dup_key
        first_t = t if first_t is None else first_t
        last_t = t
        for iv in intervals:
            if iv["host"] in ("", host) and iv["_start"] <= t <= iv["_end"]:
                iv["requests"] += 1
                if isinstance(e.get("status_code"), int) and e["status_code"] >= 500:
                    iv["server_errors"] += 1
        if not host:
            counts["no_host"] += 1
            continue
        svc = services.setdefault(host, {"host": host, "requests": 0, "labeled": 0, "activities": {}})
        svc["requests"] += 1
        activity, conflict = compiled.activity(host, method, path, params)
        if conflict:
            counts["conflicting_definition"] += 1
            conflicts.setdefault(_stable(conflict), conflict)
        link = (compiled.links.get(host) or {}).get("content") or {}
        ref = _session_ref(e, link)
        if ref:
            key = ("s", host, ref)
        else:
            key = ("c", host, e.get("src_ip") or "", e.get("user_agent") or "")
        s = sessions.get(key)
        if s is not None and not ref and s.last is not None and t - s.last > opt["idle_seconds"]:
            done.append(s)  # a candidate grouping ends after a long silence: later requests may be someone else
            part = s.part + 1
            s = None
        else:
            part = s.part if s else 0
        if s is None:
            cookie = link.get("session_cookie")
            s = sessions[key] = _Session(key, host, "session" if ref else "candidate",
                                         f"세션 쿠키 {cookie}의 값이 같음(지식으로 확인된 세션 식별자)" if ref else
                                         "같은 출발지 IP·서비스·User-Agent, 시간 인접 — 같은 사용자라는 근거는 아님", ref)
            s.part = part
            s.first, s.ua = t, e.get("user_agent")
            counts["sessions_confirmed" if ref else "sessions_candidate"] += 1
        s.last = t
        s.total += 1
        if e.get("src_ip"):
            s.src_ips.add(e["src_ip"])

        if activity is None:
            counts["unlabeled"] += 1
            if path.lower().endswith(STATIC_EXT):
                counts["static_skipped"] += 1
                continue
            s.unlabeled += 1
            template = (e.get("uri_template") or path).split("?")[0]
            label = f"미등록 {method} {template}".strip()
            row = unlabeled_paths.setdefault((host, method, template), {"host": host, "method": method,
                                                                       "path": template, "count": 0, "first": _iso(t),
                                                                       "example_event_id": e.get("event_id")})
            row["count"] += 1
            row["last"] = _iso(t)
        else:
            counts["labeled"] += 1
            svc["labeled"] += 1
            used = svc["activities"].setdefault(activity.id, {"knowledge_id": activity.id, "version": activity.version,
                                                             "meaning": activity.meaning, "role": activity.role,
                                                             "count": 0})
            used["count"] += 1
            label = activity.meaning
            step = _step(e, t, activity, method, path, params, uid, link, s, apps, alert_index, opt, signature)
            _advance_auth(s, step)
            if len(s.steps) < opt["max_steps"]:
                if s.steps and s.steps[-1]["_t"] == t:
                    step["order_uncertain"] = s.steps[-1]["order_uncertain"] = True  # equal times: order not established
                s.steps.append(step)
            else:
                s.omitted += 1
        if s.prev_label is not None:
            tr = transitions.setdefault((host, s.prev_label, label), {
                "host": host, "from": s.prev_label, "to": label, "count": 0, "sessions": 0, "first": _iso(t),
                "_first": t, "gaps": [], "example_event_ids": []})
            tr["count"] += 1
            tr["last"] = _iso(t)
            if len(tr["gaps"]) < 2000:
                tr["gaps"].append(round(t - s.prev_t, 3))
            if (s.prev_label, label) not in s.seen_pairs:
                s.seen_pairs.add((s.prev_label, label))
                tr["sessions"] += 1
                if len(tr["example_event_ids"]) < 3 and e.get("event_id"):
                    tr["example_event_ids"].append(e["event_id"])
        s.prev_label, s.prev_t = label, t

    done.extend(sessions.values())
    flows = [f for f in (_flow(s, compiled, intervals, opt) for s in done if s.steps) if f]
    flows.sort(key=lambda f: (-f["attention"], f["start"] or ""))
    shown = flows[:opt["max_flows"]]
    discovery = _discovery(transitions, compiled, baseline_end, history or set())
    by_host_unlabeled = sorted(unlabeled_paths.values(), key=lambda r: -r["count"])
    for row in by_host_unlabeled[:200]:
        row["suggestion"] = _suggest(row, compiled)
    for iv in intervals:
        iv.pop("_start"), iv.pop("_end")
    status = "no_data" if not counts["records_read"] else "partial" if truncated else "complete"
    return {
        "engine": ENGINE_VERSION, "status": status, "counts": counts,
        "time": {"first": _iso(first_t), "last": _iso(last_t), "basis": "기록의 발생 시각(수집·업로드 시각 아님)",
                 "skew_seconds": opt["skew_seconds"],
                 "note": "발생 시각 순으로 정렬했습니다. 같은 시각의 기록은 순서를 정하지 않았고, 시각이 없는 기록은 흐름에 넣지 않았습니다."},
        "completeness": {"truncated": truncated, "max_records": opt["max_records"],
                         "flows_total": len(flows), "flows_shown": len(shown),
                         "sessions_without_known_activity": sum(1 for s in done if not s.steps),
                         "note": "처리 한도를 넘은 기록은 검사하지 않았습니다." if truncated else ""},
        "services": [{**svc, "activities": sorted(svc["activities"].values(), key=lambda a: -a["count"]),
                      "link": _link_status(compiled, svc["host"])} for svc in
                     sorted(services.values(), key=lambda v: -v["requests"])][:100],
        "flows": shown,
        "unregistered": by_host_unlabeled[:200],
        "discovery": discovery,
        "ddos": intervals,
        "conflicts": list(conflicts.values()),
        "side": {"app_events": len(app_events), "alerts": len(alerts), "ddos_intervals": len(intervals)},
    }


def _session_ref(e: dict, link: dict) -> str | None:
    cookie = link.get("session_cookie")
    if not cookie:
        return None
    for item in ext(e, "req_cookie_refs") or []:
        name, _, ref = str(item).partition("=")
        if name == cookie and ref:
            return ref
    return None


def _link_status(compiled: Compiled, host: str) -> dict:
    link = (compiled.links.get(host) or {})
    c = link.get("content") or {}
    return {"knowledge_id": link.get("id"), "version": link.get("version"),
            "session_cookie": c.get("session_cookie") or "", "request_id_confirmed": bool(c.get("request_id_confirmed")),
            "text": ("세션 쿠키 " + c["session_cookie"] + "로 요청을 연결합니다." if c.get("session_cookie") else
                     "세션 식별자가 확인되지 않아 출발지 IP·시간 기준 후보로만 묶었습니다.")
                    + (" uuid를 요청 ID로 확인했습니다." if c.get("request_id_confirmed") else
                       " uuid가 요청 ID인지 수집 레코드 ID인지는 확인되지 않았습니다.")}


def _step(e, t, activity: Activity, method, path, params, uid, link, s: _Session, apps: SideIndex,
          alert_index: SideIndex, opt, signature) -> dict:
    step = {"_t": t, "time": e.get("timestamp"), "event_id": e.get("event_id"), "method": method, "path": path,
            "status_code": e.get("status_code"), "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"),
            "dst_port": e.get("dst_port"),
            "meaning": activity.meaning, "role": activity.role,
            "knowledge": {"id": activity.id, "version": activity.version},
            "outcome": "unknown", "outcome_basis": "결과 확인 기준이 등록되지 않았습니다.", "order_uncertain": False}
    if activity.object_param and activity.object_param in params:
        step["object"] = params[activity.object_param]
        step["object_basis"] = f"요청 파라미터 {activity.object_param}"
    confirmed_request = bool(link.get("request_id_confirmed")) and uid not in (None, "", "-")
    app_hits, app_basis, app_confirmed = [], "", False
    if confirmed_request and str(uid) in apps.by_request:
        app_hits, app_basis, app_confirmed = apps.by_request[str(uid)], "요청 ID 일치", True
    elif s.ref and s.ref in apps.by_session:
        app_hits = SideIndex.near(apps.by_session[s.ref], t, opt["join_seconds"])
        app_basis, app_confirmed = f"같은 세션, {opt['join_seconds']}초 이내", True
    elif (e.get("src_ip"), s.host) in apps.by_src:
        app_hits = SideIndex.near(apps.by_src[(e.get("src_ip"), s.host)], t, opt["join_seconds"])
        app_basis = f"같은 출발지 IP·서비스, {opt['join_seconds']}초 이내(후보)"
    if activity.outcomes:
        step["outcome_basis"] = "결과 확인 기준에 맞는 기록이 없습니다."
    for rule in activity.outcomes:
        if (rule.get("source") or "http") == "http":
            if _rule_hit(rule, e):
                step["outcome"] = rule.get("result") or "unknown"
                step["outcome_basis"] = f"이 요청의 {rule.get('field')} = {_rule_value(e, rule.get('field') or '')} (등록된 결과 기준)"
                break
            continue
        rows = [a for a in app_hits if not rule.get("event") or str(ext(a, "event") or "").casefold()
                == str(rule["event"]).casefold()]
        hit = next((a for a in rows if _rule_hit(rule, a)), None)
        if hit is None:
            continue
        if app_confirmed:
            step["outcome"] = rule.get("result") or "unknown"
            step["outcome_basis"] = (f"애플리케이션 기록 {ext(hit, 'event') or ''}의 {rule.get('field')} = "
                                     f"{_rule_value(hit, rule.get('field') or '')} ({app_basis})")
        else:
            step["outcome_candidate"] = rule.get("result")
            step["outcome_basis"] = (f"애플리케이션 기록에 {rule.get('result')} 후보가 있으나 연결이 확정되지 않았습니다"
                                     f" ({app_basis}).")
        step["app_event_id"] = hit.get("event_id")
        if app_confirmed and hit.get("user"):
            step["account"] = hit["user"]
            step["account_basis"] = f"애플리케이션 기록의 계정 ({app_basis})"
        target = ext(hit, "target")
        if app_confirmed and target not in (None, "", "-"):
            step["object"], step["object_basis"] = str(target), f"애플리케이션 기록의 대상 ({app_basis})"
        break
    if "account" not in step and app_confirmed and app_basis == "요청 ID 일치":
        # Only a record of this very request names its account; a nearby record of the session may be another act.
        who = next((a.get("user") for a in app_hits if a.get("user")), None)
        if who:
            step["account"], step["account_basis"] = who, f"애플리케이션 기록의 계정 ({app_basis})"
    step["devices"] = _device_links(e, t, uid, confirmed_request, s.host, path, alert_index, opt, signature)
    return step


def _device_links(e, t, uid, confirmed_request, host, path, alert_index: SideIndex, opt, signature) -> list[dict]:
    out, seen = [], set()

    def add(alert, link, basis):
        if alert.get("event_id") in seen or len(out) >= 10:
            return
        seen.add(alert.get("event_id"))
        row = {"event_id": alert.get("event_id"), "source": alert.get("data_source"), "time": alert.get("timestamp"),
               "alert_name": alert.get("alert_name"), "device": ext(alert, "_device_name"),
               "rule_id": ext(alert, "rule_id") or ext(alert, "signature_id"),
               "rule_version": ext(alert, "rule_version") or ext(alert, "signature_version"),
               "device_action": ext(alert, "action"), "enforcement_action": alert.get("enforcement_action"),
               "http_status": alert.get("status_code"), "link": link, "link_basis": basis,
               "seconds_from_request": round(alert["_t"] - t, 3)}
        if signature:
            row["signature"] = signature(ext(alert, "vendor") or "", ext(alert, "product") or "",
                                         row["rule_id"] or "", alert.get("alert_name") or "")
        out.append(row)

    if uid not in (None, "", "-") and str(uid) in alert_index.by_request:
        for alert in alert_index.by_request[str(uid)]:
            if confirmed_request:
                add(alert, "same_request", "요청 ID 일치(요청 ID로 확인된 필드)")
            else:
                add(alert, "candidate", "uuid 값이 같음 — uuid가 요청 ID인지 확인되지 않아 후보로 둡니다")
    for alert in SideIndex.near(alert_index.by_src.get((e.get("src_ip"), host), []), t, opt["join_seconds"]):
        alert_path = split_uri(alert.get("uri"))[0] if alert.get("uri") else None
        if alert_path and alert_path != path:
            continue
        add(alert, "candidate", f"같은 출발지 IP·서비스{'·경로' if alert_path else ''}, {opt['join_seconds']}초 이내 — 같은 요청이라는 근거는 아님")
    if not host:
        return out
    for alert in SideIndex.near(alert_index.by_src.get((e.get("src_ip"), ""), []), t, opt["join_seconds"]):
        if alert.get("dst_ip") and e.get("dst_ip") and alert["dst_ip"] != e["dst_ip"]:
            continue
        add(alert, "candidate", f"같은 출발지·목적지 IP, {opt['join_seconds']}초 이내 — 같은 통신이라는 근거는 아님")
    return out


def _advance_auth(s: _Session, step: dict) -> None:
    """The authentication context of each step, from what was observed before it in the same grouping."""
    a, role, out = s.auth, step["role"], step["outcome"]
    if step.get("account"):
        if role == "auth_attempt" and out != "success":
            # The account named in an attempt that did not succeed is not an authenticated account.
            s.attempted.add(step["account"])
            step["account_note"] = "시도한 계정(인증 성공이 확인된 계정이 아님)"
        else:
            s.accounts.setdefault(step["account"], step.get("account_basis") or "")
    if role in ("lookup", "change", "other"):
        if a["logout_at"] is not None and (a["success_at"] is None or a["success_at"] < a["logout_at"]):
            step["auth_context"] = "after_logout"
        elif a["success_at"] is not None:
            step["auth_context"] = "after_success"
        elif a["failures"]:
            step["auth_context"] = "after_failure_only"
        elif a["attempts"]:
            step["auth_context"] = "after_attempt_unknown"
        else:
            step["auth_context"] = "no_prior_auth_observed"
    elif role == "auth_attempt":
        a["attempts"] += 1
        if out == "success":
            a["success_at"], a["state"] = step["_t"], "success"
        elif out == "failure":
            a["failures"] += 1  # a failed attempt does not cancel an earlier or another valid session
    elif role == "logout":
        a["logout_at"] = step["_t"]


AUTH_TEXT = {
    "after_success": "인증 성공이 확인된 뒤의 요청",
    "after_failure_only": "앞선 인증 시도가 실패로 확인됨(성공 기록 없음)",
    "after_attempt_unknown": "앞선 인증 시도의 성공 여부가 확인되지 않음",
    "no_prior_auth_observed": "앞선 인증 기록이 이 자료에 없음(수집 구간 이전 인증·SSO·기존 세션일 수 있음)",
    "after_logout": "로그아웃 기록 뒤의 요청(재인증 기록 없음)",
}


def _flow(s: _Session, compiled: Compiled, intervals: list[dict], opt) -> dict | None:
    steps = s.steps
    confirmed, inferred, unknown, checks, flags = [], [], [], [], []
    attention = 0
    accounts = sorted(s.accounts)
    meanings = []
    for st in steps:
        if not meanings or meanings[-1] != st["meaning"]:
            meanings.append(st["meaning"])
    lookups = [st for st in steps if st["role"] in ("lookup", "change")]
    attempts = [st for st in steps if st["role"] == "auth_attempt"]
    session_confirmed = s.link == "session"
    ref8 = (s.ref or "")[:8]

    if session_confirmed:
        confirmed.append(f"세션 참조 {ref8}의 요청 {s.total}건을 한 세션으로 연결했습니다({s.link_text}).")
    else:
        inferred.append(f"요청 {s.total}건을 한 흐름 후보로 묶었습니다({s.link_text}).")
        unknown.append("같은 세션인지 확인되지 않았습니다. 세션 식별 쿠키를 지식으로 등록하면 세션 단위로 다시 연결합니다.")
        checks.append("이 서비스의 세션 식별 쿠키 이름을 확인해 '연결 기준'으로 등록")
    for st in attempts:
        when = _clock(st["time"])
        if st["outcome"] == "success":
            confirmed.append(f"{when} {st['meaning']}: 성공 ({st['outcome_basis']})")
        elif st["outcome"] == "failure":
            confirmed.append(f"{when} {st['meaning']}: 실패 ({st['outcome_basis']})")
            if isinstance(st.get("status_code"), int) and 200 <= st["status_code"] < 300:
                flags.append("http_200_but_failed")
                confirmed.append(f"{when} 이 요청의 HTTP 응답은 {st['status_code']}이지만 인증 결과는 실패입니다.")
        else:
            unknown.append(f"{when} {st['meaning']}의 성공 여부 ({st['outcome_basis']})")
    contexts = {st.get("auth_context") for st in lookups}
    for st in lookups:
        when, ctx = _clock(st["time"]), st.get("auth_context")
        if st["outcome"] == "unknown":
            unknown.append(f"{when} {st['meaning']}의 처리 결과 ({st['outcome_basis']})")
        else:
            confirmed.append(f"{when} {st['meaning']}: {'처리됨' if st['outcome'] == 'success' else '처리되지 않음'} ({st['outcome_basis']})")
        if ctx == "after_success" and not session_confirmed:
            st["auth_context_note"] = "같은 세션인지는 확인되지 않음"
        if st.get("object") and st.get("account"):
            same = str(st["object"]) == str(st["account"])
            st["object_relation"] = "self" if same else "other"
            if not same:
                flags.append("other_target")
        elif st.get("object") and accounts:
            st["object_relation"] = "self" if str(st["object"]) == accounts[0] and len(accounts) == 1 else "other"
            if st["object_relation"] == "other":
                flags.append("other_target")
    if "after_failure_only" in contexts:
        flags.append("lookup_after_failed_auth")
        attention += 3
        checks.append("인증 실패 뒤 조회가 실제로 처리됐는지(응답 본문·애플리케이션 기록), 다른 유효 세션·SSO가 있었는지 확인")
    if "after_logout" in contexts:
        flags.append("lookup_after_logout")
        attention += 3
        checks.append("로그아웃 뒤 요청이 서버에서 거부됐는지 확인")
    if "no_prior_auth_observed" in contexts:
        flags.append("no_prior_auth_observed")
        unknown.append("이 흐름의 인증 기록이 자료에 없습니다. 인증되지 않은 상태가 확인된 것은 아닙니다.")
        checks.append("수집 구간 이전의 인증 기록·SSO 기록을 요청")
    if "after_attempt_unknown" in contexts:
        checks.append("인증 결과를 알 수 있는 애플리케이션 기록을 요청하거나 결과 확인 기준을 등록")
    if "other_target" in flags:
        attention += 2
        checks.append("조회 대상이 확인된 계정과 다릅니다. 이 계정의 조회 권한(업무 권한·위임)을 확인")
    if s.attempted - set(accounts):
        confirmed.append("인증에 성공하지 못한 시도의 계정: " + ", ".join(sorted(s.attempted - set(accounts))[:5]))
    if len(accounts) > 1:
        flags.append("several_accounts")
        attention += 1
        unknown.append(f"한 흐름에서 계정이 {len(accounts)}개 확인됩니다({', '.join(accounts[:5])}). 계정 전환인지 공용 단말인지 확인이 필요합니다.")

    devices = []
    for st in steps:
        for d in st.get("devices") or []:
            devices.append({**d, "step_event_id": st["event_id"]})
            blocked = d.get("enforcement_action") == "blocked"
            succeeded = st["outcome"] == "success"
            if blocked and (succeeded or (isinstance(st.get("status_code"), int) and st["status_code"] < 400)):
                flags.append("device_block_vs_success")
                detail = (f"{_clock(d['time'])} {d.get('source', '').upper()} '{d.get('alert_name')}' 장비 조치 {d.get('device_action')}"
                          f" ↔ {_clock(st['time'])} {st['meaning']} HTTP {st.get('status_code')}"
                          f"{' · 업무 결과 성공' if succeeded else ''}")
                if d["link"] == "same_request":
                    unknown.append("같은 요청에 대해 장비 차단 기록과 요청 처리 기록이 함께 있습니다: " + detail
                                   + ". 장비가 실제로 차단했는지(탐지 전용·사후 차단)와 응답 주체를 확인해야 합니다.")
                else:
                    unknown.append("장비 차단 기록과 가까운 시각의 요청 처리 기록이 있습니다: " + detail
                                   + f". 같은 요청인지 확인되지 않았습니다(장비 기록이 요청보다 {d['seconds_from_request']:+.1f}초). 재시도·다른 요청일 수 있습니다.")
                checks.append("장비의 실제 조치 방식(차단/탐지 전용)과 같은 요청 여부(요청 ID·원문) 확인")
    if devices:
        attention += 2
        if any(d["link"] == "same_request" for d in devices):
            confirmed.append(f"보안장비 기록 {sum(1 for d in devices if d['link'] == 'same_request')}건이 같은 요청으로 연결됩니다(요청 ID 일치).")
        if any(d["link"] == "candidate" for d in devices):
            inferred.append(f"보안장비 기록 {sum(1 for d in devices if d['link'] == 'candidate')}건이 같은 시간대의 관련 후보입니다.")
    if "device_block_vs_success" in flags:
        attention += 3
    overlapping = [iv["id"] for iv in intervals if iv["host"] in ("", s.host)
                   and iv["_start"] <= s.last and iv["_end"] >= s.first]
    if overlapping:
        inferred.append("이 흐름의 시간대에 같은 서비스의 DDoS 관측 구간이 있습니다. 집계 자료이므로 이 흐름의 행위로 연결하지 않았습니다.")

    conformance, explained = _conformance(steps, compiled, s.host)
    for c in conformance:
        if c["status"] == "deviates":
            attention += 2
            flags.append("deviates_from_registered_flow")
    if any(st.get("order_uncertain") for st in steps):
        unknown.append("같은 시각의 기록이 있어 그 사이의 순서는 확정하지 않았습니다.")
    if s.omitted:
        unknown.append(f"이 흐름의 뒤쪽 {s.omitted}개 단계는 표시 한도를 넘어 생략했습니다(전체 로그에서 확인).")

    summary = _summary(s, steps, meanings, accounts, lookups, attempts, session_confirmed, ref8)
    for st in steps:
        st.pop("_t", None)
        if st.get("auth_context"):
            st["auth_context_text"] = AUTH_TEXT[st["auth_context"]]
    key = f"{s.host}|{s.link}|{(s.ref or '|'.join(sorted(s.src_ips)))[:40]}|{_iso(s.first)}"
    return {"key": key, "host": s.host, "link": s.link, "link_text": s.link_text, "session_ref": ref8 or None,
            "accounts": accounts, "attempted_accounts": sorted(s.attempted - set(accounts))[:10], "src_ips": sorted(s.src_ips)[:10], "start": _iso(s.first), "end": _iso(s.last),
            "requests": s.total, "unregistered_requests": s.unlabeled, "summary": summary,
            "sequence": meanings[:30], "steps": steps, "steps_omitted": s.omitted,
            "auth": {"attempts": s.auth["attempts"], "failures": s.auth["failures"],
                     "success_confirmed": s.auth["success_at"] is not None},
            "conformance": conformance, "unexplained_steps": [st["event_id"] for st in steps
                                                             if st["event_id"] not in explained][:50],
            "confirmed": _uniq(confirmed), "inferred": _uniq(inferred), "unknown": _uniq(unknown),
            "next_checks": _uniq(checks), "flags": sorted(set(flags)), "devices": devices[:50],
            "ddos_interval_ids": overlapping, "attention": attention}


def _uniq(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))[:40]


def _clock(ts) -> str:
    t = epoch(ts)
    if t is None:
        return ""
    return datetime.fromtimestamp(t + 9 * 3600, timezone.utc).strftime("%m-%d %H:%M:%S")  # shown in KST


def _summary(s, steps, meanings, accounts, lookups, attempts, session_confirmed, ref8) -> str:
    success = next((st for st in attempts if st["outcome"] == "success"), None)
    after = [st for st in lookups if st.get("auth_context") == "after_success"]
    if success and after and session_confirmed:
        who = f"계정 {accounts[0]}의 " if len(accounts) == 1 else ""
        target = after[0]
        relation = {"self": "본인 대상 ", "other": "다른 대상 "}.get(target.get("object_relation"), "")
        basis = "세션 일치" + ("와 계정 일치" if accounts else "")
        return (f"{who}{success['meaning']} 성공 이후 동일 세션 {ref8}에서 {relation}{target['meaning']}이(가) "
                f"{len(after)}회 수행되었습니다. 연결 근거는 {basis}입니다.")
    if attempts and lookups:
        first = attempts[0]
        state = {"success": "성공이 확인됐지만", "failure": "실패로 확인됐고", "unknown": "성공 여부가 확인되지 않았고"}[first["outcome"]]
        link = "동일 세션 여부는 확인되지 않았습니다" if not session_confirmed else f"동일 세션 {ref8}입니다"
        return (f"{first['meaning']} 이후 {lookups[0]['meaning']} 요청이 관측되었습니다. 인증은 {state}, {link}.")
    if lookups and not attempts:
        return (f"{lookups[0]['meaning']} 요청 {len(lookups)}건이 관측되었습니다. 앞선 인증 기록은 이 자료에 없습니다"
                f"({'동일 세션 ' + ref8 if session_confirmed else '세션 미확인'}).")
    return " → ".join(meanings[:8]) + f" ({len(steps)}단계)"


def _conformance(steps: list[dict], compiled: Compiled, host: str) -> tuple[list[dict], set]:
    """Compare the observed order with each registered flow of the service. Returns results and explained steps."""
    out, explained = [], set()
    ids = [st["knowledge"]["id"] for st in steps]
    for item in compiled.flows.get(host, []):
        c = item["content"]
        wanted = c.get("steps") or []
        if not wanted or not any(w.get("activity") in ids for w in wanted):
            continue
        position, deviations, matched, last_t = 0, [], [], None
        for w in wanted:
            name = (compiled.by_id.get(w.get("activity")) or {}).get("content", {}).get("meaning") or "등록되지 않은 단계"
            found = next((i for i in range(position, len(steps)) if ids[i] == w.get("activity")), None)
            if found is None:
                earlier = next((i for i in range(0, position) if ids[i] == w.get("activity")), None)
                if earlier is not None and not w.get("optional"):
                    deviations.append(f"'{name}' 단계가 등록된 순서보다 먼저 관측됨")
                elif not w.get("optional"):
                    deviations.append(f"'{name}' 단계가 관측되지 않음(자료에 없을 뿐일 수 있음)")
                continue
            st = steps[found]
            if w.get("state") and st["outcome"] != w["state"]:
                deviations.append(f"'{name}' 결과가 {_ko(w['state'])}이어야 하나 {_ko(st['outcome'])}")
            gap = c.get("max_gap_seconds")
            t = epoch(st["time"])
            if gap and last_t is not None and t is not None and t - last_t > gap:
                deviations.append(f"'{name}' 앞 간격 {int(t - last_t)}초가 등록된 최대 간격 {gap}초보다 김")
            last_t = t
            matched.append(st["event_id"])
            position = found + 1
            if w.get("repeat"):
                while position < len(steps) and ids[position] == w.get("activity"):
                    matched.append(steps[position]["event_id"])
                    position += 1
        status = "matched" if not deviations else "deviates"
        explained.update(matched)
        out.append({"knowledge_id": item["id"], "version": item["version"], "name": c.get("name") or item.get("title"),
                    "classification": c.get("classification") or "undetermined", "status": status,
                    "deviations": deviations, "matched_steps": len(matched),
                    "note": "등록된 흐름과 순서·결과가 같습니다. 이 사건이 정상이라는 판단은 아닙니다." if status == "matched"
                    else "등록된 흐름과 다른 부분이 있습니다."})
    return out, explained


def _ko(state: str) -> str:
    return {"success": "성공", "failure": "실패", "unknown": "미확인"}.get(state, state)


def _discovery(transitions: dict, compiled: Compiled, baseline_end: float | None, history: set) -> dict:
    """Directly-follows transitions seen in the records, and which of them nothing registered explains."""
    registered = set()
    for host, flows in compiled.flows.items():
        for item in flows:
            names = [(compiled.by_id.get(w.get("activity")) or {}).get("content", {}).get("meaning")
                     for w in item["content"].get("steps") or []]
            optional = [bool(w.get("optional")) for w in item["content"].get("steps") or []]
            for i, a in enumerate(names):
                if (item["content"].get("steps") or [])[i].get("repeat"):
                    registered.add((host, a, a))
                for j in range(i + 1, len(names)):
                    registered.add((host, a, names[j]))
                    if not optional[j]:
                        break
    rows = []
    for (host, a, b), tr in transitions.items():
        gaps = sorted(tr.pop("gaps"))
        first = tr.pop("_first")
        row = {**tr, "explained_by_registered_flow": (host, a, b) in registered,
               "unregistered_step": a.startswith("미등록 ") or b.startswith("미등록 "),
               "median_gap_seconds": gaps[len(gaps) // 2] if gaps else None,
               "max_gap_seconds": gaps[-1] if gaps else None}
        if baseline_end is not None:
            row["new_since_baseline"] = first >= baseline_end
        if history:
            row["new_vs_earlier_analyses"] = (host, a, b) not in history
        rows.append(row)
    rows.sort(key=lambda r: (r["explained_by_registered_flow"], -r["sessions"], -r["count"]))
    return {"transitions": rows[:500], "transitions_total": len(rows),
            "baseline": {"end": _iso(baseline_end) if baseline_end else None,
                         "earlier_analyses_transitions": len(history),
                         "note": "기준은 평가 대상보다 앞선 자료만 씁니다. 처음 관측된 전이는 '처음 보임'일 뿐 공격이라는 뜻이 아니고, 자주 관측된 전이도 정상이라는 뜻이 아닙니다."}}


def _suggest(row: dict, compiled: Compiled) -> dict | None:
    """A non-binding hint for an unregistered path: the same path registered under another service."""
    for host, rows in compiled.activities.items():
        if host == row["host"]:
            continue
        for a in rows:
            if a.match == "exact" and a.path == row["path"]:
                return {"meaning": a.meaning, "role": a.role, "from_host": host,
                        "text": f"다른 서비스({host})의 같은 경로에 '{a.meaning}'이(가) 등록되어 있습니다. 자동 적용하지 않았습니다."}
    return None


def _ddos_intervals(events: list[dict]) -> list[dict]:
    out = []
    for i, e in enumerate(sorted(events, key=lambda v: v.get("timestamp") or "")):
        start = epoch(e.get("timestamp"))
        end_raw = ext(e, "end_time")
        end = _interval_end(ext(e, "start_time"), end_raw, start)
        if start is None:
            continue
        out.append({"id": f"D{i + 1}", "event_id": e.get("event_id"), "host": norm_host(e.get("hostname")),
                    "target_ip": e.get("dst_ip"), "start": e.get("timestamp"), "end_raw": end_raw,
                    "vector": ext(e, "vector"), "metric": ext(e, "metric"), "unit": ext(e, "unit"),
                    "value": ext(e, "value"), "interval_seconds": ext(e, "interval_seconds"),
                    "detection_state": ext(e, "detection_state"), "mitigation_state": ext(e, "mitigation_state"),
                    "device": ext(e, "_device_name"), "requests": 0, "server_errors": 0,
                    "_start": start, "_end": end if end is not None else start,
                    "note": "집계 구간입니다. 구간 안의 요청 수·5xx 응답 수는 HTTP 기록에서 센 값이며 서비스 영향의 증명이 아닙니다."})
    return out


def _naive(raw):
    if raw in (None, "", "-"):
        return None
    try:
        return datetime.fromisoformat(str(raw).strip().replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None


def _interval_end(start_raw, end_raw, start: float | None) -> float | None:
    """End of an interval: the exported length added to the normalised start (both columns share one clock)."""
    a, b = _naive(start_raw), _naive(end_raw)
    if a is None or b is None or start is None or (a.tzinfo is None) != (b.tzinfo is None):
        return None
    length = (b - a).total_seconds()
    return start + length if length >= 0 else None
