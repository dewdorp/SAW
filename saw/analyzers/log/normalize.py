"""CES normalization helpers: uri_template, params, UA class, enrichment, tags (docs/06, docs/19 §3)."""
from __future__ import annotations

import re
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from saw.analyzers.http.useragent import classify_ua
from saw.analyzers.ioc.enrichment import OfflineEnricher, default_enricher
from saw.analyzers.ioc.observables import ip_scope
from saw.analyzers.patterns import pattern_tags

CES_VERSION = "1.0"
_NS = uuid.UUID("5a3c2f0e-6b1d-4c8e-9f7a-0123456789ab")

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUM = re.compile(r"^-?\d+$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?|\d{10}(\d{3})?)$")
_TOKEN = re.compile(r"^[A-Za-z0-9+/_=.-]{20,}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def event_id(file_id: str, offset: int | str) -> str:
    return str(uuid.uuid5(_NS, f"{file_id}:{offset}"))


def token_class(t: str) -> str | None:
    if not t:
        return None
    if _NUM.match(t):
        return "<NUM>"
    if _UUID.match(t):
        return "<UUID>"
    if _IP.match(t):
        return "<IP>"
    if _TIME.match(t):
        return "<TIME>"
    if _HEX.match(t):
        return "<HEX>"
    if _EMAIL.match(t):
        return "<EMAIL>"
    if _TOKEN.match(t) and (any(c.isdigit() for c in t) and any(c.isalpha() for c in t)):
        return "<TOKEN>"
    return None


def uri_template(uri: str | None) -> tuple[str | None, str | None, dict[str, str], list[str]]:
    """Returns (url_path, uri_template, params, param_names). Deterministic (docs/19 §3)."""
    if not uri:
        return None, None, {}, []
    path, _, query = uri.partition("?")
    query = query.partition("#")[0]
    segs = []
    params: dict[str, str] = {}
    for i, s in enumerate(path.split("/")):
        c = token_class(urllib.parse.unquote(s))
        segs.append(c or s)
        if c in ("<NUM>", "<UUID>", "<HEX>"):
            params[f"path[{i}]"] = s  # path identifiers are parameters too (/api/customer/10001)
    tpath = "/".join(segs)
    names: list[str] = []
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        k = k[:128]
        names.append(k)
        if k not in params:
            params[k] = v[:2048]
    all_names = sorted(set(params))
    if names:
        tq = "&".join(f"{k}={token_class(params[k]) or '<STR>'}" for k in sorted(set(names)))
        return path, f"{tpath}?{tq}", params, all_names
    return path, tpath, params, all_names


_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                       "Nov", "Dec"], 1)}
_LOCAL_DT = re.compile(
    r"^(\d{4})[-./]\s?(\d{1,2})[-./]\s?(\d{1,2})\.?[ T]+(?:(오전|오후|AM|PM|am|pm)\s*)?(\d{1,2}):(\d{2})(?::(\d{2}))?"
    r"(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")
_COMPACT_DT = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$")


def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_time(raw: str | None, assumed_tz: str = "Asia/Seoul") -> tuple[str | None, str]:
    """Returns (utc_iso, quality) with quality in exact|assumed_tz|invalid."""
    if not raw:
        return None, "invalid"
    s = raw.strip().strip("[]")
    tz = ZoneInfo(assumed_tz)
    # apache/nginx: 05/Oct/2026:03:11:04 +0900
    m = re.match(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*([+-]\d{4})?", s)
    if m:
        d, mon, y, H, M, S, frac, off = m.groups()
        dt = datetime(int(y), _MONTHS.get(mon, 1), int(d), int(H), int(M), int(S),
                      int((frac or "0")[:6].ljust(6, "0")))
        if off:
            sign = 1 if off[0] == "+" else -1
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))))
            return to_utc_iso(dt), "exact"
        return to_utc_iso(dt.replace(tzinfo=tz)), "assumed_tz"
    # epoch seconds / ms
    if re.fullmatch(r"\d{10}(\.\d+)?", s):
        return to_utc_iso(datetime.fromtimestamp(float(s), timezone.utc)), "exact"
    if re.fullmatch(r"\d{13}", s):
        return to_utc_iso(datetime.fromtimestamp(int(s) / 1000, timezone.utc)), "exact"
    if re.fullmatch(r"\d{16,19}", s):  # ns (cloudflare)
        return to_utc_iso(datetime.fromtimestamp(int(s[:16]) / 1e6, timezone.utc)), "exact"
    # syslog 3164: Oct  5 03:11:04 (no year)
    m = re.match(r"(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", s)
    if m and m.group(1) in _MONTHS:
        now = datetime.now(tz)
        dt = datetime(now.year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)),
                      int(m.group(5)), tzinfo=tz)
        if dt > now + timedelta(days=2):
            dt = dt.replace(year=now.year - 1)
        return to_utc_iso(dt), "assumed_tz"
    # Korean product / Excel exports: 2026/10/03 17:38:47, 2026.10.3 오후 5:38:47, 20261003173847
    m = _LOCAL_DT.match(s)
    c = None if m else _COMPACT_DT.match(s)
    if m or c:
        y, mo, d, ampm, H, M, S, frac, off = m.groups() if m else (*c.groups()[:3], None, *c.groups()[3:], None, None)
        h = int(H)
        if ampm in ("오후", "PM", "pm") and h < 12:
            h += 12
        elif ampm in ("오전", "AM", "am") and h == 12:
            h = 0
        zone = tz
        if off == "Z":
            zone = timezone.utc
        elif off:
            o = off.replace(":", "")
            zone = timezone((1 if o[0] == "+" else -1) * timedelta(hours=int(o[1:3]), minutes=int(o[3:5])))
        try:
            dt = datetime(int(y), int(mo), int(d), h, int(M), int(S or 0), int((frac or "0")[:6].ljust(6, "0")),
                          tzinfo=zone)
        except ValueError:
            return None, "invalid"
        return to_utc_iso(dt), "exact" if off else "assumed_tz"
    try:
        iso = s.replace("Z", "+00:00")
        if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", iso):
            iso = iso.replace(" ", "T", 1)
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return to_utc_iso(dt.replace(tzinfo=tz)), "assumed_tz"
        return to_utc_iso(dt), "exact"
    except ValueError:
        return None, "invalid"


def _int(v) -> int | None:
    try:
        return int(v) if v not in (None, "", "-") else None
    except (TypeError, ValueError):
        return None


def finalize(ev: dict, *, enricher: OfflineEnricher | None = None, assumed_tz: str = "Asia/Seoul",
             observation: dict | None = None, context_snapshot: dict | None = None) -> dict:
    """Fill derived/enrichment fields on a CES event in place."""
    from saw.behavior.observation import observe_fields

    # Metadata is producer-owned: uploaded ext objects never supply this trust boundary.
    trusted = dict(observation) if observation is not None else observe_fields(ev)
    ev["ext"] = {**(ev.get("ext") if isinstance(ev.get("ext"), dict) else {}), "saw_observation": trusted}
    en = enricher or default_enricher()
    # Explicit appliance actions only: an HTTP status never proves blocking or allowing.
    action_keys = {"action", "securityaction", "wafaction", "차단여부", "조치", "대응"}
    actions = []
    ext = ev.get("ext") or {}
    sources = [ev, ext] + [v for v in ext.values() if isinstance(v, dict)]
    for source in sources:
        for key, value in source.items():
            if str(key).lower().replace("_", "").replace(" ", "") in action_keys and isinstance(value, str):
                word = value.strip().lower()
                if word in {"block", "blocked", "deny", "denied", "drop", "차단"}:
                    actions.append("blocked")
                elif word in {"allow", "allowed", "permit", "permitted", "pass", "허용", "통과"}:
                    actions.append("allowed")
    if len(set(actions)) == 1:
        ev["enforcement_action"] = actions[0]
    elif actions:
        ev["enforcement_action"] = "conflicting"
    if "timestamp_raw" in ev and not ev.get("timestamp"):
        ev["timestamp"], ev["timestamp_quality"] = parse_time(ev["timestamp_raw"], assumed_tz)
    for k in ("src_port", "dst_port", "status_code", "bytes_in", "bytes_out"):
        if k in ev:
            ev[k] = _int(ev[k])
    for k in ("user_agent", "user", "method", "uri", "hostname", "src_ip", "dst_ip", "domain"):
        if ev.get(k) in ("-", "", "(empty)"):
            ev[k] = None
    if ev.get("method"):
        ev["method"] = str(ev["method"]).upper()[:16]
    if ev.get("status_code"):
        ev["status_class"] = f"{str(ev['status_code'])[0]}xx"
    if ev.get("uri"):
        path, tpl, params, names = uri_template(ev["uri"])
        ev["url_path"], ev["uri_template"] = path, tpl
        q = str(ev["uri"]).partition("?")[2]
        if q:
            ev["url_query"] = q[:4096]
        if names:
            ev["params"], ev["param_names"] = params, names
            tags = set(ev.get("tags") or [])
            for v in params.values():
                if any(c in v for c in "'\"<>;|`$%{}()") or ".." in v:
                    for t in pattern_tags(urllib.parse.unquote(urllib.parse.unquote(v))):
                        tags.add(f"pattern:{t}")
            if tags:
                ev["tags"] = sorted(tags)
        elif path:
            tags = set(ev.get("tags") or [])
            dec = urllib.parse.unquote(urllib.parse.unquote(path))
            if any(c in dec for c in "'\"<>;|`$") or ".." in dec:
                for t in pattern_tags(dec):
                    tags.add(f"pattern:{t}")
            if tags:
                ev["tags"] = sorted(tags)
    if ev.get("uri") or ev.get("user_agent"):
        from saw.detectors.signatures import sig_tags  # known traces (tools, published exploits, web shells): data-driven

        found = sig_tags(ev)
        if found:
            ev["tags"] = sorted({*(ev.get("tags") or []), *found})
    if "user_agent" in ev:
        ev["ua_class"] = classify_ua(ev.get("user_agent"))["class"]
    if ev.get("src_ip"):
        scope = ip_scope(ev["src_ip"])
        ev["src_ip_scope"] = scope
        if scope == "external":
            info = en.lookup_ip(ev["src_ip"])
            ev["src_asn"], ev["src_as_org"] = info.get("asn"), info.get("as_org")
            ev["src_geo_country"], ev["src_cloud"] = info.get("country"), info.get("cloud", "none")
            if info.get("tor"):
                ev.setdefault("tags", []).append("tor_exit")
        else:
            ev["src_cloud"] = "none"
    if ev.get("dst_ip"):
        ev["dst_ip_scope"] = ip_scope(str(ev["dst_ip"]))
        if ev["dst_ip_scope"] == "external" and ev.get("data_source", "").startswith(("zeek", "suricata")):
            info = en.lookup_ip(str(ev["dst_ip"]))
            ev["dst_asn"], ev["dst_as_org"] = info.get("asn"), info.get("as_org")
            ev["dst_geo_country"], ev["dst_cloud"] = info.get("country"), info.get("cloud", "none")
    from saw.observation.connection import connection_observation
    obs = connection_observation(ev, context_snapshot=context_snapshot)
    ev["ext"]["observation"] = obs
    profile = (context_snapshot or {}).get("profile") or {}
    time_profile = profile.get("time") or {}
    # The same verified occurrence time must drive indexing, scope filters, and analysis.
    # Preserve the upload-default interpretation for provenance; never rewrite old rows.
    if (obs["context"]["resolved"] and time_profile.get("verified") is True
            and time_profile.get("role") in {"occurred", "start", "end"}
            and (profile.get("source_fields") or {}).get("timestamp") and obs.get("timestamp")):
        obs["ces_timestamp_raw"] = ev.get("timestamp_raw")
        obs["ces_timestamp_precision"] = trusted.get("timestamp_precision", "unknown")
        trusted["timestamp_precision"] = obs["timestamp_precision"]
        obs["timestamp_basis"] = "verified_device_profile"
        ev["timestamp"], ev["timestamp_quality"] = parse_time(
            str(obs["timestamp_raw"]), time_profile.get("timezone") or "Asia/Seoul")
        ev["timestamp_raw"] = obs["timestamp_raw"]
    else:
        obs["timestamp_basis"] = "parser_or_upload_default"
    ev["ces_version"] = CES_VERSION
    return {k: v for k, v in ev.items() if v is not None}
