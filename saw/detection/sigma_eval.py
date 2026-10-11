"""Sigma rule validation (pySigma) + deterministic evaluation over CES events for historical testing (docs/31 §4).

pySigma (LGPL, unmodified) parses/validates and converts to OpenSearch Lucene for production SIEM-side testing.
Local historical testing evaluates the rule's detection logic directly against CES events (SQLite event store),
because Lucene cannot run there. Supported: selection maps/lists, modifiers contains|startswith|endswith|re|all|cidr,
conditions with and/or/not/parentheses and `1 of x*` / `all of x*`, plus SAW threshold (count / distinct by group).
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any

import regex as bounded_re
import yaml

# Sigma taxonomy (webserver / proxy / dns / firewall) → CES fields
FIELD_MAP = {
    "cs-uri-stem": "url_path", "cs-uri-query": "url_query", "cs-uri": "uri", "c-uri": "uri", "c-uri-stem": "url_path",
    "c-uri-query": "url_query", "sc-status": "status_code", "c-ip": "src_ip", "src_ip": "src_ip", "dst_ip": "dst_ip",
    "cs-method": "method", "c-useragent": "user_agent", "cs-user-agent": "user_agent", "cs-host": "hostname",
    "cs-referrer": "ext.referer", "sc-bytes": "bytes_out", "cs-bytes": "bytes_in", "query": "domain", "dst_port": "dst_port",
    "src_port": "src_port", "User": "user", "user": "user", "ja4": "ja4", "ja3": "ja3", "sni": "domain",
    "uri_template": "uri_template", "status_code": "status_code", "user_agent": "user_agent", "method": "method",
    "url_path": "url_path", "domain": "domain", "data_source": "data_source", "event_type": "event_type",
}
LOGSOURCE_SOURCES = {"webserver": ["web", "waf"], "proxy": ["web", "waf"], "dns": ["zeek_dns"], "firewall": ["firewall", "zeek_conn"],
                     "network_connection": ["zeek_conn"], "authentication": ["linux", "windows", "vpn", "web"]}
LOCAL_FIELDS = set(FIELD_MAP.values()) | {"event_id", "timestamp", "hostname", "bytes_out", "bytes_in", "protocol",
                                         "session_id", "src_ip_scope", "dst_ip_scope", "status_class", "params", "param_names", "tags"}
MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cidr", "cased", "exists"}
REGEX_TIMEOUT = 0.01
MAX_VALUE_LENGTH = 65536


class SigmaError(ValueError):
    pass


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise SigmaError("YAML mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


@dataclass
class CompiledRule:
    title: str
    detections: dict[str, list[list[tuple[str, list[str], list[Any]]]]]  # name -> OR of AND-groups of (field, modifiers, values)
    condition: str
    data_sources: list[str]
    tags: list[str] = field(default_factory=list)
    level: str = "medium"
    falsepositives: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    ast: tuple = ()


def local_field(name: str) -> str:
    mapped = FIELD_MAP.get(name, name)
    if mapped not in LOCAL_FIELDS and not re.fullmatch(r"ext\.[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*){0,3}", mapped):
        raise SigmaError("unsupported local field")
    return mapped


def validate_with_pysigma(text: str) -> list[str]:
    """Returns a list of problems (empty == valid) using pySigma's parser."""
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError as PySigmaError

    try:
        c = SigmaCollection.from_yaml(text)
        errs = []
        for r in c.rules:
            errs += [str(e) for e in (getattr(r, "errors", None) or [])]
        if not c.rules:
            errs.append("no rule found")
        return errs
    except PySigmaError as e:
        return [str(e)]
    except Exception as e:  # noqa: BLE001 - YAML parser errors are user input problems
        return [f"{type(e).__name__}: {e}"]


def saw_pipeline():
    """pySigma processing pipeline: Sigma taxonomy fields → SAW CES fields (saw-* OpenSearch indices)."""
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    mapping = {k: v for k, v in FIELD_MAP.items() if k != v}
    return ProcessingPipeline(name="SAW CES field mapping", priority=20,
                              items=[ProcessingItem(identifier="saw_ces_fields", transformation=FieldMappingTransformation(mapping))])


def to_opensearch_lucene(text: str) -> list[str]:
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.collection import SigmaCollection

    return [str(q) for q in OpensearchLuceneBackend(processing_pipeline=saw_pipeline()).convert(SigmaCollection.from_yaml(text))]


def _items(sel: Any) -> list[list[tuple[str, list[str], list[Any]]]]:
    """Selection → OR-list of AND-groups."""
    if isinstance(sel, list):  # list of maps = OR ; list of plain values = keyword search (unsupported)
        if not 1 <= len(sel) <= 64 or any(not isinstance(x, dict) for x in sel):
            raise SigmaError("selection must contain 1..64 maps")
        groups = []
        for x in sel:
            if isinstance(x, dict):
                groups += _items(x)
            else:
                raise SigmaError("keyword (field-less) selections are not supported for local testing")
        return groups
    if not isinstance(sel, dict) or not 1 <= len(sel) <= 64:
        raise SigmaError("selection must be a map or list of maps")
    group = []
    for k, v in sel.items():
        parts = str(k).split("|")
        f, mods = parts[0], parts[1:]
        ces = local_field(f)
        vals = v if isinstance(v, list) else [v]
        if not 1 <= len(vals) <= 128 or any(type(x) not in (str, int, float, bool, type(None)) for x in vals):
            raise SigmaError("selection values must be a nonempty bounded list of scalar values")
        if set(mods) - MODIFIERS or len(mods) != len(set(mods)):
            raise SigmaError("unsupported or duplicate local modifier")
        if len(set(mods) & {"contains", "startswith", "endswith", "re", "cidr", "exists"}) > 1:
            raise SigmaError("incompatible local modifiers")
        if "exists" in mods and (mods != ["exists"] or len(vals) != 1 or type(vals[0]) is not bool):
            raise SigmaError("exists requires one boolean value")
        for value in vals:
            if isinstance(value, str) and len(value) > 4096:
                raise SigmaError("selection value too long")
            if set(mods) & {"contains", "startswith", "endswith", "re", "cidr", "cased"} and not isinstance(value, str):
                raise SigmaError("string modifier requires string values")
            if "cidr" in mods:
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    raise SigmaError("invalid CIDR value") from None
            if "re" in mods:
                _regex(value)
        group.append((ces, mods, vals))
    return [group]


def compile_rule(text: str) -> CompiledRule:
    if not isinstance(text, str) or len(text.encode("utf-8")) > 65536:
        raise SigmaError("rule exceeds local size limit")
    try:
        d = yaml.load(text, Loader=_UniqueLoader)
    except (yaml.YAMLError, RecursionError, TypeError):
        raise SigmaError("invalid or excessively nested YAML") from None
    if not isinstance(d, dict) or "detection" not in d:
        raise SigmaError("rule needs a detection section")
    if not isinstance(d["detection"], dict) or not 2 <= len(d["detection"]) <= 65:
        raise SigmaError("detection needs 1..64 selections and a condition")
    det = dict(d["detection"])
    cond = det.pop("condition", None)
    if not cond:
        raise SigmaError("detection.condition is required")
    if isinstance(cond, list):
        if not 1 <= len(cond) <= 64 or any(not isinstance(c, str) for c in cond):
            raise SigmaError("invalid condition list")
        cond = " or ".join(f"({c})" for c in cond)
    if not isinstance(cond, str) or len(cond) > 4096:
        raise SigmaError("invalid or oversized condition")
    if "timeframe" in det:
        raise SigmaError("Sigma timeframe is unsupported locally; use the SAW threshold fields")
    if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in det):
        raise SigmaError("unsupported selection name")
    detections = {name: _items(sel) for name, sel in det.items()}
    if sum(len(values) for groups in detections.values() for group in groups for _field, _mods, values in group) > 2048:
        raise SigmaError("selection exceeds local complexity limit")
    ls = d.get("logsource") or {}
    if not isinstance(ls, dict):
        raise SigmaError("invalid logsource")
    sources = LOGSOURCE_SOURCES.get(ls.get("category") or ls.get("service") or "", [])
    if not sources or set(ls) - {"category", "service", "product", "definition"}:
        raise SigmaError("unsupported local logsource")
    if ls.get("product") or (ls.get("category") and ls.get("service")):
        raise SigmaError("product/service constraints need an explicit local mapping")
    result = CompiledRule(d.get("title", ""), detections, cond, sources, d.get("tags") or [], d.get("level", "medium"),
                          d.get("falsepositives") or [], d)
    result.ast = _condition_ast(result)
    return result


def _get(ev: dict, path: str) -> Any:
    if path in ("url_path", "url_query") and ev.get(path) is None and ev.get("uri") is not None:
        return str(ev["uri"]).partition("?")[0 if path == "url_path" else 2]
    if path == "ext.referer" and not (ev.get("ext") or {}).get("referer"):
        if ev.get("referer") is not None:
            return ev["referer"]
        refs = [prod[key] for prod in (ev.get("ext") or {}).values() if isinstance(prod, dict)
                for key in ("referer", "referrer") if prod.get(key) is not None]
        return refs or None
    cur: Any = ev
    for p in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


@lru_cache(maxsize=2048)
def _regex(value: str):
    try:
        return bounded_re.compile(value)
    except (bounded_re.error, ValueError):
        raise SigmaError("invalid local regular expression") from None


@lru_cache(maxsize=2048)
def _wild(v: str, cased: bool = False, modifier: str = ""):
    parts, i = [], 0
    while i < len(v):
        char = v[i]
        if char == "\\" and i + 1 < len(v) and v[i + 1] in "\\*?":
            i += 1
            parts.append(re.escape(v[i]))
        else:
            parts.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    pattern = "".join(parts)
    if modifier in {"contains", "endswith"}:
        pattern = ".*" + pattern
    if modifier in {"contains", "startswith"}:
        pattern += ".*"
    return bounded_re.compile(pattern, bounded_re.S | (0 if cased else bounded_re.I))


def _match_value(actual: Any, mods: list[str], expected: Any) -> bool:
    if "exists" in mods:
        return (actual is not None) is expected
    if actual is None:
        return expected is None
    if expected is None:
        return False
    if len(str(actual)) > MAX_VALUE_LENGTH:
        raise SigmaError("event field exceeds local evaluation limit")
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        try:
            return _regex(str(expected)).search(str(actual), timeout=REGEX_TIMEOUT) is not None
        except TimeoutError:
            raise SigmaError("local regular expression time limit exceeded") from None
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual), str(expected)
    modifier = next((mod for mod in mods if mod in {"contains", "startswith", "endswith"}), "")
    try:
        return bool(_wild(e, "cased" in mods, modifier).fullmatch(a, timeout=REGEX_TIMEOUT))
    except TimeoutError:
        raise SigmaError("local wildcard time limit exceeded") from None


def _match_group(ev: dict, group: list[tuple[str, list[str], list[Any]]]) -> bool:
    for f, mods, vals in group:
        actual = _get(ev, f)
        if isinstance(actual, list) and len(actual) > 128:
            raise SigmaError("event array exceeds local evaluation limit")
        if "exists" in mods:
            if not _match_value(actual, mods, vals[0]):
                return False
            continue
        if isinstance(actual, list):
            hit = lambda v, mods=mods, actual=actual: any(_match_value(x, mods, v) for x in actual)
        else:
            hit = lambda v, mods=mods, actual=actual: _match_value(actual, mods, v)
        ok = all(hit(v) for v in vals) if "all" in mods else any(hit(v) for v in vals)
        if not ok:
            return False
    return True


_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)", re.IGNORECASE)


def _tokens(cond: str) -> list[str]:
    pos, out = 0, []
    while pos < len(cond):
        m = _TOK.match(cond, pos)
        if not m:
            if cond[pos:].strip() == "":
                break
            raise SigmaError(f"cannot parse condition near: {cond[pos:pos + 20]!r}")
        out.append(m.group(1).lower() if m.group(1).lower() in ("and", "or", "not", "1 of", "all of") else m.group(1))
        pos = m.end()
    return out


def _condition_ast(rule: CompiledRule) -> tuple:
    toks = _tokens(rule.condition)
    if len(toks) > 256:
        raise SigmaError("condition exceeds local complexity limit")
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        if pos >= len(toks):
            raise SigmaError("unexpected end of condition")
        pos += 1
        return toks[pos - 1]

    def primary():
        t = take()
        if t == "(":
            v = expr()
            if take() != ")":
                raise SigmaError("unbalanced parentheses")
            return v
        if t == "not":
            return ("not", primary())
        if t in ("1 of", "all of"):
            pat = take()
            names = [n for n in rule.detections if _wild(pat).fullmatch(n, timeout=REGEX_TIMEOUT)] if pat != "them" else list(rule.detections)
            if not names:
                raise SigmaError(f"no detection matches {pat}")
            return ("or" if t == "1 of" else "and", *(('ident', n) for n in names))
        if t is None:
            raise SigmaError("unexpected end of condition")
        if t not in rule.detections:
            raise SigmaError("unknown detection identifier")
        return ("ident", t)

    def term():
        v = primary()
        while peek() == "and":
            take()
            r = primary()
            v = ("and", v, r)
        return v

    def expr():
        v = term()
        while peek() == "or":
            take()
            r = term()
            v = ("or", v, r)
        return v

    out = expr()
    if pos != len(toks):
        raise SigmaError("trailing tokens in condition")
    return out


def evaluate(rule: CompiledRule, ev: dict) -> bool:
    cache: dict[str, bool] = {}

    def walk(node):
        op = node[0]
        if op == "ident":
            name = node[1]
            if name not in cache:
                cache[name] = any(_match_group(ev, group) for group in rule.detections[name])
            return cache[name]
        if op == "not":
            return not walk(node[1])
        values = (walk(child) for child in node[1:])
        return all(values) if op == "and" else any(values)

    return walk(rule.ast or _condition_ast(rule))


def validate_threshold(threshold: dict) -> dict:
    if not threshold:
        return {}
    if not isinstance(threshold, dict) or set(threshold) - {"group_by", "timespan_sec", "count_gte", "distinct_field"}:
        raise SigmaError("unsupported threshold fields")
    count = threshold.get("count_gte")
    span = threshold.get("timespan_sec", 600)
    if type(count) is not int or not 1 <= count <= 500000 or type(span) is not int or not 1 <= span <= 604800:
        raise SigmaError("threshold count/time must be positive bounded integers")
    groups = threshold.get("group_by") or []
    if not isinstance(groups, list) or len(groups) > 4 or any(not isinstance(x, str) for x in groups):
        raise SigmaError("threshold group_by requires at most four fields")
    groups = [local_field(x) for x in groups]
    if len(set(groups)) != len(groups):
        raise SigmaError("duplicate threshold group field")
    distinct = threshold.get("distinct_field")
    if distinct is not None and not isinstance(distinct, str):
        raise SigmaError("invalid threshold distinct field")
    return {"count_gte": count, "timespan_sec": span, "group_by": groups,
            **({"distinct_field": local_field(distinct)} if distinct else {})}


def apply_threshold(hits: list[dict], threshold: dict) -> list[dict]:
    """Sorted sliding windows; each event and distinct value enters/leaves a window once."""
    th = validate_threshold(threshold)
    if not th:
        return hits
    groups: dict[tuple, list[tuple[float, dict]]] = {}

    def key(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    for event in hits:
        values = [_get(event, name) for name in th["group_by"]]
        if any(value is None for value in values):
            raise SigmaError("threshold group field is missing")
        try:
            ts = datetime.fromisoformat(str(event.get("timestamp") or ""))
            if ts.tzinfo is None:
                raise ValueError
        except ValueError:
            raise SigmaError("threshold requires a valid timezone-aware timestamp") from None
        groups.setdefault(tuple(key(value) for value in values), []).append((ts.timestamp(), event))
    out = []
    for events in groups.values():
        events.sort(key=lambda item: item[0])
        values = [(_get(event, th["distinct_field"]) if th.get("distinct_field") else None) for _, event in events]
        values = [key(value) if value is not None else None for value in values]
        counts: Counter = Counter()
        left = 0
        coverage = [0] * (len(events) + 1)
        for right, (ts, _event) in enumerate(events):
            if values[right] is not None:
                counts[values[right]] += 1
            while ts - events[left][0] > th["timespan_sec"]:
                if values[left] is not None:
                    counts[values[left]] -= 1
                    if counts[values[left]] == 0:
                        del counts[values[left]]
                left += 1
            n = len(counts) if th.get("distinct_field") else right - left + 1
            if n >= th["count_gte"]:
                coverage[left] += 1
                coverage[right + 1] -= 1
        active = 0
        for index, (_, event) in enumerate(events):
            active += coverage[index]
            if active:
                out.append(event)
    return out


def attack_tags(rule: CompiledRule) -> list[str]:
    return sorted({t.split(".", 1)[1].upper() for t in rule.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())})
