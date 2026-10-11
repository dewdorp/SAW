"""Sigma rule validation (pySigma) + deterministic evaluation over CES events for historical testing (docs/31 §4).

pySigma (LGPL, unmodified) parses/validates and converts to OpenSearch Lucene for production SIEM-side testing.
Local historical testing evaluates the rule's detection logic directly against CES events (SQLite event store),
because Lucene cannot run there. Supported: selection maps/lists, modifiers contains|startswith|endswith|re|all|cidr,
conditions with and/or/not/parentheses and `1 of x*` / `all of x*`, plus SAW threshold (count / distinct by group).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

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


class SigmaError(ValueError):
    pass


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
    except Exception as e:  # noqa: BLE001 - yaml/other parse errors are user input problems
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
        groups = []
        for x in sel:
            if isinstance(x, dict):
                groups += _items(x)
            else:
                raise SigmaError("keyword (field-less) selections are not supported for local testing")
        return groups
    if not isinstance(sel, dict):
        raise SigmaError("selection must be a map or list of maps")
    group = []
    for k, v in sel.items():
        parts = str(k).split("|")
        f, mods = parts[0], parts[1:]
        ces = FIELD_MAP.get(f, f)
        vals = v if isinstance(v, list) else [v]
        group.append((ces, mods, vals))
    return [group]


def compile_rule(text: str) -> CompiledRule:
    try:
        d = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SigmaError(f"invalid YAML: {e}") from None
    if not isinstance(d, dict) or "detection" not in d:
        raise SigmaError("rule needs a detection section")
    det = dict(d["detection"])
    cond = det.pop("condition", None)
    if not cond:
        raise SigmaError("detection.condition is required")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    det.pop("timeframe", None)
    detections = {name: _items(sel) for name, sel in det.items()}
    ls = d.get("logsource") or {}
    sources = LOGSOURCE_SOURCES.get(ls.get("category") or ls.get("service") or "", [])
    return CompiledRule(d.get("title", ""), detections, str(cond), sources, d.get("tags") or [], d.get("level", "medium"),
                        d.get("falsepositives") or [], d)


def _get(ev: dict, path: str) -> Any:
    cur: Any = ev
    for p in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _wild(v: str) -> re.Pattern:
    return re.compile("^" + re.escape(v).replace(r"\*", ".*").replace(r"\?", ".") + "$", re.I | re.S)


def _match_value(actual: Any, mods: list[str], expected: Any) -> bool:
    if actual is None:
        return expected is None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    a, e = str(actual), str(expected)
    if "contains" in mods:
        e = f"*{e}*"
    elif "startswith" in mods:
        e = f"{e}*"
    elif "endswith" in mods:
        e = f"*{e}"
    return bool(_wild(e).match(a))


def _match_group(ev: dict, group: list[tuple[str, list[str], list[Any]]]) -> bool:
    for f, mods, vals in group:
        actual = _get(ev, f)
        if isinstance(actual, list):
            hit = lambda v: any(_match_value(x, mods, v) for x in actual)  # noqa: E731
        else:
            hit = lambda v: _match_value(actual, mods, v)  # noqa: E731
        ok = all(hit(v) for v in vals) if "all" in mods else any(hit(v) for v in vals)
        if not ok:
            return False
    return True


_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*]+)", re.I)


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


def evaluate(rule: CompiledRule, ev: dict) -> bool:
    cache: dict[str, bool] = {}

    def ident(name: str) -> bool:
        if name not in cache:
            if name not in rule.detections:
                raise SigmaError(f"unknown detection identifier {name}")
            cache[name] = any(_match_group(ev, g) for g in rule.detections[name])
        return cache[name]

    toks = _tokens(rule.condition)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        if pos >= len(toks):
            raise SigmaError("unexpected end of condition")
        pos += 1
        return toks[pos - 1]

    def primary() -> bool:
        t = take()
        if t == "(":
            v = expr()
            if take() != ")":
                raise SigmaError("unbalanced parentheses")
            return v
        if t == "not":
            return not primary()
        if t in ("1 of", "all of"):
            pat = take()
            names = [n for n in rule.detections if _wild(pat).match(n)] if pat != "them" else list(rule.detections)
            if not names:
                raise SigmaError(f"no detection matches {pat}")
            vals = [ident(n) for n in names]
            return any(vals) if t == "1 of" else all(vals)
        if t is None:
            raise SigmaError("unexpected end of condition")
        return ident(t)

    def term() -> bool:
        v = primary()
        while peek() == "and":
            take()
            r = primary()
            v = v and r
        return v

    def expr() -> bool:
        v = term()
        while peek() == "or":
            take()
            r = term()
            v = v or r
        return v

    out = expr()
    if pos != len(toks):
        raise SigmaError("trailing tokens in condition")
    return out


def attack_tags(rule: CompiledRule) -> list[str]:
    return sorted({t.split(".", 1)[1].upper() for t in rule.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())})
