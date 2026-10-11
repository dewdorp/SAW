"""Potential attack-pattern detection on (decoded) parameter values (docs/17 §3).

Never asserts an attack: returns "Potential … Pattern" with evidence, counter-evidence and confidence.
libinjection is used when its binding is installed (ENV-15); otherwise a deterministic heuristic tokenizer.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

try:  # pragma: no cover - optional native binding (ENV-15)
    import libinjection as _libinj  # type: ignore
except Exception:  # noqa: BLE001
    _libinj = None

LIBINJECTION_AVAILABLE = _libinj is not None


@dataclass
class Evidence:
    kind: str
    value: str
    span: tuple[int, int] | None = None


@dataclass
class PatternHit:
    pattern: str
    label: str
    confidence: str
    location: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    not_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern, "label": self.label, "confidence": self.confidence, "location": self.location,
            "evidence": [{"kind": e.kind, "value": e.value, "span": list(e.span) if e.span else None}
                         for e in self.evidence],
            "not_evidence": self.not_evidence,
        }


def _conf(n_signals: int, strong: bool) -> str:
    if strong and n_signals >= 2:
        return "high"
    if n_signals >= 2 or strong:
        return "medium"
    return "low"


def _span_ev(kind: str, m: re.Match) -> Evidence:
    return Evidence(kind, m.group(0)[:200], (m.start(), m.end()))


# ---------------------------------------------------------------- SQLi
_SQL_TAUT = re.compile(r"(?i)['\"`)\s]\s*(or|and|\|\||&&)\s*['\"`(]?\s*(\w+|'[^']*')\s*(=|like|<|>)\s*['\"`(]?\s*\w*")
_SQL_UNION = re.compile(r"(?i)\bunion\b[\s/*()]+(all[\s/*()]+)?select\b")
_SQL_TIME = re.compile(r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(?")
_SQL_COMMENT = re.compile(r"(--[\s\-]|#\s*$|/\*.*?\*/|;\s*--)")
_SQL_KW = re.compile(r"(?i)\b(select|insert|update|delete|drop|union|from|where|information_schema|"
                     r"xp_cmdshell|exec|concat|char|substring|ascii|extractvalue|updatexml|load_file|outfile)\b")
_SQL_STACK = re.compile(r"(?i);\s*(drop|insert|update|delete|exec|declare|select)\b")
_QUOTE_BREAK = re.compile(r"^[^'\"]*['\"`]|['\"`]\s*\)")


def detect_sqli(v: str) -> PatternHit | None:
    ev: list[Evidence] = []
    strong = False
    if _libinj is not None:  # pragma: no cover
        r = _libinj.is_sql_injection(v)
        if r.get("is_sqli"):
            ev.append(Evidence("libinjection", f"fingerprint {r.get('fingerprint')}"))
            strong = True
    for rx, kind, st in ((_SQL_TAUT, "tautology", True), (_SQL_UNION, "union_select", True),
                         (_SQL_TIME, "time_based", True), (_SQL_STACK, "stacked_query", True)):
        m = rx.search(v)
        if m:
            ev.append(_span_ev(kind, m))
            strong = strong or st
    kws = {m.group(1).lower() for m in _SQL_KW.finditer(v)}
    if len(kws) >= 2:
        ev.append(Evidence("sql_keywords", ", ".join(sorted(kws))))
    m = _SQL_COMMENT.search(v)
    if m and (ev or _QUOTE_BREAK.search(v)):
        ev.append(_span_ev("sql_comment", m))
    if _QUOTE_BREAK.search(v) and ev:
        ev.append(Evidence("quote_break", "unbalanced quote"))
    if not ev or (len(ev) == 1 and ev[0].kind == "sql_keywords" and len(kws) < 3):
        return None
    return PatternHit("potential_sql_injection", "Potential SQL Injection Pattern", _conf(len(ev), strong),
                      evidence=ev)


# ---------------------------------------------------------------- XSS
_XSS_TAG = re.compile(r"(?i)<\s*(script|svg|img|iframe|body|object|embed|video|audio|math|details|marquee|a)\b[^>]*")
_XSS_HANDLER = re.compile(r"(?i)\bon[a-z]{3,20}\s*=")
_XSS_PROTO = re.compile(r"(?i)(javascript|vbscript|data\s*:\s*text/html)\s*:")
_XSS_FUNC = re.compile(r"(?i)\b(alert|prompt|confirm|eval|document\.cookie|String\.fromCharCode)\s*[(.`]")


def detect_xss(v: str) -> PatternHit | None:
    ev = []
    for rx, kind in ((_XSS_TAG, "html_tag"), (_XSS_HANDLER, "event_handler"), (_XSS_PROTO, "script_protocol"),
                     (_XSS_FUNC, "js_function")):
        m = rx.search(v)
        if m:
            ev.append(_span_ev(kind, m))
    strong = any(e.kind in ("event_handler", "script_protocol") for e in ev) or \
        any(e.kind == "html_tag" and "script" in e.value.lower() for e in ev)
    if not ev or (len(ev) == 1 and ev[0].kind == "html_tag" and not strong):
        return None
    return PatternHit("potential_xss", "Potential XSS Pattern", _conf(len(ev), strong), evidence=ev)


# ---------------------------------------------------------------- traversal / LFI
_TRAV = re.compile(r"(\.\.[/\\])|(\.\.%2f)|(\.\.%5c)|(%2e%2e[/\\%])|(\.\.%c0%af)|(\.{4}//)", re.I)
_SENSITIVE_PATH = re.compile(r"(?i)(/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|/proc/self/|web\.config|"
                             r"\.htaccess|/\.env\b|\.git/config|id_rsa)")
_WRAPPER = re.compile(r"(?i)\b(php|file|zip|phar|expect|data)://")


def detect_traversal(v: str) -> PatternHit | None:
    ev = []
    m = _TRAV.search(v)
    if m:
        ev.append(_span_ev("traversal_sequence", m))
    m = _SENSITIVE_PATH.search(v)
    if m:
        ev.append(_span_ev("sensitive_path", m))
    m = _WRAPPER.search(v)
    if m and m.group(1).lower() != "data":
        ev.append(_span_ev("stream_wrapper", m))
    if not ev:
        return None
    label = "Potential Directory Traversal / LFI Pattern"
    return PatternHit("potential_traversal_lfi", label, _conf(len(ev), any(e.kind == "sensitive_path" for e in ev)),
                      evidence=ev)


# ---------------------------------------------------------------- RFI / SSRF
_URL_IN_VALUE = re.compile(r"(?i)\b(https?|ftp|gopher|dict|ldap|file)://([^/\s?#:]+)")
_METADATA = {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}


def detect_ssrf_rfi(v: str, param_name: str = "") -> PatternHit | None:
    m = _URL_IN_VALUE.search(v)
    if not m:
        return None
    scheme, host = m.group(1).lower(), m.group(2).lower().strip("[]")
    ev = [_span_ev("url_in_parameter", m)]
    strong = False
    if scheme in ("gopher", "dict", "ldap", "file"):
        ev.append(Evidence("dangerous_scheme", scheme))
        strong = True
    if host in _METADATA:
        ev.append(Evidence("cloud_metadata_endpoint", host))
        strong = True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            ev.append(Evidence("internal_address", host))
            strong = True
    except ValueError:
        if host in ("localhost",) or host.endswith(".internal") or host.endswith(".local"):
            ev.append(Evidence("internal_hostname", host))
            strong = True
    if re.search(r"(?i)(url|uri|path|dest|redirect|target|callback|feed|host|site|file|include|page)", param_name):
        ev.append(Evidence("url_like_param_name", param_name))
    if len(ev) == 1:
        return None
    return PatternHit("potential_ssrf_rfi", "Potential SSRF / RFI Pattern", _conf(len(ev), strong), evidence=ev)


# ---------------------------------------------------------------- command injection
_CMD_SEP = re.compile(r"(;|\|\|?|&&|\$\(|`|\n)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd|"
                      r"ping|nslookup|echo|python|perl|certutil|bitsadmin)\b", re.I)
_CMD_SUBST = re.compile(r"\$\([^)]{1,100}\)|`[^`]{1,100}`")


def detect_cmdi(v: str) -> PatternHit | None:
    ev = []
    m = _CMD_SEP.search(v)
    if m:
        ev.append(_span_ev("separator_command", m))
    m = _CMD_SUBST.search(v)
    if m:
        ev.append(_span_ev("command_substitution", m))
    if not ev:
        return None
    return PatternHit("potential_command_injection", "Potential Command Injection Pattern",
                      _conf(len(ev), bool(_CMD_SEP.search(v))), evidence=ev)


# ---------------------------------------------------------------- SSTI
_SSTI = re.compile(r"\{\{\s*[^}]{1,80}\}\}|\$\{[^}]{1,80}\}|<%=?[^%]{1,80}%>|#\{[^}]{1,80}\}|\{%[^%]{1,80}%\}")
_SSTI_STRONG = re.compile(r"(?i)(\d+\s*\*\s*\d+|__class__|__mro__|__globals__|config\.|self\.|\.getClass\(|"
                          r"Runtime|T\(java|jndi:)")


def detect_ssti(v: str) -> PatternHit | None:
    m = _SSTI.search(v)
    if not m:
        return None
    ev = [_span_ev("template_expression", m)]
    s = _SSTI_STRONG.search(m.group(0))
    if s:
        ev.append(Evidence("template_payload", s.group(0)))
    if "jndi:" in v.lower():
        ev.append(Evidence("jndi_lookup", "jndi:"))
    if len(ev) == 1 and not s:
        return None
    return PatternHit("potential_ssti", "Potential SSTI / Expression Injection Pattern", _conf(len(ev), bool(s)),
                      evidence=ev)


# ---------------------------------------------------------------- deserialization
_DESER = [
    (re.compile(r"rO0AB[A-Za-z0-9+/=]{4,}"), "java_serialized_base64"),
    (re.compile(r"(?i)aced0005"), "java_serialized_hex"),
    (re.compile(r"O:\d+:\"[A-Za-z0-9_\\]+\":\d+:\{"), "php_object"),
    (re.compile(r"\x80[\x02-\x05].{0,40}(c__builtin__|cos\nsystem|cposix)", re.S), "python_pickle"),
    (re.compile(r"(?i)AAEAAAD/////"), "dotnet_binaryformatter"),
    (re.compile(r"(?i)\"\$type\"\s*:\s*\"[^\"]*(ObjectDataProvider|WindowsIdentity|Process)"), "json_net_type"),
]


def detect_deserialization(v: str) -> PatternHit | None:
    ev = []
    for rx, kind in _DESER:
        m = rx.search(v)
        if m:
            ev.append(_span_ev(kind, m))
    if not ev:
        return None
    return PatternHit("potential_deserialization", "Potential Insecure Deserialization Pattern", "medium",
                      evidence=ev)


VALUE_DETECTORS = [detect_sqli, detect_xss, detect_traversal, detect_cmdi, detect_ssti, detect_deserialization]


def scan_value(value: str, param_name: str = "", location: str = "") -> list[PatternHit]:
    hits = []
    for fn in VALUE_DETECTORS:
        h = fn(value)
        if h:
            h.location = location
            hits.append(h)
    h = detect_ssrf_rfi(value, param_name)
    if h:
        h.location = location
        hits.append(h)
    return hits


def pattern_tags(value: str) -> list[str]:
    """Short tags for log enrichment (e.g. 'sqli', 'xss')."""
    short = {"potential_sql_injection": "sqli", "potential_xss": "xss", "potential_traversal_lfi": "traversal",
             "potential_command_injection": "cmdi", "potential_ssti": "ssti",
             "potential_deserialization": "deser", "potential_ssrf_rfi": "ssrf"}
    return sorted({short[h.pattern] for h in scan_value(value)})
