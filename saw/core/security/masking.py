"""Sensitive data masking (docs/12 §3.1). Applied at display / export / LLM layers."""
from __future__ import annotations

import re
from dataclasses import dataclass

_RRN = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-?([1-8])(\d{6})(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PHONE = re.compile(r"(?<!\d)(01[016789])[- ]?(\d{3,4})[- ]?(\d{4})(?!\d)")
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})")
_COOKIE = re.compile(r"(?i)\b(set[_-]?cookie|cookie)(\s*[=:]\s*)([^\r\n\",]+)")
_SECRET_NAMES = r"password|passwd|pwd|secret|token|api_?key|access_?key"
# name=value, also when the "=" is still percent-encoded (once or more): a decoded parameter keeps its value hidden
_SECRET_PARAM = re.compile(rf"(?i)\b({_SECRET_NAMES})(=|%(?:25)*3d)([^&\s\"']+)")
# "name": "value" in JSON bodies (the key may carry a prefix/suffix: user_password, accessToken, ...)
_SECRET_JSON = re.compile(
    rf"""(?i)("[\w.-]{{0,40}}(?:{_SECRET_NAMES})[\w.-]{{0,40}}"\s*:\s*)("(?:[^"\\]|\\.)*"|[^\s,}}\]]+)""")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


@dataclass
class MaskResult:
    text: str
    kinds: list[str]


def _mask_card(m: re.Match) -> str:
    raw = m.group(0)
    digits = re.sub(r"\D", "", raw)
    if not (13 <= len(digits) <= 19) or not luhn_ok(digits):
        return raw
    return f"{digits[:4]}-****-****-{digits[-4:]}"


def mask_text(text: str) -> MaskResult:
    kinds: list[str] = []

    def track(kind: str, pattern: re.Pattern, repl) -> None:
        nonlocal text
        new = pattern.sub(repl, text)
        if new != text:
            kinds.append(kind)
            text = new

    track("jwt", _JWT, lambda m: f"eyJ…[JWT len={len(m.group(0))}]")
    track("cookie", _COOKIE, lambda m: f"{m.group(1)}{m.group(2)}●●●●[len={len(m.group(3))}]")
    track("auth_header", _BEARER, lambda m: f"{m.group(1)} ●●●●[len={len(m.group(2))}]")
    track("secret_param", _SECRET_PARAM, lambda m: f"{m.group(1)}{m.group(2)}●●●●")
    track("secret_param", _SECRET_JSON, lambda m: f'{m.group(1)}"●●●●"')
    track("rrn", _RRN, lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}-{m.group(4)}******")
    track("card", _CARD, _mask_card)
    track("phone", _PHONE, lambda m: f"{m.group(1)}-****-{m.group(3)}")
    track("email", _EMAIL, lambda m: f"{m.group(1)}***@{m.group(2)}")
    return MaskResult(text, kinds)


SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}

_MASK_FIELDS = ("raw_event", "uri", "url_query", "user_agent")


def mask_event(ev: dict) -> tuple[dict, list[str]]:
    """Display-layer masking of a CES event (storage keeps the original; docs/12 §3.1)."""
    out = dict(ev)
    kinds: set[str] = set()
    for k in _MASK_FIELDS:
        if isinstance(out.get(k), str):
            r = mask_text(out[k])
            out[k] = r.text
            kinds.update(r.kinds)
    if isinstance(out.get("params"), dict):
        ps = {}
        for k, v in out["params"].items():
            if re.search(r"(?i)(pass|pwd|secret|token|session|auth|key)", k) and v:
                ps[k] = mask_value(str(v))
                kinds.add("secret_param")
            else:
                r = mask_text(str(v))
                ps[k] = r.text
                kinds.update(r.kinds)
        out["params"] = ps
    if isinstance(out.get("ext"), dict):
        def walk(o):
            if isinstance(o, dict):
                return {k: walk(v) for k, v in o.items()}
            if isinstance(o, list):
                return [walk(v) for v in o]
            if isinstance(o, str):
                r = mask_text(o)
                kinds.update(r.kinds)
                return r.text
            return o
        out["ext"] = walk(out["ext"])
    if kinds:
        out["_masked"] = sorted(kinds)
    return out, sorted(kinds)


def mask_value(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "●" * len(value)
    return "●●●●" + value[-keep:]
