"""Deterministic payload transforms + automatic decode-chain search (docs/17 §6, ADR-0011)."""
from __future__ import annotations

import base64
import binascii
import gzip
import html
import json
import math
import re
import urllib.parse
import zlib
from collections import Counter
from dataclasses import dataclass, field

MAX_OUTPUT = 10 * 1024 * 1024
MAX_DEPTH = 8


class TransformError(ValueError):
    pass


class Incomplete(str):
    """Output of a transform whose input ended early (e.g. a cut-off gzip stream): usable, but not the whole thing."""
    note = "입력이 중간에 끊겨 있어 풀린 부분까지만 표시함"


def _to_text(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def _limit(b: bytes) -> bytes:
    if len(b) > MAX_OUTPUT:
        raise TransformError("output exceeds limit")
    return b


def t_url_decode(s: str) -> str:
    if "%" not in s and "+" not in s:
        raise TransformError("no url encoding")
    out = urllib.parse.unquote_plus(s) if "+" in s and "%" in s else urllib.parse.unquote(s)
    if out == s:
        raise TransformError("unchanged")
    return out


def t_base64(s: str) -> str:
    t = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", t) or len(t) < 8:
        raise TransformError("not base64")
    t += "=" * (-len(t) % 4)
    try:
        return _to_text(_limit(base64.b64decode(t, validate=True)))
    except (binascii.Error, ValueError) as e:
        raise TransformError(str(e)) from None


def t_base64url(s: str) -> str:
    t = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", t) or len(t) < 8 or not re.search(r"[-_]", t):
        raise TransformError("not base64url")
    t += "=" * (-len(t) % 4)
    try:
        return _to_text(_limit(base64.urlsafe_b64decode(t)))
    except (binascii.Error, ValueError) as e:
        raise TransformError(str(e)) from None


def t_hex(s: str) -> str:
    t = re.sub(r"(\\x|0x|\s|:)", "", s)
    if len(t) < 4 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        raise TransformError("not hex")
    return _to_text(_limit(bytes.fromhex(t)))


def t_unicode_escape(s: str) -> str:
    if not re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}", s):
        raise TransformError("no unicode escapes")
    s2 = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s2 = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s2)
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s2)


def t_html_entity(s: str) -> str:
    if not re.search(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", s):
        raise TransformError("no html entities")
    out = html.unescape(s)
    if out == s:
        raise TransformError("unchanged")
    return out


def _decompress(data: bytes, wbits: int = 47) -> tuple[bytes, bool]:
    """(output, complete). wbits 47 auto-detects gzip/zlib. complete=False: the stream stopped before its end marker."""
    d = zlib.decompressobj(wbits=wbits)
    out = d.decompress(data, MAX_OUTPUT + 1)
    return _limit(out), d.eof


def t_gzip(s: str) -> str:
    raw = s.encode("latin-1", errors="ignore")
    if not raw.startswith(b"\x1f\x8b"):
        raise TransformError("not gzip")
    try:
        out, complete = _decompress(raw)
    except (zlib.error, gzip.BadGzipFile) as e:
        raise TransformError(str(e)) from None
    if not out and not complete:
        raise TransformError("gzip stream is cut off before any data")
    return _to_text(out) if complete else Incomplete(_to_text(out))


def t_deflate(s: str) -> str:
    raw = s.encode("latin-1", errors="ignore")
    try:
        out, complete = _decompress(raw, -15)
    except zlib.error as e:
        raise TransformError(str(e)) from None
    if not out:
        raise TransformError("empty")
    return _to_text(out) if complete else Incomplete(_to_text(out))


def t_ps_encoded(s: str) -> str:
    m = re.search(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{8,})", s)
    payload = m.group(1) if m else s.strip()
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
        out = raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise TransformError(str(e)) from None
    if not out.isprintable() and sum(c.isprintable() for c in out) / max(1, len(out)) < 0.9:
        raise TransformError("not printable")
    return out


def t_jwt(s: str) -> str:
    parts = s.strip().split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        raise TransformError("not jwt")
    try:
        hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        body = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, binascii.Error) as e:
        raise TransformError(str(e)) from None
    return json.dumps({"header": hdr, "payload": body, "signature_present": bool(parts[2])}, ensure_ascii=False)


TRANSFORMS = {
    "url_decode": t_url_decode,
    "base64": t_base64,
    "base64url": t_base64url,
    "hex": t_hex,
    "unicode_escape": t_unicode_escape,
    "html_entity": t_html_entity,
    "gzip": t_gzip,
    "deflate": t_deflate,
    "ps_encoded": t_ps_encoded,
    "jwt": t_jwt,
}

LABELS = {
    "url_decode": "URL Decode", "base64": "Base64", "base64url": "Base64URL", "hex": "Hex",
    "unicode_escape": "Unicode Escape", "html_entity": "HTML Entity", "gzip": "Gunzip", "deflate": "Inflate",
    "ps_encoded": "PowerShell EncodedCommand", "jwt": "JWT Decode",
}

# CyberChef recipe names for "Open in CyberChef"
CYBERCHEF = {
    "url_decode": "URL_Decode()", "base64": "From_Base64('A-Za-z0-9%2B/%3D',true)",
    "base64url": "From_Base64('A-Za-z0-9-_',true)", "hex": "From_Hex('Auto')",
    "unicode_escape": "Unescape_Unicode_Characters('%5C%5Cu')", "html_entity": "From_HTML_Entity()",
    "gzip": "Gunzip()", "deflate": "Raw_Inflate(0,0,'Adaptive',false,false)",
    "ps_encoded": "From_Base64('A-Za-z0-9%2B/%3D',true)Decode_text('UTF-16LE (1200)')",
    "jwt": "JWT_Decode()",
}


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\r\n\t") / len(s)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def meaningfulness(s: str) -> float:
    """Higher = more human/structured. Used to decide whether a decode step made progress."""
    score = printable_ratio(s) * 2
    if re.search(r"[<>{}()\[\];=/'\"]|\.\./|select|union|script|http|cmd|powershell", s, re.I):
        score += 0.5
    score -= max(0.0, entropy(s) - 4.5) * 0.3
    return score


@dataclass
class Step:
    op: str
    label: str
    input_preview: str
    output: str
    note: str = ""  # e.g. the input was cut off: the output is only the part that could be recovered


@dataclass
class Chain:
    steps: list[Step] = field(default_factory=list)
    output: str = ""
    confidence: str = "low"
    incomplete: bool = False  # some step worked on cut-off input

    def recipe(self) -> str:
        return "".join(CYBERCHEF[s.op] for s in self.steps)


def apply_chain(s: str, ops: list[str]) -> Chain:
    ch = Chain(output=s)
    cur = s
    for op in ops:
        if op not in TRANSFORMS:
            raise TransformError(f"unknown transform {op}")
        out = TRANSFORMS[op](cur)
        ch.steps.append(Step(op, LABELS[op], cur[:200], str(out), getattr(out, "note", "")))
        cur = str(out)
    ch.output = cur
    ch.incomplete = any(s.note for s in ch.steps)
    ch.confidence = "low" if ch.incomplete else "high"
    return ch


_ORDER = ["url_decode", "html_entity", "unicode_escape", "jwt", "ps_encoded", "base64url", "base64", "hex",
          "gzip", "deflate"]


def auto_decode(s: str, max_depth: int = MAX_DEPTH) -> Chain:
    """Greedy deterministic search: at each depth apply the first transform that keeps the result meaningful."""
    ch = Chain(output=s)
    cur = s
    for _ in range(max_depth):
        best: tuple[str, str] | None = None
        for op in _ORDER:
            try:
                out = TRANSFORMS[op](cur)
            except TransformError:
                continue
            except Exception:
                continue
            if not out or out == cur:
                continue
            if op in ("base64", "base64url", "hex") and (printable_ratio(out) < 0.85 and not out.startswith("\x1f\x8b")):
                continue
            if op in ("url_decode", "html_entity", "unicode_escape", "jwt", "ps_encoded") or \
                    meaningfulness(out) >= meaningfulness(cur) - 0.2 or out.startswith("\x1f\x8b"):
                best = (op, out)
                break
        if best is None:
            break
        ch.steps.append(Step(best[0], LABELS[best[0]], cur[:200], str(best[1]), getattr(best[1], "note", "")))
        cur = str(best[1])
    ch.output = cur
    ch.incomplete = any(s.note for s in ch.steps)
    ch.confidence = "high" if ch.steps and printable_ratio(cur) > 0.95 else ("medium" if ch.steps else "low")
    if ch.incomplete:
        ch.confidence = "low"
    return ch
