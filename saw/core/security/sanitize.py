"""Untrusted-data helpers: filename sanitizing, CSV injection guard, control-char visualization."""
from __future__ import annotations

import re
import unicodedata

_PATH_SEP = re.compile(r"[\\/]+")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_BIDI = re.compile("[‪-‮⁦-⁩​-‏﻿]")


def sanitize_filename(name: str, max_len: int = 255) -> str:
    """Display-only filename (storage never uses user filenames; docs/09 §3)."""
    name = unicodedata.normalize("NFC", name or "")
    name = _PATH_SEP.sub("_", name)
    name = _CTRL.sub("", name)
    name = _BIDI.sub("", name)
    name = name.strip().lstrip(".")
    if not name:
        name = "unnamed"
    return name[:max_len]


def is_safe_member_path(path: str) -> bool:
    """Archive member path check (zip slip / absolute / drive letters / NUL)."""
    if not path or "\x00" in path:
        return False
    p = path.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return False
    parts = [x for x in p.split("/") if x not in ("", ".")]
    return ".." not in parts and len(parts) > 0


_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> str:
    s = "" if value is None else str(value)
    if s.startswith(_CSV_DANGEROUS):
        return "'" + s
    return s


_VISIBLE = {
    "\t": "⇥", "\r": "␍", "\x00": "␀", "‮": "⟨RLO⟩", "‭": "⟨LRO⟩", "​": "⟨ZWSP⟩",
    "‪": "⟨LRE⟩", "‫": "⟨RLE⟩", "‬": "⟨PDF⟩", "⁦": "⟨LRI⟩", "⁧": "⟨RLI⟩",
    "⁨": "⟨FSI⟩", "⁩": "⟨PDI⟩", "﻿": "⟨BOM⟩", "‎": "⟨LRM⟩", "‏": "⟨RLM⟩",
}


def visualize_controls(s: str) -> str:
    out = []
    for ch in s:
        if ch in _VISIBLE:
            out.append(_VISIBLE[ch])
        elif ch != "\n" and (ord(ch) < 0x20 or ord(ch) == 0x7F):
            out.append(f"⟨0x{ord(ch):02x}⟩")
        else:
            out.append(ch)
    return "".join(out)


def contains_bidi(s: str) -> bool:
    return bool(_BIDI.search(s))
