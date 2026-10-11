"""File identification for transferred objects: magic bytes, category, entropy, declared-vs-actual mismatch.

Categories drive the malware-delivery detector: executable / script / exploit_content (Flash, Java) /
archive / document / image / web / text / unknown. Content is never executed or rendered.
"""
from __future__ import annotations

import math
import re
from collections import Counter

EXECUTABLE, SCRIPT, EXPLOIT, ARCHIVE, DOCUMENT, IMAGE, WEB, TEXT, UNKNOWN = (
    "executable", "script", "exploit_content", "archive", "document", "image", "web", "text", "unknown")

_MAGIC: list[tuple[bytes, int, str, str, str]] = [  # (magic, offset, kind, mime, category)
    (b"MZ", 0, "pe", "application/x-dosexec", EXECUTABLE),
    (b"\x7fELF", 0, "elf", "application/x-executable", EXECUTABLE),
    (b"\xcf\xfa\xed\xfe", 0, "macho", "application/x-mach-binary", EXECUTABLE),
    (b"\xca\xfe\xba\xbe", 0, "java_class", "application/java-vm", EXPLOIT),  # also Mach-O fat; class is likelier over HTTP
    (b"FWS", 0, "swf", "application/x-shockwave-flash", EXPLOIT),
    (b"CWS", 0, "swf", "application/x-shockwave-flash", EXPLOIT),
    (b"ZWS", 0, "swf", "application/x-shockwave-flash", EXPLOIT),
    (b"%PDF", 0, "pdf", "application/pdf", DOCUMENT),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", "application/x-ole-storage", DOCUMENT),
    (b"{\\rtf", 0, "rtf", "application/rtf", DOCUMENT),
    (b"PK\x03\x04", 0, "zip", "application/zip", ARCHIVE),
    (b"Rar!\x1a\x07", 0, "rar", "application/x-rar", ARCHIVE),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "application/x-7z-compressed", ARCHIVE),
    (b"\x1f\x8b", 0, "gzip", "application/gzip", ARCHIVE),
    (b"MSCF", 0, "cab", "application/vnd.ms-cab-compressed", ARCHIVE),
    (b"\x89PNG\r\n\x1a\n", 0, "png", "image/png", IMAGE),
    (b"\xff\xd8\xff", 0, "jpeg", "image/jpeg", IMAGE),
    (b"GIF8", 0, "gif", "image/gif", IMAGE),
    (b"RIFF", 0, "riff", "application/octet-stream", IMAGE),
    (b"\x00\x00\x01\x00", 0, "ico", "image/x-icon", IMAGE),
]
_HTML = re.compile(rb"^\s*(<!doctype html|<html|<head|<body|<script|<iframe|<div|<\?xml)", re.IGNORECASE)
_SCRIPT_SIGS = [
    (re.compile(rb"^#!\s*/(usr/)?bin/(env\s+)?(ba|z|da)?sh"), "shell", "text/x-shellscript"),
    (re.compile(rb"(?i)(invoke-expression|iex\s*\(|new-object\s+net\.webclient|-encodedcommand|frombase64string)"), "powershell", "text/x-powershell"),
    (re.compile(rb"(?i)(createobject\s*\(\s*\"wscript\.shell|wscript\.createobject|execute\s*\()"), "vbscript", "text/vbscript"),
    (re.compile(rb"(?i)(<\?php|eval\s*\(\s*\$_(post|get|request)|base64_decode\s*\()"), "php", "application/x-php"),
    (re.compile(rb"(?i)<%@?\s*(page|language)|runtime\.getruntime\(\)\.exec"), "jsp_asp", "text/x-server-script"),
    (re.compile(rb"(?i)^@?echo off|^\s*(cmd|start)\s+/[ck]"), "batch", "application/x-bat"),
]
EXT_CATEGORY = {
    **dict.fromkeys(["exe", "dll", "scr", "sys", "com", "msi", "elf", "bin", "so", "dylib"], EXECUTABLE),
    **dict.fromkeys(["ps1", "vbs", "vbe", "js", "jse", "hta", "bat", "cmd", "sh", "php", "jsp", "jspx", "asp", "aspx",
                     "py", "pl", "wsf"], SCRIPT),
    **dict.fromkeys(["swf", "jar", "class"], EXPLOIT),
    **dict.fromkeys(["zip", "rar", "7z", "gz", "tgz", "cab", "iso"], ARCHIVE),
    **dict.fromkeys(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "hwp", "hwpx"], DOCUMENT),
    **dict.fromkeys(["png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg"], IMAGE),
    **dict.fromkeys(["html", "htm", "css", "json", "xml"], WEB),
    **dict.fromkeys(["txt", "log", "csv"], TEXT),
}
SERVER_SCRIPT_EXT = {"php", "jsp", "jspx", "asp", "aspx", "war", "cfm", "phtml", "php5", "ashx", "asmx"}


_PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"


def printable_ratio(b: bytes) -> float:
    """Share of printable ASCII bytes (C-speed: translate deletes printable bytes, the rest are counted)."""
    return 1.0 - len(b.translate(None, _PRINTABLE)) / len(b) if b else 0.0


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def identify(b: bytes) -> tuple[str, str, str]:
    """→ (kind, mime, category) from content only."""
    head = b[:4096]
    for magic, off, kind, mime, cat in _MAGIC:
        if head[off:off + len(magic)] == magic:
            if kind == "zip":
                if b"META-INF/MANIFEST.MF" in b[:65536] or b".class" in b[:65536]:
                    return "jar", "application/java-archive", EXPLOIT
                if b"[Content_Types].xml" in b[:65536]:
                    return "ooxml", "application/vnd.openxmlformats-officedocument", DOCUMENT
                if b"AndroidManifest.xml" in b[:65536]:
                    return "apk", "application/vnd.android.package-archive", EXECUTABLE
            if kind == "ole" and b"M\x00S\x00I" in b[:65536]:
                return "msi", "application/x-msi", EXECUTABLE
            if kind == "pe" and len(b) > 0x40:
                pe = int.from_bytes(b[0x3C:0x40], "little")
                if not (0 < pe < len(b) - 4 and b[pe:pe + 4] == b"PE\0\0"):
                    continue  # "MZ" text, not a PE
            return kind, mime, cat
    textual = printable_ratio(head) > 0.85
    if textual:  # script/HTML signatures only make sense for text (skips regex work on binary bodies)
        for rx, kind, mime in _SCRIPT_SIGS:
            if rx.search(head):
                return kind, mime, SCRIPT
        if _HTML.match(head):
            return "html", "text/html", WEB
        if printable_ratio(head) > 0.95:
            return "text", "text/plain", TEXT
    return "data", "application/octet-stream", UNKNOWN


def extension(name: str | None) -> str:
    if not name or "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()[:10]


def declared_category(filename: str | None, content_type: str | None) -> str | None:
    ext = extension(filename)
    if ext in EXT_CATEGORY:
        return EXT_CATEGORY[ext]
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct.startswith("image/"):
        return IMAGE
    if ct in ("text/html", "text/css", "application/json", "text/xml", "application/xml", "application/javascript"):
        return WEB
    if ct.startswith("text/"):
        return TEXT
    if ct in ("application/pdf", "application/msword"):
        return DOCUMENT
    return None


def is_masquerade(actual: str, declared: str | None) -> bool:
    """Executable/script content delivered as something harmless (image, document, web, text)."""
    return actual in (EXECUTABLE, SCRIPT) and declared in (IMAGE, DOCUMENT, WEB, TEXT)
