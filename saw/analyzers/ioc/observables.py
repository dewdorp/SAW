"""Observable extraction & classification (IPv4/IPv6/Domain/URL/Hash), defang/refang."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache

import tldextract

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled PSL snapshot, never fetches

_REFANG = [
    (re.compile(r"(?i)\bhxxp(s?)"), r"http\1"),
    (re.compile(r"(?i)\bfxp\b"), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]", re.I), "@"),
]

IPV4 = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.]|\.\d)")
IPV6 = re.compile(r"(?<![:\w])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?|::(?:[0-9a-fA-F]{1,4}:?){1,7})(?![:\w])")
URL = re.compile(r"(?i)\b((?:https?|ftp)://[^\s\"'<>()\[\]{}]+)")
DOMAIN = re.compile(r"(?i)(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![\w-])")
HASH = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_FILE_EXT = {"php", "asp", "aspx", "jsp", "js", "css", "html", "htm", "json", "xml", "txt", "log", "png", "jpg",
             "gif", "svg", "ico", "exe", "dll", "zip", "gz", "tar", "py", "java", "do", "action", "cgi", "pl",
             "conf", "ini", "env", "bak", "sql", "yml", "yaml", "md", "csv", "pdf", "map", "woff", "woff2", "ttf"}


def refang(s: str) -> str:
    for rx, rep in _REFANG:
        s = rx.sub(rep, s)
    return s


_REFANG_ANY = re.compile(r"(?i)\bhxxps?|\bfxp\b|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[:\]|\[/\]|\[@\]|\[at\]")


def refang_with_map(s: str) -> tuple[str, list[int]]:
    """Refang and return, for each output char, the index of its source char (for span highlighting)."""
    out: list[str] = []
    idx: list[int] = []
    pos = 0
    for m in _REFANG_ANY.finditer(s):
        out.extend(s[pos:m.start()])
        idx.extend(range(pos, m.start()))
        rep = refang(m.group(0))
        out.extend(rep)
        idx.extend([m.start()] * len(rep))
        pos = m.end()
    out.extend(s[pos:])
    idx.extend(range(pos, len(s)))
    idx.append(len(s))
    return "".join(out), idx


def defang(value: str) -> str:
    return value.replace("http", "hxxp", 1).replace(".", "[.]") if value else value


@dataclass
class Observable:
    type: str  # ipv4|ipv6|domain|url|md5|sha1|sha256|sha512
    value: str
    span: tuple[int, int]
    scope: str = ""  # internal|external|reserved for IPs

    def to_dict(self) -> dict:
        return {"type": self.type, "value": self.value, "span": list(self.span), "scope": self.scope,
                "defanged": defang(self.value)}


@lru_cache(maxsize=65536)  # logs repeat the same addresses: parse each once
def ip_scope(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "invalid"
    if a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local:
        return "reserved"
    if a.is_private:
        return "internal"
    return "external"


_AFFILIATE_LOCAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "0.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128")]


@lru_cache(maxsize=65536)
def affiliate_local(ip: str) -> bool:
    """True when the address is re-used inside each organisation (RFC 1918, CGNAT, loopback, link-local, ULA).

    Such an address names a different host in every affiliate (and over time with DHCP/NAT/VPN), so it must
    never be merged across affiliates. Unparsable values are treated as local: never merge what is unknown.
    """
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return True
    return any(a in n for n in _AFFILIATE_LOCAL if n.version == a.version)


def valid_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    ext = _TLD(d)
    if not ext.suffix or not ext.domain:
        return False
    last = d.rsplit(".", 1)[-1]
    if last in _FILE_EXT and not ext.suffix:
        return False
    return not (ext.suffix in _FILE_EXT and len(d.split(".")) == 2)


def registered_domain(d: str) -> str:
    e = _TLD(d.lower().rstrip("."))
    return f"{e.domain}.{e.suffix}" if e.suffix else d


def extract(text: str) -> list[Observable]:
    out: list[Observable] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= x or a >= y for x, y in taken)

    for m in URL.finditer(text):
        out.append(Observable("url", m.group(1).rstrip(".,;"), (m.start(1), m.end(1))))
        taken.append((m.start(1), m.end(1)))
    for m in IPV4.finditer(text):
        # skip version-like strings: preceded by 'v', '/', or a letter immediately (e.g. httpx/0.27.1.2)
        pre = text[max(0, m.start() - 1): m.start()]
        if pre.isalpha() or pre == "/":
            continue
        if free(m.start(1), m.end(1)) or True:
            out.append(Observable("ipv4", m.group(1), (m.start(1), m.end(1)), ip_scope(m.group(1))))
    for m in IPV6.finditer(text):
        v = m.group(1)
        try:
            ipaddress.ip_address(v.split("%")[0])
        except ValueError:
            continue
        if v.count(":") >= 2 and free(m.start(1), m.end(1)):
            out.append(Observable("ipv6", v, (m.start(1), m.end(1)), ip_scope(v)))
    for m in HASH.finditer(text):
        n = len(m.group(1))
        t = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[n]
        if free(m.start(1), m.end(1)):
            out.append(Observable(t, m.group(1).lower(), (m.start(1), m.end(1))))
            taken.append((m.start(1), m.end(1)))
    for m in DOMAIN.finditer(text):
        d = m.group(1)
        if IPV4.fullmatch(d) or not valid_domain(d):
            continue
        if free(m.start(1), m.end(1)):
            out.append(Observable("domain", d.lower().rstrip("."), (m.start(1), m.end(1))))
    # de-duplicate (type, value) keeping first span
    seen, uniq = set(), []
    for o in sorted(out, key=lambda o: o.span):
        k = (o.type, o.value)
        if k not in seen:
            seen.add(k)
            uniq.append(o)
    return uniq


def classify(value: str) -> str | None:
    v = refang(value.strip())
    if IPV4.fullmatch(v):
        return "ipv4"
    try:
        if ":" in v and ipaddress.ip_address(v.split("%")[0]).version == 6:
            return "ipv6"
    except ValueError:
        pass
    if URL.fullmatch(v):
        return "url"
    if HASH.fullmatch(v):
        return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[len(v)]
    if DOMAIN.fullmatch(v) and valid_domain(v):
        return "domain"
    return None
