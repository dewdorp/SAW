"""TLS ClientHello / ServerHello / Certificate parsing: SNI, ALPN, versions, JA3, JA3S, JA4 (FoxIO spec, TLS-over-TCP 't')
and the server certificate (sent in clear up to TLS 1.2; TLS 1.3 encrypts it, so it is absent there)."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
            0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3"}
ZEEK_VERSIONS = {0x0304: "TLSv13", 0x0303: "TLSv12", 0x0302: "TLSv11", 0x0301: "TLSv10", 0x0300: "SSLv3"}
CIPHERS = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
           0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
           0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
           0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
           0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
           0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
           0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"}


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list[int]
    extensions: list[int]
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)


@dataclass
class ServerHello:
    version: int
    cipher: int
    legacy_version: int = 0
    extensions: list[int] = field(default_factory=list)


def _handshake(buf: bytes, want: int) -> bytes | None:
    """Return the body of the first handshake message of type `want` from TLS records at the start of `buf`."""
    hs = b""
    i = 0
    while i + 5 <= len(buf) and len(hs) < 65536:
        ctype, _ver, rlen = buf[i], struct.unpack("!H", buf[i + 1:i + 3])[0], struct.unpack("!H", buf[i + 3:i + 5])[0]
        if ctype != 22:  # handshake
            break
        hs += buf[i + 5:i + 5 + rlen]
        i += 5 + rlen
        if len(hs) >= 4 and hs[0] == want and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
            break
    if len(hs) < 4 or hs[0] != want:
        return None
    n = int.from_bytes(hs[1:4], "big")
    return hs[4:4 + n] if len(hs) >= 4 + n else None


def looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 6 and payload[0] == 22 and payload[1] == 3 and payload[2] <= 4 and payload[5] in (1, 2)


def parse_client_hello(buf: bytes) -> ClientHello | None:
    b = _handshake(buf, 1)
    if b is None or len(b) < 38:
        return None
    try:
        ver = struct.unpack("!H", b[0:2])[0]
        i = 34
        i += 1 + b[i]  # session id
        cl = struct.unpack("!H", b[i:i + 2])[0]
        ciphers = [struct.unpack("!H", b[j:j + 2])[0] for j in range(i + 2, i + 2 + cl, 2)]
        i += 2 + cl
        i += 1 + b[i]  # compression methods
        ch = ClientHello(ver, ciphers, [])
        if i + 2 > len(b):
            return ch
        end = min(len(b), i + 2 + struct.unpack("!H", b[i:i + 2])[0])
        i += 2
        while i + 4 <= end:
            et, el = struct.unpack("!HH", b[i:i + 4])
            ed = b[i + 4:i + 4 + el]
            ch.extensions.append(et)
            if et == 0 and len(ed) >= 5 and ed[2] == 0:
                nl = struct.unpack("!H", ed[3:5])[0]
                ch.sni = ed[5:5 + nl].decode("ascii", "replace").lower() or None
            elif et == 16 and len(ed) >= 2:
                j = 2
                while j < len(ed):
                    ln = ed[j]
                    ch.alpn.append(ed[j + 1:j + 1 + ln].decode("latin-1"))
                    j += 1 + ln
            elif et == 43 and ed:
                ch.supported_versions = [struct.unpack("!H", ed[j:j + 2])[0] for j in range(1, 1 + ed[0] - 1, 2)]
            elif et == 13 and len(ed) >= 2:
                ch.sig_algs = [struct.unpack("!H", ed[j:j + 2])[0] for j in range(2, 2 + struct.unpack("!H", ed[:2])[0] - 1, 2)]
            elif et == 10 and len(ed) >= 2:
                ch.groups = [struct.unpack("!H", ed[j:j + 2])[0] for j in range(2, 2 + struct.unpack("!H", ed[:2])[0] - 1, 2)]
            elif et == 11 and ed:
                ch.point_formats = list(ed[1:1 + ed[0]])
            i += 4 + el
        return ch
    except (struct.error, IndexError):
        return None


def parse_server_hello(buf: bytes) -> ServerHello | None:
    b = _handshake(buf, 2)
    if b is None or len(b) < 38:
        return None
    try:
        ver = legacy = struct.unpack("!H", b[0:2])[0]
        exts: list[int] = []
        i = 34
        i += 1 + b[i]
        cipher = struct.unpack("!H", b[i:i + 2])[0]
        i += 3  # cipher + compression
        if i + 2 <= len(b):
            end = min(len(b), i + 2 + struct.unpack("!H", b[i:i + 2])[0])
            i += 2
            while i + 4 <= end:
                et, el = struct.unpack("!HH", b[i:i + 4])
                exts.append(et)
                if et == 43 and el == 2:
                    ver = struct.unpack("!H", b[i + 4:i + 6])[0]
                i += 4 + el
        return ServerHello(ver, cipher, legacy, exts)
    except (struct.error, IndexError):
        return None


def _h12(parts: list[str]) -> str:
    s = ",".join(parts)
    return hashlib.sha256(s.encode()).hexdigest()[:12] if s else "000000000000"


def ja4(ch: ClientHello, proto: str = "t") -> str:
    vers = [v for v in ch.supported_versions if not is_grease(v)]
    ver = VERSIONS.get(max(vers) if vers else ch.legacy_version, "00")
    ciphers = [c for c in ch.ciphers if not is_grease(c)]
    exts = [e for e in ch.extensions if not is_grease(e)]
    alpn = "00"
    if ch.alpn and ch.alpn[0]:
        a = ch.alpn[0]
        if a[0].isascii() and a[0].isalnum() and a[-1].isascii() and a[-1].isalnum():
            alpn = a[0] + a[-1]
        else:
            h = a.encode("latin-1").hex()
            alpn = h[0] + h[-1]
    a_part = f"{proto}{ver}{'d' if ch.sni else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}"
    b_part = _h12(sorted(f"{c:04x}" for c in ciphers))
    ext_sorted = sorted(f"{e:04x}" for e in exts if e not in (0x0000, 0x0010))
    c_src = ",".join(ext_sorted)
    if ch.sig_algs:
        c_src += "_" + ",".join(f"{s:04x}" for s in ch.sig_algs if not is_grease(s))
    c_part = hashlib.sha256(c_src.encode()).hexdigest()[:12] if ext_sorted else "000000000000"
    return f"{a_part}_{b_part}_{c_part}"


def ja3(ch: ClientHello) -> str:
    def j(xs: list[int]) -> str:
        return "-".join(str(x) for x in xs if not is_grease(x))
    s = f"{ch.legacy_version},{j(ch.ciphers)},{j(ch.extensions)},{j(ch.groups)},{j(ch.point_formats)}"
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


def ja3s(sh: ServerHello) -> str:
    s = f"{sh.legacy_version},{sh.cipher},{'-'.join(str(e) for e in sh.extensions)}"
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


def handshake_messages(buf: bytes, limit: int = 262144):
    """Clear-text handshake messages (type, body) from the TLS records at the start of one direction's stream."""
    hs = bytearray()
    i = 0
    while i + 5 <= len(buf) and len(hs) < limit:
        if buf[i] != 22:  # ChangeCipherSpec / application data: the rest is encrypted
            break
        rlen = struct.unpack("!H", buf[i + 3:i + 5])[0]
        hs += buf[i + 5:i + 5 + rlen]
        i += 5 + rlen
    j = 0
    while j + 4 <= len(hs):
        n = int.from_bytes(hs[j + 1:j + 4], "big")
        if j + 4 + n > len(hs):
            break
        yield hs[j], bytes(hs[j + 4:j + 4 + n])
        j += 4 + n


def parse_certificates(buf: bytes, max_certs: int = 10) -> list[bytes]:
    """DER certificates of the server's Certificate message (leaf first)."""
    for t, body in handshake_messages(buf):
        if t != 11 or len(body) < 3:
            continue
        end = min(len(body), 3 + int.from_bytes(body[0:3], "big"))
        out, k = [], 3
        while k + 3 <= end and len(out) < max_certs:
            n = int.from_bytes(body[k:k + 3], "big")
            if k + 3 + n > end:
                break
            out.append(body[k + 3:k + 3 + n])
            k += 3 + n
        return out
    return []


def cert_info(der: bytes) -> dict | None:
    """Fields an analyst checks on a server certificate. Description only: nothing is trusted or validated."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        from cryptography.x509.oid import NameOID

        c = x509.load_der_x509_certificate(der)

        def cn(name) -> str | None:
            a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return str(a[0].value)[:256] if a else None

        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []
        try:
            is_ca = bool(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        except x509.ExtensionNotFound:
            is_ca = False
        key = c.public_key()
        ktype, kbits = (("rsa", key.key_size) if isinstance(key, rsa.RSAPublicKey) else
                        ("ec", key.curve.key_size) if isinstance(key, ec.EllipticCurvePublicKey) else
                        ("dsa", key.key_size) if isinstance(key, dsa.DSAPublicKey) else (type(key).__name__, None))
        return {"subject": c.subject.rfc4514_string()[:512], "subject_cn": cn(c.subject),
                "issuer": c.issuer.rfc4514_string()[:512], "issuer_cn": cn(c.issuer),
                "san": [str(x)[:256] for x in san[:20]], "serial": format(c.serial_number, "x")[:64],
                "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                "self_signed": c.issuer == c.subject, "is_ca": is_ca, "key_type": ktype, "key_bits": kbits,
                "sig_hash": c.signature_hash_algorithm.name if c.signature_hash_algorithm else None,
                "sha1": c.fingerprint(hashes.SHA1()).hex(), "sha256": c.fingerprint(hashes.SHA256()).hex()}
    except Exception:  # noqa: BLE001 - hostile or garbled DER must never break the analysis
        return None


def name_matches(host: str, cert: dict) -> bool:
    """Does the TLS server name match the certificate (SAN DNS names, else CN; one-label wildcards)?"""
    host = host.lower().rstrip(".")
    names = [n.lower() for n in (cert.get("san") or [])] or ([cert["subject_cn"].lower()] if cert.get("subject_cn") else [])
    for n in names:
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False
