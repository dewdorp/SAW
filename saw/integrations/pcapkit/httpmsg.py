"""HTTP/1.x request/response extraction from reassembled TCP streams, including bodies.

Bodies: Content-Length, chunked transfer coding, read-until-close; Content-Encoding gzip/deflate is decoded
with an output cap and ratio limit (decompression bombs). multipart/form-data parts with filenames are exposed
as uploads. HEAD / 1xx / 204 / 304 responses carry no body. Everything here is untrusted input.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field

METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ", b"PROPFIND ",
           b"MOVE ", b"COPY ", b"MKCOL ")
REQ_LINE = re.compile(rb"^([A-Z]{3,10}) (\S{1,8192}) HTTP/(\d\.\d)\r?$")
RESP_LINE = re.compile(rb"^HTTP/(\d\.\d) (\d{3})(?: ([^\r\n]{0,200}))?\r?$")
MAX_HEADERS = 16 * 1024
MAX_BODY = 64 * 1024 * 1024
MAX_DECODED = 64 * 1024 * 1024
MAX_RATIO = 200
_FNAME = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', re.IGNORECASE)


@dataclass
class Upload:
    field: str
    filename: str | None
    content_type: str | None
    data: bytes


@dataclass
class Req:
    method: str
    uri: str
    version: str
    headers: dict[str, str]
    body: bytes = b""
    body_len: int = 0
    offset: int = 0
    uploads: list[Upload] = field(default_factory=list)

    @property
    def host(self) -> str | None:
        return self.headers.get("host")

    @property
    def user_agent(self) -> str | None:
        return self.headers.get("user-agent")

    @property
    def referrer(self) -> str | None:
        return self.headers.get("referer")


@dataclass
class Resp:
    status: int
    msg: str
    headers: dict[str, str]
    body: bytes = b""            # decoded (dechunked + decompressed), possibly truncated
    body_len: int = 0            # bytes on the wire
    offset: int = 0
    complete: bool = True
    decode_note: str = ""

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")

    @property
    def filename(self) -> str | None:
        m = _FNAME.search(self.headers.get("content-disposition", ""))
        return m.group(1).strip() if m else None


def looks_like_http_request(p: bytes) -> bool:
    return p.startswith(METHODS)


def _headers(block: bytes) -> dict[str, str]:
    h: dict[str, str] = {}
    for ln in block.split(b"\n")[1:]:
        k, sep, v = ln.partition(b":")
        if sep:
            key = k.strip().lower().decode("latin-1")
            val = v.strip().decode("latin-1")[:4096]
            h[key] = f"{h[key]}, {val}" if key in h and key != "set-cookie" else val
    return h


def _dechunk(buf: bytes, i: int) -> tuple[bytes, int, bool]:
    out = bytearray()
    while i < len(buf) and len(out) <= MAX_BODY:
        end = buf.find(b"\r\n", i, i + 64)
        if end < 0:
            return bytes(out), len(buf), False
        size_s = buf[i:end].split(b";")[0].strip()
        try:
            size = int(size_s, 16)
        except ValueError:
            return bytes(out), end, False
        i = end + 2
        if size == 0:
            trailer_end = buf.find(b"\r\n\r\n", i - 2)
            return bytes(out), (trailer_end + 4 if trailer_end >= 0 else min(len(buf), i + 2)), True
        out += buf[i:i + size]
        i += size + 2
    return bytes(out), min(i, len(buf)), False


def _decode(body: bytes, encoding: str) -> tuple[bytes, str]:
    enc = encoding.lower().strip()
    if enc not in ("gzip", "x-gzip", "deflate"):
        return body, ("unsupported content-encoding " + enc) if enc and enc != "identity" else ""
    try:
        wbits = 16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(body, MAX_DECODED)
        except zlib.error:
            d = zlib.decompressobj(-zlib.MAX_WBITS)  # raw deflate (common server bug)
            out = d.decompress(body, MAX_DECODED)
        if body and len(out) / max(1, len(body)) > MAX_RATIO:
            return out[: len(body) * MAX_RATIO], "decompression ratio limit"
        if d.unconsumed_tail:
            return out, "decoded output capped"
        return out, "" if d.eof else "compressed body is cut off: decoded only up to the missing part"
    except zlib.error as e:
        return body, f"content-encoding decode failed: {e}"


def _multipart(body: bytes, ctype: str) -> list[Upload]:
    m = re.search(r'boundary="?([^";]+)"?', ctype, re.IGNORECASE)
    if not m:
        return []
    boundary = b"--" + m.group(1).encode("latin-1")
    out = []
    for part in body.split(boundary)[1:]:
        if part.startswith(b"--"):
            break
        head, sep, data = part.lstrip(b"\r\n").partition(b"\r\n\r\n")
        if not sep:
            continue
        hd = _headers(b"x\n" + head)
        disp = hd.get("content-disposition", "")
        fn = _FNAME.search(disp)
        name = re.search(r'\bname="?([^";]+)"?', disp, re.IGNORECASE)
        out.append(Upload(name.group(1) if name else "", fn.group(1).strip() if fn else None, hd.get("content-type"),
                          data[:-2] if data.endswith(b"\r\n") else data))
        if len(out) >= 50:
            break
    return out


def _head(stream: bytes, i: int, first: re.Pattern[bytes]):
    end = stream.find(b"\r\n\r\n", i, i + MAX_HEADERS)
    sep = 4
    if end < 0:
        end, sep = stream.find(b"\n\n", i, i + MAX_HEADERS), 2
    if end < 0:
        return None
    block = stream[i:end]
    m = first.match(block.split(b"\n", 1)[0])
    if not m:
        return None
    return m, _headers(block), end + sep


def requests(stream: bytes, limit: int = 1000) -> list[Req]:
    out, i = [], 0
    while i < len(stream) and len(out) < limit:
        h = _head(stream, i, REQ_LINE)
        if h is None:
            break
        m, hd, j = h
        cl = hd.get("content-length", "")
        if hd.get("transfer-encoding", "").lower().startswith("chunked"):
            body, nxt, _ = _dechunk(stream, j)
        else:
            n = int(cl) if cl.isdigit() else 0
            body, nxt = stream[j:j + min(n, MAX_BODY)], j + n
        r = Req(m.group(1).decode(), m.group(2).decode("latin-1"), m.group(3).decode(), hd, body, len(body), i)
        if "multipart/form-data" in hd.get("content-type", "").lower():
            r.uploads = _multipart(body, hd["content-type"])
        elif r.method == "PUT" and body:
            r.uploads = [Upload("", r.uri.split("?")[0].rsplit("/", 1)[-1] or None, hd.get("content-type"), body)]
        out.append(r)
        i = nxt
    return out


def responses(stream: bytes, methods: list[str] | None = None, limit: int = 1000) -> list[Resp]:
    out, i, k = [], 0, 0
    methods = methods or []
    while i < len(stream) and len(out) < limit:
        h = _head(stream, i, RESP_LINE)
        if h is None:
            break
        m, hd, j = h
        status = int(m.group(2))
        if 100 <= status < 200:  # interim (100 Continue): no body, not a final response
            i = j
            continue
        method = methods[k] if k < len(methods) else "GET"
        complete, note = True, ""
        if method == "HEAD" or status in (204, 304):
            raw, nxt = b"", j
        elif hd.get("transfer-encoding", "").lower().startswith("chunked"):
            raw, nxt, complete = _dechunk(stream, j)
        elif hd.get("content-length", "").isdigit():
            n = int(hd["content-length"])
            raw, nxt = stream[j:j + min(n, MAX_BODY)], j + n
            complete = len(raw) >= min(n, MAX_BODY)
        else:  # read until connection close
            raw, nxt = stream[j:j + MAX_BODY], len(stream)
        body = raw
        if hd.get("content-encoding"):
            body, note = _decode(raw, hd["content-encoding"])
        out.append(Resp(status, (m.group(3) or b"").decode("latin-1"), hd, body, len(raw), i, complete, note))
        i, k = nxt, k + 1
    return out
