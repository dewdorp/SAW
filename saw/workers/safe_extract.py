"""Safe decompression (docs/10 §5): streaming byte counters, ratio/total/entry/depth limits, no links, no paths.

Output files are written under keys chosen by the caller; archive member names are only kept as display names.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from saw.core.security.sanitize import is_safe_member_path, sanitize_filename

CHUNK = 1024 * 1024


class ExtractionError(Exception):
    pass


@dataclass
class Limits:
    max_ratio: int = 200
    max_total: int = 500 * 1024**3
    max_entries: int = 10_000
    max_depth: int = 3


@dataclass
class Extracted:
    display_name: str
    path: Path  # local temp file
    size: int
    depth: int


def sniff(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(512)
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if head[:8] == b"ElfFile\x00":
        return "evtx"
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
        return "executable"
    if b"\x00" in head[:512] and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "binary"
    return "text"


class _Counter:
    def __init__(self, compressed_size: int, limits: Limits, state: dict):
        self.compressed = max(1, compressed_size)
        self.limits = limits
        self.state = state

    def add(self, n: int, written: int) -> None:
        self.state["total"] += n
        if self.state["total"] > self.limits.max_total:
            raise ExtractionError("total decompressed size limit exceeded")
        if written > 10 * CHUNK and written / self.compressed > self.limits.max_ratio:
            raise ExtractionError(f"Possible archive bomb (ratio 1:{written // self.compressed})")


def _copy(src: BinaryIO, dst: Path, counter: _Counter) -> int:
    written = 0
    with open(dst, "wb") as out:
        while True:
            b = src.read(CHUNK)
            if not b:
                break
            written += len(b)
            counter.add(len(b), written)
            out.write(b)
    return written


def extract(path: Path, display_name: str, workdir: Path, limits: Limits | None = None,
            new_name: Callable[[], str] | None = None) -> Iterator[Extracted]:
    """Yields leaf (non-archive) files. Raises ExtractionError on limit violations."""
    limits = limits or Limits()
    state = {"total": 0, "entries": 0}
    seq = [0]

    def nm() -> str:
        seq[0] += 1
        return new_name() if new_name else f"x{seq[0]:06d}"

    def walk(p: Path, disp: str, depth: int) -> Iterator[Extracted]:
        kind = sniff(p)
        if kind not in ("gzip", "zip", "bzip2", "xz", "tar"):
            yield Extracted(disp, p, p.stat().st_size, depth)
            return
        if depth >= limits.max_depth:
            raise ExtractionError(f"nesting depth > {limits.max_depth}")
        csize = p.stat().st_size
        if kind in ("gzip", "bzip2", "xz"):
            opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
            out = workdir / nm()
            try:
                with opener(p, "rb") as src:
                    _copy(src, out, _Counter(csize, limits, state))
            except (OSError, EOFError, lzma.LZMAError) as e:
                raise ExtractionError(f"corrupt {kind}: {e}") from None
            inner = disp[: -len(Path(disp).suffix)] if Path(disp).suffix.lower() in (".gz", ".bz2", ".xz", ".tgz") else disp
            if disp.lower().endswith(".tgz"):
                inner = disp[:-4] + ".tar"
            yield from walk(out, inner, depth + 1)
            return
        if kind == "zip":
            try:
                zf = zipfile.ZipFile(p)
            except zipfile.BadZipFile as e:
                raise ExtractionError(f"corrupt zip: {e}") from None
            with zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    state["entries"] += 1
                    if state["entries"] > limits.max_entries:
                        raise ExtractionError("too many archive entries")
                    if not is_safe_member_path(info.filename):
                        continue  # zip slip / absolute paths are skipped (recorded by caller via names)
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        continue  # symlink
                    if info.flag_bits & 0x1:
                        raise ExtractionError("encrypted zip requires password (not supported in this step)")
                    out = workdir / nm()
                    with zf.open(info) as src:
                        _copy(src, out, _Counter(max(1, info.compress_size), limits, state))
                    yield from walk(out, f"{disp}:{sanitize_filename(info.filename.replace('/', '_'))}", depth + 1)
            return
        if kind == "tar":
            try:
                tf = tarfile.open(p, "r:*")
            except tarfile.TarError as e:
                raise ExtractionError(f"corrupt tar: {e}") from None
            with tf:
                for m in tf:
                    if not m.isfile():
                        continue  # dirs, symlinks, hardlinks, devices
                    state["entries"] += 1
                    if state["entries"] > limits.max_entries:
                        raise ExtractionError("too many archive entries")
                    if not is_safe_member_path(m.name):
                        continue
                    src = tf.extractfile(m)
                    if src is None:
                        continue
                    out = workdir / nm()
                    _copy(src, out, _Counter(max(1, csize), limits, state))
                    yield from walk(out, f"{disp}:{sanitize_filename(m.name.replace('/', '_'))}", depth + 1)

    yield from walk(path, display_name, 0)
