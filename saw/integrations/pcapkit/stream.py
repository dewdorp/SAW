"""One direction of a TCP connection, reassembled in sequence order (bounded).

Handles out-of-order arrival, retransmissions/overlaps (first copy wins, as most IDS stream policies do),
sequence wrap-around and gaps: missing ranges are counted as missed bytes and recorded as gap offsets, and data
after a gap is still kept so later headers can be parsed. Stored bytes per direction are capped; the rest is
only counted. Offsets are relative to the first byte after the SYN (or the first byte seen mid-stream).
"""
from __future__ import annotations

import bisect

MAX_PENDING_SEGMENTS = 512
MAX_PENDING_BYTES = 2 * 1024 * 1024


class Stream:
    __slots__ = (
        "_read_pos",
        "base",
        "cap",
        "data",
        "gaps",
        "missed",
        "next_rel",
        "pending",
        "pending_bytes",
        "seg_ts",
        "truncated",
    )

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.data = bytearray()
        self.base: int | None = None           # absolute sequence number of relative offset 0
        self.next_rel = 0                      # next expected relative offset
        self.pending: dict[int, tuple[bytes, int, float]] = {}  # rel -> (captured, wire_len, ts)
        self.pending_bytes = 0
        self.missed = 0                        # bytes never captured (gaps, snaplen truncation)
        self.truncated = 0                     # captured bytes not stored (cap)
        self.seg_ts: list[tuple[int, float]] = []  # (offset in data, timestamp)
        self.gaps: list[int] = []              # offsets in data where bytes are missing
        self._read_pos = 0

    def syn(self, seq: int) -> None:
        if self.base is None:
            self.base = (seq + 1) & 0xFFFFFFFF

    def add(self, seq: int, payload: bytes, ts: float, wire_len: int | None = None) -> None:
        n = wire_len if wire_len is not None else len(payload)
        if n <= 0:
            return
        if self.base is None:  # mid-stream capture
            self.base = seq & 0xFFFFFFFF
        rel = (seq - self.base) & 0xFFFFFFFF
        if rel > 0x7FFFFFFF:  # older than the stream start
            return
        if rel < self.next_rel:  # overlap / retransmission: first copy wins
            skip = self.next_rel - rel
            if skip >= n:
                return
            payload, n, rel = payload[skip:], n - skip, self.next_rel
        if rel == self.next_rel:
            self._append(payload, n, ts)
            self._drain()
            return
        if rel not in self.pending and len(self.pending) < MAX_PENDING_SEGMENTS:
            self.pending[rel] = (payload, n, ts)
            self.pending_bytes += len(payload)
        if len(self.pending) >= MAX_PENDING_SEGMENTS or self.pending_bytes > MAX_PENDING_BYTES:
            self.flush_gaps()

    def _append(self, payload: bytes, n: int, ts: float) -> None:
        room = self.cap - len(self.data)
        if room > 0 and payload:
            if len(self.seg_ts) < 8192:
                self.seg_ts.append((len(self.data), ts))
            self.data += payload[:room]
        self.truncated += max(0, len(payload) - max(room, 0))
        if n > len(payload):  # snaplen-truncated segment: the tail is missing
            self.missed += n - len(payload)
            if len(self.data) < self.cap:
                self.gaps.append(len(self.data))
        self.next_rel += n

    def _drain(self) -> None:
        while self.pending:
            k = min(self.pending)
            if k > self.next_rel:
                return
            payload, n, ts = self.pending.pop(k)
            self.pending_bytes -= len(payload)
            if k + n > self.next_rel:
                skip = self.next_rel - k
                self._append(payload[skip:], n - skip, ts)

    def flush_gaps(self) -> None:
        """Bridge remaining holes (end of connection or buffer pressure): count them and continue."""
        while self.pending:
            k = min(self.pending)
            if k > self.next_rel:
                self.missed += k - self.next_rel
                if len(self.data) < self.cap:
                    self.gaps.append(len(self.data))
                self.next_rel = k
            self._drain()

    def new_data(self) -> bytes:
        """Bytes stored since the previous call (incremental parsers such as the FTP control channel)."""
        out = bytes(self.data[self._read_pos:])
        self._read_pos = len(self.data)
        return out

    def ts_at(self, offset: int, default: float) -> float:
        i = bisect.bisect_right(self.seg_ts, (offset, float("inf"))) - 1
        return self.seg_ts[i][1] if i >= 0 else default

    def has_gap_in(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self.gaps, start)
        return i < len(self.gaps) and self.gaps[i] < end

    def lines(self, default_ts: float, limit: int = 5000) -> list[tuple[float, str]]:
        """Text lines (CRLF or LF) with the timestamp of the segment that carried each line."""
        out, start, buf = [], 0, bytes(self.data)
        while start < len(buf) and len(out) < limit:
            end = buf.find(b"\n", start)
            if end < 0:
                end = len(buf)
            out.append((self.ts_at(start, default_ts), buf[start:end].rstrip(b"\r").decode("latin-1")))
            start = end + 1
        return out
