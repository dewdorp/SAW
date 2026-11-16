"""Parser plugin framework (docs/19 §2). Unknown fields are kept in ext.<product>.*; raw is always kept."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

RAW_MAX = 32 * 1024
LINE_MAX = 1024 * 1024


@dataclass
class RawLine:
    text: str
    offset: int
    line_no: int
    length: int = -1  # bytes in the source file (encoding-aware); -1 = len(text as UTF-8)


@dataclass
class Parsed:
    fields: dict[str, Any]
    ext: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None  # stored raw_event replacing the line (the original file is kept)
    redact: bool = False  # line carries secrets (cookies): mask it whenever it is stored or shown
    observation: dict[str, str] = field(init=False)

    def __post_init__(self):
        from saw.behavior.observation import observe_fields

        self.observation = observe_fields(self.fields)


@dataclass
class Failed:
    reason: str


@dataclass
class Skip:
    """Header/comment line: neither an event nor a failure."""


ParseResult = Parsed | Failed | Skip


def unique_names(names: list[str]) -> tuple[list[str], list[str]]:
    """Column names made unique (status, status_2, ...) so that no column silently replaces another one.

    Returns (names, the names that occurred more than once).
    """
    seen: dict[str, int] = {}
    out, repeated = [], []
    for n in names:
        k = n.lower()
        seen[k] = seen.get(k, 0) + 1
        if seen[k] == 1:
            out.append(n)
            continue
        if n not in repeated:
            repeated.append(n)
        alt = f"{n}_{seen[k]}"
        while alt.lower() in seen:
            seen[k] += 1
            alt = f"{n}_{seen[k]}"
        seen[alt.lower()] = 1
        out.append(alt)
    return out, repeated


class LogParser(Protocol):
    id: str
    version: str
    data_source: str
    product: str
    event_type: str

    def detect(self, sample: list[str]) -> float: ...
    def parse_line(self, line: str) -> ParseResult: ...


class BaseParser:
    id = "base"
    version = "1.0.0"
    data_source = "custom"
    product = "unknown"
    event_type = "log"
    stateful = False  # e.g. IIS / CSV need header lines
    warnings: list[str] = []  # things the analyst should know about this file (set per file by reset()/parse)

    def detect(self, sample: list[str]) -> float:
        lines = [s for s in sample if s.strip() and not s.startswith("#")]
        if not lines:
            return 0.0
        ok = sum(1 for s in lines if isinstance(self.parse_line(s), Parsed))
        return ok / len(lines)

    def parse_line(self, line: str) -> ParseResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def reset(self) -> None:
        """Reset per-file state (stateful parsers)."""

    def safe_parse_line(self, line: str) -> ParseResult:
        """One malformed record fails alone, with its reason; the records around it keep parsing."""
        try:
            return self.parse_line(line)
        except (ValueError, TypeError, OverflowError, ArithmeticError, KeyError, IndexError, UnicodeError) as exc:
            return Failed(f"이 행을 해석하지 못했습니다({type(exc).__name__}): {str(exc)[:200]}")

    def parse(self, lines: Iterator[RawLine]) -> Iterator[tuple[RawLine, ParseResult]]:
        self.reset()
        for rl in lines:
            if len(rl.text) > LINE_MAX:
                yield rl, Failed("line exceeds 1 MB limit")
                continue
            yield rl, self.safe_parse_line(rl.text)
