"""Parameter Analyzer (docs/19 §5): per (uri_template, param) value profile, incl. sequential ratio."""
from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict

from saw.core.schemas.query import Filter
from saw.storage.eventstore import EventStorePort

MAX_VALUES = 200_000


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _type_of(values: list[str]) -> str:
    sample = values[:500]
    if not sample:
        return "empty"
    def frac(rx):
        return sum(1 for v in sample if rx.fullmatch(v)) / len(sample)
    if frac(re.compile(r"-?\d+")) > 0.95:
        return "numeric"
    if frac(re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) > 0.95:
        return "uuid"
    if frac(re.compile(r"[0-9a-fA-F]{16,}")) > 0.95:
        return "hex"
    if frac(re.compile(r"[^@\s]+@[^@\s]+")) > 0.95:
        return "email"
    if len(set(sample)) <= 20:
        return "enum"
    if frac(re.compile(r"[A-Za-z0-9+/_=-]{20,}")) > 0.9:
        return "token"
    return "free-text"


def profile_values(rows: list[tuple[str | None, str | None, str]]) -> dict:
    """rows: (timestamp, actor_key, value) in time order.

    Logs usually have 1-second resolution, so events inside the same second have no reliable order:
    ties are ordered by numeric value (otherwise storage order would randomly break sequences).
    """
    def _tie(r):
        v = r[2]
        return (r[0] or "", int(v) if re.fullmatch(r"-?\d{1,18}", v) else 0)

    rows = sorted(rows, key=_tie)
    values = [v for _, _, v in rows]
    vtype = _type_of(values)
    uniq = len(set(values))
    prof: dict = {"type": vtype, "count": len(values), "unique": uniq,
                  "sampled": len(values) >= MAX_VALUES}
    lengths = sorted(len(v) for v in values) or [0]
    prof["length"] = {"min": lengths[0], "p50": lengths[len(lengths) // 2], "p95": lengths[int(len(lengths) * .95)],
                      "max": lengths[-1]}
    prof["entropy_avg"] = round(statistics.fmean(_entropy(v) for v in values[:5000]), 2) if values else 0
    if vtype == "numeric":
        nums = [int(v) for v in values if re.fullmatch(r"-?\d+", v)]
        if nums:
            lo, hi = min(nums), max(nums)
            prof["numeric_range"] = {"min": lo, "max": hi,
                                     "coverage": round(len(set(nums)) / max(1, hi - lo + 1), 3)}
        by_actor: dict[str, list[int]] = defaultdict(list)
        for _, actor, v in rows:
            if re.fullmatch(r"-?\d+", v):
                by_actor[actor or "-"].append(int(v))
        deltas: list[int] = []
        for seq in by_actor.values():
            deltas += [b - a for a, b in zip(seq, seq[1:], strict=False)]
        # global time-ordered sequence also counts (distributed enumeration across many IPs)
        gl = [int(v) for v in values if re.fullmatch(r"-?\d+", v)]
        g_deltas = [b - a for a, b in zip(gl, gl[1:], strict=False)]
        def seq_ratio(ds):
            if not ds:
                return 0.0
            mode, _ = Counter(ds).most_common(1)[0]
            return sum(1 for d in ds if d == mode and 0 < abs(d) <= 2) / len(ds)
        r_actor, r_global = seq_ratio(deltas), seq_ratio(g_deltas)
        best = deltas if r_actor >= r_global else g_deltas
        prof["sequential_ratio"] = round(max(r_actor, r_global), 4)
        prof["sequential_basis"] = "per_source" if r_actor >= r_global else "global_time_order"
        prof["increment"] = (f"{Counter(best).most_common(1)[0][0]:+d}" if best else None)
        prof["step_sample"] = gl[:: max(1, len(gl) // 200)][:200]
    pref = _common_affix([v for v in values[:2000]], prefix=True)
    suf = _common_affix([v for v in values[:2000]], prefix=False)
    if pref:
        prof["common_prefix"] = pref
    if suf:
        prof["common_suffix"] = suf
    fam = Counter()
    from saw.analyzers.patterns import pattern_tags

    for v in set(values[:20000]):
        if any(c in v for c in "'\"<>;|`$%{}()") or ".." in v:
            for t in pattern_tags(v):
                fam[t] += 1
    if fam:
        prof["payload_families"] = dict(fam)
    prof["samples"] = list(dict.fromkeys(values))[:10]
    prof["potential_behavior"] = ("Sequential Enumeration" if prof.get("sequential_ratio", 0) >= 0.8
                                  and uniq >= 100 else None)
    return prof


def _common_affix(vals: list[str], prefix: bool) -> str | None:
    if len(vals) < 5:
        return None
    s = vals if prefix else [v[::-1] for v in vals]
    p = s[0]
    for v in s[1:]:
        while not v.startswith(p) and p:
            p = p[:-1]
        if not p:
            return None
    if len(p) < 2:
        return None
    return p if prefix else p[::-1]


def collect(events: EventStorePort, inv: str, uri_template: str, param: str,
            extra: list[Filter] | None = None) -> list[tuple[str | None, str | None, str]]:
    return collect_many(events, inv, uri_template, [param], extra)[param]


def collect_many(events: EventStorePort, inv: str, uri_template: str, params: list[str],
                 extra: list[Filter] | None = None) -> dict[str, list[tuple[str | None, str | None, str]]]:
    """All parameters of one template in a single pass (one scan per template, not per parameter)."""
    rows: dict[str, list[tuple[str | None, str | None, str]]] = {p: [] for p in params}
    open_ = set(params)
    for e in events.iterate(inv, [Filter(field="uri_template", value=uri_template)] + (extra or []),
                            fields=["timestamp", "src_ip", "params"]):
        ps = e.get("params") or {}
        for p in list(open_):
            v = ps.get(p)
            if v is not None:
                rows[p].append((e.get("timestamp"), e.get("src_ip"), str(v)))
                if len(rows[p]) >= MAX_VALUES:
                    open_.discard(p)
        if not open_:
            break
    return rows
