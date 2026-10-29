"""Signature packs: detection content kept as data (saw/detectors/packs/*.yaml), not as code.

A signature recognises a known trace in one request - an attack tool's name, the path of a published vulnerability,
a web shell file name, an operating-system command in a parameter. Matching happens once, when the event is
normalised (`sig_tags` adds "sig:<id>" tags); the detector then only counts tags, so hundreds of signatures cost no
more at analysis time than one. Behaviour that needs counting or ordering stays in the code detectors.

Why data: the platform runs in a closed network. New content has to be addable there by editing a list, and every
rule carries examples that the test-suite replays, so a typo in a rule is caught before it ships.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from saw.core.schemas.query import AggRequest, Filter
from saw.detectors.base import AttackMap, DetectorContext, FindingDraft, check, metric

PACK_DIR = Path(__file__).parent / "packs"
FIELDS = ("ua", "path", "query", "uri", "referer", "upload", "any")
SUCCESS_MODES = ("matters", "ignore", "only")
TAG = "sig:"
ADVICE = "\n\n### 확인·대응 권고 (분석가 판단 후 수행)\n"


class PackError(ValueError):
    pass


@dataclass(frozen=True)
class Signature:
    id: str
    title: str
    group: str
    group_title: str
    stage: str
    severity: float
    confidence: str
    attack: tuple[str, ...]
    success: str
    where: str
    explain: str
    checks: tuple[str, ...]
    cve: str = ""
    needles: tuple[str, ...] = ()
    all_needles: tuple[str, ...] = ()
    regex: str = ""
    regex_not: str = ""
    methods: tuple[str, ...] = ()
    raw: bool = False       # compare with the request as written (lower-cased only), not URL-decoded
    raw_also: bool = False  # compare with both forms
    examples: tuple[Any, ...] = ()
    benign: tuple[Any, ...] = ()
    rx: re.Pattern | None = field(default=None, compare=False, repr=False)
    rx_not: re.Pattern | None = field(default=None, compare=False, repr=False)

    @property
    def tag(self) -> str:
        return TAG + self.id

    def hits(self, text: str) -> bool:
        if not text:
            return False
        if self.all_needles and not all(n in text for n in self.all_needles):
            return False
        found = bool(self.all_needles) and not self.needles and self.rx is None
        found = found or any(n in text for n in self.needles) or (self.rx is not None and self.rx.search(text) is not None)
        return found and not (self.rx_not is not None and self.rx_not.search(text))


def _compile(sid: str, src: str) -> re.Pattern:
    try:
        return re.compile(src)
    except re.error as e:
        raise PackError(f"{sid}: bad regex ({e})") from None


def _load_file(path: Path) -> list[Signature]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for g in doc.get("groups") or []:
        gid = g["id"]
        for r in g.get("rules") or []:
            sid = f"{gid}.{r['id']}"
            where = r.get("where", g.get("where", "uri"))
            success = r.get("success", g.get("success", "matters"))
            if where not in FIELDS:
                raise PackError(f"{sid}: where must be one of {FIELDS}")
            if success not in SUCCESS_MODES:
                raise PackError(f"{sid}: success must be one of {SUCCESS_MODES}")
            if not (r.get("match") or r.get("all") or r.get("regex")):
                raise PackError(f"{sid}: needs match, all or regex")
            needles = tuple(str(x) for x in r.get("match") or ())
            if any(n != n.lower() for n in (*needles, *(r.get("all") or ()))):
                raise PackError(f"{sid}: match/all values must be lower case (requests are lower-cased before comparing)")
            out.append(Signature(
                id=sid, title=str(r["title"]), group=gid, group_title=str(g["title"]), stage=str(r.get("stage", g["stage"])),
                severity=float(r.get("severity", g["severity"])), confidence=str(r.get("confidence", g.get("confidence", "medium"))),
                attack=tuple(r.get("attack", g.get("attack") or ())), success=success, where=where,
                explain=str(r.get("explain", g.get("explain", ""))), checks=tuple(r.get("checks", g.get("checks") or ())),
                cve=str(r.get("cve", "")), needles=needles, all_needles=tuple(str(x) for x in r.get("all") or ()),
                regex=str(r.get("regex", "")), regex_not=str(r.get("regex_not", "")),
                methods=tuple(str(m).upper() for m in r.get("method") or ()), raw=bool(r.get("raw")),
                raw_also=bool(r.get("raw_also")), examples=tuple(r.get("examples") or ()), benign=tuple(r.get("benign") or ()),
                rx=_compile(sid, r["regex"]) if r.get("regex") else None,
                rx_not=_compile(sid, r["regex_not"]) if r.get("regex_not") else None))
    return out


@lru_cache(maxsize=1)
def load_pack() -> tuple[Signature, ...]:
    sigs: list[Signature] = []
    for p in sorted(PACK_DIR.glob("*_signatures.yaml")):
        sigs += _load_file(p)
    ids = [s.id for s in sigs]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise PackError(f"duplicate signature ids: {sorted(dup)}")
    return tuple(sigs)


@lru_cache(maxsize=1)
def by_id() -> dict[str, Signature]:
    return {s.id: s for s in load_pack()}


@lru_cache(maxsize=1)
def _by_field() -> dict[str, tuple[Signature, ...]]:
    out: dict[str, list[Signature]] = {f: [] for f in FIELDS}
    for s in load_pack():
        out[s.where].append(s)
    return {k: tuple(v) for k, v in out.items()}


# ---------------------------------------------------------------- gate: is this request worth a closer look?
# Almost every request matches no signature. Running a few hundred patterns over each of them is what makes
# signature matching slow, so each signature states which plain word it cannot match without ("sqlmap", "jndi",
# "phpunit", ...). All those words go into one prefix-factored expression that is searched once per request; only a
# hit leads to the real patterns. The words are derived from the rule itself (see _required), never typed by hand,
# so a rule cannot be "optimised" into missing things. Rules made only of symbols have no such word and are always
# checked.
def _required(src: str) -> set[str] | None:
    """Plain lower-case words (3+ letters/digits) of which at least one occurs in every text the pattern matches,
    or None when that cannot be guaranteed."""
    import re._parser as sre  # the standard library's own regex parser

    def runs(items) -> set[str] | None:
        best: set[str] | None = None
        cur = ""

        def close() -> None:
            nonlocal best, cur
            if len(cur) >= 3 and (best is None or len(cur) > max(map(len, best))):
                best = {cur}
            cur = ""

        for op, arg in items:
            name = str(op)
            if name == "LITERAL" and (chr(arg).isalnum() or chr(arg) in "_-"):
                cur += chr(arg).lower()
                continue
            close()
            got = None
            if name == "SUBPATTERN":
                got = runs(arg[3])
            elif name == "BRANCH":
                parts = [runs(x) for x in arg[1]]
                got = None if any(x is None for x in parts) else set().union(*parts)
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT") and arg[0] >= 1:
                got = runs(arg[2])
            elif name == "ATOMIC_GROUP":
                got = runs(arg)
            if got is not None and (best is None or min(map(len, got)) > min(map(len, best))):
                best = got
        close()
        return best

    try:
        return runs(sre.parse(src))
    except Exception:  # noqa: BLE001 - an expression the parser cannot analyse is simply always checked
        return None


def _gate_words(s: Signature) -> set[str] | None:
    if s.methods:
        return None
    if s.rx is not None and (s.rx.flags != re.UNICODE or re.search(r"\(\?[aiLmsux-]+:", s.regex)):
        return None  # scoped/global flags can match text without the literal word (notably Unicode casefolding)
    parts: list[set[str] | None] = [_required(re.escape(n)) for n in s.needles]
    if s.regex:
        parts.append(_required(s.regex))
    if s.all_needles and not s.needles and not s.regex:
        parts.append(_required(re.escape(s.all_needles[0])))
    if not parts or any(x is None for x in parts):
        return None
    return set().union(*parts)


def _trie_regex(words: set[str]) -> str:
    trie: dict = {}
    for w in sorted(words):
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def emit(node: dict) -> str:
        if "" in node:  # a word ends here: nothing longer needs to be read to know the gate is open
            return ""
        alts = [re.escape(ch) + emit(sub) for ch, sub in sorted(node.items())]
        return alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"

    return emit(trie)


@lru_cache(maxsize=1)
def _gate() -> tuple[re.Pattern | None, dict[str, tuple[Signature, ...]], tuple[Signature, ...]]:
    """(expression that reports the gate words present, word -> signatures that need a word starting with it,
    signatures without a gate word that are checked for every request)."""
    need: dict[str, list[Signature]] = {}
    always: list[Signature] = []
    for s in load_pack():
        w = _gate_words(s)
        if w is None:
            if not s.methods:
                always.append(s)
        else:
            for x in w:
                need.setdefault(x, []).append(s)
    if not need:
        return None, {}, tuple(always)
    # the expression stops at the shortest word of a family ("app" for "appscan"): map it to the whole family
    tops = [w for w in need if not any(w != o and w.startswith(o) for o in need)]
    family = {top: tuple({s.id: s for w, sigs in need.items() if w.startswith(top) for s in sigs}.values()) for top in tops}
    return re.compile("(?=(" + _trie_regex(set(need)) + "))"), family, tuple(always)


@lru_cache(maxsize=1)
def _always_prefilter() -> dict[str, re.Pattern | None]:
    """The signatures without a gate word, combined per field: one search tells whether any of them needs a look."""
    out: dict[str, list[str]] = {f: [] for f in FIELDS}
    for s in _gate()[2]:
        parts = [re.escape(n) for n in s.needles]
        if s.rx is not None:
            # Combining captures changes numeric backreferences, can collide named groups, and moves global
            # flags away from the expression start. Such rules bypass the prefilter and keep their own regex.
            parts.append("" if s.rx.groups or s.rx.flags != re.UNICODE else f"(?:{s.regex})")
        if s.all_needles and not s.needles and s.rx is None:
            parts.append(re.escape(s.all_needles[0]))  # one required symbol is sufficient to open the gate
        out[s.where] += parts
    return {f: (re.compile("|".join(parts)) if parts else None) for f, parts in out.items()}


@lru_cache(maxsize=1)
def _by_method() -> dict[str, tuple[Signature, ...]]:
    out: dict[str, list[Signature]] = {}
    for s in load_pack():
        for m in s.methods:
            out.setdefault(m, []).append(s)
    return {k: tuple(v) for k, v in out.items()}


def _decode(v: str) -> str:
    return urllib.parse.unquote(urllib.parse.unquote(v)).lower() if "%" in v else v.lower()


def _ext_values(ev: dict, names: tuple[str, ...]) -> str:
    out = []
    for prod in (ev.get("ext") or {}).values():
        if isinstance(prod, dict):
            for n in names:
                v = prod.get(n)
                if isinstance(v, list):
                    out += [str(x) for x in v if x]
                elif v:
                    out.append(str(v))
    return "\n".join(out)


def texts_of(ev: dict) -> dict[str, tuple[str, str]]:
    """Per field: (decoded lower-case text, text as written in lower case)."""
    uri = str(ev.get("uri") or "")
    path, _, query = uri.partition("?")
    ua = str(ev.get("user_agent") or "")
    referer = str(ev.get("referer") or "") or _ext_values(ev, ("referer", "referrer"))
    upload = _ext_values(ev, ("upload_filename", "orig_filenames"))
    raw = {"ua": ua, "path": path, "query": query, "uri": uri, "referer": referer, "upload": upload,
           "any": "\n".join(x for x in (uri, ua, referer) if x)}
    # in a query string "+" is a space: commands arrive as cmd=wget+http://... and have to read as "wget http://..."
    q = (urllib.parse.unquote(urllib.parse.unquote_plus(query)) if ("%" in query or "+" in query) else query).lower()
    dec = {k: _decode(v) for k, v in raw.items() if v}
    if query:
        dec["query"] = q
        dec["uri"] = dec.get("path", "") + "?" + q
        dec["any"] = "\n".join(x for x in (dec["uri"], dec.get("ua", ""), dec.get("referer", "")) if x)
    return {k: (dec[k], v.lower()) for k, v in raw.items() if v}


def _fits(s: Signature, tx: dict[str, tuple[str, str]]) -> bool:
    pair = tx.get(s.where)
    if pair is None:
        return False
    dec, raw = pair
    return s.hits(raw) if s.raw else (s.hits(dec) or (s.raw_also and s.hits(raw)))


def sig_ids(ev: dict) -> list[str]:
    """Ids of all signatures the event matches."""
    tx = texts_of(ev)
    if not tx:
        return []
    gate, family, always = _gate()
    out: set[str] = set()
    if gate is not None:
        blob = "\n".join(dict.fromkeys([d for k, (d, _r) in tx.items() if k != "any"]
                                     + [r for k, (d, r) in tx.items() if r != d and k != "any"]))
        for word in set(gate.findall(blob)):
            out.update(s.id for s in family[word] if _fits(s, tx))
    pre = _always_prefilter()
    for fld, (dec, raw) in tx.items():
        rx = pre[fld]
        if rx is not None and (rx.search(dec) or (raw != dec and rx.search(raw))):
            out.update(s.id for s in always if s.where == fld and _fits(s, tx))
    method = str(ev.get("method") or "").upper()
    if method:
        out.update(s.id for s in _by_method().get(method, ()) if _fits(s, tx))
    return sorted(out)


def sig_tags(ev: dict) -> list[str]:
    return [TAG + i for i in sig_ids(ev)]


# ---------------------------------------------------------------- detector
def _advice(lines: tuple[str, ...]) -> str:
    return (ADVICE + "\n".join(f"- {x}" for x in lines)) if lines else ""


class SignatureMatch:
    """One finding per signature that got a successful answer; attempts that were all refused are folded into one
    finding per group and stage, so a scanner that tries two hundred known paths shows up as one line, not two hundred."""
    id, version, category, stage = "sig.match", "1.1.0", "sig", "EXPLOITATION"
    data_sources = {"web", "waf", "zeek_http"}

    def _counts(self, ctx: DetectorContext) -> dict[str, int]:
        inv = ctx.investigation_id
        try:
            buckets = ctx.events.aggregate(inv, [], AggRequest(type="terms", field="tags", size=1000))["buckets"]
            got = {str(b["key"])[len(TAG):]: int(b["count"]) for b in buckets if str(b["key"]).startswith(TAG)}
            if got or not buckets:
                return got
        except Exception:  # noqa: BLE001 - a store that cannot aggregate arrays: count per signature instead
            pass
        return {s.id: n for s in load_pack() if (n := ctx.events.count(inv, [Filter(field="tags", value=s.tag)]))}

    def run(self, ctx: DetectorContext) -> list[FindingDraft]:
        inv, es = ctx.investigation_id, ctx.events
        disabled = set(ctx.params.get("sig_disabled") or ())
        known = by_id()
        counts = {i: n for i, n in self._counts(ctx).items() if i in known and i not in disabled}
        if not counts:
            return []
        stats: dict[str, dict[str, Any]] = {}
        policy_views = ctx.params.get("signature_policy_views") or {}
        for sid, n in counts.items():
            es = policy_views.get(sid, ctx.events)
            flt = [Filter(field="tags", value=TAG + sid)]
            if sid in policy_views:
                n = es.count(inv, flt)
                if not n:
                    continue
            ok = es.count(inv, flt + [Filter(field="status_class", value="2xx")])
            lo, hi = es.time_bounds(inv, flt)
            srcs = [r["key"]["src_ip"] for r in es.group_by(inv, flt, ["src_ip"], [], size=10) if r["key"].get("src_ip")]
            stats[sid] = {"n": n, "ok": ok, "lo": lo, "hi": hi, "srcs": srcs, "flt": flt,
                          "sample_ids": [e["event_id"] for e in es.search(inv, flt, limit=20)["events"]]}
        out: list[FindingDraft] = []
        folded: dict[tuple[str, str], list[Signature]] = {}
        for sid, st in stats.items():
            s = known[sid]
            if s.success == "only" and not st["ok"]:
                continue
            if s.success == "ignore" or not st["ok"]:
                folded.setdefault((s.group, s.stage), []).append(s)
            else:
                out.append(self._single(ctx, s, st))
        for sigs in folded.values():
            out.append(self._single(ctx, sigs[0], stats[sigs[0].id]) if len(sigs) == 1 and sigs[0].success != "ignore"
                       else self._folded(ctx, sigs, stats))
        return out

    def _samples(self, ctx: DetectorContext, flt: list[Filter]) -> list[str]:
        return [e["event_id"] for e in ctx.events.search(ctx.investigation_id, flt, limit=20)["events"]]

    def _single(self, ctx: DetectorContext, s: Signature, st: dict) -> FindingDraft:
        won = st["ok"] > 0 and s.success != "ignore"
        title = s.title + (" — 성공 응답 있음" if won else "")
        checks = [check("알려진 흔적과 일치", True, f"{st['n']:,}건", s.cve or s.id),
                  check("성공 응답(2xx) 있음", won, f"{st['ok']:,}건",
                        "2xx는 요청이 받아들여졌다는 뜻이며 공격 성공의 확정은 아닙니다")]
        explain = (f"{s.title}: 일치하는 요청 {st['n']:,}건, 그중 성공 응답(2xx) {st['ok']:,}건. {s.explain}"
                   + _advice(s.checks))
        return FindingDraft(
            self.id, self.version, title, f"sig.{s.group}", s.stage, s.severity, s.confidence,
            [metric("requests", st["n"], label="일치한 요청"), metric("success_2xx", st["ok"], label="성공 응답(2xx)"),
             metric("sources", len(st["srcs"]), label="출발지")],
            checks, [f"ip:{x}" for x in st["srcs"]], {"filters": [f.model_dump() for f in st["flt"]], "time": None},
            st["lo"], st["hi"], f"sig:{s.id}",
            attack=[AttackMap(t, "high" if won else "medium", "알려진 흔적과 일치" + (", 성공 응답 있음" if won else ""),
                              condition_met=won or s.success == "ignore") for t in s.attack],
            success_signal=won, explanation=explain, sample_event_ids=st["sample_ids"], total_events=st["n"])

    def _folded(self, ctx: DetectorContext, sigs: list[Signature], stats: dict) -> FindingDraft:
        sigs = sorted(sigs, key=lambda s: -stats[s.id]["n"])
        head = sigs[0]
        # Base keys on the full pack, so absent stage matches cannot change a finding identity.
        mixed_stage = any(s.group == head.group and s.stage != head.stage for s in load_pack())
        dedup_key = f"sig-group:{head.group}" + (f":{head.stage}" if mixed_stage else "")
        n = sum(stats[s.id]["n"] for s in sigs)
        srcs = list(dict.fromkeys(x for s in sigs for x in stats[s.id]["srcs"]))[:10]
        los = [stats[s.id]["lo"] for s in sigs if stats[s.id]["lo"]]
        his = [stats[s.id]["hi"] for s in sigs if stats[s.id]["hi"]]
        flt = [Filter(field="tags", op="in", value=[s.tag for s in sigs])]
        names = ", ".join(f"{s.title} {stats[s.id]['n']:,}건" for s in sigs[:8]) + (f" 외 {len(sigs) - 8}종" if len(sigs) > 8 else "")
        refused = head.success != "ignore"
        title = f"{head.group_title} {len(sigs)}종" + (" (성공 응답 없음)" if refused else "")
        explain = (f"{head.group_title}: {names}." + (" 모두 성공 응답(2xx)을 받지 못했습니다." if refused else "")
                   + f" {head.explain}" + _advice(head.checks))
        return FindingDraft(
            self.id, self.version, title, f"sig.{head.group}", head.stage, max(s.severity for s in sigs), head.confidence,
            [metric("requests", n, label="일치한 요청"), metric("signatures", len(sigs), label="일치한 흔적 종류"),
             metric("sources", len(srcs), label="출발지")],
            [check("알려진 흔적과 일치", True, f"{len(sigs)}종 {n:,}건"),
             check("성공 응답(2xx) 있음", False if refused else None, "0건" if refused else "응답과 무관한 종류")],
            [f"ip:{x}" for x in srcs], {"filters": [f.model_dump() for f in flt], "time": None},
            min(los) if los else None, max(his) if his else None, dedup_key,
            attack=[AttackMap(t, "medium", "알려진 흔적과 일치(성공 응답 없음)" if refused else "알려진 도구·수집 서비스",
                              condition_met=not refused) for t in dict.fromkeys(t for s in sigs for t in s.attack)][:6],
            success_signal=False, explanation=explain, sample_event_ids=list(dict.fromkeys(e for s in sigs for e in stats[s.id]["sample_ids"]))[:20], total_events=n)


# ---------------------------------------------------------------- catalogue (for the rule list in the UI and docs)
def catalog() -> list[dict[str, Any]]:
    return [{"id": s.id, "title": s.title, "group": s.group, "group_title": s.group_title, "stage": s.stage,
             "severity": s.severity, "confidence": s.confidence, "attack": list(s.attack), "cve": s.cve,
             "where": s.where, "success": s.success, "explain": s.explain, "checks": list(s.checks),
             "examples": [e if isinstance(e, str) else dict(e) for e in s.examples][:3]} for s in load_pack()]
