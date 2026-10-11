"""An optimization must preserve the full matcher for every supported rule form."""
from __future__ import annotations

import pytest

from saw.detectors import signatures as sg


def _signature(ident, *, where="uri", needles=(), all_needles=(), regex="", raw=False, raw_also=False):
    return sg.Signature(id=ident, title=ident, group="test", group_title="test", stage="RECON", severity=.1,
                        confidence="low", attack=(), success="ignore", where=where, explain="test", checks=(),
                        needles=needles, all_needles=all_needles, regex=regex, raw=raw, raw_also=raw_also,
                        rx=sg._compile(ident, regex) if regex else None)


def _naive(event):
    texts = sg.texts_of(event)
    method = str(event.get("method") or "").upper()
    return sorted(s.id for s in sg.load_pack() if (not s.methods or method in s.methods) and sg._fits(s, texts))


@pytest.fixture
def pack(monkeypatch):
    caches = (sg.by_id, sg._by_field, sg._gate, sg._always_prefilter, sg._by_method)

    def install(signatures):
        monkeypatch.setattr(sg, "load_pack", lambda: tuple(signatures))
        for function in caches:
            function.cache_clear()
    yield install
    for function in caches:
        function.cache_clear()


def test_symbol_only_all_rule_is_not_dropped(pack):
    pack([_signature("test.symbols", all_needles=("..", "/"))])
    assert sg.sig_ids({"uri": "/../"}) == _naive({"uri": "/../"}) == ["test.symbols"]
    assert sg.sig_ids({"uri": "/"}) == []


@pytest.mark.parametrize("where", ["ua", "referer", "upload", "any"])
@pytest.mark.parametrize("raw", [True, False])
def test_gate_preserves_raw_text_in_every_supported_field(pack, where, raw):
    pack([_signature("test.raw", where=where, needles=("%74oken",), raw=raw, raw_also=not raw)])
    event = {"uri": "/", "user_agent": "%74oken", "ext": {"test": {"referer": "%74oken", "upload_filename": "%74oken"}}}
    assert sg.sig_ids(event) == _naive(event) == ["test.raw"]


@pytest.mark.parametrize("regexes,event", [
    ((r"(?i)^[$]$",), {"uri": "$"}),
    ((r"^[$]$",), {"uri": "$"}),
    ((r"([$])\1", r"(%)\1"), {"uri": "%%"}),
    ((r"(?P<symbol>[$])", r"(?P<symbol>[%])"), {"uri": "%"}),
])
def test_prefilter_preserves_individual_regex_semantics(pack, regexes, event):
    pack([_signature(f"test.regex{i}", regex=regex) for i, regex in enumerate(regexes)])
    assert sg.sig_ids(event) == _naive(event)


@pytest.mark.parametrize("regex", [r"(?i)idi", r"(?i:idi)"])
def test_gate_does_not_assume_ascii_literal_for_casefolded_regex(pack, regex):
    pack([_signature("test.unicode_case", regex=regex)])
    event = {"uri": "\u0131d\u0131"}
    assert sg.sig_ids(event) == _naive(event) == ["test.unicode_case"]


def test_shipped_pack_agrees_with_full_matcher():
    from tests.unit.test_signature_pack import BENIGN, event_for

    events = [{"method": method, "uri": uri, "user_agent": ua} for method, uri, ua in BENIGN]
    events += [event_for(s, value) for s in sg.load_pack() for value in (*s.examples, *s.benign)]
    for event in events:
        assert sg.sig_ids(event) == _naive(event)
