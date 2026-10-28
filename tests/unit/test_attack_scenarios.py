"""The synthetic attack-scenario corpus is labelled, parseable and free of live payloads."""
import json

from saw.detectors.ndr_policy import STAGES
from saw.devtools import attack_scenarios as gen
from saw.parsers.base import Failed, Parsed
from saw.parsers.security_csv import KoFirewallCsvParser, KoNdrCsvParser


def _parse(data: bytes, parser):
    text = data.decode("cp949")
    p = parser()
    detect = p.detect([text.split("\r\n", 1)[0]])
    parsed = failed = 0
    for line in text.split("\r\n"):
        if not line.strip():
            continue
        result = p.parse_line(line)
        parsed += isinstance(result, Parsed)
        failed += isinstance(result, Failed)
    return detect, parsed, failed


def test_corpus_is_labelled_parseable_and_defanged(tmp_path):
    out = tmp_path / "corpus"
    summary = gen.generate(out)
    assert summary["scenarios"] == len(gen.REGISTRY) >= 30
    assert summary["attack"] >= 20 and summary["benign_control"] >= 3
    assert set(summary["stages"]) <= STAGES

    records = [json.loads(line) for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == summary["scenarios"]
    assert len({r["id"] for r in records}) == len(records)
    catalog = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["scenarios"] == summary["scenarios"] and len(catalog["catalog"]) == summary["scenarios"]

    seen_files = 0
    for record in records:
        assert record["schema"] == gen.SCHEMA and record["synthetic"] is True
        assert record["contains_live_payload"] is False
        assert record["kind"] in ("attack", "benign_control")
        assert record["stage"] in STAGES
        assert all(isinstance(t, str) and t.startswith("T") for t in record["technique"])
        assert record["summary"] and record["expected_signal"]
        assert record["outputs"] and set(record["outputs"]) <= {"fw", "ndr"}
        for kind, info in record["outputs"].items():
            data = (out / info["file"]).read_bytes()
            assert len(data) == info["bytes"]
            parser = KoFirewallCsvParser if kind == "fw" else KoNdrCsvParser
            detect, parsed, failed = _parse(data, parser)
            # Each file is recognised by its dedicated parser and every row parses.
            assert detect >= 0.9 and failed == 0 and parsed == info["rows"] > 0
            low = data.decode("cp949").lower()
            assert not any(bad in low for bad in gen.DENYLIST)
            seen_files += 1
    assert seen_files == summary["files"]


def test_benign_and_attack_both_present_for_contrastive_labels():
    kinds = {s.kind for s in gen.REGISTRY}
    assert kinds == {"attack", "benign_control"}
    # Every attack scenario names at least one MITRE technique; benign controls name none.
    for s in gen.REGISTRY:
        assert (len(s.technique) > 0) == (s.kind == "attack")
