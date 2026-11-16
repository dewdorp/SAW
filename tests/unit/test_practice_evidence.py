"""Release practice cards must cite the actual CSV records supplied to the analyst."""
import csv
import json
import re
from pathlib import Path


def test_practice_answers_and_csv_evidence_match_the_bundled_files():
    web = Path(__file__).resolve().parents[2] / "apps" / "web"
    cases = json.loads((web / "src/pages/practice/practice-cases.json").read_text("utf-8"))["cases"]
    assert {c["id"] for c in cases} == {f"C{i:03d}" for i in range(1, 21)}
    assert len(cases) == 20
    rows = 0
    for c in cases:
        root = web / "public/practice-data/v1" / c["id"]
        logs = {}
        for kind in ("ndr", "fw"):
            with (root / f"{kind}.csv").open(encoding="utf-8-sig", newline="") as stream:
                logs[kind] = list(csv.DictReader(stream))
                rows += len(logs[kind])
        assert c["initial"]["evidence"], c["id"]
        for evidence in c["initial"]["evidence"]:
            match = re.fullmatch(r"(ndr|fw)\.csv:(\d+)", evidence["id"])
            assert match, (c["id"], evidence["id"])
            kind, line = match[1], int(match[2])
            assert 2 <= line <= len(logs[kind]) + 1, (c["id"], evidence["id"])
            row = logs[kind][line - 2]  # header is CSV line 1
            assert all(str(value) == row[key] for key, value in evidence["fields"].items()), (c["id"], evidence["id"])
        assert len(c["followups"]) == len({x["id"] for x in c["followups"]}) == 4
        for stage in [c["initial"], *c["followups"]]:
            opts = stage["options"]
            assert len(opts) == len({o["text"] for o in opts}) == len({o["id"] for o in opts}) == 4
            assert sum(o["id"] == stage["correctId"] for o in opts) == 1
            assert stage["rationale"].strip() and all(o["explanation"].strip() for o in opts)
    assert rows == 6216
