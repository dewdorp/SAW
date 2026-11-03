"""Release practice cards must cite the actual CSV records supplied to the analyst."""
import csv
import ipaddress
import json
import re
from pathlib import Path

from saw.devtools import practice_cases

WEB = Path(__file__).resolve().parents[2] / "apps" / "web"
SECTORS = ["가상 은행", "가상 카드사", "가상 증권사", "가상 캐피탈", "가상 생명보험사", "가상 손해보험사", "가상 저축은행"]
# Private and documentation ranges only: no case may name a real-world address.
ALLOWED = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _cases():
    return json.loads((WEB / "src/pages/practice/practice-cases.json").read_text("utf-8"))["cases"]


def _logs(case_id):
    logs = {}
    for kind in ("ndr", "fw"):
        with (WEB / "public/practice-data/v1" / case_id / f"{kind}.csv").open(encoding="utf-8-sig", newline="") as stream:
            logs[kind] = list(csv.DictReader(stream))
    return logs


def test_practice_answers_and_csv_evidence_match_the_bundled_files():
    cases = _cases()
    assert [c["id"] for c in cases] == [f"C{i:03d}" for i in range(1, 101)]
    original_rows = 0
    for c in cases:
        logs = _logs(c["id"])
        if int(c["id"][1:]) <= 20:
            original_rows += len(logs["ndr"]) + len(logs["fw"])
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
    # The hand-authored first twenty are unchanged.
    assert original_rows == 6216
    assert sum(len(c["followups"]) for c in cases) == 400


def test_generated_cases_are_reproducible_and_their_aggregates_match_the_rows():
    assert practice_cases.main(["--check"]) == 0
    for c in _cases()[20:]:
        logs = _logs(c["id"])
        m = re.search(r"\((ndr|fw)\.csv (\d+)–(\d+)행\)", c["initial"]["observation"])
        assert m, c["id"]
        rows = logs[m[1]][int(m[2]) - 2:int(m[3]) - 1]
        assert rows, c["id"]
        outcome = "status" if m[1] == "ndr" else "action"
        cited = {e["fields"].get(outcome) for e in c["initial"]["evidence"]}
        # Every outcome the window shows is backed by at least one cited row.
        assert {r[outcome] for r in rows} <= cited, c["id"]
        for label, value in re.findall(r"HTTP (\d{3}) (\d+)건", c["initial"]["observation"]):
            assert sum(r["status"] == label for r in rows) == int(value), (c["id"], label)
        for label, value in re.findall(r"\b(allow|deny) (\d+)건", c["initial"]["observation"]):
            assert sum(r["action"] == label for r in rows) == int(value), (c["id"], label)
        # "이 구간 NDR n건·FW m건" counts the rows of both files inside the stated window.
        w = re.search(r"관심 구간 (\d\d/\d\d \d\d:\d\d:\d\d)–(\d\d/\d\d \d\d:\d\d:\d\d) KST\. 이 구간 NDR (\d+)건·FW (\d+)건",
                      c["initial"]["observation"])
        assert w, c["id"]

        def inside(value, w=w):
            return w[1] <= f"{value[5:7]}/{value[8:10]} {value[11:19]}" <= w[2]

        assert sum(inside(r["event_time"]) for r in logs["ndr"]) == int(w[3]), c["id"]
        assert sum(inside(r["_time"]) for r in logs["fw"]) == int(w[4]), c["id"]


def test_every_address_is_private_or_documentation_and_payloads_are_defanged():
    for c in _cases():
        logs = _logs(c["id"])
        for kind, rows in logs.items():
            for r in rows:
                for key in ("src_ip", "dest_ip", "dst_ip", "_device_ip"):
                    if r.get(key):
                        ip = ipaddress.ip_address(r[key])
                        assert any(ip in n for n in ALLOWED), (c["id"], kind, key)
                assert "<script" not in str(r).lower() and "union select" not in str(r).lower(), c["id"]


def test_each_practice_case_is_set_in_a_named_financial_sector():
    """Examples read as the affiliates an analyst works with; all are synthetic names."""
    text = (WEB / "src/pages/practice/practice-cases.json").read_text("utf-8")
    cases = json.loads(text)["cases"]
    seen = []
    for c in cases:
        named = [s for s in SECTORS if c["summary"].startswith(s + " ·") and c["initial"]["observation"].startswith(s + " ·")]
        assert len(named) == 1, c["id"]
        seen.append(named[0])
    assert set(seen) == set(SECTORS) and "가상 관계사 A" not in text and "가상 관계사 B" not in text
    # Every case says on its face that its logs are synthetic.
    assert all(c["title"].startswith("[가상] ") for c in cases)


def test_every_practice_csv_is_read_by_the_english_ndr_and_fw_parsers():
    """A practice CSV uploaded into an investigation parses completely with the dedicated parsers."""
    from saw.parsers.registry import parse_text

    for c in _cases():
        for kind, parser in (("ndr", "en_ndr_http_csv"), ("fw", "en_fw_csv")):
            text = (WEB / "public/practice-data/v1" / c["id"] / f"{kind}.csv").read_text("utf-8-sig")
            out = parse_text(text, investigation_id="practice")
            assert out["parser"] == parser and out["failed"] == 0, (c["id"], kind, out["parser"], out["failed"])
            assert len(out["events"]) == len(text.splitlines()) - 1, (c["id"], kind)
