"""Real synthetic observations -> frozen report -> shared projection and actual XLSX."""
import sys
import tracemalloc
from copy import deepcopy
from html import unescape
from importlib.util import find_spec
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

N = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
     "c": "http://schemas.openxmlformats.org/drawingml/2006/chart"}
SHEETS = ["요약", "상세", "확인 필요", "통계", "시간 추이", "근거", "적용 기준", "범위·한계"]


def api():
    assert find_spec("saw.reports.projection"), "frozen report projection missing"
    assert find_spec("saw.reports.xlsx"), "real XLSX writer missing"
    from saw.reports.projection import project
    from saw.reports.xlsx import ReportCancelled, ReportLimit, write
    return project, write, ReportCancelled, ReportLimit


def frozen():
    from saw.observation.device import analyze_device
    from tests.unit.test_device_observation import profile, rows
    contexts, executions = [], []
    examples = [
        ("WAF", "request", [{"kind": "request", "request_id": str(i), "uri": "/a/" + str(i),
                             "action": "allow", "edge_status": 403, "origin_status": 200} for i in range(6)]),
        ("IPS", "alert", [{"kind": "alert", "signature_id": "s", "action": "drop"} for _ in range(3)]),
        ("DDoS", "interval_summary", [{"kind": "interval", "begin": f"2026-10-20T00:0{i}:00Z",
             "end": f"2026-10-20T00:0{i+1}:00Z", "rate": 2000, "target": "192.0.2.1",
             "attack_type": "synthetic", "mitigation": "before"} for i in range(3)]),
        ("NDR", "dns", [{"kind": "dns", "domain": "synthetic.example"} for _ in range(4)]),
        ("FW", "flow", [{"kind": kind, "timestamp": f"2026-10-20T00:0{i}:00Z",
                        "session_id": "S", "sent": sent, "received": received, "action": "allow"}
                       for i, (kind, sent, received) in enumerate([("start", 0, 0), ("interim", 100, 900), ("end", 300, 1200)])]),
    ]
    for device, kind, entries in examples:
        ctx = profile(device, kind, rate_unit="pps", packet_available=True)
        ctx["observer"].update(device_id="dev-" + device, device_profile_version_id="p-" + device)
        contexts.append({"evidence_id": "e-" + device, "source_context": {
            "id": "c-" + device, "sha256": "a" * 64, "snapshot": ctx}, "files": []})
        result = analyze_device(device.lower() + ".observation", rows(ctx, entries))
        executions.append({"detector_id": device.lower() + ".observation",
            "detector_version": result["engine_version"], "status": result["status"],
            "input_count": result["counts"]["records"], "match_count": len(result["candidates"]),
            "elapsed_ms": 1, "effective_config": {"values": result["policy"]}, "detail": result})
    check = {"check_id": "check-1", "revision_id": "cr-1", "revision": 2, "payload_sha256": "b" * 64,
             "payload": {"id": "check-1", "target_label": "한글 확인", "note": "<script>unsafe</script>", "source_state": "valid"}}
    task = {"id": "fu-1", "revision_id": "fv-1", "revision": 3, "payload_sha256": "c" * 64,
       "payload": {"schema": "saw.followup.v1", "check_ref": {k: check[k] for k in ("check_id", "revision_id", "revision", "payload_sha256")},
        "question": "=HYPERLINK(\"https://invalid.test\",\"식\")", "reason": "정확 버전", "needed_data": ["원문"],
        "items": ["프로세스"], "priority": "high", "owner": {"org_unit_id": "responsible", "department": None, "user_id": None},
        "due_at": None, "status": "replied", "reply": {"note": "https://invalid.test/?q=1", "evidence": [
            {"investigation_id": "i", "event_id": "raw-1"}], "received_at": "2026-10-21T00:00:00Z", "received_by": "u"},
        "verification": None, "disposition": None, "origin": {"kind": "analyst", "check_id": "check-1"}}}
    return {"schema_version": "saw.report.v2", "created_at": "2026-10-21T01:00:00Z",
        "masking_policy": "authenticated-source-acl-v1",
        "scope": {"kind": "investigation", "selections": [{"investigation_id": "i", "analysis_run_id": "r", "followup_version_ids": None}]},
        "items": [{"investigation": {"id": "i", "display_id": "INV-가상", "title": "한글 <가상>", "org_unit": "가상 A", "org_unit_id": "A"},
          "analysis": {"id": "r", "version": 7, "status": "partial", "scope": {"org_unit_id": "A"},
             "created_at": "2026-10-21T00:00:00Z", "finished_at": "2026-10-21T00:01:00Z",
             "input_sha256": "d" * 64, "input_manifest": {"evidence": contexts}, "executions": executions,
             "findings": [{"id": "fs-1", "sha256": "f" * 64, "finding": {"id": "finding-1",
                  "title": "독립 Finding", "explanation_md": "성공 미확인", "metrics": [
                       {"name": "zero", "observed": 0, "unit": "bytes"},
                       {"name": "missing", "observed": None, "unit": "bytes"}],
                  "evidence_refs": {"sample_event_ids": ["raw-1"], "total": 1,
                    "query": {"filters": [{"field": "event_id", "value": ["raw-1"]}]}}}}]} ,
          "checks": [check], "followups": [task]}],
        "limits": ["가상 자료만 사용"], "schema_limits": {"max_snapshot_bytes": 16777216}}


def section(p, key):
    return next(x for x in p["sections"] if x["key"] == key)


def workbook(path):
    with ZipFile(path) as z:
        root = ET.fromstring(z.read("xl/workbook.xml"))
        names = [x.attrib["name"] for x in root.findall("s:sheets/s:sheet", N)]
        strings = []
        if "xl/sharedStrings.xml" in z.namelist():
            strings = ["".join(x.itertext()) for x in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("s:si", N)]
        sheets = []
        for i in range(1, 9):
            parsed = ET.fromstring(z.read(f"xl/worksheets/sheet{i}.xml"))
            out = []
            for row in parsed.findall("s:sheetData/s:row", N):
                values = {}
                for c in row.findall("s:c", N):
                    v = c.find("s:v", N)
                    value = v.text if v is not None else ""
                    if c.attrib.get("t") == "s":
                        value = strings[int(value)]
                    elif c.attrib.get("t") == "inlineStr":
                        value = "".join(t.text or "" for t in c.findall(".//s:t", N))
                    values[c.attrib["r"].rstrip("0123456789")] = (value, c.attrib.get("t", "n"))
                out.append(values)
            sheets.append(out)
        return names, sheets, {name: z.read(name) for name in z.namelist()}


def test_projection_uses_real_device_values_without_mutation_or_fake_totals():
    project, _, _, _ = api()
    data = frozen()
    before = deepcopy(data)
    p = project(data)
    assert [s["title"] for s in p["sections"]] == SHEETS
    assert data == before and p == project(data)
    stats = section(p, "statistics")["rows"]
    assert any(r["cells"]["field"] == "src_to_dst_bytes" and r["cells"]["value"] == 300 for r in section(p, "details")["rows"])
    assert any(r["cells"]["field"] == "observed" and r["cells"]["value"] == 0 for r in stats)
    assert any(r["cells"]["field"] == "observed" and r["cells"]["value"] == "미산출" for r in stats)
    assert any("cr-1" in str(r["cells"]) for r in section(p, "followups")["rows"])
    assert any("fv-1" in str(r["cells"]) for r in section(p, "followups")["rows"])
    timeline = section(p, "timeline")["rows"]
    assert {r["cells"]["unit"] for r in timeline} >= {"requests", "alerts", "pps", "dns_records"}
    assert not any(r["cells"]["detector_id"] == "fw.observation" for r in timeline)
    assert all(r["row_ref"] and r["source_pointer"].startswith("/items/0/") for r in timeline)
    assert any("세션 시각" in str(r["cells"]) for r in section(p, "limits")["rows"])
    assert not any(r["cells"]["field"] == "grand_total" for s in p["sections"] for r in s["rows"])


def test_v1_adapts_without_inventing_revisions_and_unsupported_schema_rejected():
    project, _, _, Limit = api()
    data = frozen()
    item = data["items"][0]
    old = {"schema_version": "saw.report.v1", **item, "limits": ["예전"]}
    old.pop("followups", None)
    old["checks"] = [item["checks"][0]["payload"]]
    p = project(old)
    assert any("미보존" in str(r["cells"]) for r in section(p, "limits")["rows"])
    assert not any(r["cells"]["field"] == "revision_id" for r in section(p, "followups")["rows"])
    with pytest.raises((ValueError, Limit)):
        project({"schema_version": "saw.report.v999"})


def test_real_zip_eight_sheets_literal_cells_and_projection_html_parity(tmp_path):
    project, write, _, _ = api()
    from saw.reports.html import render
    data = frozen()
    p = project(data)
    path = tmp_path / "실제.xlsx"
    manifest = write(data, path)
    names, sheets, members = workbook(path)
    assert names == SHEETS
    html = render(SimpleNamespace(content=data, version=1, content_sha256=p["content_sha256"]))
    assert "&lt;script&gt;unsafe&lt;/script&gt;" in html and "<script>" not in html
    for sec, rows in zip(p["sections"], sheets):
        header, data_rows = raw_table(rows)
        headers = {v[0]: k for k, v in header.items()}
        by_ref = {r[headers["행 참조"]][0]: r for r in data_rows}
        for r in sec["rows"]:
            assert r["row_ref"] in html and r["row_ref"] in by_ref
            actual = by_ref[r["row_ref"]]
            for col in sec["columns"]:
                expected = r["cells"].get(col["key"], "")
                got = actual[headers[col["label"]]][0]
                assert got == str(expected), (sec["key"], col["key"], got, expected)
                assert str(expected) in unescape(html)
    payloads = ["=HYPERLINK(\"https://invalid.test\",\"식\")", "https://invalid.test/?q=1"]
    all_cells = [v for sheet in sheets for row in sheet for v in row.values()]
    assert all(any(v == text and kind in {"s", "inlineStr"} for v, kind in all_cells) for text in payloads)
    assert any(v == "0" and kind == "n" for v, kind in all_cells)
    assert not any("externalLink" in k or "vbaProject" in k for k in members)
    assert not any(b'TargetMode="External"' in v for k, v in members.items() if k.endswith(".rels"))
    assert not any(b"<f>" in v or b"<ddeLink" in v for k, v in members.items() if "/worksheets/sheet" in k)
    from saw.core.application.provenance import digest
    assert manifest["content_sha256"] == digest(data)
    assert manifest["bytes"] == path.stat().st_size and len(manifest["sha256"]) == 64
    assert manifest["dependency_version"] == "3.2.9"


def test_chart_series_keep_scope_unit_action_and_missing_bins_separate(tmp_path):
    project, write, _, _ = api()
    data = frozen()
    second = deepcopy(data["items"][0])
    second["investigation"]["id"] = "j"
    second["analysis"]["id"] = "r2"
    for ex in second["analysis"]["executions"]:
        for point in ex["detail"].get("timeline", []):
            point["context"][0] = "B"
    data["items"].append(second)
    p = project(data)
    assert p["charts"] and all(len(c["row_refs"]) >= 1 for c in p["charts"])
    # DDoS's rate remains a mean series; it never combines units or two organizations.
    assert {c["unit"] for c in p["charts"]} >= {"requests", "alerts", "pps", "dns_records"}
    for c in p["charts"]:
        refs = c["row_refs"]
        rows = [r for r in section(p, "timeline")["rows"] if r["row_ref"] in refs]
        assert len({(r["cells"]["investigation_id"], r["cells"]["unit"], r["cells"]["statistic"], r["cells"]["context"]) for r in rows}) == 1
    path = tmp_path / "charts.xlsx"
    manifest = write(data, path)
    _, _, members = workbook(path)
    charts = [ET.fromstring(v) for k, v in members.items() if k.startswith("xl/charts/chart") and k.endswith(".xml")]
    assert len(charts) == manifest["chart_count"] == len(p["charts"])
    for chart in charts:
        formulas = [x.text for x in chart.findall(".//c:f", N)]
        assert formulas and all("'시간 추이'!" in x and "[" not in x and "]" not in x for x in formulas)


def test_ddos_mapped_sampling_cannot_create_comparison_chart(tmp_path):
    project, _, _, _ = api()
    data = frozen()
    snapshots = data["items"][0]["analysis"]["input_manifest"]["evidence"]
    ddos = next(x["source_context"]["snapshot"] for x in snapshots if x["evidence_id"] == "e-DDoS")
    ddos["profile"]["source_fields"]["sampling_ratio"] = "row_sample"
    p = project(data)
    assert not any(c["unit"] == "pps" for c in p["charts"])
    assert any("sampling" in str(x).lower() for x in p["limitations"])
    assert any(r["cells"]["unit"] == "pps" for r in section(p, "timeline")["rows"])


def test_utf16_continuations_reconstruct_original_without_truncation(tmp_path):
    project, write, _, _ = api()
    data = frozen()
    text = "가" * 32766 + "😀" + "나" * 3000
    data["items"][0]["followups"][0]["payload"]["reason"] = text
    p = project(data)
    row = next(r for r in section(p, "followups")["rows"] if r["cells"]["field"] == "reason" and r["cells"]["value"] == text)
    path = tmp_path / "long.xlsx"
    manifest = write(data, path)
    _, sheets, _ = workbook(path)
    header, data_rows = raw_table(sheets[2])
    headers = {v[0]: k for k, v in header.items()}
    parts = [r for r in data_rows if r[headers["행 참조"]][0] == row["row_ref"]]
    assert len(parts) == 2
    assert "".join(r[headers["값"]][0] for r in parts) == text
    assert all(len(r[headers["값"]][0].encode("utf-16-le")) // 2 <= 32767 for r in parts)
    assert [r[headers["분할 순번"]][0] for r in parts] == ["1", "2"]
    assert manifest["splits"] and manifest["sections"][2]["rows"] > len(section(p, "followups")["rows"])


def test_cancel_and_bounds_preserve_existing_file_and_cleanup_owned_temp(tmp_path, monkeypatch):
    _, write, Cancelled, Limit = api()
    import saw.reports.xlsx as module
    target = tmp_path / "existing.xlsx"
    target.write_bytes(b"previous artifact")
    calls = 0
    def stop():
        nonlocal calls
        calls += 1
        return calls > 5
    with pytest.raises(Cancelled):
        write(frozen(), target, cancelled=stop)
    assert target.read_bytes() == b"previous artifact"
    assert list(tmp_path.iterdir()) == [target]
    monkeypatch.setattr(module, "MAX_SHEET_ROWS", 5)
    with pytest.raises(Limit):
        write(frozen(), target)
    assert target.read_bytes() == b"previous artifact"


def test_writer_memory_is_bounded_for_real_workbook(tmp_path):
    _, write, _, _ = api()
    data = frozen()
    data["items"][0]["analysis"]["findings"] = []
    data["items"][0]["checks"] = []
    data["items"][0]["followups"] = []
    data["items"][0]["analysis"]["executions"] = []
    data["limits"] = ["한글 메모 " + str(i) + "x" * 100 for i in range(12000)]
    tracemalloc.start()
    manifest = write(data, tmp_path / "bounded.xlsx")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert manifest["bytes"] > 10000
    assert peak < 80 * 1024 * 1024

def test_computed_limit_rows_reference_real_frozen_source_and_labels_are_readable():
    project, _, _, _ = api()
    data = frozen()
    p = project(data)
    for sec in p["sections"]:
        for row in sec["rows"]:
            source = data
            for part in row["source_pointer"].split("/")[1:]:
                token = part.replace("~1", "/").replace("~0", "~")
                source = source[int(token)] if isinstance(source, list) else source[token]
    assert any(r["cells"].get("label") == "출발지 → 목적지 바이트" for r in section(p, "details")["rows"])


def test_invalid_numeric_or_trusted_location_conflict_omits_chart_but_keeps_measured_rows():
    project, _, _, _ = api()
    data = frozen()
    evidence = data["items"][0]["analysis"]["input_manifest"]["evidence"]
    duplicate = deepcopy(evidence[2])
    duplicate["source_context"]["snapshot"]["observer"]["observation_point"] = "other-edge"
    evidence.append(duplicate)
    p = project(data)
    assert any("conflict" in str(x) for x in p["limitations"])
    assert not any(c["unit"] == "pps" for c in p["charts"])
    assert sum(r["cells"]["unit"] == "pps" for r in section(p, "timeline")["rows"]) == 3


def test_nonfinite_snapshot_and_large_projection_are_explicit_limits(monkeypatch):
    project, _, _, Limit = api()
    data = frozen()
    data["limits"] = [float("nan")]
    with pytest.raises(Limit):
        project(data)
    import saw.reports.projection as module
    monkeypatch.setattr(module, "MAX_PROJECTED_ROWS", 5)
    with pytest.raises(Limit):
        project(frozen())


def test_callback_exception_after_workbook_close_preserves_previous_publication(tmp_path):
    _, write, _, _ = api()
    target = tmp_path / "published.xlsx"
    target.write_bytes(b"prior")
    class Superseded(Exception):
        pass
    def guard():
        # The ZIP header appears after Workbook.close(), not while sheet XML is streaming.
        temps = list(tmp_path.glob(".saw-report-*.xlsx"))
        if temps and temps[0].read_bytes()[:2] == b"PK":
            raise Superseded()
        return False
    with pytest.raises(Superseded):
        write(frozen(), target, cancelled=guard)
    assert target.read_bytes() == b"prior" and list(tmp_path.iterdir()) == [target]

def test_workbook_creation_metadata_uses_frozen_report_time(tmp_path):
    _, write, _, _ = api()
    data = frozen()
    path = tmp_path / "frozen-time.xlsx"
    write(data, path)
    with ZipFile(path) as z:
        core = ET.fromstring(z.read("docProps/core.xml"))
        created = core.find("{http://purl.org/dc/terms/}created")
        assert created.text == "2026-10-21T01:00:00Z"


def test_pure_projection_and_writer_import_do_not_load_database_or_models():
    import subprocess
    script = "import sys; import saw.reports.projection, saw.reports.xlsx, saw.reports.projection_html; assert not any(k.split('.')[0] in {'torch','transformers','sentence_transformers','sqlalchemy'} for k in sys.modules)"
    subprocess.run([sys.executable, "-B", "-c", script], check=True, cwd=Path(__file__).resolve().parents[2])

@pytest.mark.parametrize("invalid", ["time", "statistic"])
def test_unrepresentable_time_or_unknown_statistic_cannot_make_rate_chart(invalid):
    project, _, _, _ = api()
    data = frozen()
    points = data["items"][0]["analysis"]["executions"][2]["detail"]["timeline"]
    for point in points:
        if invalid == "time":
            point["start_epoch"] = 10**20
        else:
            point["statistic"] = None
    p = project(data)
    assert not any(c["unit"] == "pps" for c in p["charts"])
    assert any(r["cells"]["unit"] == "pps" for r in section(p, "timeline")["rows"])


def test_formula_like_detector_label_is_never_a_chart_formula(tmp_path):
    _, write, _, _ = api()
    data = frozen()
    data["items"][0]["analysis"]["executions"][0]["detector_id"] = "=external!X1"
    path = tmp_path / "label.xlsx"
    write(data, path)
    with ZipFile(path) as z:
        chart = ET.fromstring(z.read("xl/charts/chart1.xml"))
        formulas = [x.text for x in chart.findall(".//c:f", N)]
        assert formulas and all("external" not in x for x in formulas)
        assert "장비 관측" in "".join(chart.itertext())
    _, sheets, _ = workbook(path)
    assert any(value == "=external!X1" and kind in {"inlineStr", "s"}
               for sheet in sheets for row in sheet for value, kind in row.values())

def test_missing_sampling_is_explained_in_korean_with_machine_reason_retained():
    project, _, _, _ = api()
    data = frozen()
    data["items"][0]["analysis"]["input_manifest"]["evidence"][2]["source_context"]["snapshot"]["profile"]["source_fields"]["sampling_ratio"] = "sample"
    p = project(data)
    assert any("sampling_ratio_row_mapping_not_preserved" == x["reason"] for x in p["limitations"])
    assert any("샘플링" in str(r["cells"]["value"]) for r in section(p, "limits")["rows"])


def raw_table(rows):
    index = next(i for i, row in enumerate(rows) if any(value == "행 참조" for value, _kind in row.values()))
    header = rows[index]
    ref_column = next(col for col, (value, _kind) in header.items() if value == "행 참조")
    return header, [row for row in rows[index+1:] if ref_column in row]


def test_readable_overview_precedes_collapsed_full_provenance_and_matches_workbook(tmp_path):
    project, write, _, _ = api()
    from saw.reports.projection_html import render
    data = frozen()
    data["scope"]["kind"] = "selected_followups"
    task = data["items"][0]["followups"][0]["payload"]
    task["status"] = "verified"
    task["verification"] = {"outcome": "insufficient_data", "basis": "자료 부족", "evidence": []}
    p = project(data)
    assert "선택한 후속 확인" in p["overview"]["title"]
    overview = p["overview"]["lines"]
    assert any("한글 <가상>" in str(x["value"]) for x in overview)
    assert any("자료 부족" in str(x["value"]) for x in overview)
    assert any("FW" in str(x) and "300" not in str(x) and "세션 1" in str(x["value"]) for x in overview)
    html = render(data)
    assert html.index("한글 &lt;가상&gt;") < html.index("<details")
    assert "<details open" not in html
    assert "원문 위치와 전체 고정 투영" in html
    path = tmp_path / "readable.xlsx"
    write(data, path)
    _, sheets, members = workbook(path)
    all_summary = [value for row in sheets[0] for value, _kind in row.values()]
    assert all(str(line["value"]) in all_summary for line in overview)
    raw_header = next(i for i, row in enumerate(sheets[0]) if any(v == "행 참조" for v, _kind in row.values()))
    assert raw_header > 10
    for index in range(1, 9):
        xml = ET.fromstring(members[f"xl/worksheets/sheet{index}.xml"])
        hidden = xml.findall("s:cols/s:col", N)
        assert any(c.attrib.get("hidden") == "1" and c.attrib["min"] == "1" for c in hidden)
    assert any("숨김 해제" in value for value in all_summary)


def test_partial_and_not_applicable_stay_distinct_in_readable_overview():
    project, _, _, _ = api()
    data = frozen()
    executions = data["items"][0]["analysis"]["executions"]
    executions[0]["detail"]["status"] = "partial"
    executions[1]["detail"]["status"] = "not_applicable"
    overview = project(data)["overview"]
    assert any("WAF" in str(x) and "일부만 완료" in str(x["value"]) for x in overview["lines"])
    assert any("IPS" in str(x) and "적용 대상 아님" in str(x["value"]) for x in overview["lines"])
    assert not any("전체 이벤트 합계" in str(x) for x in overview["lines"])


def test_long_question_cannot_hide_insufficient_outcome_or_chart_limit():
    project, _, _, _ = api()
    data = frozen()
    task = data["items"][0]["followups"][0]["payload"]
    task["question"] = "긴 질문 " * 200
    task["status"] = "verified"
    task["verification"] = {"outcome": "insufficient_data"}
    p = project(data)
    followup = next(x["value"] for x in p["overview"]["lines"] if x["label"] == "확인 필요")
    assert "자료 부족" in followup and "정상 판정 아님" in followup
    assert any("세션 시각" in str(x["value"]) for x in p["overview"]["lines"])


def test_generic_execution_overview_groups_status_counts_without_metric_sums():
    project, _, _, _ = api()
    data = frozen()
    executions = data["items"][0]["analysis"]["executions"]
    for index, state in enumerate(["not_applicable"] * 20 + ["partial", "failed"]):
        executions.append({"detector_id": f"generic-{index}", "status": state,
            "input_count": 99999, "match_count": 888, "detail": {"status": "complete"}})
    p = project(data)
    lines = p["overview"]["lines"]
    device = [line for line in lines if line["label"] in {"FW 관측", "WAF 관측", "IPS 관측", "DDoS 관측", "NDR 관측"}]
    grouped = [line["value"] for line in lines if line["label"] == "기타 탐지 실행"]
    assert len(device) == 5 and len(grouped) == 3
    assert any("적용 대상 아님" in value and "20개" in value for value in grouped)
    assert any("일부만 완료" in value and "1개" in value for value in grouped)
    assert any("실패" in value and "1개" in value for value in grouped)
    assert all("99999" not in value and "888" not in value for value in grouped)
    assert not any(line["label"] == "추가 탐지 관측" for line in lines)
    raw_ids = {row["cells"]["value"] for row in section(p, "summary")["rows"]
               if row["cells"]["field"] == "detector_id"}
    assert {f"generic-{i}" for i in range(22)} <= raw_ids


@pytest.mark.parametrize(("risk", "label"), [("low", "낮음"), ("medium", "중간"), ("high", "높음")])
def test_human_risk_label_is_korean_while_exact_source_is_retained(risk, label):
    project, _, _, _ = api()
    data = frozen()
    data["items"][0]["analysis"]["findings"][0]["finding"]["risk_level"] = risk
    p = project(data)
    value = next(line["value"] for line in p["overview"]["lines"] if line["label"] == "관측·판단")
    assert "위험 " + label in value
    assert any(row["cells"]["field"] == "risk_level" and row["cells"]["value"] == risk
               for row in section(p, "details")["rows"])
