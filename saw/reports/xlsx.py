"""Stream a frozen report to a safe, atomic eight-sheet XLSX artifact."""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from saw.reports.projection import ReportCancelled, ReportLimit, project

MAX_SHEET_ROWS = 1_048_576
CELL_UNITS = 32_767
META = (("row_ref", "행 참조"), ("source_pointer", "원본 경로"), ("row_type", "행 종류"))
CONTINUATION = (("continuation_index", "분할 순번"), ("continuation_count", "분할 수"))


def _check(cancelled):
    if cancelled and cancelled():
        raise ReportCancelled("report_export_cancelled")


def _chunks(value):
    if not isinstance(value, str):
        return [value]
    if len(value.encode("utf-16-le")) // 2 <= CELL_UNITS:
        return [value]
    chunks, start, units = [], 0, 0
    for index, char in enumerate(value):
        size = 2 if ord(char) > 0xFFFF else 1
        if units + size > CELL_UNITS:
            chunks.append(value[start:index])
            start, units = index, 0
        units += size
    chunks.append(value[start:])
    return chunks


def _parts(section, row):
    values = [row[key] for key, _ in META] + [row["cells"].get(col["key"], "") for col in section["columns"]]
    pieces = [_chunks(value) for value in values]
    # References must be intact on every physical continuation row.
    if any(len(value) != 1 for value in pieces[:len(META)]):
        raise ReportLimit("report_reference_cell_limit")
    count = max(map(len, pieces))
    for index in range(count):
        yield [value[0] if col < len(META) else value[index] if index < len(value) else ""
               for col, value in enumerate(pieces)] + [index+1, count]


def _formula(sheet, rows, column):
    from xlsxwriter.utility import xl_rowcol_to_cell
    refs = ["'" + sheet.replace("'", "''") + "'!" + xl_rowcol_to_cell(row, column, True, True) for row in rows]
    # All references are constructed from controlled sheet names and checked numeric row/column positions.
    return "=" + (refs[0] if len(refs) == 1 else "(" + ",".join(refs) + ")")


def _introduction(projection, section):
    hint = {"label": "표시 안내",
            "value": "A:G 기술 열은 처음에 숨겨져 있습니다. 열 머리글에서 숨김 해제로 행 참조·원본 경로·ID·항목 키를 볼 수 있습니다. 요약 아래 전체 투영은 행 그룹의 +로 펼칩니다."}
    if section["key"] == "summary":
        return [{"label": "SAW 저장 보고서", "value": projection["overview"]["title"]},
                *projection["overview"]["lines"], hint]
    return [hint]


def write(content, path, *, cancelled=None):
    """Publish only a complete XLSX. Exceptions/cancellation leave an existing destination untouched."""
    import xlsxwriter

    if xlsxwriter.__version__ != "3.2.9":
        raise RuntimeError("report_xlsx_dependency_version_mismatch")
    _check(cancelled)
    projection = project(content)
    _check(cancelled)
    section_manifest, splits = [], []
    for section in projection["sections"]:
        physical = 0
        for index, row in enumerate(section["rows"]):
            if index % 128 == 0:
                _check(cancelled)
            count = sum(1 for _ in _parts(section, row))
            physical += count
            if physical + len(_introduction(projection, section)) + 2 > MAX_SHEET_ROWS:
                raise ReportLimit("report_excel_row_limit")
            if count > 1:
                splits.append({"row_ref": row["row_ref"], "source_pointer": row["source_pointer"], "parts": count})
        section_manifest.append({"key": section["key"], "title": section["title"], "rows": physical,
                                 "logical_rows": len(section["rows"]),
                                 "intro_rows": len(_introduction(projection, section)),
                                 "header_row": len(_introduction(projection, section))})
    _check(cancelled)
    destination = Path(path)
    if not destination.parent.is_dir():
        raise ValueError("report_output_directory_missing")
    fd, temp_name = tempfile.mkstemp(prefix=".saw-report-", suffix=".xlsx", dir=destination.parent)
    os.close(fd)
    wb = None
    closed = False
    try:
        wb = xlsxwriter.Workbook(temp_name, {"constant_memory": True, "strings_to_formulas": False,
            "strings_to_urls": False, "strings_to_numbers": False, "tmpdir": str(destination.parent)})
        created_at = content.get("created_at")
        try:
            created = datetime.fromisoformat(str(created_at))
            created = created.replace(tzinfo=UTC) if created.tzinfo is None else created.astimezone(UTC)
        except (ValueError, TypeError):
            created = datetime(1980, 1, 1, tzinfo=UTC)  # deterministic package metadata for legacy content
        wb.set_properties({"title": "SAW 고정 보고서", "comments": projection["content_sha256"], "created": created})
        header = wb.add_format({"bold": True, "bg_color": "#173453", "font_color": "#FFFFFF",
                                "font_name": "Malgun Gothic", "text_wrap": True})
        text_format = wb.add_format({"font_name": "Malgun Gothic", "valign": "top", "text_wrap": True})
        timeline_sheet, timeline_positions, timeline_columns = None, {}, {}
        for section in projection["sections"]:
            sheet = wb.add_worksheet(section["title"])
            titles = [label for _, label in META] + [col["label"] for col in section["columns"]] + [
                label for _, label in CONTINUATION]
            introduction = _introduction(projection, section)
            header_row = len(introduction)
            label_col = len(META)+next(i for i, c in enumerate(section["columns"]) if c["key"] == "label")
            value_col = len(META)+next(i for i, c in enumerate(section["columns"]) if c["key"] == "value")
            sheet.freeze_panes(1 if section["key"] == "summary" else header_row+1, 0)
            sheet.set_selection(0, label_col, 0, label_col)
            sheet.set_column(0, len(titles)-1, 22)
            sheet.set_column(0, label_col-1, 22, None, {"hidden": True})
            sheet.set_column(label_col, label_col, 30)
            sheet.set_column(value_col, value_col, 70)
            for intro_row, line in enumerate(introduction):
                _check(cancelled)
                sheet.set_row(intro_row, min(220, max(30, 16*(len(str(line["value"]))//30+1))))
                sheet.write_string(intro_row, label_col, line["label"], header)
                sheet.write_string(intro_row, value_col, str(line["value"]), text_format)
            sheet.set_row(header_row, 30, None, {"collapsed": section["key"] == "summary"})
            for col, title in enumerate(titles):
                sheet.write_string(header_row, col, title, header)
            physical = header_row+1
            if section["key"] == "timeline":
                timeline_sheet = sheet
                timeline_columns = {col["key"]: len(META)+i for i, col in enumerate(section["columns"])}
            for index, row in enumerate(section["rows"]):
                if index % 128 == 0:
                    _check(cancelled)
                if section["key"] == "timeline":
                    timeline_positions[row["row_ref"]] = physical
                for values in _parts(section, row):
                    if section["key"] == "summary":
                        sheet.set_row(physical, None, None, {"hidden": True, "level": 1})
                    for col, value in enumerate(values):
                        if isinstance(value, (int, float)) and not isinstance(value, bool):
                            result = sheet.write_number(physical, col, value, text_format)
                        else:
                            result = sheet.write_string(physical, col, str(value), text_format)
                        if result != 0:
                            raise ReportLimit("report_excel_cell_write_failed")
                    physical += 1
            sheet.autofilter(header_row, 0, max(header_row, physical-1), len(titles)-1)
            if section["key"] == "summary" and physical > header_row+1:
                sheet.set_row(physical, None, None, {"collapsed": True})
        for index, series in enumerate(projection["charts"]):
            _check(cancelled)
            rows = [timeline_positions[ref] for ref in series["row_refs"]]
            chart = wb.add_chart({"type": "scatter"})
            chart.add_series({"name": "관측값", "categories": _formula("시간 추이", rows, timeline_columns["start"]),
                "values": _formula("시간 추이", rows, timeline_columns["value"]),
                "line": {"none": True}, "marker": {"type": "circle", "size": 5}})
            chart.set_title({"name": series["title"]})
            chart.set_x_axis({"name": "관측 구간 시작 (UTC epoch 초)", "num_format": "0"})
            chart.set_y_axis({"name": series["unit"] + " · " + series["statistic"]})
            chart.set_legend({"none": True})
            timeline_sheet.insert_chart(index*16+1, len(META)+len(projection["sections"][4]["columns"])+3,
                                        chart, {"x_scale": 1.1, "y_scale": 0.85})
        _check(cancelled)
        wb.close()
        closed = True
        _check(cancelled)
        output_hash = sha256()
        with open(temp_name, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024*1024), b""):
                _check(cancelled)
                output_hash.update(chunk)
        manifest = {"schema": "saw.report.xlsx.manifest.v1", "content_sha256": projection["content_sha256"],
            "sections": section_manifest, "chart_count": len(projection["charts"]), "splits": splits,
            "omissions": projection["limitations"], "dependency_version": xlsxwriter.__version__,
            "bytes": os.path.getsize(temp_name), "sha256": output_hash.hexdigest()}
        _check(cancelled)
        os.replace(temp_name, destination)
        return manifest
    finally:
        try:
            if wb is not None and not closed:
                wb.close()
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
