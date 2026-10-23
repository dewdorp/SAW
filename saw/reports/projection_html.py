"""Escaped HTML over the same model-free report projection as XLSX."""
from html import escape

from saw.reports.projection import ReportCancelled, project

CSS = """body{margin:0;background:#f4f6f9;color:#18263b;font:15px/1.7 sans-serif}main{max-width:1500px;margin:auto;padding:30px}
h1{font-size:26px}.brief{background:white;border:1px solid #d6dfeb;border-radius:10px;padding:18px;margin:14px 0}.brief-row{display:grid;grid-template-columns:160px 1fr;gap:14px;border-bottom:1px solid #edf0f5;padding:10px 0}.brief-row p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}details{margin:18px 0}summary{cursor:pointer;padding:12px;background:#eaf0f7}h2{margin-top:30px}.table-scroll{overflow:auto;background:white;border:1px solid #d6dfeb}
table{border-collapse:collapse;font-size:13px}th,td{padding:9px;border:1px solid #d6dfeb;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere;min-width:120px;max-width:650px}
th{background:#eaf0f7;text-align:left}small{color:#4b5c71}@media print{body{background:white}main{padding:0}.table-scroll{overflow:visible}}"""


def render(content, *, cancelled=None):
    model = project(content)
    def check():
        if cancelled and cancelled():
            raise ReportCancelled("report_export_cancelled")
    check()
    out = ['<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
           '<title>SAW 고정 보고서</title><style>' + CSS + '</style></head><body><main>',
           ]
    h = lambda value: escape(str(value), quote=True)
    out.append("<h1>" + h(model["overview"]["title"]) + "</h1><section class=\"brief\">")
    for line in model["overview"]["lines"]:
        out.append('<div class="brief-row"><strong>' + h(line["label"]) + "</strong><p>" + h(line["value"]) + "</p></div>")
    out.append("</section><h2>근거와 원문 참조</h2><p>다음 표를 열면 저장된 전체 값·단위·분모·버전과 원문 위치를 확인할 수 있습니다.</p>")
    for section in model["sections"]:
        check()
        out.append('<details><summary>원문 위치와 전체 고정 투영 · ' + h(section["title"]) + '</summary><div class="table-scroll"><table><thead><tr>')
        out.extend('<th>' + h(x) + '</th>' for x in ["행 참조", "원본 경로", "행 종류"] + [c["label"] for c in section["columns"]])
        out.append('</tr></thead><tbody>')
        for index, row in enumerate(section["rows"]):
            if index % 128 == 0:
                check()
            out.append('<tr data-row-ref="' + h(row["row_ref"]) + '">')
            values = [row["row_ref"], row["source_pointer"], row["row_type"]] + [row["cells"].get(c["key"], "") for c in section["columns"]]
            out.extend('<td>' + h(value) + '</td>' for value in values)
            out.append('</tr>')
        out.append('</tbody></table></div></details>')
    check()
    out.append('<small>내용 지문: ' + model["content_sha256"] + '</small></main></body></html>')
    return "".join(out)
