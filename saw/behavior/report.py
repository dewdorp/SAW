"""Printable, self-contained view of an immutable behavior result."""
from __future__ import annotations

import json
from html import escape
from typing import Any


STATE = {"conditional_code_derived": "코드에서 확인한 조건부 문자열", "code_defined_unreachable": "설명된 버전에서 도달할 수 없는 코드 경로", "existing_normalized_tags": "기존 정규화 태그 일치", "available": "자료 있음", "partial": "일부 자료", "not_collected": "미수집",
         "threshold_met": "기준 도달", "below_threshold": "기준 미만",
         "unavailable": "판단 자료 없음", "insufficient_data": "자료 부족",
         "observed": "관측", "not_observed": "이번 자료에서 미관측",
         "answered": "답변 기록", "follow_up": "후속확인 필요", "not_applicable": "해당 없음",
         "done": "완료", "degraded": "일부 실패", "failed": "실패", "pending": "대기", "skipped": "건너뜀",
         "normal": "정상", "suspicious": "의심", "malicious": "악성", "undetermined": "판단 불가"}


def text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return escape(str(value), quote=True)


def table(headers: list[str], rows: list[list[Any]]) -> str:
    return "<table><thead><tr>" + "".join(f"<th>{text(h)}</th>" for h in headers) + (
        "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{text(v)}</td>" for v in row)
                                        + "</tr>" for row in rows) + "</tbody></table>")


def items(values: Any) -> str:
    if not values:
        return '<p class="muted">저장된 항목 없음</p>'
    if isinstance(values, dict):
        values = [f"{key}: {text(value)}" for key, value in values.items()]
    return "<ul>" + "".join(f"<li>{text(x)}</li>" for x in values) + "</ul>"


def chart(timeline: dict) -> str:
    buckets = timeline.get("buckets") or []
    if not buckets:
        return '<p class="muted">시각이 있는 관측값 없음</p>'
    shown = buckets[:400]
    maximum = max((b.get("count") or 0 for b in shown), default=1) or 1
    width = 720 / max(len(shown), 1)
    bars = []
    for i, bucket in enumerate(shown):
        count = bucket.get("count") or 0
        height = 138 * max(0, count) / maximum
        bars.append(f'<rect x="{40 + i * width:.3f}" y="{158 - height:.3f}" '
                    f'width="{max(width - .5, .2):.3f}" height="{height:.3f}" '
                    f'data-count="{text(count)}" fill="#246581"><title>'
                    f'{text(bucket.get("start"))} / {text(count)}건</title></rect>')
    remainder = " · 표시 한도 400구간" if len(buckets) > 400 else ""
    return (
        '<figure><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 198" '
        'role="img" aria-label="저장된 관측 시계열"><line x1="40" x2="760" y1="158" y2="158" '
        'stroke="#8c9aa0"/><text x="8" y="20" font-size="11">' + text(maximum) + "</text>"
        + "".join(bars)
        + '<text x="40" y="181" font-size="10">' + text(shown[0].get("start"))
        + '</text><text x="760" y="195" text-anchor="end" font-size="10">'
        + text(shown[-1].get("end_exclusive")) + "</text></svg>"
        + f'<figcaption>그림 1. {text(timeline.get("coverage_label"))} · '
        f'{text(timeline.get("interval_seconds"))}초 고정 구간 · UTC{remainder}. '
        '막대는 저장된 관측 건수이며 지표의 이동 시간창과 다릅니다. 빈 구간은 수집 연속성을 증명하지 않습니다.</figcaption></figure>')


def render_report(result_dto: dict, analyst_checks: list | None = None) -> str:
    """Render saved values only; analyst statements cannot modify observations."""
    saved = result_dto.get("result") or {}
    obs = saved.get("observations") or {}
    summary = obs.get("summary") or {}
    timeline = obs.get("timeline") or {}
    execution = obs.get("execution") or {}
    profile = saved.get("profile") or {}
    scope = saved.get("scope") or {}
    manifest = saved.get("source_manifest") or {}
    files = [{**file, "tz_assumed": entry.get("tz_assumed"), "evidence_id": entry.get("evidence_id")}
             for entry in manifest.get("evidence") or [] for file in entry.get("files") or []]
    sections = []

    def section(number: int, title: str, body: str) -> None:
        sections.append(f'<section><h2>{number}. {text(title)}</h2>{body}</section>')

    section(1, "분석 범위와 저장 버전", table(["항목", "저장값"], [
        ["결과 / 버전", f'{result_dto.get("id")} / v{result_dto.get("version")}'],
        ["생성 시각 / 작성자", f'{result_dto.get("created_at")} / {result_dto.get("created_by")}'],
        ["분석 IP / 역할", {"ips": scope.get("ips"), "role": scope.get("role")}],
        ["시간 범위", scope.get("time")], ["구조화 필터", scope.get("filters")],
        ["관측 기준", (saved.get("methodology") or {}).get("source_basis") or timeline.get("coverage_label")]]))
    section(2, "수집 범위와 자료 품질",
            '<p>필드 미수집, 기록된 빈 값, 알 수 없는 상태를 구분합니다. 기록된 빈 UA는 헤더 부재의 증거가 아닙니다. '
            '관측 간격이 비었다는 사실만으로 수집 중단이나 요청 부재를 단정하지 않습니다.</p>'
            + table(["입력 파일", "파서", "상태", "파싱 건수", "실패 건수", "해석 시간대 (가정)"], [
                [f.get("display_name") or f.get("id"), f.get("parser_id") or "미기록",
                 STATE.get(f.get("parse_status"), f.get("parse_status")) or "미기록",
                 f.get("events_parsed") if f.get("events_parsed") is not None else "미기록",
                 f.get("events_failed") if f.get("events_failed") is not None else "미기록",
                 f.get("tz_assumed") or "미기록"] for f in files[:60]])
            + f'<p class="muted">입력 파일 {len(files)}개 중 최대 60개 표시. 파일 전체 파싱 건수는 선택 범위의 관측 건수와 다를 수 있습니다.</p>'
            + table(["품질 항목", "저장값"], [[k, v] for k, v in (obs.get("quality") or {}).items()])
            + ('<p class="warning">제한으로 중단: ' + text(execution.get("reason")) + ". 전체 범위 결론에 사용할 수 없습니다.</p>"
               if execution.get("truncated") else "")
            + table(["처리 상태", "값"], [[k, execution.get(k)] for k in ("scanned", "processed", "truncated", "reason")]))
    section(3, "계산된 관측값 요약", table(["항목", "저장값"], [
        ["관측 건수", summary.get("count")], ["처음 / 마지막", [summary.get("first"), summary.get("last")]],
        ["메서드별", summary.get("methods")], ["관측 서비스", summary.get("services")],
        ["상태 코드별", summary.get("status_codes")], ["조치별", summary.get("actions")],
        ["서로 다른 경로", summary.get("unique_paths")], ["기록된 UA", summary.get("user_agents")]]))
    section(4, "시간 변화와 최대 시간창", chart(timeline)
            + table(["지표", "시작 (포함)", "끝 (제외)", "값"], [
                [x.get("metric_id"), x.get("start"), x.get("end_exclusive"), x.get("value")]
                for x in (timeline.get("annotations") or [])]))
    metric_rows = []
    for metric in obs.get("metrics") or []:
        window = metric.get("window") or {}
        cells = [
            f'{metric.get("label")} / {metric.get("window_seconds")}초', metric.get("value"),
            [STATE.get(metric.get("data_state"), metric.get("data_state")), STATE.get(metric.get("result"), metric.get("result"))],
            f'{metric.get("reference_threshold")} / {metric.get("applied_threshold")}',
            f'{metric.get("eligible_count")} / {metric.get("excluded_count")}',
            "부분 시간창" if metric.get("partial_window") else "관측 기간 충족",
            [window.get("start"), window.get("end_exclusive"), window.get("src_ip"), window.get("service")],
        ]
        metric_rows.append(f'<tr data-metric-id="{text(metric.get("id"))}" '
                           f'data-value="{text(metric.get("value")) if metric.get("value") is not None else ""}">'
                           + "".join(f"<td>{text(value)}</td>" for value in cells) + "</tr>")
    section(5, "다섯 가지 이동 시간창 지표",
            '<p>WhitepaperReference는 참고 기준입니다. 기준 도달만으로 도구·행위 주체·침해 여부를 결정하지 않습니다. '
            '각 출발지와 목적 서비스별 [시작, 끝) 최대값이며 같은 시각 기록에는 선후관계를 부여하지 않습니다.</p>'
            '<table class="metrics"><caption>표 1. 저장된 지표와 적용 기준</caption><thead><tr>'
            + "".join(f"<th>{x}</th>" for x in ("지표 / 시간창", "값", "자료 상태 / 기준 비교", "참고 / 적용 기준", "대상 / 제외", "시간 범위", "최대 구간 / 대상"))
            + "</tr></thead><tbody>" + "".join(metric_rows) + "</tbody></table>"
            + table(["동반 조건 충족 구간", "저장값", "시작 (포함)", "끝 (제외)", "대상 / 근거"], [
                [m.get("label"), f'UA {m["qualifying_window"]["value"]} / 404 {m["qualifying_window"]["status404"]}',
                 m["qualifying_window"].get("start"), m["qualifying_window"].get("end_exclusive"),
                 [m["qualifying_window"].get("src_ip"), m["qualifying_window"].get("service"), m["qualifying_window"].get("evidence_ids")]]
                for m in obs.get("metrics") or [] if m.get("qualifying_window")])
            + '<p class="muted">UA 최대값과 404 동반 조건을 만족한 창이 다르면 별도 구간으로 표시합니다.</p>'
            + '<p class="muted">미수집 값은 0으로 치환하지 않습니다. 반복 요청의 쿼리는 보존하며 요청 본문 동등성을 주장하지 않습니다.</p>')
    section(6, "조건부 신호와 근거", table(["신호", "상태 / 건수", "자료 / 확인 방법", "조건", "한계", "근거 ID"], [
        [x.get("label"), [STATE.get(x.get("state"), x.get("state")), x.get("count")],
         [x.get("source"), STATE.get(x.get("verification"), x.get("verification")), x.get("rule_ids")], x.get("conditions"), x.get("limits"), x.get("evidence_ids")]
        for x in obs.get("indicators") or []]))
    followup_blocks = []
    for followup in obs.get("followups") or []:
        rows = [
            ["질문 버전", followup.get("question_version")],
            ["적용 조건", followup.get("condition") or followup.get("conditions")],
            ["질문", followup.get("question")], ["필요 자료", followup.get("needed_data")],
            ["허용된 확인 행동", followup.get("allowed_actions")],
            ["해결 조건", followup.get("resolution_criteria")],
            ["미해결 시 처리", followup.get("if_unresolved")],
            ["금지 단정", followup.get("forbidden_claims")],
            ["확인 내용", followup.get("items")],
        ]
        rows = [[label, "이 저장 결과에는 미기록" if value is None else value] for label, value in rows]
        followup_blocks.append("<h3>" + text(followup.get("label") or followup.get("target") or "추가 확인")
                               + "</h3>" + table(["항목", "저장된 후속확인"], rows))
    section(7, "후속확인과 해석 한계", items(obs.get("limits")) + "".join(followup_blocks))
    checks = [c for c in analyst_checks or [] if c.get("state", "active") == "active"
              and (c.get("behavior") or {}).get("result_id") == result_dto.get("id")]
    section(8, "분석가 해석과 확인 기록",
            '<p>아래 내용은 현재 활성 확인 기록의 분석가 해석입니다. 위 계산된 관측값과 분리되며 저장된 측정값을 바꾸지 않습니다.</p>'
            + (table(["기록 / 작성자", "답변 상태 / 판단", "근거·메모", "후속확인"], [
                [[c.get("id"), c.get("author") or c.get("author_name")],
                 [STATE.get((c.get("behavior") or {}).get("answer_status"), (c.get("behavior") or {}).get("answer_status")),
                  STATE.get(c.get("judgement"), c.get("judgement"))], c.get("note"),
                 (c.get("behavior") or {}).get("follow_up")] for c in checks])
               if checks else '<p class="muted">이 저장 결과에 연결된 활성 확인 기록 없음</p>'))
    selected = saved.get("selected_evidence") or []
    section(9, "재현 정보와 출처",
            table(["항목", "저장값"], [
                ["결과 SHA-256", result_dto.get("result_sha256")], ["방법 정의", saved.get("methodology")],
                ["적용 프로필", profile], ["입력 출처 요약", {"data_epoch": manifest.get("data_epoch"), "evidence_count": len(manifest.get("evidence") or []), "file_count": len(files), "source_job_count": len(manifest.get("source_jobs") or [])}],
                ["실행 한도", execution.get("limits")]])
            + table(["입력 파일 ID", "원본 파일 지문", "처리 지문"], [
                [f.get("id"), f.get("sha256"), (f.get("processing_run") or {}).get("run_digest")] for f in files[:60]])
            + table(["대표 근거 ID", "가려진 관측 지문", "캡처 원문 지문", "원문 지문 범위"], [
                [x.get("event_id"), x.get("sha256"), x.get("raw_sha256"),
                 {"basis": (x.get("source") or {}).get("raw_hash_basis"), "bytes": (x.get("source") or {}).get("raw_bytes_hashed")}]
                for x in selected[:60]])
            + f'<p class="muted">대표 근거 {len(selected)}건 중 최대 60건의 지문을 표시합니다. '
            '원문 확인은 조사 권한과 원본 자료 보존 상태를 따릅니다. Theori ARTEX 백서의 분석 구조와 참고 기준을 활용하며 '
            '백서 실험 결과와 로고는 포함하지 않습니다. 모든 수치와 도표는 위 저장 버전의 관측 결과입니다.</p>')
    css = """@page{size:A4;margin:14mm 13mm}*{box-sizing:border-box}body{font-family:Arial,'Malgun Gothic',sans-serif;color:#172f3c;font-size:10px;line-height:1.55;margin:0}header{border-bottom:3px solid #246581;padding:0 0 12px;margin:0 0 18px}h1{font-size:24px;margin:5px 0}h2{font-size:14px;margin:20px 0 8px;border-bottom:1px solid #cad4da;padding-bottom:5px}p{margin:6px 0}section{break-inside:auto}h2{break-after:avoid}h3{font-size:11px;break-after:avoid;margin:10px 0 5px}table{width:100%;border-collapse:collapse;table-layout:fixed;margin:8px 0;overflow-wrap:anywhere}tr,figure{break-inside:avoid}thead{display:table-header-group}th,td{border:1px solid #d6dfe3;text-align:left;vertical-align:top;padding:5px}th{background:#ecf2f5;font-weight:600}caption,figcaption{text-align:left;color:#526775;font-size:9px;margin:5px 0}svg{width:100%;height:auto}figure{margin:8px 0}.muted{color:#526775}.warning{border-left:3px solid #a65c16;padding:7px;background:#fff4df}.metrics{font-size:9px}.metrics th:nth-child(1){width:15%}.metrics th:last-child{width:23%}footer{margin-top:18px;border-top:1px solid #cad4da;font-size:9px;color:#526775}@media screen{body{max-width:900px;margin:28px auto;padding:20px;background:#fff}}"""
    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>행위 분석 보고서 · v' + text(result_dto.get("version")) + "</title><style>"
            + css + "</style></head><body><header><p>SAW · 조사 관측 보고서</p>"
            '<h1>웹 행위 분석</h1><p>저장된 계산 결과 · 분석가 확인 기록</p></header>'
            + "".join(sections) + '<footer>SAW · 계산된 관측값과 분석가 해석을 구분한 보고서 · 시각 UTC</footer></body></html>')
