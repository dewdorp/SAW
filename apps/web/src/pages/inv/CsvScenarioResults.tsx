import { fmtNum } from "../../lib/format";

const STATUS: Record<string, string> = {
  complete: "완료", completed: "완료", completed_match: "완료·후보 있음", completed_no_match: "완료·조건 적중 없음",
  partial: "일부 처리", limited: "한도 도달", failed: "실패", cancelled: "취소", running: "실행 중",
  skipped: "미실행", not_applicable: "적용 불가", insufficient_data: "자료 부족",
};
const FIELDS: Record<string, string> = {
  timestamp: "탐지시간 · 해석 가능한 시각", source_ip: "출발지IP · 유효 IP", destination_ip: "목적지IP · 유효 IP",
  opaque_destination: "목적지IP · 불투명 식별값", http_request: "요청헤더 · HTTP 요청 표기(요약 포함)", http_request_line: "완전한 HTTP 요청행 표기", http_request_summary: "메서드·경로 요약 표기", http_response: "응답값 · 유효 HTTP 응답 코드",
  session_id: "세션ID", reported_alert: "공격명 · 원천 장비의 경보 분류", verified_context: "확인된 원천 맥락",
  verified_counters: "확인된 방향 카운터 의미", verified_time: "확인된 시간 의미", record_kind: "확인된 세션 기록 종류",
};
const LIMITATIONS: Record<string, string> = {
  no_ground_truth: "이 자료만으로 정오탐 정답을 알 수 없습니다.",
  collection_scope_requires_confirmation: "수집 범위·필터·손실 여부는 별도 확인이 필요합니다.",
  unverified_context: "원천 맥락이 확인되지 않은 기록이 있습니다.",
  unverified_counter_semantics: "송신바이트·수신바이트의 방향·누적/차분 의미를 확인해야 합니다.",
  unverified_time_semantics: "세션시간 단위와 장비 시각 의미를 확인해야 합니다.",
  missing_record_kind: "세션 시작·중간·종료 종류가 확인되지 않은 기록이 있습니다.",
  missing_session_id: "세션ID가 없는 기록이 있습니다.", missing_timestamp: "해석 가능한 탐지시간이 없는 기록이 있습니다.",
  opaque_destination: "불투명 목적지에서 국가·내부망·실제 IP를 추정할 수 없습니다.",
  reported_alert_is_not_truth: "공격명은 원천 장비의 주장입니다. 허용·탐지·HTTP 200도 침해 성공이나 정답을 뜻하지 않습니다.",
  multiple_source_devices: "여러 장비가 섞인 내보내기는 검증된 단일 프로필을 적용하기 전에 장비별로 분리해 확인하세요.",
  not_all_rows_are_http: "모든 기록이 HTTP 요청은 아닙니다. 연결 기록과 HTTP 요청을 구분하세요.",
};
const SCENARIO_STATUS: Record<string, string> = { matched_candidate: "흐름 후보 있음", no_chain: "연결 조건 적중 없음", insufficient_evidence: "단계 근거 부족" };
const ROLES: Record<string, string> = { source: "출발지", destination: "목적지", any: "전체 역할" };
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? fmtNum(value) : "미기록";
const amount = (value: unknown, unit = "건") => count(value) === "미기록" ? "미기록" : `${count(value)}${unit}`;
const text = (value: unknown) => typeof value === "string" && value ? value : "미기록";
const rows = (value: unknown): any[] => Array.isArray(value) ? value.filter(row => row && typeof row === "object") : [];
const complete = (status: string) => ["complete", "completed", "completed_match", "completed_no_match"].includes(status);

export function CsvScenarioResults({ executions, onFindings, onSourceContext }: { executions: any[]; onFindings: () => void; onSourceContext: () => void }) {
  const csvExecution = executions.find(row => row.detector_id === "csv.readiness");
  const flowExecution = executions.find(row => row.detector_id === "scenario.flow");
  const csv = csvExecution?.detail?.schema === "csv-readiness/1" ? csvExecution.detail : null;
  const flow = flowExecution?.detail?.schema === "scenario-execution/1" ? flowExecution.detail : null;
  const upstream = executions.filter(row => !["csv.readiness", "scenario.flow"].includes(row.detector_id) && !complete(row.status));
  return <>
    <section aria-label="CSV 자료 준비도" className="panel pb col" style={{ gap: 12 }}>
      <h4>CSV 자료 준비도 · {STATUS[csvExecution?.status] || "상태 미기록"}</h4>
      <p className="small muted">이 실행에 저장된 형식·필드 검사입니다. 자료 준비도는 탐지 실행·정오탐 정답·침해 여부 판정과 별개입니다. 메서드·경로 요약 표기는 실제 패킷·HTTP 버전의 증명이 아닙니다.</p>
      {!csv ? <p>CSV 준비도 상세 미기록. 현재 자료로 과거 결과를 재계산하지 않습니다.</p> : <>
        <div>검사한 기록 {amount(csv.counts?.records)} / 형식 일치 전체 {amount(csv.input_records)}</div>
        <div className="small">{csv.limits?.coverage_complete === false || ["partial", "cancelled", "limited"].includes(csv.status) || ["partial", "cancelled", "limited", "failed"].includes(csvExecution.status)
          ? "일부만 검사했습니다. 아래 집계는 검사한 기록에 한정됩니다."
          : csv.limits?.coverage_complete === true && complete(csvExecution.status) ? "설정된 실행 범위의 형식 일치 기록 검사 완료. 수집의 완전성은 별도 확인이 필요합니다."
          : "검사 범위 완료 여부 미기록. 전체 검사 완료로 해석할 수 없습니다."} · 기록 검사 상한 {amount(csv.limits?.max_records)}</div>
        {rows(csv.formats).map((format, index) => <article key={index} className="col" style={{ gap: 8 }}>
          <h5>{({ fw: "FW CSV", ndr: "NDR CSV" } as Record<string, string>)[format.format] || "CSV 형식 미기록"} · 검사 {amount(format.records)} · 원천 장비 표기 {amount(format.source_devices, "종")}</h5>
          {format.source_devices_limited === true && <p className="small">장비 수 집계 상한에 도달했습니다. 표시한 장비 수는 최소 관측 수입니다.</p>}
          <div style={{ overflowX: "auto" }}><table className="t"><caption>필드별 해당 기록 / 검사한 기록</caption><thead><tr><th>필드·확인 항목</th><th>기록 수</th></tr></thead><tbody>{Object.entries(FIELDS).map(([key, label]) => <tr key={key}><th>{label}</th><td>{count(format.fields?.[key])} / {count(format.records)}</td></tr>)}</tbody></table></div>
          {Array.isArray(format.limitations) && format.limitations.length > 0 && <ul className="small muted">{format.limitations.map((code: unknown, i: number) => <li key={i}>{typeof code === "string" && LIMITATIONS[code] || "해석할 수 없는 추가 제한 항목이 저장되어 있습니다."}</li>)}</ul>}
        </article>)}
        {!rows(csv.formats).length && <p>저장된 형식별 검사 결과가 없습니다. 입력·검사 건수와 실행 상태를 함께 확인하세요.</p>}
      </>}
      <p className="small muted">원문 장비IP·그룹명은 내부 장비 식별이나 장비 간 동일 자산을 증명하지 않습니다. 수집 범위·계측 의미가 미확인이면 그대로 미확인으로 남습니다.</p>
      <button className="btn sm" onClick={onSourceContext}>장비·자료 의미 확인</button>
    </section>
    <section aria-label="시나리오 실행 결과" className="panel pb col" style={{ gap: 12 }}>
      <h4>시나리오 실행 결과 · {STATUS[flowExecution?.status] || "상태 미기록"}</h4>
      <p className="small muted">이 실행에 고정된 탐지 결과와 시나리오 묶음의 실제 연관 검사입니다. 무적중·단계 근거 부족은 정상이나 오탐 정답이 아닙니다. 최종 판정은 분석가가 근거 원문·수집 범위·장비 의미를 확인해 남깁니다.</p>
      {upstream.length > 0 && <div role="note" aria-label="상위 탐지 실행 한계" className="small"><b>상위 탐지기의 실패·부분 처리·미실행·자료 부족을 함께 확인하세요. 이 실행의 흐름 결과를 정상·정오탐 정답으로 해석할 수 없습니다.</b><details><summary>완료로 기록되지 않은 상위 실행 {upstream.length}개</summary><ul>{upstream.map((row, index) => <li key={index}>{text(row.detector_id)} · {STATUS[row.status] || "상태 미확인"}</li>)}</ul></details></div>}
      {!flow ? <p>시나리오 실행 상세 미기록. 현재 자료로 과거 결과를 재계산하지 않습니다.</p> : <>
        <div>입력 탐지 {amount(flow.counts?.input_findings)} · 조건 검토 대상 {amount(flow.counts?.eligible_findings)} · 제외 {amount(flow.counts?.excluded_findings)}</div>
        <div className="small">엔진 버전 {text(flow.engine_version)} · 시나리오 묶음 SHA256 <span className="mono" style={{ overflowWrap: "anywhere" }}>{text(flow.pack_sha256)}</span></div>
        <p className="small muted">시나리오별 출력 상한 {amount(flow.max_results_per_scenario)}. 후보 수는 연관 검사기가 반환한 표시 결과이며 전체 가능한 연결 수가 아닙니다.</p>
        {rows(flow.scenarios).map((scenario, index) => <article className="panel pb col" key={index} style={{ gap: 8 }}>
          <h5 style={{ overflowWrap: "anywhere" }}>{text(scenario.title)} · <span className="mono">{text(scenario.id)}</span></h5>
          <b>{SCENARIO_STATUS[scenario.status] || "결과 상태 미기록"}</b>
          <div>표시된 흐름 후보 {amount(scenario.match_count)}</div>
          <div className="small">최대 시간창 {amount(scenario.max_span_seconds, "초")} · 주소 역할 {ROLES[scenario.entity_role] || "미기록"} · 엄격한 시간 순서 {scenario.strict_order === true ? "적용" : scenario.strict_order === false ? "미적용" : "미기록"}</div>
          <table className="t"><caption>단계별 조건에 맞는 탐지 근거 수</caption><thead><tr><th>단계</th><th>탐지 근거</th></tr></thead><tbody>{rows(scenario.steps).map((step, i) => <tr key={i}><th style={{ overflowWrap: "anywhere" }}>{text(step.name)}</th><td>{count(step.eligible_findings)}</td></tr>)}</tbody></table>
          <p className="small muted">단계별 건수는 서로 겹칠 수 있으며 하나의 연결·동일 자산·공격 순서가 성립했다는 뜻은 아닙니다.</p>
          {typeof scenario.explain === "string" && scenario.explain && <p className="small">{scenario.explain}</p>}
          {typeof scenario.next_step === "string" && scenario.next_step && <div role="note" aria-label="지금 할 일" className="small"><b>지금 할 일 </b>{scenario.next_step}</div>}
          {Array.isArray(scenario.missing_steps) && scenario.missing_steps.length > 0 && <div className="small">근거 없는 단계: {scenario.missing_steps.filter((name: unknown) => typeof name === "string").join(", ")}</div>}
          {Array.isArray(scenario.checks) && scenario.checks.length > 0 && <details><summary className="small">확인 항목 {scenario.checks.length}개</summary><ul className="small">{scenario.checks.map((item: unknown, i: number) => typeof item === "string" ? <li key={i}>{item}</li> : null)}</ul></details>}
        </article>)}
        {!rows(flow.scenarios).length && <p>저장된 시나리오별 결과가 없습니다. 0건 적중이나 정상으로 해석할 수 없습니다.</p>}
        {Array.isArray(flow.limitations) && flow.limitations.map((line: unknown, index: number) => typeof line === "string" ? <p className="small muted" key={index}>{line}</p> : null)}
      </>}
      <p className="small muted">선택한 실행의 탐지 스냅샷은 이력 아래에서 확인할 수 있습니다. 현재 탐지 결과는 선택한 과거 실행과 다를 수 있습니다. 원문은 실제 저장된 탐지 근거 참조에서 확인하세요.</p>
      <button className="btn sm" onClick={onFindings}>현재 탐지 결과에서 근거 확인</button>
    </section>
  </>;
}