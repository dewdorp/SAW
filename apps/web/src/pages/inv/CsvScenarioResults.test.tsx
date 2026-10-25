import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CsvScenarioResults } from "./CsvScenarioResults";
import { AnalysisHistoryTab } from "./AnalysisHistoryTab";
import { mockApi, renderUI } from "../../test/helpers";
import { useInvStore } from "../../context/invContext";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); useInvStore.setState({ byInv: {} }); });
const readiness = { detector_id: "csv.readiness", status: "partial", detail: {
  schema: "csv-readiness/1", status: "partial", counts: { records: 3 }, input_records: 9,
  limits: { max_records: 3, coverage_complete: false, device_count_limit: 1000 },
  formats: [{ format: "fw", records: 2, source_devices: 2, source_devices_limited: false,
    fields: { timestamp: 2, source_ip: 2, destination_ip: 1, opaque_destination: 1, verified_context: 0 },
    limitations: ["multiple_source_devices", "opaque_destination", "unverified_counter_semantics"] },
    { format: "ndr", records: 1, source_devices: 1, source_devices_limited: true,
      fields: { timestamp: 0, http_request: 1, http_response: 0, reported_alert: 1 },
      limitations: ["reported_alert_is_not_truth", "missing_timestamp", "not_all_rows_are_http"] }],
} };
const scenario = { detector_id: "scenario.flow", status: "complete", detail: {
  schema: "scenario-execution/1", engine_version: "synthetic-v1", pack_sha256: "synthetic-pack-sha",
  counts: { input_findings: 8, eligible_findings: 5, excluded_findings: 3 }, max_results_per_scenario: 2,
  scenarios: [
    { id: "synthetic-match", title: "가상 탐색 흐름", status: "matched_candidate", match_count: 2, steps: [{ name: "가상 탐색", eligible_findings: 3 }], max_span_seconds: 120, entity_role: "source", strict_order: true },
    { id: "synthetic-empty", title: "가상 연결 없음", status: "no_chain", match_count: 0, steps: [{ name: "가상 단계", eligible_findings: 2 }], max_span_seconds: 60, entity_role: "any", strict_order: false },
    { id: "synthetic-missing", title: "가상 근거 부족", status: "insufficient_evidence", match_count: 0, steps: [{ name: "누락 단계", eligible_findings: 0 }], max_span_seconds: 60, entity_role: "destination", strict_order: true },
  ],
} };
const show = (executions: any[]) => render(<CsvScenarioResults executions={executions} onFindings={() => {}} onSourceContext={() => {}} />);

describe("frozen CSV and scenario history", () => {
  it("keeps checked records distinct from total input and missing field counts distinct from zero", () => {
    show([readiness, scenario]);
    const panel = screen.getByRole("region", { name: "CSV 자료 준비도" });
    expect(within(panel).getByText("검사한 기록 3건 / 형식 일치 전체 9건")).toBeTruthy();
    expect(within(panel).getByText(/일부만 검사/)).toBeTruthy();
    expect(within(panel).getByText(/기록 검사 상한 3건/)).toBeTruthy();
    const tables = within(panel).getAllByRole("table");
    expect(within(tables[0]).getByRole("row", { name: "확인된 원천 맥락 0 / 2" })).toBeTruthy();
    expect(within(tables[0]).getByRole("row", { name: "요청헤더 · HTTP 요청 표기(요약 포함) 미기록 / 2" })).toBeTruthy();
    expect(within(tables[1]).getByRole("row", { name: "응답값 · 유효 HTTP 응답 코드 0 / 1" })).toBeTruthy();
    expect(within(tables[1]).getByRole("row", { name: "완전한 HTTP 요청행 표기 미기록 / 1" })).toBeTruthy();
    expect(within(tables[1]).getByRole("row", { name: "메서드·경로 요약 표기 미기록 / 1" })).toBeTruthy();
    expect(within(panel).getByText(/여러 장비가 섞인 내보내기는/)).toBeTruthy();
    expect(within(panel).getByText(/불투명 목적지에서 국가·내부망/)).toBeTruthy();
    expect(within(panel).getByText(/장비 수 집계 상한에 도달/)).toBeTruthy();
  });


  it("distinguishes saved full request-line and method-target summary counts without inferring packet evidence", () => {
    show([{ ...readiness, detail: { ...readiness.detail, formats: [{ format: "ndr", records: 4,
      fields: { http_request: 3, http_request_line: 2, http_request_summary: 1 } }] } }]);
    const panel = screen.getByRole("region", { name: "CSV 자료 준비도" });
    expect(within(panel).getByRole("row", { name: "요청헤더 · HTTP 요청 표기(요약 포함) 3 / 4" })).toBeTruthy();
    expect(within(panel).getByRole("row", { name: "완전한 HTTP 요청행 표기 2 / 4" })).toBeTruthy();
    expect(within(panel).getByRole("row", { name: "메서드·경로 요약 표기 1 / 4" })).toBeTruthy();
    expect(within(panel).getByText(/요약 표기는 실제 패킷·HTTP 버전의 증명이 아닙니다/)).toBeTruthy();
  });
  it("renders actual statuses and stored matcher constraints without calling no-chain normal", () => {
    show([scenario]);
    const panel = screen.getByRole("region", { name: "시나리오 실행 결과" });
    expect(within(panel).getByText("입력 탐지 8건 · 조건 검토 대상 5건 · 제외 3건")).toBeTruthy();
    expect(within(panel).getByText(/엔진 버전 synthetic-v1/)).toBeTruthy();
    expect(within(panel).getByText("synthetic-pack-sha")).toBeTruthy();
    expect(within(panel).getByRole("row", { name: "가상 탐색 3" })).toBeTruthy();
    expect(within(panel).getByText("흐름 후보 있음")).toBeTruthy();
    expect(within(panel).getByText("연결 조건 적중 없음")).toBeTruthy();
    expect(within(panel).getByText("단계 근거 부족")).toBeTruthy();
    expect(within(panel).getByText("표시된 흐름 후보 2건")).toBeTruthy();
    expect(within(panel).getByText(/전체 가능한 연결 수가 아닙니다/)).toBeTruthy();
    expect(within(panel).getByText(/최대 시간창 120초 · 주소 역할 출발지 · 엄격한 시간 순서 적용/)).toBeTruthy();
    expect(within(panel).getByText(/최종 판정은 분석가가/)).toBeTruthy();
  });

  it("leaves old or unsupported history unrecorded and does not manufacture zero", () => {
    show([{ detector_id: "csv.readiness", status: "complete", detail: { schema: "csv-readiness/9" } }, { detector_id: "scenario.flow", status: "complete" }]);
    expect(screen.getByText(/CSV 준비도 상세 미기록/)).toBeTruthy();
    expect(screen.getByText(/시나리오 실행 상세 미기록/)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
    expect(screen.getAllByText(/현재 자료로 과거 결과를 재계산하지 않습니다/)).toHaveLength(2);
  });

  it("does not turn missing totals or incomplete executions into complete zero results", () => {
    show([{ ...readiness, status: "complete", detail: { ...readiness.detail, status: "complete", input_records: undefined, limits: {} } }, scenario,
      { detector_id: "synthetic.failed", status: "failed" }, { detector_id: "synthetic.partial", status: "partial" },
      { detector_id: "synthetic.disabled", status: "skipped" }]);
    expect(screen.getByText("검사한 기록 3건 / 형식 일치 전체 미기록")).toBeTruthy();
    expect(screen.getByText(/검사 범위 완료 여부 미기록/)).toBeTruthy();
    const warning = screen.getByRole("note", { name: "상위 탐지 실행 한계" });
    expect(warning.textContent).toContain("synthetic.failed · 실패");
    expect(warning.textContent).toContain("synthetic.partial · 일부 처리");
    expect(warning.textContent).toContain("synthetic.disabled · 미실행");
    expect(warning.textContent).toContain("정상·정오탐 정답으로 해석할 수 없습니다");
  });

  it("renders untrusted scenario names as text", () => {
    const title = '<img src=x onerror="alert(1)">';
    show([{ ...scenario, detail: { ...scenario.detail, scenarios: [{ ...scenario.detail.scenarios[0], title, steps: [{ name: "<script>bad()</script>", eligible_findings: 1 }] }] } }]);
    expect(screen.getByRole("heading", { name: /<img src=x/ }).textContent).toContain(title);
    expect(screen.getByText("<script>bad()</script>")).toBeTruthy();
    expect(document.querySelector("img, script")).toBeNull();
  });

  it("connects the selected retained run to existing source and finding tabs without invented event IDs", async () => {
    const run = { id: "synthetic-run", version: 1, status: "complete", executions: [readiness, scenario], findings: [], summary: {}, scope: {} };
    mockApi({
      "GET /investigations/i1/analysis-runs": [200, { runs: [run] }],
      "GET /investigations/i1/analysis-runs/synthetic-run": [200, run],
      "GET /source-context/org-units": [200, []], "GET /source-context/investigations/i1/devices": [200, []],
      "GET /investigations/i1/report-versions": [200, { reports: [] }],
    });
    renderUI(<AnalysisHistoryTab inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: "장비·자료 의미 확인" }));
    expect(useInvStore.getState().get("i1").tab).toBe("source-context");
    fireEvent.click(screen.getByRole("button", { name: "현재 탐지 결과에서 근거 확인" }));
    expect(useInvStore.getState().get("i1")).toMatchObject({ tab: "findings", eventId: null, filters: [] });
    expect(screen.getByText(/현재 탐지 결과는 선택한 과거 실행과 다를 수 있습니다/)).toBeTruthy();
  });
});