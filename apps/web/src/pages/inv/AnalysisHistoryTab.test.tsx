import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { AnalysisHistoryTab } from "./AnalysisHistoryTab";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); useInvStore.setState({ byInv: {} }); });
const run = { id: "r2", version: 2, status: "completed", scope: { evidence_ids: ["ev1"] }, summary: {}, created_at: "2026-10-20T00:00:00Z", input_sha256: "input-sha", findings: [], executions: [
  { detector_id: "fw.observation", status: "completed", detector_version: "1", input_count: 3, match_count: 1, detail: { counts: { records: 3, sessions: 1, new_connections: 1, deny_attempts: 0, unresolved_records: 0, omitted_sessions: 2, omitted_candidates: 0 }, sessions: [{ src_to_dst_bytes: 300, dst_to_src_bytes: 1200, duration_seconds: 60, event_refs: ["evt1", "evt2"] }], candidates: [], limits: { max_sessions: 100 }, quality: { unknown_actions: 0 } } },
  { detector_id: "unavailable", status: "failed", input_count: null, match_count: null, detail: { reason: "필드 미수집" } },
] };
const routes = (extra = {}) => ({
  "GET /investigations/i1/analysis-runs": [200, { runs: [run], next_before_version: 2 }],
  "GET /investigations/i1/analysis-runs/r2": [200, run],
  "GET /source-context/org-units": [200, []],
  "GET /source-context/investigations/i1/devices": [200, []],
  "GET /investigations/i1/report-versions": [200, { reports: [] }], ...extra,
}) as any;
describe("analysis history", () => {
  it("renders record versus session counters and preserves unavailable counts", async () => {
    mockApi(routes()); renderUI(<AnalysisHistoryTab inv="i1" />);
    expect(await screen.findByRole("row", { name: /기록.*3/ })).toBeTruthy();
    expect(screen.getByRole("row", { name: /^세션 1$/ })).toBeTruthy();
    expect(screen.getByRole("row", { name: /unavailable.*실패.*미확인/ })).toBeTruthy();
    expect(screen.getByText("300")).toBeTruthy(); expect(screen.getByText("1,200")).toBeTruthy();
    expect(screen.getByText(/max_sessions/)).toBeTruthy();
  });
  it("drills down using pinned event references instead of current filters", async () => {
    useInvStore.getState().set("i1", { filters: [{ field: "src_ip", op: "is", value: "192.0.2.4" }] });
    mockApi(routes()); renderUI(<AnalysisHistoryTab inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: "세션 1 근거 원문" }));
    expect(useInvStore.getState().get("i1")).toMatchObject({ tab: "raw", time: null, filters: [{ field: "event_id", op: "in", value: ["evt1", "evt2"] }] });
  });
  it("loads older history and saves a report bound to the selected run", async () => {
    const api = mockApi(routes({ "GET /investigations/i1/analysis-runs": (c: any) => [200, c.url.includes("before_version=2") ? { runs: [{ ...run, id: "r1", version: 1 }], next_before_version: null } : { runs: [run], next_before_version: 2 }], "GET /investigations/i1/analysis-runs/r1": [200, { ...run, id: "r1", version: 1 }], "POST /investigations/i1/report-versions": [201, { id: "report1", version: 1, content_sha256: "report-sha" }] }));
    renderUI(<AnalysisHistoryTab inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: "이전 분석 더 보기" }));
    await screen.findByRole("option", { name: /v1/ });
    fireEvent.change(screen.getByLabelText("분석 실행 선택"), { target: { value: "r1" } });
    await waitFor(() => expect(api.find("GET", "/investigations/i1/analysis-runs/r1")).toHaveLength(1));
    fireEvent.click(await screen.findByRole("button", { name: "선택 실행 HTML 보고서 저장" }));
    expect(await screen.findByRole("link", { name: /저장 보고서 v1/ })).toHaveProperty("href", expect.stringContaining("/report-versions/report1/html"));
    expect(api.find("POST", "/investigations/i1/report-versions")[0].body).toEqual({ analysis_run_id: "r1" });
  });
  it("does not invent results for an investigation without runs", async () => {
    mockApi(routes({ "GET /investigations/i1/analysis-runs": [200, { runs: [], next_before_version: null }] }));
    renderUI(<AnalysisHistoryTab inv="i1" />);
    expect(await screen.findByText(/저장된 분석 실행이 없습니다/)).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });
  it("shows a report failure without a download link", async () => {
    mockApi(routes({ "POST /investigations/i1/report-versions": [409, { detail: "실행 완료 전 저장 불가" }] }));
    renderUI(<AnalysisHistoryTab inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: "선택 실행 HTML 보고서 저장" }));
    expect(await screen.findByText(/실행 완료 전 저장 불가/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: /저장 보고서 v/ })).toBeNull();
  });
});

it("renders complete execution counts and object references from the native API", async () => {
  mockApi(routes({ "GET /investigations/i1/analysis-runs/r2": [200, { ...run, status: "complete", executions: [{ ...run.executions[0], status: "complete", detail: { ...run.executions[0].detail, sessions: [{ src_to_dst_bytes: 300, dst_to_src_bytes: 1200, event_refs: [{ event_id: "native-e1", evidence_id: "ev1" }] }] } }] }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  expect(await screen.findByRole("row", { name: /fw.observation 1 완료 3 1/ })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "세션 1 근거 원문" }));
  expect(useInvStore.getState().get("i1").filters).toEqual([{ field: "event_id", op: "in", value: ["native-e1"] }]);
});

it("launches a service-free scoped analysis with explicit device, organization and visible filters", async () => {
  useInvStore.getState().set("i1", { filters: [{ field: "action", op: "is", value: "allowed" }], time: { start: "2026-10-20T00:00:00Z", end: "2026-10-21T00:00:00Z" } });
  const api = mockApi(routes({
    "GET /source-context/org-units": [200, [{ id: "oa", display_name: "가상 A사" }]],
    "GET /source-context/investigations/i1/devices": [200, [{ id: "d1", display_name: "가상 FW-01" }]],
    "POST /investigations/i1/analysis-runs": [202, { id: "job-scope", state: "ANALYZING" }],
    "GET /jobs/job-scope": [200, { id: "job-scope", state: "ANALYZING", events_done: 3 }],
  }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  await screen.findByRole("option", { name: "가상 FW-01" });
  fireEvent.change(screen.getByLabelText("분석 관계사"), { target: { value: "oa" } });
  fireEvent.change(screen.getByLabelText("분석 장비"), { target: { value: "d1" } });
  fireEvent.click(screen.getByRole("button", { name: "선택 범위로 장비 분석 실행" }));
  expect(await screen.findByRole("link", { name: "분석 작업 보기" })).toHaveProperty("href", expect.stringContaining("/jobs/job-scope"));
  expect(api.find("POST", "/investigations/i1/analysis-runs")[0].body).toEqual({ org_unit_id: "oa", device_id: "d1", filters: [{ field: "action", op: "is", value: "allowed" }], time: { start: "2026-10-20T00:00:00Z", end: "2026-10-21T00:00:00Z" } });
});

it("does not display fallback zero counts for a failed firewall execution", async () => {
  mockApi(routes({ "GET /investigations/i1/analysis-runs/r2": [200, { ...run, status: "failed", executions: [{ ...run.executions[0], status: "failed", input_count: 0, match_count: 0, detail: { counts: { records: 0, sessions: 0 } } }] }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  expect(await screen.findByRole("row", { name: /^기록 미확인$/ })).toBeTruthy();
  expect(screen.getByRole("row", { name: /^세션 미확인$/ })).toBeTruthy();
});
it("surfaces scoped analysis rejection without opening a job", async () => {
  mockApi(routes({ "POST /investigations/i1/analysis-runs": [403, { detail: "해당 장비 분석 권한 없음" }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  fireEvent.click(screen.getByRole("button", { name: "선택 범위로 장비 분석 실행" }));
  expect(await screen.findByText(/해당 장비 분석 권한 없음/)).toBeTruthy();
  expect(screen.queryByRole("link", { name: "분석 작업 보기" })).toBeNull();
});

it("treats the native COMPLETED job state as terminal and allows another launch", async () => {
  const api = mockApi(routes({ "POST /investigations/i1/analysis-runs": [202, { id: "native-complete", state: "QUEUED" }], "GET /jobs/native-complete": [200, { id: "native-complete", state: "COMPLETED", events_done: 3 }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  await screen.findByRole("row", { name: /unavailable.*실패/ });
  fireEvent.click(screen.getByRole("button", { name: "선택 범위로 장비 분석 실행" }));
  await screen.findByRole("link", { name: "분석 작업 보기" });
  await waitFor(() => expect(screen.getByRole("status").textContent).toContain("완료"));
  expect((screen.getByRole("button", { name: "선택 범위로 장비 분석 실행" }) as HTMLButtonElement).disabled).toBe(false);
  await waitFor(() => expect(api.find("GET", "/investigations/i1/analysis-runs").length).toBeGreaterThan(1));
  await waitFor(() => expect(api.find("GET", "/investigations/i1/analysis-runs/r2").length).toBeGreaterThan(1));
});

it("refreshes the selected run detail after a native job completes", async () => {
  const api = mockApi(routes({ "POST /investigations/i1/analysis-runs": [202, { id: "refresh-job", state: "QUEUED" }], "GET /jobs/refresh-job": [200, { id: "refresh-job", state: "COMPLETED" }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  await screen.findByRole("row", { name: /unavailable.*실패/ });
  fireEvent.click(screen.getByRole("button", { name: "선택 범위로 장비 분석 실행" }));
  await waitFor(() => expect(api.find("GET", "/investigations/i1/analysis-runs/r2").length).toBeGreaterThan(1));
});
it("renders actual backend transfer and long-flow candidate names in Korean", async () => {
  mockApi(routes({ "GET /investigations/i1/analysis-runs/r2": [200, { ...run, executions: [{ ...run.executions[0], detail: { ...run.executions[0].detail, candidates: [{ kind: "transfer_asymmetry", event_refs: ["evt1"] }, { kind: "long_flow", event_refs: ["evt2"] }] } }] }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  expect(await screen.findByText("전송 비대칭 후보")).toBeTruthy();
  expect(screen.getByText("장기 연결 후보")).toBeTruthy();
});

it("prioritizes FW counts and readable candidate metrics over collapsed execution structures", async () => {
  mockApi(routes({ "GET /investigations/i1/analysis-runs/r2": [200, { ...run, executions: [
    { ...run.executions[0], detail: { ...run.executions[0].detail, counts: { records: 9, sessions: 1, new_connections: 1, deny_attempts: 6, candidates: 1 }, candidates: [{ kind: "scan", event_refs: ["evt1"], metrics: { unique_destinations: 6, unique_ports: 8 } }] } },
    { detector_id: "http.not-applicable", status: "not_applicable", detail: { reason: "no HTTP input" } },
  ] }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  const records = await screen.findByRole("row", { name: /^기록 9$/ });
  expect(screen.getByRole("row", { name: /^세션 1$/ })).toBeTruthy();
  expect(screen.getByRole("row", { name: /^거부 시도 6$/ })).toBeTruthy();
  expect(screen.getByRole("row", { name: /^SAW 후보 1$/ })).toBeTruthy();
  expect(screen.getByRole("row", { name: /^시작 기록이 있는 접속 1$/ })).toBeTruthy();
  expect(screen.queryByText("검증된 새 연결")).toBeNull();
  expect(screen.getByText("서로 다른 목적지")).toBeTruthy();
  expect(screen.getByText("서로 다른 포트")).toBeTruthy();
  expect((screen.getByText("후보 구조 상세").closest("details") as HTMLDetailsElement).open).toBe(false);
  expect(screen.queryByRole("row", { name: /http.not-applicable/ })).toBeNull();
  expect(records.compareDocumentPosition(screen.getByText(/탐지기 실행 상태 —/)) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "적용 불가 탐지기 1개 보기" }));
  expect(screen.getByRole("row", { name: /http.not-applicable/ })).toBeTruthy();
  const details = screen.getAllByText("품질·계산 한도·적용 기준·미실행 사유").map(node => node.closest("details"));
  expect(details.every(node => !node?.open)).toBe(true);
});

it.each([
  ["failed", { error_type: "TimeoutError", reason: "synthetic_timeout" }, "미확인", "TimeoutError"],
  ["not_applicable", { reason: "required_source_missing" }, "미확인", "required_source_missing"],
  ["complete", { quality: {} }, "0개", "quality"],
])("keeps %s firewall diagnostic details and distinguishes missing quality from zero", async (status, diagnostic, quality, retainedText) => {
  mockApi(routes({ "GET /investigations/i1/analysis-runs/r2": [200, { ...run, executions: [{ ...run.executions[0], status, detail: diagnostic }] }] }));
  renderUI(<AnalysisHistoryTab inv="i1" />);
  expect(await screen.findByText(`품질 확인 항목 ${quality}`)).toBeTruthy();
  const details = screen.getByText("품질·계산 한도·적용 기준·미실행 사유").closest("details")!;
  expect(details.open).toBe(false);
  expect(details.textContent).toContain(retainedText);
});
