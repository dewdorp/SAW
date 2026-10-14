import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { Assistant } from "./Assistant";

const status = { available: true, provider: "llama_cpp", model: "synthetic/model-a", is_llm: true, synthetic_only: true, detail: "CPU 합성 시험용" };
const context = {
  scope: { investigation_id: "i1", finding_id: "f1", finding_display_id: "FND-1", time: { start: "2026-10-14T01:00:00Z", end: "2026-10-14T01:15:00Z" }, query_available: true, matched_events: 80, sampled_events: 1, sample_limit: 20, truncated: true },
  finding: { display_id: "FND-1", title: "요청과 오류 동시 증가", risk_level: "medium", metrics: [{ name: "requests", label: "요청 건수", observed: 80, baseline: { min: 8, max: 12, median: 10, source: "앞선 90분" } }], checks: [], attack: [] },
  observations: ["요청 80건과 오류 증가를 관측했습니다."], alternatives: ["정상 배치와 자동 재시도 가능성을 확인하세요."],
  next_checks: ["작업 일정과 서버 오류 기록을 비교하세요."], limitations: ["침해 성공은 확인되지 않았습니다."],
  citations: [{ id: "FND-1", type: "finding", finding_id: "f1" }, { id: "EVT-1", type: "event", event_id: "e1" }],
};
const response = {
  id: "r1", answer_md: "합성 근거를 사람이 확인해야 합니다.", citations: [{ id: "FND-1", valid: true }],
  citation_valid: true, injection_signals: [], provider: "llama_cpp", model: "synthetic/model-a", is_llm: true,
  label: "AI 생성 초안 · 사실 검토 필요", query: null, context_size: { findings: 1, samples: 1 }, latency_ms: 50,
  output_status: "validated_draft", execution_status: "executed", claim_support: "NOT_VALIDATED", output_reason: null,
  context_scope: "selected_finding", scope: context.scope,
};
beforeEach(() => { useInvStore.setState({ byInv: {} }); useInvStore.getState().set("i1", { findingId: "f1" }); });
afterEach(() => vi.unstubAllGlobals());
async function setup(result = response, health = status) {
  const api = mockApi({ "GET /ai/status": [200, health], "GET /ai/context": [200, context], "POST /ai/actions": [200, result],
    "POST /investigations/i1/notes": [200, { id: "n1" }] });
  renderUI(<Assistant inv="i1" />);
  await screen.findByText(context.observations[0]);
  fireEvent.click(await screen.findByRole("button", { name: "근거 설명" }));
  return api;
}

it("labels executed model output as an unverified draft and preserves reviewed note saving", async () => {
  const api = await setup();
  expect(await screen.findByText("실제 모델 추론 실행됨")).toBeTruthy();
  expect(screen.getByText("AI 생성 초안 · 사실 검토 필요")).toBeTruthy();
  expect(screen.getByText(/문장별 사실 근거는 검증되지 않았습니다/)).toBeTruthy();
  expect(screen.getByText(/합성 데이터 전용/)).toBeTruthy();
  expect(screen.getByText(response.answer_md)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "노트로 저장" }));
  await waitFor(() => expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(1));
  expect(api.find("POST", "/investigations/i1/notes")[0].body.links).toEqual(["FND-1"]);
  expect(await screen.findByText("노트에 저장했습니다.")).toBeTruthy();
});

it.each(["invalid_structure", "invalid_citations"])("hides rejected output and blocks note saving for %s", async (reason) => {
  const api = await setup({ ...response, output_status: "rejected", output_reason: reason as any,
    answer_md: "REJECTED-BODY-SHOULD-NOT-RENDER", citation_valid: false,
    label: "AI 출력 검증 실패 · 답변 미채택" });
  expect(await screen.findByText("AI 출력 검증 실패 · 답변 미채택")).toBeTruthy();
  expect(screen.getByText("실제 모델 추론 실행됨")).toBeTruthy();
  expect(screen.getByText(/답변을 표시하거나 저장하지 않습니다/)).toBeTruthy();
  expect(screen.queryByText("REJECTED-BODY-SHOULD-NOT-RENDER")).toBeNull();
  const save = screen.getByRole("button", { name: "노트로 저장" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);
  fireEvent.click(save);
  expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(0);
});

it("distinguishes a deterministic template from actual model inference", async () => {
  await setup({ ...response, is_llm: false, provider: "template", model: "template-v1",
    label: "오프라인 템플릿 (LLM 아님)", output_status: "template", execution_status: "not_applicable", claim_support: "DETERMINISTIC_TEMPLATE" },
    { ...status, is_llm: false, provider: "template", model: "template-v1", synthetic_only: false });
  expect(await screen.findByText("템플릿 생성 · LLM 추론 없음")).toBeTruthy();
  expect(screen.queryByText("실제 모델 추론 실행됨")).toBeNull();
  expect(screen.queryByText("AI 생성 초안 · 사실 검토 필요")).toBeNull();
  expect(screen.getByText(response.answer_md)).toBeTruthy();
});


it.each([
  ["cpu_context_limit", 400, "입력 크기가 CPU 모델의 한도를 넘었습니다"],
  ["cpu_wall_budget", 400, "CPU 추론이 허용된 실행 시간을 넘겨 중지되었습니다"],
  ["cpu_output_limit", 400, "CPU 실행기의 출력 크기가 허용 한도를 넘어 중지되었습니다"],
  ["cpu_cancelled", 400, "CPU 추론 요청이 취소되어 답변을 표시하지 않습니다"],
  ["cpu_native_failed", 400, "CPU 실행기가 정상적으로 종료되지 않았습니다"],
  ["ai_session_changed", 403, "로그인 세션이 만료되거나 변경되어 답변을 표시하지 않습니다"],
  ["local_ai_synthetic_investigation_required", 403, "합성 시험용으로 허용된 조사에서만"],
  ["ai_context_authorization_changed", 403, "참조한 지식의 승인 또는 접근 권한이 바뀌었습니다"],
  ["ai_authorization_changed", 403, "사용 권한이 변경되어 답변을 표시하지 않습니다"],
  ["model_selection_changed_output_not_published", 400, "추론 중 모델 선택이 바뀌어 답변을 표시하지 않습니다"],
])("explains %s without implying that a model answer was generated", async (code, statusCode, message) => {
  mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, context], "POST /ai/actions": [Number(statusCode), { detail: code }] });
  renderUI(<Assistant inv="i1" />);
  await screen.findByText(context.observations[0]);
  fireEvent.click(await screen.findByRole("button", { name: "근거 설명" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining(String(message)));
  expect(screen.queryByText("실제 모델 추론 실행됨")).toBeNull();
  expect(screen.queryByRole("button", { name: "노트로 저장" })).toBeNull();
});

it("shows deterministic evidence without a model and opens mapped evidence", async () => {
  const api = mockApi({ "GET /ai/status": [200, { ...status, available: false, is_llm: false, provider: "none", model: null }], "GET /ai/context": [200, context] });
  renderUI(<Assistant inv="i1" />);
  expect(await screen.findByText(context.observations[0])).toBeTruthy();
  expect(screen.getByText("근거 요약 · 모델 추론 없음")).toBeTruthy();
  expect(screen.getByText(/일치 80건 · 원문 바로가기 표본 1건/)).toBeTruthy();
  expect(screen.getByText(/주요 3개 생성은 저장된 탐지 지표를 사용하며 이벤트 원문을 전달하지 않습니다/)).toBeTruthy();
  expect(screen.getByText(context.alternatives[0])).toBeTruthy();
  expect(screen.getByText(context.next_checks[0])).toBeTruthy();
  expect((screen.getByRole("button", { name: "근거 설명" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByText("측정값·확인 결과·근거 열기"));
  expect(screen.getByText(/요청 건수: 관측 80 · 기준 8 ~ 12 · 중앙값 10/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "근거 EVT-1 열기" }));
  expect(useInvStore.getState().get("i1").eventId).toBe("e1");
  fireEvent.click(screen.getByRole("button", { name: "근거 FND-1 열기" }));
  expect(useInvStore.getState().get("i1").tab).toBe("findings");
  expect(api.find("POST", "/ai/actions")).toHaveLength(0);
});

it("requires a selected finding and does not fetch an investigation-wide preview", async () => {
  useInvStore.getState().set("i1", { findingId: null });
  const api = mockApi({ "GET /ai/status": [200, status] });
  renderUI(<Assistant inv="i1" />);
  expect(await screen.findByText(/탐지 목록에서 분석할 탐지를 선택하세요/)).toBeTruthy();
  for (const name of ["근거 설명", "추가 확인 추천", "보고서 초안"]) expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.find("GET", "/ai/context")).toHaveLength(0);
  expect(api.find("POST", "/ai/actions")).toHaveLength(0);
});

it("distinguishes unreviewed checks from failed and satisfied conditions", async () => {
  mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, { ...context,
    finding: { ...context.finding, checks: [
      { label: "수집 연속성", passed: null, value: null },
      { label: "충족한 조건", passed: true, value: 80 },
      { label: "미충족 조건", passed: false, value: 0 },
    ] },
  }] });
  renderUI(<Assistant inv="i1" />);
  await screen.findByText(context.observations[0]);
  fireEvent.click(screen.getByText("측정값·확인 결과·근거 열기"));
  expect(screen.getByText("수집 연속성: 미확인 · 자료 없음")).toBeTruthy();
  expect(screen.getByText("충족한 조건: 조건 충족 · 80")).toBeTruthy();
  expect(screen.getByText("미충족 조건: 조건 미충족 · 0")).toBeTruthy();
  expect(screen.queryByText(/수집 연속성: 조건 미충족/)).toBeNull();
});

it("shows an unavailable evidence query as not queried rather than zero matches", async () => {
  mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, { ...context,
    scope: { ...context.scope, query_available: false, matched_events: null, sampled_events: 0, truncated: false, time: null },
  }] });
  renderUI(<Assistant inv="i1" />);
  expect(await screen.findByText("근거 조회 범위 없음 · 조회하지 않음")).toBeTruthy();
  expect(screen.queryByText(/일치 0건/)).toBeNull();
  expect(screen.queryByText(/탐지 근거의 전체 시간 범위/)).toBeNull();
});

it("preserves a real zero count when an evidence query is available", async () => {
  mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, { ...context,
    scope: { ...context.scope, query_available: true, matched_events: 0, sampled_events: 0, truncated: false },
  }] });
  renderUI(<Assistant inv="i1" />);
  expect(await screen.findByText(/일치 0건 · 원문 바로가기 표본 0건/)).toBeTruthy();
  expect(screen.queryByText("근거 조회 범위 없음 · 조회하지 않음")).toBeNull();
});

it("keeps a status failure visible while displaying deterministic evidence", async () => {
  mockApi({ "GET /ai/status": [503, { detail: "상태 조회 실패" }], "GET /ai/context": [200, context] });
  renderUI(<Assistant inv="i1" />);
  expect(await screen.findByText(context.observations[0])).toBeTruthy();
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("상태 조회 실패"));
  expect(screen.queryByText("오프라인 템플릿 (LLM 아님)")).toBeNull();
  expect((screen.getByRole("button", { name: "근거 설명" }) as HTMLButtonElement).disabled).toBe(true);
});

it("shows a save failure without claiming success or saving automatically", async () => {
  const api = mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, context], "POST /ai/actions": [200, response], "POST /investigations/i1/notes": [500, { detail: "노트 저장 실패" }] });
  renderUI(<Assistant inv="i1" />);
  await screen.findByText(context.observations[0]);
  fireEvent.click(screen.getByRole("button", { name: "보고서 초안" }));
  await screen.findByText(response.answer_md);
  expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(0);
  fireEvent.click(screen.getByRole("button", { name: "노트로 저장" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("노트 저장 실패"));
  expect(screen.queryByText("노트에 저장했습니다.")).toBeNull();
});

it("clears a completed answer on a finding switch and never saves it in the new scope", async () => {
  const api = await setup();
  await screen.findByText(response.answer_md);
  act(() => useInvStore.getState().set("i1", { findingId: "f2" }));
  expect(screen.queryByText(response.answer_md)).toBeNull();
  expect(screen.queryByRole("button", { name: "노트로 저장" })).toBeNull();
  expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(0);
});

it.each(["mismatch", "missing"])("rejects %s server-reported scope for selected finding output", async (state) => {
  const api = await setup({ ...response, scope: state === "mismatch" ? { ...context.scope, finding_id: "f2" } : null } as any);
  expect(await screen.findByText(/선택한 탐지와 응답 범위가 다릅니다/)).toBeTruthy();
  expect(screen.queryByText(response.answer_md)).toBeNull();
  expect((screen.getByRole("button", { name: "노트로 저장" }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(0);
});

it.each(["finding", "investigation"])("ignores a late answer after the %s changes and prevents duplicate generation", async (scope) => {
  const api = mockApi({ "GET /ai/status": [200, status], "GET /ai/context": [200, context] });
  const fetch = globalThis.fetch;
  let finish!: (value: Response) => void;
  let requests = 0;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input).endsWith("/ai/actions")) { requests++; return new Promise<Response>((resolve) => { finish = resolve; }); }
    return fetch(input, init);
  }));
  function Host() {
    const inv = useInvStore((s) => s.byInv.navigation?.tab || "i1");
    return <Assistant inv={inv} />;
  }
  renderUI(<Host />);
  await screen.findByText(context.observations[0]);
  fireEvent.click(screen.getByRole("button", { name: "근거 설명" }));
  await waitFor(() => expect(requests).toBe(1));
  expect((screen.getByRole("button", { name: "추가 확인 추천" }) as HTMLButtonElement).disabled).toBe(true);
  act(() => {
    if (scope === "finding") useInvStore.getState().set("i1", { findingId: "f2" });
    else { useInvStore.getState().set("i2", { findingId: "f2" }); useInvStore.getState().set("navigation", { tab: "i2" }); }
  });
  await act(async () => { finish(new Response(JSON.stringify(response), { status: 200, headers: { "content-type": "application/json" } })); });
  expect(screen.queryByText(response.answer_md)).toBeNull();
  expect(screen.queryByRole("button", { name: "노트로 저장" })).toBeNull();
  expect(api.find("POST", "/investigations/i1/notes")).toHaveLength(0);
  expect(api.find("POST", "/investigations/i2/notes")).toHaveLength(0);
});
