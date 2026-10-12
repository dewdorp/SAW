import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { Assistant } from "./Assistant";

const status = { available: true, provider: "llama_cpp", model: "synthetic/model-a", is_llm: true, synthetic_only: true, detail: "CPU 합성 시험용" };
const response = {
  id: "r1", answer_md: "합성 근거를 사람이 확인해야 합니다.", citations: [{ id: "FND-1", valid: true }],
  citation_valid: true, injection_signals: [], provider: "llama_cpp", model: "synthetic/model-a", is_llm: true,
  label: "AI 생성 초안 · 사실 검토 필요", query: null, context_size: { findings: 1, samples: 1 }, latency_ms: 50,
  output_status: "validated_draft", execution_status: "executed", claim_support: "NOT_VALIDATED", output_reason: null,
};
beforeEach(() => useInvStore.setState({ byInv: {} }));
afterEach(() => vi.unstubAllGlobals());
async function setup(result = response, health = status) {
  const api = mockApi({ "GET /ai/status": [200, health], "POST /ai/actions": [200, result],
    "POST /investigations/i1/notes": [200, { id: "n1" }] });
  renderUI(<Assistant inv="i1" />);
  fireEvent.click(await screen.findByRole("button", { name: "왜 이상한가?" }));
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
  mockApi({ "GET /ai/status": [200, status], "POST /ai/actions": [Number(statusCode), { detail: code }] });
  renderUI(<Assistant inv="i1" />);
  fireEvent.click(await screen.findByRole("button", { name: "왜 이상한가?" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining(String(message)));
  expect(screen.queryByText("실제 모델 추론 실행됨")).toBeNull();
  expect(screen.queryByRole("button", { name: "노트로 저장" })).toBeNull();
});
