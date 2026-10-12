import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../App";
import { ME, mockApi, renderUI } from "../test/helpers";

const admin = { ...ME, roles: ["admin"], permissions: ["ai.models.manage"] };
const model = {
  pack_id: "cpu-test-a", model_id: "synthetic/model-a", revision: "fixed-revision",
  checkpoint_kind: "INSTRUCT", prompt_format: "chatml", quantization: "Q4_K_M",
  manifest_sha256: "a".repeat(64), status: "FILES_VERIFIED", synthetic_only: true,
  validated_at: "2026-10-12T00:00:00Z", actual_inference: "NOT_RUN", detail: "파일 검증 완료",
};
const catalog = {
  active_pack_id: null as string | null,
  runtime: { configured: true, verified: false, version: "b11429", detail: "실행 확인 전" },
  limits: { threads: 4, context: 1024, max_new_tokens: 128, max_seconds: 300, max_memory_bytes: 8589934592 },
  models: [model], synthetic_only: true,
};
function setup(extra: Parameters<typeof mockApi>[0] = {}, me = admin) {
  const api = mockApi({ "GET /auth/me": [200, me], "GET /jobs": [200, []],
    "GET /admin/local-models": [200, catalog], ...extra });
  renderUI(<App />, { route: "/admin/local-models" });
  return api;
}
afterEach(() => vi.unstubAllGlobals());

it("shows the CPU limits, file-only verification and unadopted quality without claiming inference", async () => {
  setup();
  await screen.findByRole("heading", { name: "로컬 모델 관리" });
  expect(screen.getByText(/합성 데이터 전용/)).toBeTruthy();
  expect(screen.getByText(/운영 품질 미채택/)).toBeTruthy();
  expect(await screen.findByText("cpu-test-a")).toBeTruthy();
  expect(screen.getByText("실제 추론 미실행")).toBeTruthy();
  expect(screen.getByText("런타임 미확인")).toBeTruthy();
  expect(screen.getByText(/4 스레드/)).toBeTruthy();
  expect(screen.getByText(/300초/)).toBeTruthy();
  expect(screen.getByText("a".repeat(64))).toBeTruthy();
});

it("does not fetch models or expose model actions without the management permission", async () => {
  const api = setup({}, ME);
  expect(await screen.findByText("로컬 모델 관리 권한이 필요합니다.")).toBeTruthy();
  expect(api.find("GET", "/admin/local-models")).toHaveLength(0);
  expect(screen.queryByRole("button", { name: "검증 등록" })).toBeNull();
  expect(screen.queryByRole("link", { name: "로컬 모델" })).toBeNull();
});

it("validates a pack ID from the inbox, never a supplied filesystem path", async () => {
  const api = setup({ "POST /admin/local-models/validate": [200, model] });
  const input = await screen.findByLabelText("반입 묶음 ID");
  const button = screen.getByRole("button", { name: "검증 등록" }) as HTMLButtonElement;
  fireEvent.change(input, { target: { value: "_leading-underscore" } });
  expect(button.disabled).toBe(true);
  fireEvent.change(input, { target: { value: "../outside" } });
  expect(button.disabled).toBe(true);
  fireEvent.click(button);
  expect(api.find("POST", "/admin/local-models/validate")).toHaveLength(0);
  fireEvent.change(input, { target: { value: "cpu-test-a" } });
  fireEvent.click(button);
  await waitFor(() => expect(api.find("POST", "/admin/local-models/validate")).toHaveLength(1));
  expect(api.find("POST", "/admin/local-models/validate")[0].body).toEqual({ pack_id: "cpu-test-a" });
  expect(await screen.findByRole("status")).toHaveProperty("textContent", expect.stringContaining("검증 등록"));
  expect(screen.getByText("실제 추론 미실행")).toBeTruthy();
});

it("requires a trimmed reason before activating and reflects successful server selection", async () => {
  let active = false;
  const api = setup({
    "GET /admin/local-models": () => [200, { ...catalog, active_pack_id: active ? model.pack_id : null,
      models: [{ ...model, actual_inference: active ? "EXECUTED" : "NOT_RUN" }] }],
    "POST /admin/local-models/activate": () => { active = true; return [200, { active_pack_id: model.pack_id,
      previous_pack_id: null, actual_inference: "EXECUTED", quality_adopted: false }]; },
  });
  const row = await screen.findByRole("article", { name: "모델 cpu-test-a" });
  const button = within(row).getByRole("button", { name: "합성 시험용으로 선택" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("선택·해제 사유"), { target: { value: "    " } });
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("선택·해제 사유"), { target: { value: "  합성 자료 생성 시험  " } });
  fireEvent.click(button);
  await waitFor(() => expect(api.find("POST", "/admin/local-models/activate")).toHaveLength(1));
  expect(api.find("POST", "/admin/local-models/activate")[0].body).toEqual({ pack_id: "cpu-test-a", reason: "합성 자료 생성 시험" });
  expect(await within(row).findByText("현재 선택됨")).toBeTruthy();
  expect(within(row).getByText("실제 추론 실행됨")).toBeTruthy();
  expect(screen.getByText(/운영 품질 미채택/)).toBeTruthy();
});

it("keeps the previous selection when the activation probe is rejected", async () => {
  const api = setup({
    "GET /admin/local-models": [200, { ...catalog, active_pack_id: "previous-pack" }],
    "POST /admin/local-models/activate": [400, { detail: "합성 추론 확인 실패" }],
  });
  await screen.findByText("cpu-test-a");
  fireEvent.change(screen.getByLabelText("선택·해제 사유"), { target: { value: "실패 경로 확인" } });
  fireEvent.click(screen.getByRole("button", { name: "합성 시험용으로 선택" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("합성 추론 확인 실패"));
  expect(screen.getByText("previous-pack")).toBeTruthy();
  expect(screen.queryByText("현재 선택됨")).toBeNull();
  expect(api.find("POST", "/admin/local-models/activate")).toHaveLength(1);
});

it("deactivates the selected model with a reason and refreshes the current selection", async () => {
  let active = true;
  const api = setup({
    "GET /admin/local-models": () => [200, { ...catalog, active_pack_id: active ? model.pack_id : null }],
    "POST /admin/local-models/deactivate": () => { active = false; return [200, { active_pack_id: null }]; },
  });
  const button = await screen.findByRole("button", { name: "모델 선택 해제" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("선택·해제 사유"), { target: { value: "  합성 시험 종료  " } });
  fireEvent.click(button);
  await waitFor(() => expect(api.find("POST", "/admin/local-models/deactivate")).toHaveLength(1));
  expect(api.find("POST", "/admin/local-models/deactivate")[0].body).toEqual({ reason: "합성 시험 종료" });
  expect(await screen.findByText("선택된 모델 없음")).toBeTruthy();
});

it("shows catalog errors instead of presenting an empty successful catalog", async () => {
  setup({ "GET /admin/local-models": [503, { detail: "모델 목록을 읽을 수 없습니다" }] });
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("모델 목록을 읽을 수 없습니다"));
  expect(screen.queryByRole("button", { name: "합성 시험용으로 선택" })).toBeNull();
});


it("explains a fixed model-integrity rejection in Korean without registering success", async () => {
  setup({ "POST /admin/local-models/validate": [400, { detail: "model_file_hash_mismatch" }] });
  fireEvent.change(await screen.findByLabelText("반입 묶음 ID"), { target: { value: "cpu-test-a" } });
  fireEvent.click(screen.getByRole("button", { name: "검증 등록" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("모델 파일의 무결성 확인에 실패했습니다"));
  expect(screen.queryByRole("status")).toBeNull();
});
