import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../App";
import { ME, mockApi, renderUI } from "../test/helpers";
const admin = { ...ME, roles: ["admin"], permissions: ["admin.data.delete"] };
const target = { target_type: "investigation", target_id: "inv-1", display_id: "INV-TEST-001", status: "open" };
const preview = { ...target, confirmation: "INV-TEST-001", fingerprint: "a".repeat(64),
  counts: { events: 20, files: 1, invalidated_findings: 2 }, blockers: [], blocker_details: [],
  retained: ["감사·증거 인계·처리 이력"], scope_note: "활성 자료 정리" };
function setup(extra: Parameters<typeof mockApi>[0] = {}, me = admin) {
  const api = mockApi({ "GET /auth/me": [200, me], "GET /jobs": [200, []],
    "GET /admin/data": [200, { items: [target], deletions: [], has_more: false }],
    "POST /admin/data/deletion-preview": [200, preview], ...extra });
  renderUI(<App />, { route: "/admin/data" });
  return api;
}
afterEach(() => vi.unstubAllGlobals());

it("requires administrator permission without fetching metadata", async () => {
  const api = setup({}, ME);
  expect(await screen.findByText("데이터 관리 권한이 필요합니다.")).toBeTruthy();
  expect(api.find("GET", "/admin/data")).toHaveLength(0);
});
it("requires fresh preview, reason and exact ID before deletion", async () => {
  const api = setup({ "POST /admin/data/deletions": [200, { id: "d1", state: "COMPLETED", step: "completed", counts: {}, retained: [] }] });
  fireEvent.click(await screen.findByRole("button", { name: "삭제 영향 확인" }));
  await screen.findByText("감사·증거 인계·처리 이력");
  const button = screen.getByRole("button", { name: "확인한 범위 삭제" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("삭제 사유"), { target: { value: "가상 자료 정리" } });
  fireEvent.change(screen.getByLabelText("대상 ID 확인"), { target: { value: "WRONG" } });
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("대상 ID 확인"), { target: { value: "INV-TEST-001" } });
  fireEvent.click(button);
  await waitFor(() => expect(api.find("POST", "/admin/data/deletions")).toHaveLength(1));
  expect(api.find("POST", "/admin/data/deletions")[0].body.preview_fingerprint).toBe(preview.fingerprint);
  expect(await screen.findByRole("status")).toHaveProperty("textContent", expect.stringContaining("정리 완료"));
});
it("shows legal hold blocker and never enables deletion", async () => {
  const api = setup({ "POST /admin/data/deletion-preview": [200, { ...preview, blockers: ["legal_hold"],
    blocker_details: [{ code: "legal_hold", message: "법적 보존 책임자의 검토가 필요합니다." }] }] });
  fireEvent.click(await screen.findByRole("button", { name: "삭제 영향 확인" }));
  expect(await screen.findByText("법적 보존 책임자의 검토가 필요합니다.")).toBeTruthy();
  expect((screen.getByRole("button", { name: "확인한 범위 삭제" }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.find("POST", "/admin/data/deletions")).toHaveLength(0);
});
it("does not call partial deletion a success and allows explicit retry", async () => {
  const failed = { id: "d1", target_id: "inv-1", state: "FAILED", step: "events_removed", error_code: "events_removed_failed", counts: {}, retained: [] };
  const api = setup({ "GET /admin/data": [200, { items: [], deletions: [failed], has_more: false }],
    "POST /admin/data/deletions/d1/retry": [200, { ...failed, state: "COMPLETED", error_code: "" }] });
  expect(await screen.findByText("미완료 · 재시도 필요")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "삭제 재시도" }));
  await waitFor(() => expect(api.find("POST", "/admin/data/deletions/d1/retry")).toHaveLength(1));
});
