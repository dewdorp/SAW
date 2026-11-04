import { cleanup, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { ME, mockApi, renderUI } from "../../test/helpers";
import { QuestionBundles } from "./QuestionBundles";

const endpoint = "/investigations/i1/long-window-comparisons";
const base: Parameters<typeof mockApi>[0] = { "GET /auth/me": [200, ME], "GET /investigations/i1/question-bundles": [200, { bundles: [] }] };
const scope = { baseline_start: "2026-04-06T00:00:00Z", baseline_end: "2026-06-01T00:00:00Z", recent_start: "2026-06-01T00:00:00Z", recent_end: "2026-06-08T00:00:00Z" };
const counts = { baseline: 1030, recent: 1250 };
const filters = [{ field: "event_id", op: "in", value: ["e1", "e2"] }];
const time = { start: scope.recent_start, end: scope.recent_end, end_exclusive: true };
const candidate = { kind: "outbound", src: "10.0.0.1", dst: "198.51.100.1", port: 443, observed: "최근 2건 송신", baseline: "이전 송신 0건", corroboration: "FW·NDR 주소 일치", next_check: "백업 일정을 대조하세요.", filters, time, evidence_ids: ["e1", "e2"], corroborating_event_ids: ["n1"] };
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
beforeEach(() => useInvStore.setState({ byInv: {} }));
function setup(status: string, candidates: unknown[]) {
  const result = mockApi({ ...base, [`GET ${endpoint}`]: [200, { status, scope, counts, candidates, note: "직전 8주의 주간 기록 기준" }] });
  renderUI(<QuestionBundles inv="i1" />);
  return result;
}
it("opens only on demand with an empty standard queue and passes this candidate's query to the same investigation", async () => {
  const api = setup("ready", [candidate]);
  const button = await screen.findByRole("button", { name: "장기 로그 비교" });
  expect(api.find("GET", endpoint)).toHaveLength(0);
  fireEvent.click(button);
  const region = within(screen.getByRole("region", { name: "장기 로그 비교" }));
  await region.findByRole("heading", { name: /외부 송신 후보.*포트 443/ });
  for (const value of [candidate.observed, candidate.baseline, candidate.corroboration, candidate.next_check]) expect(region.getByText(value)).toBeTruthy();
  expect(region.getByText(/1,030건/)).toBeTruthy();
  fireEvent.click(region.getByRole("button", { name: "이 후보의 원문 보기" }));
  expect(useInvStore.getState().get("i1")).toMatchObject({ tab: "raw", filters, time, evidenceColumns: { cols: expect.arrayContaining(["bytes_out"]) } });
  fireEvent.click(region.getByRole("button", { name: "대조한 NDR 원문 예시 1건 보기" }));
  expect(useInvStore.getState().get("i1")).toMatchObject({ tab: "raw", time, filters: [{ field: "event_id", op: "in", value: ["n1"] }] });
  expect(api.find("GET", endpoint)).toHaveLength(1);
  expect(api.calls.every(c => c.method === "GET")).toBe(true);
});
it.each([["insufficient", "비교할 자료가 부족합니다."], ["partial", "계산 한도 도달"], ["ready", "두 기간을 비교한 결과 조건에 맞는 후보가 없습니다."]])("explains %s when no candidate is available", async (status, label) => {
  setup(status, []);
  fireEvent.click(await screen.findByRole("button", { name: "장기 로그 비교" }));
  expect(await screen.findByText(label)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "이 후보의 원문 보기" })).toBeNull();
});
it("lets the analyst retry a failed comparison", async () => {
  let calls = 0;
  mockApi({ ...base, [`GET ${endpoint}`]: () => ++calls === 1 ? [503, "error"] : [200, { status: "ready", scope, counts, candidates: [], note: "재시도 성공" }] });
  renderUI(<QuestionBundles inv="i1" />);
  fireEvent.click(await screen.findByRole("button", { name: "장기 로그 비교" }));
  fireEvent.click(await screen.findByRole("button", { name: "비교 다시 시도" }));
  await screen.findByText(/재시도 성공/);
  expect(calls).toBe(2);
});
