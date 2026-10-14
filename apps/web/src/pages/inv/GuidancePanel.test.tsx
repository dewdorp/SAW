import { cleanup, act, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ContextPanel } from "./ContextPanel";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); useInvStore.setState({ byInv: {} }); });
const result = {
  methodology: { id: "soc-guidance", version: "soc-guidance/1.0", digest: "digest" },
  scope: { scope_key: "scoped", effective_time: null, evidence_manifest: [] },
  facts: [{ id: "total", label: "WAF 요청", value: 120, data_state: "available", query_ref: "q1", evidence_refs: ["e1"] }, { id: "blocked", label: "차단", value: 118, data_state: "available", query_ref: "q1", evidence_refs: [] }, { id: "allowed", label: "허용", value: 2, data_state: "available", query_ref: "q1", evidence_refs: [] }],
  unknowns: [{ source: "WAS", state: "not_collected", reason: "처리 결과 미수집" }, { source: "EDR", state: "forbidden", reason: "분석가의 조회 권한 없음" }],
  questions: [{ rule_id: "A", question_id: "A", title: "허용된 요청의 처리 결과 확인", purpose: "일부 차단으로 전체 방어를 단정하지 않음", status: "open", allowed_actions: ["open_evidence", "record_answer"], needed_sources: ["WAS"], resolution_conditions: ["처리 결과 근거"], forbidden_claims: ["모두 차단됨"], answer_check_ids: [] }],
  queries: [{ id: "q1", query: { filters: [], time: null }, data_state: "available", matched_count: 120, sampled_count: 20, limit: 20, truncated: true, missing_count: 0, executed_at: "2026-10-15T01:00:00Z" }], limits: ["일치 120건 중 원문 참조 20건"],
};
function setup(reply: any = result) {
  return mockApi({ "POST /investigations/i/guidance/preview": [200, reply], "POST /investigations/i/context": [200, {}], "POST /investigations/i/checks/team": [200, { items: [] }], "GET /ai/status": [200, { available: false }], "GET /auth/me": [200, { permissions: ["investigation.write"] }] });
}

it("shows scoped counts and unavailable states; opening is not saving a check", async () => {
  useInvStore.getState().set("i", { selection: { type: "ip", value: "203.0.113.10" }, filters: [{ field: "event_type", op: "is", value: "waf" }], time: { start: "2026-10-14T00:00:00Z" } });
  const api = setup(); renderUI(<ContextPanel inv="i" />);
  expect(await screen.findByText("현재 확인된 내용")).toBeTruthy();
  expect(screen.getByText("120")).toBeTruthy();
  expect(screen.getByText("조회 권한 없음")).toBeTruthy();
  expect(api.find("POST", "/investigations/i/checks")).toHaveLength(0);
  expect(api.find("POST", "/investigations/i/guidance/preview")[0].body).toMatchObject({ target_type: "entity", target_key: "ip:203.0.113.10", role: "either", filters: [{ field: "event_type", op: "is", value: "waf" }], time: { start: "2026-10-14T00:00:00Z" } });
  fireEvent.change(screen.getByLabelText("IP 역할"), { target: { value: "dst" } });
  await waitFor(() => expect(api.find("POST", "/investigations/i/guidance/preview").at(-1)?.body.role).toBe("dst"));
  act(() => useInvStore.getState().set("i", { time: { start: "2026-10-14T01:00:00Z" } }));
  await waitFor(() => expect(api.find("POST", "/investigations/i/guidance/preview").at(-1)?.body.time.start).toBe("2026-10-14T01:00:00Z"));
});

it("does not render failed queries as a zero count", async () => {
  setup({ ...result, facts: [{ id: "total", label: "WAF 요청", value: null, data_state: "query_failed", evidence_refs: [] }], questions: [], queries: [] });
  renderUI(<ContextPanel inv="i" />);
  expect(await screen.findByText("조회 실패")).toBeTruthy();
  expect(screen.getByText("건수 미확인")).toBeTruthy();
  expect(screen.queryByText("0")).toBeNull();
});


it("continues an external-only IP inquiry inside the existing investigation", async () => {
  const api = setup({ ...result, facts: [], questions: [], queries: [] });
  renderUI(<ContextPanel inv="i" />);
  fireEvent.change(screen.getByLabelText("조사할 IP"), { target: { value: "198.51.100.77" } });
  fireEvent.click(screen.getByRole("button", { name: "이 조사에서 IP 확인" }));
  await waitFor(() => expect(api.find("POST", "/investigations/i/guidance/preview").at(-1)?.body.target_key).toBe("ip:198.51.100.77"));
  expect(api.find("POST", "/investigations")).toHaveLength(0);
  expect(useInvStore.getState().get("i").selection).toEqual({ type: "ip", value: "198.51.100.77" });
});
