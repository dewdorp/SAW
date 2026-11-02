import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { QuestionBundles } from "./QuestionBundles";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
beforeEach(() => { useInvStore.setState({ byInv: {} }); });

const TIME = { start: "2026-10-12T15:00:00+00:00", end: "2026-10-13T15:00:00+00:00", end_exclusive: true };
const SCOPE = { investigation_id: "i1", org_unit_id: "o1", time: TIME, version: "question-bundles/2", run_at: "2026-11-02T00:00:00Z" };
const item = { title: "내부 서버 10.20.1.10가 외부 클라이언트 198.51.100.50에게 보낸 응답 96.0MB — 외부 반출 후보",
  observed: "응답 96MB", basis: { threshold_bytes: 1 }, records: 12,
  filters: [{ field: "data_source", op: "in", value: ["web"] }, { field: "data_source", op: "is", value: "web" }, { field: "src_ip", op: "is", value: "198.51.100.50" }],
  unknown: ["실제 데이터 종류"], normal_possibilities: ["정상 백업"], next_questions: ["승인된 업무였는지", "처리 내용"], entities: [], time: {} };
const spreadDef = { title: "D. 확산", defaults: { window_minutes: 0, min_targets: 10, dst_ports: [] },
  params: [{ name: "window_minutes", label: "관측창", type: "int", default: 0, min: 0, max: 44640, unit: "분" },
    { name: "min_targets", label: "서로 다른 목적지 수", type: "int", default: 10, min: 1, max: 100000, unit: "개 이상" },
    { name: "dst_ports", label: "목적지 포트로 한정", type: "port_list", default: [] }] };
const data = { version: "question-bundles/2", sensitivity: "normal", note: "판정이 아닙니다. 정상이라는 뜻이 아닙니다.", scope: SCOPE,
  limits: { items_shown: 10, groups: 1000, timeline_records: 20000 },
  definitions: { spread: spreadDef },
  questions: [{ id: "Q06", question: "한 출발지가 여러 대상 또는 포트를 접촉했는가?", bundle: "spread", inputs: ["FW"], status: "looked_none", completeness: "complete" },
    { id: "Q09", question: "WAF·IPS 경보가 실제 어떤 요청과 연결되는가?", bundle: null, inputs: ["WAF·IPS"], status: "not_connected", needs: "WAF·IPS 원천이 필요합니다" }],
  bundles: [{ id: "web_attack", title: "A. 웹 공격", status: "insufficient_data", missing: ["HTTP 요청 기록"], items: [] },
    { id: "transfer", title: "B. 대량 반출", status: "found", items: [item], records: 15, found: 1, shown: 1, completeness: "complete",
      partial_reasons: [], examined: { groups: 2, group_limit: 1000 }, description: "바이트 합계 50MB 이상" },
    { id: "spread", title: "D. 확산", status: "looked_none", items: [], records: 75, found: 0, shown: 0, completeness: "partial",
      partial_reasons: ["출발지 3개 중 상위 1개만 계산"], examined: { groups: 1, groups_total: 3, group_limit: 1 },
      description: "조사 기간 전체에서 서로 다른 목적지 10개 이상", parameters: spreadDef.defaults }] };

describe("question bundles", () => {
  it("separates no data, nothing found and partial computation, and opens evidence in the card's own scope", async () => {
    const events = Array.from({ length: 12 }, (_, i) => ({ event_id: `e${i}` }));
    const api = mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "POST /investigations/i1/query/events": [200, { events }],
      "POST /investigations/i1/checks": [201, { id: "c1" }],
    }) as any;
    renderUI(<QuestionBundles inv="i1" />);
    expect(await screen.findByText("자료 부족 — 판단 불가")).toBeTruthy();
    expect(screen.getAllByText(/이 기준에서는 보이지 않음 \(정상 판정 아님\)/).length).toBeGreaterThan(0);
    expect(screen.getByText(/일부만 계산: 출발지 3개 중 상위 1개만 계산/)).toBeTruthy();
    expect(screen.getByText(/계산한 그룹 1개 \/ 전체 3개/)).toBeTruthy();
    expect(screen.getByText("아직 연결 안 됨")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "같은 범위 전체 로그 보기" }));
    const st = useInvStore.getState().byInv.i1;
    expect(st.tab).toBe("raw");
    expect(st.filters).toEqual(item.filters);
    expect(st.time).toEqual(TIME);
    fireEvent.click(screen.getByRole("button", { name: "확인 기록으로 남기고 확인 요청 작성" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/checks")).toHaveLength(1));
    expect(api.find("POST", "/investigations/i1/query/events")[0].body.time).toEqual(TIME);
    const body = api.find("POST", "/investigations/i1/checks")[0].body;
    expect(body.scope).toMatchObject({ coverage: "all", loaded: 12, query: { filters: item.filters, time: TIME } });
    expect(body.scope.origin).toMatchObject({ kind: "question", bundle: "transfer", scope: SCOPE, item: { next_questions: item.next_questions } });
    expect(body.note).toContain("승인된 업무였는지 / 처리 내용");
  });

  it("edits a condition with typed inputs, runs it on the current logs and saves it as a versioned condition", async () => {
    let saved = 0;
    const api = mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "GET /investigations/i1/question-presets": [200, { items: [] }],
      "POST /investigations/i1/question-bundles/spread/preview": (c) => [200, { ...data.bundles[2], status: "found", completeness: "complete",
        partial_reasons: [], parameters: c.body.parameters, description: `${c.body.parameters.window_minutes}분 동안 서로 다른 목적지 ${c.body.parameters.min_targets}개 이상`,
        items: [{ ...item, title: "10.20.5.99가 10분 안에 목적지 15개에 접근" }], scope: SCOPE, preset: null }],
      "POST /investigations/i1/question-presets": (c) => [201, { id: "p1", version: ++saved, scope_kind: c.body.scope_kind, scope_ko: "같은 관계사의 조사", name: c.body.name, parameters: c.body.parameters }],
      "PUT /investigations/i1/question-presets/p1": [409, { detail: "다른 사람이 먼저 이 조건을 수정했습니다." }],
    }) as any;
    renderUI(<QuestionBundles inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: "조건 수정" }));
    fireEvent.change(screen.getByLabelText("관측창"), { target: { value: "10" } });
    fireEvent.change(screen.getByLabelText("서로 다른 목적지 수"), { target: { value: "12" } });
    expect(screen.getByText("저장하지 않은 변경")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "현재 로그로 미리 보기" }));
    expect(await screen.findByText("10.20.5.99가 10분 안에 목적지 15개에 접근")).toBeTruthy();
    expect(api.find("POST", "/investigations/i1/question-bundles/spread/preview")[0].body).toEqual({ sensitivity: "normal",
      parameters: { window_minutes: 10, min_targets: 12, dst_ports: [] } });
    expect(screen.getByText("미리 보기 · 저장 안 됨")).toBeTruthy();
    expect(screen.getByText("조건: 10분 동안 서로 다른 목적지 12개 이상")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("조건 이름"), { target: { value: "관리 포트 빠른 접촉" } });
    fireEvent.change(screen.getByLabelText("적용 범위"), { target: { value: "affiliate" } });
    fireEvent.click(screen.getByRole("button", { name: "조건 저장" }));
    expect(await screen.findByText(/v1으로 저장했습니다/)).toBeTruthy();
    expect(api.find("POST", "/investigations/i1/question-presets")[0].body).toMatchObject({ bundle: "spread", scope_kind: "affiliate",
      parameters: { window_minutes: 10, min_targets: 12 } });
    expect(screen.queryByText("저장하지 않은 변경")).toBeNull();
    fireEvent.change(screen.getByLabelText("서로 다른 목적지 수"), { target: { value: "14" } });
    fireEvent.click(screen.getByRole("button", { name: "새 버전으로 저장" }));
    expect((await screen.findByRole("alert")).textContent).toContain("먼저 이 조건을 수정했습니다");
    expect(api.find("PUT", "/investigations/i1/question-presets/p1")[0].body.expected_version).toBe(1);
  });
});
