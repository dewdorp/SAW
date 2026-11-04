import { act, cleanup, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInv, useInvStore } from "../../context/invContext";
import { ME, mockApi, renderUI } from "../../test/helpers";
import { ChecksTab } from "./ChecksTab";
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
  it("lets an analyst compare a candidate with any chosen reference and keeps the two sources distinct", async () => {
    const api = mockApi({ "GET /auth/me": [200, ME], "GET /investigations/i1/question-bundles": [200, data] });
    renderUI(<QuestionBundles inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: /내부 서버 10.20.1.10/ }));
    fireEvent.click(screen.getByRole("button", { name: "이 활동과 사례 직접 대조" }));
    await act(async () => { await vi.dynamicImportSettled(); });
    const picker = await screen.findByRole("combobox", { name: "참고할 가상 사례" });
    expect(within(picker).getAllByRole("option")).toHaveLength(101);
    fireEvent.change(picker, { target: { value: "C100" } });
    const comparison = within(screen.getByRole("region", { name: "직접 선택한 사례와 대조" }));
    expect(comparison.getByText(item.observed)).toBeTruthy();
    expect(comparison.getByRole("heading", { name: /C100.*외부 DNS/ })).toBeTruthy();
    expect(comparison.getByRole("link", { name: "이 사례의 근거와 후속 자료" }).getAttribute("href")).toBe("/casebook?case=C100&investigation=i1");
    expect(api.calls.every(c => c.method === "GET")).toBe(true);
  });

  it("reads a worked comparison without extra scans or writes and reopens the exact chosen evidence", async () => {
    const span = { start: "2026-10-13T02:10:00Z", end: "2026-10-13T02:11:00Z", end_exclusive: false };
    const candidate = (ip: string, targets: number) => ({ ...item, title: `포트 접촉: ${ip}`, records: targets,
      basis: { observed_targets: targets, observed_ports: 1, port_records: targets, allowed_records: 2,
        blocked_records: targets - 2, threshold_targets: 4, threshold_ports: 7 }, evidence_time: span,
      filters: [{ field: "src_ip", op: "is", value: ip }, { field: "dst_port", op: "is", value: 443 }] });
    const rows = [candidate("10.10.1.1", 6), candidate("10.10.1.2", 8)];
    const api = mockApi({ "GET /auth/me": [200, { permissions: [] }], "GET /investigations/i1/question-bundles": [200,
      { ...data, bundles: [{ ...data.bundles[2], status: "found", found: 2, items: rows }] }] });
    renderUI(<QuestionBundles inv="i1" />);
    await screen.findByRole("link", { name: "모범 분석 읽기" });
    const panel = within(screen.getByRole("region", { name: "내 로그와 비교할 사례" }));
    expect((await panel.findByRole("link", { name: "모범 분석 읽기" })).getAttribute("href")).toBe("/casebook?case=C010&investigation=i1");
    fireEvent.change(panel.getByLabelText("이번 조사에서 연결된 관측"), { target: { value: "1" } });
    expect(panel.getByText(/10.10.1.2 · 목적지 8개/)).toBeTruthy();
    expect(panel.getByText(/끝 시각 포함/)).toBeTruthy();
    expect(panel.getByText(/일부 후보만 비교/)).toBeTruthy();
    fireEvent.click(panel.getByRole("button", { name: "내 로그의 근거 보기" }));
    expect(useInvStore.getState().get("i1")).toMatchObject({ tab: "raw", filters: rows[1].filters, time: span });
    expect(api.calls.every(c => c.method === "GET")).toBe(true);
    expect(api.find("GET", "/investigations/i1/question-bundles")).toHaveLength(1);
  });

  it("keeps manual comparison available when a result belongs to another investigation", async () => {
    mockApi({ "GET /auth/me": [200, ME], "GET /investigations/i1/question-bundles": [200,
      { ...data, scope: { ...SCOPE, investigation_id: "another" } }] });
    renderUI(<QuestionBundles inv="i1" />);
    await screen.findByText(/정상 여부는 판단할 수 없습니다/);
    const panel = within(screen.getByRole("region", { name: "내 로그와 비교할 사례" }));
    expect(panel.getByRole("link", { name: "전체 분석 사례집 보기" }).getAttribute("href")).toBe("/casebook?investigation=i1");
    expect(panel.queryByRole("button", { name: "내 로그의 근거 보기" })).toBeNull();
    expect(panel.queryByRole("link", { name: "모범 분석 읽기" })).toBeNull();
  });

  it("keeps the triggering window inclusive and creates only a linked draft when requested", async () => {
    const span = { start: "2026-10-13T02:10:00Z", end: "2026-10-13T02:11:00Z", end_exclusive: false };
    const candidate = { ...item, title: "10.20.0.2가 1분 동안 10개 포트에 접촉", evidence_time: span };
    const bundles = [data.bundles[0], { ...data.bundles[1], items: [candidate], id: "spread", title: "D. 확산" },
      { ...data.bundles[2], id: "periodic" }];
    const events = Array.from({ length: 12 }, (_, i) => ({ event_id: `e${i}` }));
    const api = mockApi({
      "GET /auth/me": [200, ME], "GET /investigations/i1/question-bundles": [200, { ...data, bundles }],
      "GET /investigations/i1/question-examples": [200, { items: [], total: 0, catalog_total: 120 }],
      "POST /investigations/i1/query/events": [200, { events }],
      "POST /investigations/i1/checks": [201, { id: "new-c1", target_label: candidate.title }],
      "GET /investigations/i1/checks": [200, { checks: [] }],
      "GET /investigations/i1/follow-ups": [200, { items: [] }],
      "GET /investigations/i1/follow-ups/choices": [200, { users: [], org_units: [] }],
      "GET /investigations/i1/follow-ups/draft": [200, { question: "이 시간에 승인된 점검이 있었나요?", target: { dst_ports: [443] } }],
    });
    function Flow() { const ctx = useInv("i1"); return ctx.tab === "checks" ? <ChecksTab inv="i1" /> : <QuestionBundles inv="i1" />; }
    renderUI(<Flow />);
    const activity = await screen.findByRole("button", { name: new RegExp("10개 포트에 접촉") });
    expect(activity.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText("정상 백업")).toBeNull();
    expect(screen.getByText(/자료 부족 1개/)).toBeTruthy();
    expect(screen.getByText(/일부만 계산 1개/)).toBeTruthy();
    fireEvent.click(activity);
    expect(screen.getByText("정상 백업")).toBeTruthy();
    expect(api.find("POST", "/investigations/i1/checks")).toHaveLength(0);
    expect(screen.getByText(/판단 범위/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "근거 12건 보기" }));
    const st = useInvStore.getState().byInv.i1;
    expect(st.tab).toBe("raw"); expect(st.filters).toEqual(item.filters); expect(st.time).toEqual(span);
    // The raw view opens with the columns that check this claim, allowed/blocked included.
    expect(st.evidenceColumns?.cols).toContain("enforcement_action");
    useInvStore.getState().set("i1", { tab: "summary" });
    // Back on the list the activity is still open.
    expect((await screen.findByRole("button", { name: new RegExp("10개 포트에 접촉") })).getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "추가 확인 요청" }));
    await screen.findByDisplayValue("이 시간에 승인된 점검이 있었나요?");
    expect(api.find("GET", "/investigations/i1/follow-ups/draft")[0].url).toContain("check_id=new-c1");
    expect(api.find("POST", "/investigations/i1/follow-ups")).toHaveLength(0);
    expect(api.find("POST", "/investigations/i1/query/events")[0].body.time).toEqual(span);
    const body = api.find("POST", "/investigations/i1/checks")[0].body;
    expect(body.scope).toMatchObject({ coverage: "observation", checked: 0, event_ids: [], query: { filters: item.filters, time: span } });
    expect(body.scope.origin).toMatchObject({ kind: "question", bundle: "spread", scope: SCOPE, item: { next_questions: item.next_questions } });
    expect(body.evidence).toEqual(events.map(e => e.event_id)); expect(body.judgement).toBeUndefined();
    expect(body.note).toContain("승인된 업무였는지 / 처리 내용");
  });

  it("shows a translated observed source, keeps the wider source condition in details, and opens the right editor", async () => {
    const mixed = { ...item, title: "같은 포트 접촉", filters: [{field:"data_source",op:"in",value:["connection","zeek_conn","firewall","web"]}] };
    const exact = { ...item, title: "통신 쌍 반복", filters: [...mixed.filters, {field:"data_source",op:"is",value:"connection"}] };
    mockApi({ "GET /investigations/i1/question-bundles": [200, { ...data, bundles: [
      {...data.bundles[1], id:"spread", items:[mixed]},
      {...data.bundles[1], id:"periodic", items:[exact]} ] }],
      "GET /investigations/i1/question-presets": [200, {items:[]}] });
    renderUI(<QuestionBundles inv="i1" />);
    const row = await screen.findByRole("button", {name:/같은 포트 접촉/});
    expect(row.textContent).not.toMatch(/connection|zeek_conn|Zeek|자료 조건|원천:/);
    // Types other than the first are folded to one line until opened.
    expect(screen.queryByRole("button", {name:/통신 쌍 반복/})).toBeNull();
    fireEvent.click(screen.getByRole("button", {name:/^반복 통신계산된 1개/}));
    expect(screen.getByRole("button", {name:/통신 쌍 반복/}).textContent).toContain("연결 기록");
    fireEvent.click(row);
    expect(screen.getByText("연결 기록 · Zeek 연결 · 방화벽 · HTTP 요청(NDR·웹)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", {name:"이 유형의 검색 조건 조정"}));
    expect(await screen.findByRole("region", {name:"조건 수정"})).toBeTruthy();
    expect(screen.getByLabelText("관측창")).toBeTruthy();
  });

  it("distinguishes filtered statistics from candidates when no investigation period is declared", async () => {
    useInvStore.getState().set("i1", { time: TIME, filters: [{field: "dst_port", op: "is", value: 443}] });
    mockApi({ "GET /investigations/i1/question-bundles": [200, { ...data, scope: { ...SCOPE, time: null } }] });
    renderUI(<QuestionBundles inv="i1" />);
    expect(await screen.findByText(/기간 미지정 · 저장된 자료 기준/)).toBeTruthy();
    expect(screen.getByText(/자료 통계는 현재 검색 조건을 따르며/)).toBeTruthy();
  });

  it("C010: a candidate seen only at high sensitivity is still open after reading its evidence and coming back", async () => {
    const eight = { ...item, title: "10.31.1.30에서 약 1분 동안 목적지 8개의 TCP 443 포트에 접촉했습니다.", records: 24 };
    const api = mockApi({
      "GET /auth/me": [200, ME],
      "GET /investigations/i1/question-bundles": (c) => [200, c.url.includes("sensitivity=high")
        ? { ...data, bundles: [{ ...data.bundles[1], id: "spread", items: [eight], found: 1 }] } : { ...data, bundles: [] }],
      "GET /investigations/i1/question-examples": [200, { items: [], total: 0, catalog_total: 120 }],
    });
    function Flow() { const ctx = useInv("i1"); return ctx.tab === "raw" ? <p>원문</p> : <QuestionBundles inv="i1" />; }
    renderUI(<Flow />);
    fireEvent.change(await screen.findByLabelText("질문 민감도"), { target: { value: "high" } });
    fireEvent.click(await screen.findByRole("button", { name: /목적지 8개의 TCP 443/ }));
    fireEvent.click(screen.getByRole("button", { name: "근거 24건 보기" }));
    expect(await screen.findByText("원문")).toBeTruthy();
    useInvStore.getState().set("i1", { tab: "summary" });
    const back = await screen.findByRole("button", { name: /목적지 8개의 TCP 443/ });
    expect(back.getAttribute("aria-expanded")).toBe("true");
    expect((screen.getByLabelText("질문 민감도") as HTMLSelectElement).value).toBe("high");
    expect(api.find("GET", "/investigations/i1/question-bundles").every((c: any, i: number) => i === 0 || c.url.includes("sensitivity=high"))).toBe(true);
    // Another investigation starts from its own defaults.
    expect(useInvStore.getState().byInv.i2?.questionView).toBeUndefined();
  });

  it("never describes a failed request as no matching activity", async () => {
    mockApi({ "GET /investigations/i1/question-bundles": [500, { detail: "질문 조회 실패" }] });
    renderUI(<QuestionBundles inv="i1" />);
    expect((await screen.findByRole("alert")).textContent).toContain("질문 조회 실패");
    expect(screen.queryByText(/표시할 후보가 없습니다/)).toBeNull();
  });

  it("closing the editor removes its unsaved preview, and the first type can be collapsed", async () => {
    mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "GET /investigations/i1/question-examples": [200, { items: [], total: 0, catalog_total: 120 }],
      "GET /investigations/i1/question-presets": [200, { items: [] }],
      "POST /investigations/i1/question-bundles/spread/preview": [200, { ...data.bundles[2], status: "found", completeness: "complete",
        partial_reasons: [], items: [{ ...item, title: "미리 본 후보 10.20.5.99" }], scope: SCOPE, preset: null }],
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderUI(<QuestionBundles inv="i1" />);
    const head = await screen.findByRole("button", { name: /^대량 전송/ });
    expect(head.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(head);
    expect(head.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(await screen.findByText("계산 결과와 조건"));
    fireEvent.click(await screen.findByRole("button", { name: "조건 수정" }));
    fireEvent.change(screen.getByLabelText("서로 다른 목적지 수"), { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "현재 로그로 미리 보기" }));
    expect(await screen.findByText("미리 본 후보 10.20.5.99")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "닫기" }));
    expect(screen.queryByText("미리 본 후보 10.20.5.99")).toBeNull();
    expect(screen.queryByText(/조건 미리 보기 적용 중/)).toBeNull();
    expect(useInvStore.getState().get("i1").questionView?.previews).toEqual({});
  });

  it("edits a condition with typed inputs, runs it on the current logs and saves it as a versioned condition", async () => {
    let saved = 0;
    const api = mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "GET /investigations/i1/question-examples": [200, { items: [], total: 0, catalog_total: 120 }],
      "GET /investigations/i1/question-presets": [200, { items: [] }],
      "POST /investigations/i1/question-bundles/spread/preview": (c) => [200, { ...data.bundles[2], status: "found", completeness: "complete",
        partial_reasons: [], parameters: c.body.parameters, description: `${c.body.parameters.window_minutes}분 동안 서로 다른 목적지 ${c.body.parameters.min_targets}개 이상`,
        items: [{ ...item, title: "10.20.5.99가 10분 안에 목적지 15개에 접근" }], scope: SCOPE, preset: null }],
      "POST /investigations/i1/question-presets": (c) => [201, { id: "p1", version: ++saved, scope_kind: c.body.scope_kind, scope_ko: "같은 관계사의 조사", name: c.body.name, parameters: c.body.parameters }],
      "PUT /investigations/i1/question-presets/p1": [409, { detail: "다른 사람이 먼저 이 조건을 수정했습니다." }],
    }) as any;
    renderUI(<QuestionBundles inv="i1" />);
    fireEvent.click(await screen.findByText("계산 결과와 조건"));
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

describe("example specifications", () => {
  it("lists the examples with execution, data and calculation states and opens the nearby question's condition", async () => {
    const examples = { catalog_total: 120, total: 1, note: "SAW에 설치된 실행 룰이 아닙니다.", items: [{ id: "D027", kind: "detection", kind_ko: "탐지 조건 명세",
      title: "하나의 서비스 포트를 향한 수평 접촉 확산", question: "한 출발지가 같은 서비스 포트로 많은 목적지를 접촉하는가?", logic: "", cannot_conclude: ["출발지가 침해되었다는 결론"],
      normal_explanations: ["자산 점검"], followup_questions: [], parameters: [{ label_ko: "서로 다른 목적지 주소 수", default: 25, unit: "addresses" }],
      execution: { state: "nearby_question", label: "자체 실행기 없음 · 가까운 계산 Q06 연결됨", question: "Q06", bundle: "spread" },
      data_readiness: { state: "profile_required", label: "장비 설정·원천 의미 확인 필요" }, calculation: { state: "not_run", label: "아직 실행 안 함" } }] };
    mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "GET /investigations/i1/question-examples": [200, examples],
      "GET /investigations/i1/question-presets": [200, { items: [] }],
    });
    renderUI(<QuestionBundles inv="i1" />);
    const toggle = await screen.findByText("더 많은 예제 찾기");
    expect(screen.queryByText("자체 실행기 없음 · 가까운 계산 Q06 연결됨")).toBeNull();
    fireEvent.click(toggle.closest("summary")!);
    expect(await screen.findByText("자체 실행기 없음 · 가까운 계산 Q06 연결됨")).toBeTruthy();
    expect(screen.getByText("아직 실행 안 함")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "D027" }));
    fireEvent.click(screen.getByRole("button", { name: "가까운 질문 Q06의 조건 열기" }));
    expect(await screen.findByRole("region", { name: "조건 수정" })).toBeTruthy();
  });
});
