import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { Assets } from "../asset/Assets";
import { Scenarios } from "../scenario/Scenarios";
import { Criteria } from "./Criteria";
import { HuntActivities } from "./HuntActivities";
import { Hunts } from "./Hunts";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); sessionStorage.clear(); });

const activity = (id: string, title: string, state = "unreviewed") => ({ id, method: "target_variation", title, observed: ["요청 60건, 서로 다른 custNo 값 60개"], why: ["같은 기능을 쓰는 다른 출발지보다 대상이 60배 많습니다."],
  normal: ["상담·정산·배치처럼 여러 고객을 차례로 조회하는 업무일 수 있습니다."], unknown: ["custNo 값이 조회 대상을 뜻하는지(파라미터 의미 미확인)"], next_checks: ["애플리케이션 기록으로 처리 결과와 계정을 확인"],
  time: { start: "2026-10-20T06:00:00Z", end: "2026-10-20T06:01:00Z" }, entities: ["10.50.9.77"], evidence: { filters: [{ field: "src_ip", op: "is", value: "10.50.9.77" }], records: 60 }, counts: { records: 60 },
  strength: "같은 출발지 IP 기준", review: { state, note: "", history: [] } });
const hunt = (extra: any = {}) => ({ progress: { state: "complete", label: "완료", active: [] }, stale: [], run: { id: "r1", version: 2, mode_label: "기본 분석 · AI 미연결", status: "complete", created_at: "2026-10-21T00:00:00Z",
  scope: { org_unit: "가상 은행", selected_records: 832, by_source: { web: 832 }, observed: { first: "2026-10-20T00:00:00Z", last: "2026-10-20T06:01:00Z" }, records_without_time: 0, note: "선택 자료 건수는 저장된 기록 수입니다." },
  methods: [{ id: "target_variation", name: "조회 대상 변화", edit: "criteria", status: "found", status_label: "후보 있음", found: 1, shown: 1, records: 832, examined: { records_read: 832 }, needs: [], partial_reasons: [] },
    { id: "q.spread", name: "확산", status: "insufficient_data", status_label: "자료 부족", found: 0, shown: 0, needs: ["FW·연결 기록"], partial_reasons: [] },
    { id: "q.web", name: "웹 요청", status: "no_match", status_label: "조건 일치 없음", found: 0, shown: 0, needs: [], partial_reasons: [] }],
  activities: [activity("a1", "10.50.9.77에서 crm.example.test/customer/view.do의 custNo 값을 60가지로 바꿔 가며 요청했습니다."), activity("a2", "두 번째 활동", "needs_check")], carried: [],
  summary: { activities: 2, shown: 2, review: { unreviewed: 1, needs_check: 1 } }, ...extra } });

describe("hunt workbench", () => {
  it("shows scope, what each method examined, and one activity in six parts; statuses are not mixed", async () => {
    const api = mockApi({ "GET /investigations/i1/hunt": [200, hunt()], "POST /investigations/i1/hunt/reviews": [201, { state: "normal_work" }],
      "GET /investigations/i1/hunt/activities/a1/evidence": [200, { rows: [{ event_id: "e1", time: "2026-10-20T06:00:00Z", source: "NDR HTTP", src: "10.50.9.77", dst: "10.40.1.10:443",
        what: "GET crm.example.test /customer/view.do?custNo=C9000", result: "200" }], shown: 1, total: 60, basis: "이 활동을 계산할 때 쓰인 기록입니다.", missing: "" }] });
    renderUI(<HuntActivities inv="i1" />);
    expect(await screen.findByText("기본 분석 · AI 미연결")).toBeTruthy();
    // The basis is shown with the statement: which records, how many of how many.
    expect(await screen.findByText("근거 기록 60건 중 1건")).toBeTruthy();
    expect(screen.getByText("GET crm.example.test /customer/view.do?custNo=C9000")).toBeTruthy();
    expect(document.querySelector(".ha-scope")!.textContent).toContain("선택 자료 832건");
    for (const heading of ["1. 무엇을 관측했나", "2. 왜 확인할 만한가", "3. 정상 업무로 설명될 가능성", "4. 아직 확인되지 않은 것", "5. 시간 흐름과 관련 원문", "6. 판단 남기기"])
      expect(screen.getByRole("heading", { name: heading })).toBeTruthy();
    expect(screen.getByText("자료 부족")).toBeTruthy();
    expect(screen.getByText("조건 일치 없음")).toBeTruthy();
    expect(screen.getByText(/정상이라는 뜻이 아닙니다/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "분석 기준에서 이 기준 고치기" }).getAttribute("href")).toBe("/criteria?method=target_variation");
    // A judgement needs a reason; "needs a check" does not.
    expect((screen.getByRole("button", { name: "정상 업무로 확인" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("판단 근거"), { target: { value: "정산 배치로 확인" } });
    fireEvent.click(screen.getByRole("button", { name: "정상 업무로 확인" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/hunt/reviews")[0].body).toEqual({ activity_id: "a1", state: "normal_work", note: "정산 배치로 확인" }));
  });

  it("keeps the selected activity and an unsent note after leaving and coming back", async () => {
    mockApi({ "GET /investigations/i1/hunt": [200, hunt()] });
    const first = renderUI(<HuntActivities inv="i1" />);
    fireEvent.click(await screen.findByRole("button", { name: /두 번째 활동/ }));
    fireEvent.change(screen.getByLabelText("판단 근거"), { target: { value: "담당 문의 중" } });
    first.unmount();
    renderUI(<HuntActivities inv="i1" />);
    expect((await screen.findByRole("heading", { name: "두 번째 활동" }))).toBeTruthy();
    expect((screen.getByLabelText("판단 근거") as HTMLTextAreaElement).value).toBe("담당 문의 중");
  });

  it("says when nothing was found without calling it normal, and when the result is out of date", async () => {
    mockApi({ "GET /investigations/i1/hunt": [200, { ...hunt({ activities: [], summary: { activities: 0, shown: 0, review: {} } }), stale: ["등록한 업무 지식이 바뀌었습니다."] }] });
    renderUI(<HuntActivities inv="i1" />);
    expect(await screen.findByText(/이 기준에서 확인할 활동을 찾지 못했습니다. 정상이라는 뜻은 아니며/)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("이 결과는 최신이 아닙니다");
  });

  it("lists hunts by what is left to do", async () => {
    mockApi({ "GET /hunts": [200, { buckets: { running: 0, review: 1, review_done: 0, done: 0 }, items: [{ id: "i1", display_id: "INV-1", title: "가상 은행 헌팅", org_unit: "가상 은행", status: "open", bucket: "review",
      progress: { state: "complete", label: "완료" }, run: { version: 2, status: "partial", records: 832, by_source: { web: 832 } }, activities: 2, unreviewed: 1, needs_check: 1, threat_confirmed: 0, created_at: "2026-10-21T00:00:00Z" }] }] });
    renderUI(<Hunts />);
    const link = await screen.findByRole("link", { name: "가상 은행 헌팅" });
    expect(link.getAttribute("href")).toBe("/inv/i1?tab=activities");
    expect(screen.getByText("일부 처리")).toBeTruthy();
    expect(screen.getByRole("button", { name: "확인 필요 1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "새 헌팅" })).toBeTruthy();
  });
});

describe("analysis criteria", () => {
  it("switches a method off, changes a threshold and saves only what differs from the default", async () => {
    const methods = [
      { id: "q.spread", name: "여러 대상·포트 접촉", what: "한 출발지가 여러 목적지나 포트에 접촉한 경우를 찾습니다.", edit: "criteria", question: "D", defaults: { min_targets: 10, min_ports: 10 },
        params: [{ name: "min_targets", label: "서로 다른 목적지 수", type: "int", default: 10, help: "", min: 1, max: 100000, unit: "개 이상" },
          { name: "min_ports", label: "서로 다른 목적지 포트 수", type: "int", default: 10, help: "", min: 1, max: 65536, unit: "개 이상" }] },
      { id: "target_variation", name: "조회 대상 변화", what: "같은 기능을 여러 대상으로 요청", edit: "criteria" },
      { id: "scenarios", name: "시나리오", what: "저장한 시나리오를 실행합니다.", edit: "scenarios" }];
    const api = mockApi({ "GET /source-context/org-units": [200, [{ id: "o1", display_name: "가상 은행" }]],
      "GET /hunt-criteria": [200, { methods, defaults: { off: [], questions: {}, target_variation: { min_targets: 8, ratio: 4 } }, common: null, own: null,
        effective: { source: "default", version: null }, can_write: true, note: "저장하면 다음 분석부터 적용됩니다." }],
      "POST /knowledge/flow-items": [201, { id: "c1", version: 1 }] });
    renderUI(<Criteria />);
    expect(await screen.findByText("기본 기준(저장된 기준 없음)")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("시나리오 사용"));
    expect(screen.getByText(/"사용 안 함"으로 표시됩니다/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("서로 다른 대상 수"), { target: { value: "20" } });
    fireEvent.click(screen.getByText("기준 값 보기·고치기"));
    fireEvent.change(screen.getByLabelText("서로 다른 목적지 포트 수"), { target: { value: "3" } });
    expect(screen.getByRole("button", { name: "기본값으로" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "시나리오 열기" }).getAttribute("href")).toBe("/scenarios");
    fireEvent.click(screen.getByRole("button", { name: "모든 관계사 공통으로 저장" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/flow-items")).toHaveLength(1));
    expect(api.find("POST", "/knowledge/flow-items")[0].body).toEqual({ kind: "criteria", org_unit_id: null,
      content: { off: ["scenarios"], questions: { spread: { min_ports: 3 } }, target_variation: { min_targets: 20, ratio: 4 } } });
    expect(await screen.findByText("저장했습니다. 다음 분석부터 적용됩니다.")).toBeTruthy();
  });
});

describe("scenarios and assets", () => {
  it("builds a scenario from a template in four steps without code and tries it on a hunt", async () => {
    const template = { id: "auth_then_lookup_variation", name: "인증 관련 접근 뒤 조회 대상 변화", executable: true, kind: "then_variation", purpose: "p", needs: ["HTTP 요청 기록"], normal_note: "상담 업무",
      defaults: { steps: [{ label: "인증 관련 접근", method: "", path: "/auth.html", match: "exact" }, { label: "회원정보 조회", method: "", path: "/memberinfo", match: "exact" }], count_unit: "distinct_param", count_param: "id", min_count: 5, window_seconds: 600, entity: "src_ip" } };
    const api = mockApi({ "GET /scenarios": [200, { scenarios: [], templates: [template, { id: "normal_batch", name: "정상 반례", executable: false, purpose: "p", needs: ["x"], reason: "반례 전용 실행기는 아직 없습니다." }] }],
      "GET /hunts": [200, { items: [{ id: "i1", display_id: "INV-1", title: "헌팅", run: { records: 34 } }] }], "GET /source-context/org-units": [200, []],
      "POST /scenarios/describe": [200, { description: "같은 출발지 IP에서 '인증 관련 접근' 뒤 10분 안에 '회원정보 조회'을(를) 서로 다른 id 값 5개 이상 요청한 흐름", unit: "서로 다른 id 값의 수" }],
      "POST /investigations/i1/scenarios/preview": [200, { status: "found", status_label: "조건을 만족한 흐름 있음", description: "d", unit: "서로 다른 id 값의 수", scope: { range: "이 헌팅의 전체 자료", selected_records: 34 }, examined: { records_read: 34 }, missing: [],
        matches: [{ entity: "10.60.1.10", host: "svc.example.test", count: 6, steps: [{ label: "인증 관련 접근" }, { label: "회원정보 조회" }] }], near: [{ kind: "reversed", text: "순서가 반대인 예" }, { kind: "outside_window", text: "시간창 밖" }], notes: ["NAT 주의"] }],
      "POST /knowledge/flow-items": [201, { id: "k1" }] });
    renderUI(<Scenarios />);
    expect(await screen.findByText("설명 자료(실행기 없음)")).toBeTruthy();
    expect(screen.getByText("반례 전용 실행기는 아직 없습니다.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "이 예제로 만들기" }));
    fireEvent.click(screen.getByRole("button", { name: "다음: 흐름 확인" }));
    expect(await screen.findByText(/서로 다른 id 값 5개 이상 요청한 흐름/)).toBeTruthy();
    expect(screen.queryByText(/JSON|YAML|SQL/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "다음: 현재 자료로 확인" }));
    fireEvent.change(screen.getByLabelText("시험할 헌팅"), { target: { value: "i1" } });
    fireEvent.click(screen.getByRole("button", { name: "한 번 시험하기" }));
    expect(await screen.findByText("10.60.1.10")).toBeTruthy();
    expect(screen.getByText("순서가 반대")).toBeTruthy();
    expect(screen.getByText("시간 범위 밖")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "다음: 저장" }));
    fireEvent.click(screen.getByRole("button", { name: "다음 헌팅부터 사용" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/flow-items")).toHaveLength(1));
    const body = api.find("POST", "/knowledge/flow-items")[0].body;
    expect(body.kind).toBe("scenario");
    expect(body.content.state).toBe("active");
    expect(body.content.steps[1].path).toBe("/memberinfo");
  });

  it("writes a scenario from scratch: pick how to look, type the steps as lines, save", async () => {
    const api = mockApi({ "GET /scenarios": [200, { scenarios: [], templates: [], kinds: [{ kind: "sequence", name: "요청이 이 순서로 이어짐", hint: "순서대로 이어진 흐름을 찾습니다.", needs: ["HTTP 요청 기록"] },
        { kind: "then_variation", name: "앞 요청 뒤 대상을 바꿔 가며 반복", hint: "h", needs: ["HTTP 요청 기록(경로·쿼리)"] }] }],
      "GET /hunts": [200, { items: [] }], "GET /source-context/org-units": [200, []], "POST /scenarios/describe": [200, { description: "세 단계 순서", unit: "순서가 완성된 횟수" }],
      "POST /knowledge/flow-items": [201, { id: "k2" }] });
    renderUI(<Scenarios />);
    fireEvent.click(await screen.findByRole("button", { name: "직접 만들기" }));
    expect((screen.getByRole("button", { name: "다음: 흐름 확인" }) as HTMLButtonElement).disabled).toBe(true);  // a name is all that is required
    fireEvent.change(screen.getByLabelText("이름"), { target: { value: "보고서 전체 내려받기" } });
    expect((screen.getByLabelText("찾는 방식") as HTMLSelectElement).value).toBe("sequence");
    fireEvent.click(screen.getByRole("button", { name: "다음: 흐름 확인" }));
    fireEvent.change(screen.getByLabelText("단계를 글로 적기"), { target: { value: "로그인: POST /login\n/report/*\n이건 경로가 아님\n전체 내려받기: GET /report/export?mode=all" } });
    fireEvent.click(screen.getByRole("button", { name: "아래 단계 카드로 바꾸기" }));
    expect(screen.getByRole("alert").textContent).toContain("읽지 못한 줄 1개");
    expect((screen.getByLabelText("3단계 포함 글자") as HTMLInputElement).value).toBe("mode=all");
    fireEvent.click(screen.getByRole("button", { name: "다음: 현재 자료로 확인" }));
    fireEvent.click(screen.getByRole("button", { name: "다음: 저장" }));
    fireEvent.click(screen.getByRole("button", { name: "초안으로 저장(시험만)" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/flow-items")).toHaveLength(1));
    const content = api.find("POST", "/knowledge/flow-items")[0].body.content;
    expect(content.template).toBe("");
    expect(content.steps).toEqual([{ label: "로그인", method: "POST", path: "/login", match: "exact", contains: "" },
      { label: "/report/", method: "", path: "/report/", match: "prefix", contains: "" },
      { label: "전체 내려받기", method: "GET", path: "/report/export", match: "exact", contains: "mode=all" }]);
  });

  it("previews a file refresh before applying and registers with a name and one identifier", async () => {
    const api = mockApi({ "GET /source-context/org-units": [200, []], "GET /asset-book": [200, { items: [], to_review: [] }],
      "POST /asset-book": [201, { id: "a1" }],
      "POST /asset-book/import/preview": [200, { columns: ["asset_id", "name", "ip"], unknown_columns: ["메모2"], counts: { new: 1, changed: 1, unchanged: 3, conflict: 1, error: 0 },
        rows: [{ line: 2, asset_id: "CRM-001", name: "고객관리", action: "changed", changes: [{ field: "owner", from: "김담당", to: "이담당" }] },
          { line: 3, asset_id: "", name: "새 자산", action: "new", changes: [] }, { line: 4, asset_id: "", name: "충돌", action: "conflict", changes: [], reason: "IP만으로는 덮어쓰지 않습니다." }],
        notes: ["빈 칸은 기존 값을 유지합니다.", "파일에 없는 자산은 지우지 않습니다."] }],
      "POST /asset-book/import/apply": [200, { applied: { new: 1, changed: 1 } }] });
    renderUI(<Assets />);
    fireEvent.change(await screen.findByLabelText("자산 이름"), { target: { value: "회원 포털" } });
    fireEvent.change(screen.getByLabelText("식별 정보"), { target: { value: "10.40.1.10" } });
    fireEvent.click(screen.getByRole("button", { name: "등록" }));
    await waitFor(() => expect(api.find("POST", "/asset-book")[0].body).toEqual({ name: "회원 포털", identifier: "10.40.1.10", org_unit_id: null }));
    fireEvent.click(screen.getByRole("button", { name: "파일로 갱신" }));
    fireEvent.change(screen.getByLabelText("자산 표 붙여넣기"), { target: { value: "자산 ID,이름\nCRM-001,고객관리" } });
    fireEvent.click(screen.getByRole("button", { name: "미리 보기" }));
    expect(await screen.findByText("신규 1 · 변경 1 · 변경 없음 3 · 충돌 1 · 오류 0")).toBeTruthy();
    expect(screen.getByText("담당자: 김담당 → 이담당")).toBeTruthy();
    expect(screen.getByText("IP만으로는 덮어쓰지 않습니다.")).toBeTruthy();
    expect(screen.getByText(/연결하지 못한 열: 메모2/)).toBeTruthy();
    expect(api.find("POST", "/asset-book/import/apply")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "신규 1건·변경 1건 적용" }));
    await waitFor(() => expect(api.find("POST", "/asset-book/import/apply")[0].body.clear_blank).toBe(false));
  });
});
