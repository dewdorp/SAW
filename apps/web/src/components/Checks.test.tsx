import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { CheckDialog, MarkBadges, TargetChecks, TeamChecks } from "./Checks";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const INV = "inv-1";
const IP = { type: "entity" as const, key: "ip:203.0.113.10", label: "ip 203.0.113.10" };

describe("Confirmation record dialog", () => {
  it("needs a question, and a reason only when judging normal or malicious", async () => {
    const api = mockApi({ [`POST /investigations/${INV}/checks`]: [201, { id: "c1" }] });
    const close = vi.fn();
    renderUI(<CheckDialog inv={INV} target={IP} onClose={close} />);
    const save = screen.getByRole("button", { name: "확인 기록 저장" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText("성공 여부"));
    expect(save.disabled).toBe(false);                                   // "checked, no judgement yet" is a valid record
    fireEvent.click(screen.getByLabelText("악성"));
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("근거"), { target: { value: "응답 200과 명령 결과 확인" } });
    fireEvent.click(save);
    await waitFor(() => expect(close).toHaveBeenCalled());
    expect(api.find("POST", `/investigations/${INV}/checks`)[0].body).toMatchObject({
      target_type: "entity", target_key: "ip:203.0.113.10", questions: ["success"], judgement: "malicious", shared: false });
  });

  it("records a search result as a sample unless the analyst says they saw all of it", async () => {
    const api = mockApi({ [`POST /investigations/${INV}/checks`]: [201, { id: "c1" }] });
    const loaded = Array.from({ length: 50 }, (_, i) => `e${i}`);
    renderUI(<CheckDialog inv={INV} onClose={vi.fn()} target={{ type: "set", key: "", label: "검색 결과", set: { query: { filters: [] }, total: 120000, loaded } }} />);
    expect(screen.getByText(/검색 결과 120,000건/)).toBeTruthy();
    fireEvent.click(screen.getByLabelText("요청 성격"));
    fireEvent.click(screen.getByRole("button", { name: "확인 기록 저장" }));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/checks`)).toHaveLength(1));
    const scope = api.find("POST", `/investigations/${INV}/checks`)[0].body.scope;
    expect(scope).toMatchObject({ coverage: "sample", total: 120000, checked: 30 });
    expect(scope.event_ids).toHaveLength(30);
  });

  it("asks for the fact and the range when sharing, never just 'normal'", () => {
    mockApi({});
    renderUI(<CheckDialog inv={INV} target={IP} onClose={vi.fn()} />);
    fireEvent.click(screen.getByLabelText("정상 업무 여부"));
    fireEvent.click(screen.getByLabelText(/다른 조사에도 공유/));
    const save = screen.getByRole("button", { name: "확인 기록 저장" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("확인한 사실"), { target: { value: "정산 배치 서버" } });
    fireEvent.change(screen.getByLabelText("확인한 범위"), { target: { value: "02~03시 호출" } });
    expect(save.disabled).toBe(false);
  });
});

describe("Marks in tables", () => {
  it("separates a mark on the record from a mark on its address", () => {
    const m = (o: object) => ({ id: "1", questions: ["nature"], judgement: "malicious", author: "kim", kind: "direct", coverage: "one", shared: false, source_state: "", ...o });
    render(<MarkBadges own={[m({})]} parent={[m({ id: "2", judgement: "normal" })]} />);
    expect(screen.getByText("✓악성").title).toContain("확인: 요청 성격");
    expect(screen.getByText("↑정상").title).toContain("이 기록을 직접 판단한 것은 아님");
  });
});

const CHECK = { id: "c1", target_key: IP.key, question_labels: ["정상 업무 여부"], questions: ["business"], judgement: "normal", judgement_ko: "정상", note: "DB팀 확인",
  coverage: "one", kind: "direct", shared: true, expired: false, share_status: "recheck", state: "active", state_note: "낮에도 접속함", state_by: "lee",
  source_state: "", author_id: "u1", author: "kim", created_at: "2026-10-10T00:00:00Z", share: {} };

describe("Records of a target", () => {
  it("lists records, shows a re-check request and cancels with a reason kept", async () => {
    const api = mockApi({ [`GET /investigations/${INV}/checks`]: [200, { checks: [CHECK], summary: {}, me: "u1" }],
      [`POST /investigations/${INV}/checks/team`]: [200, { items: [] }], [`POST /investigations/${INV}/checks/c1/cancel`]: [200, {}] });
    vi.spyOn(window, "prompt").mockReturnValue("잘못 표시");
    renderUI(<TargetChecks inv={INV} target={IP} />);
    expect(await screen.findByText("DB팀 확인")).toBeTruthy();
    expect(screen.getByText(/재확인 요청\(lee\): 낮에도 접속함/)).toBeTruthy();
    fireEvent.click(screen.getByText("내 표시 취소"));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/checks/c1/cancel`)[0].body).toEqual({ note: "잘못 표시" }));
  });
});

const TEAM = { id: "t1", target_label: "203.0.113.10", judgement: "normal", judgement_ko: "정상", share_status: "unreviewed", share_status_ko: "미검토 참고", expired: false,
  citations: 2, cited_here: false, evidence_count: 1, author: "kim", created_at: "2026-10-03T00:00:00Z", note: "", question_labels: ["정상 업무 여부"],
  source: { display_id: "INV-7", can_open: false, id: null, title: null },
  share: { fact: "정산 배치 서버로 사용됨", confirmed_scope: "02~03시 고객 조회", unconfirmed_scope: "" },
  comparison: [{ label: "시간대", result: "differ", text: "확인 때(2~3시) 밖의 시간: 14시" }, { label: "포트", result: "unknown", text: "비교할 정보 없음" }] };

describe("Team results", () => {
  it("shows the fact, its range and how this investigation differs, and lets the analyst cite it", async () => {
    const api = mockApi({ [`POST /investigations/${INV}/checks/team`]: [200, { items: [TEAM] }], [`POST /investigations/${INV}/checks/cite`]: [201, { id: "c9" }] });
    renderUI(<TeamChecks inv={INV} keys={[IP.key]} />);
    expect(await screen.findByText("팀 확인 정보 1건")).toBeTruthy();
    expect(screen.getByText("정산 배치 서버로 사용됨")).toBeTruthy();
    expect(screen.getByText("적지 않음")).toBeTruthy();                       // an unstated range is shown as unstated
    expect(screen.getByText("다름")).toBeTruthy();
    expect(screen.getByText("비교 불가")).toBeTruthy();                       // never presented as a match
    expect(screen.getByText("확인 1건 · 인용 2회")).toBeTruthy();
    expect(screen.queryByText("원래 조사 열기")).toBeNull();                  // no access to the other investigation
    fireEvent.click(screen.getByText("내 조사에 근거로 연결"));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/checks/cite`)[0].body).toEqual({ source_id: "t1" }));
  });

  it("does not offer old results as evidence", async () => {
    mockApi({ [`POST /investigations/${INV}/checks/team`]: [200, { items: [{ ...TEAM, expired: true }] }] });
    renderUI(<TeamChecks inv={INV} keys={[IP.key]} />);
    expect(await screen.findByText(/오래된 확인/)).toBeTruthy();
    expect(screen.queryByText("내 조사에 근거로 연결")).toBeNull();
  });
});
