import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { Board } from "./Board";
import { Briefing } from "./Briefing";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const AUTO = { headline: "분석 진행 중(판정 전). 높은 위험 탐지 2건을 확인하고 있습니다.", what: "10-05 02:58 ~ 03:03 · 고객 정보 대량 조회: 400건 요청",
  impact: "공격이 성공한 정황이 있는 탐지가 1건 있습니다.", done: "", todo: "조회된 번호 범위 확인\n출발지 차단 검토" };
const BRIEF = (over: any = {}) => ({
  investigation: { id: "i1", display_id: "INV-1", title: "고객 API 대량 조회", status: "in_progress", status_ko: "분석 중", verdict: null, verdict_ko: null,
    risk_level: "high", risk_ko: "높음", owner: "김분석", members: ["김분석", "박선임"], created_at: "2026-10-05T00:00:00Z", closed_at: null },
  facts: { files: 2, bytes: 1048576, events: 12345, time_range: [null, null], time_range_kst: ["2026-10-05 02:30", "2026-10-05 04:00"],
    sources: [{ key: "web", label: "웹 서버·NDR 요청 기록", count: 12345 }], findings: { critical: 0, high: 2, medium: 1, low: 0, info: 0 }, findings_total: 3, success_findings: 1 },
  top_findings: [{ id: "f1", display_id: "F-1001", risk_level: "high", risk_ko: "높음", what: "고객 정보 대량 조회", fact: "203.0.113.*** 에서 400건 요청", when: "10-05 02:58 ~ 03:03", success: true, reviewed: false, attack: [] }],
  auto: AUTO, edited: {}, text: { ...AUTO }, caveats: ["아직 종결되지 않은 조사입니다. 아래 내용은 판정 전의 중간 결과입니다."],
  edit: null, masked: true, generated_at: "2026-10-10T00:00:00Z", can_edit: true, ...over,
});
const page = () => renderUI(<Routes><Route path="/inv/:id/report" element={<Briefing />} /></Routes>, { route: "/inv/i1/report" });

describe("Report summary", () => {
  it("shows conclusion, sections, evidence and caveats on one page", async () => {
    mockApi({ "GET /investigations/i1/briefing": [200, BRIEF()] });
    page();
    const doc = await screen.findByRole("article", { name: "보고용 요약" });
    expect(within(doc).getByText(AUTO.headline)).toBeTruthy();
    for (const h of ["1. 무슨 일이 있었나", "2. 영향", "3. 조치한 내용", "4. 남은 일", "6. 분석한 자료", "7. 이 결과를 볼 때 유의할 점"]) expect(within(doc).getByText(h)).toBeTruthy();
    expect(within(doc).getByText("기록된 내용이 없습니다.")).toBeTruthy();           // nothing done yet: said, not hidden
    expect(within(doc).getByText("출발지 차단 검토")).toBeTruthy();
    expect(within(doc).getByText("확인 전")).toBeTruthy();
    expect(within(doc).getByText(/IP 주소 끝자리는 가려져 있습니다/)).toBeTruthy();
  });

  it("saves only the sections that were rewritten", async () => {
    const edited = BRIEF({ edited: { done: "방화벽 차단 완료" }, text: { ...AUTO, done: "방화벽 차단 완료" }, edit: { by: "manager", at: "2026-10-10T01:00:00Z", rev: 1 } });
    let saved = false;
    const api = mockApi({ "GET /investigations/i1/briefing": () => [200, saved ? edited : BRIEF()],
      "PUT /investigations/i1/briefing": () => { saved = true; return [200, edited]; } });
    page();
    fireEvent.click(await screen.findByRole("button", { name: "문구 고치기" }));
    fireEvent.change(screen.getByLabelText("3. 조치한 내용"), { target: { value: "방화벽 차단 완료" } });
    fireEvent.click(screen.getByRole("button", { name: "저장" }));
    await waitFor(() => expect(api.find("PUT", "/investigations/i1/briefing")).toHaveLength(1));
    expect(api.find("PUT", "/investigations/i1/briefing")[0].body).toEqual({ fields: { headline: "", what: "", impact: "", done: "방화벽 차단 완료", todo: "" } });
    expect(await screen.findByText("방화벽 차단 완료")).toBeTruthy();
    expect(screen.getByText("직접 작성")).toBeTruthy();
  });

  it("offers no editing to people who may only read, and prints from the page", async () => {
    mockApi({ "GET /investigations/i1/briefing": [200, BRIEF({ can_edit: false })] });
    const print = vi.spyOn(window, "print").mockImplementation(() => undefined);
    page();
    fireEvent.click(await screen.findByRole("button", { name: /인쇄/ }));
    expect(print).toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "문구 고치기" })).toBeNull();
  });
});

const ROW = (o: any) => ({ id: "i1", display_id: "INV-1", title: "A 조사", status: "in_progress", status_ko: "분석 중", risk_level: "high", risk_ko: "높음", verdict: null, verdict_ko: null,
  owner: "김분석", created_at: "2026-10-01T00:00:00Z", closed_at: null, last_activity: "2026-10-01T00:00:00Z", age_days: 9, idle_days: 9, high_findings: 2, stale: true, urgent: true, has_briefing_edit: false, ...o });
const BOARD = { days: 30, scope: "all", stale_days: 7, generated_at: "2026-10-10T00:00:00Z",
  tiles: { open: 1, urgent: 1, stale: 1, opened: 2, closed: 1, median_days_to_close: 3 },
  by_verdict: [{ key: "attack", label: "공격으로 판정", count: 1 }], by_risk_open: [{ key: "high", label: "높음", count: 1 }],
  by_owner: [{ owner: "김분석", open: 1, urgent: 1, stale: 1 }], weeks: [{ week: "10-05", opened: 2, closed: 1 }],
  rows: [ROW({}), ROW({ id: "i2", display_id: "INV-2", title: "B 조사", status: "closed", status_ko: "종결", verdict: "attack", verdict_ko: "공격으로 판정", stale: false, urgent: false, idle_days: 0 })] };

describe("Board", () => {
  it("puts what needs attention first and links each investigation to its report summary", async () => {
    const api = mockApi({ "GET /board": [200, BOARD] });
    renderUI(<Board />);
    expect(await screen.findByText("A 조사")).toBeTruthy();
    expect(screen.queryByText("B 조사")).toBeNull();                               // open investigations by default
    expect(screen.getByText("9일째 멈춤")).toBeTruthy();
    expect(screen.getByText("종결까지 보통 3일")).toBeTruthy();
    expect((screen.getByRole("link", { name: "보고용 요약" }) as HTMLAnchorElement).getAttribute("href")).toBe("/inv/i1/report");
    fireEvent.click(screen.getByRole("button", { name: "전체" }));
    expect(screen.getByText("B 조사")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "최근 7일" }));
    await waitFor(() => expect(api.calls.some((c) => c.url === "/board?days=7")).toBe(true));
  });
});
