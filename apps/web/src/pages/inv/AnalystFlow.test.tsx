import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../../App";
import { useInvStore, useInvTabs } from "../../context/invContext";
import { ME, mockApi, renderUI } from "../../test/helpers";
import { InternalGoldenPanel } from "./InternalGoldenPanel";
import { ScopeSummary } from "./ScopeSummary";

vi.mock("../../viz/EChart", () => ({
  EChart: ({ ariaLabel }: { ariaLabel?: string }) => <div role="img" aria-label={ariaLabel} />,
  TopBar: () => null, axisStyle: {}, safeTooltip: () => () => "",
}));

const EMPTY = { label: "", buckets: [], other: 0, recorded: 0, not_recorded: 0 };
const summary = (kind = "all", status = "complete") => ({
  scope: { org_unit: "가상 한빛금융", org_unit_id: "aff1", period_start: "2026-09-29T00:00:00+09:00", period_end: "2026-10-28T23:59:59+09:00",
    period_declared: true, observed_start: "2026-09-29T00:00:00+09:00", observed_end: "2026-10-28T23:00:00+09:00", timezone: "Asia/Seoul" },
  basis: { kind, all_events: 100000, events: kind === "all" ? 100000 : 6000, note: "" },
  time: { with_timestamp: 99990, without_timestamp: 10, outside_period: { before: 0, after: 3 },
    daily: [{ date: "2026-10-01", count: 3334 }, { date: "2026-10-02", count: 0 }], weekly: [{ week: "2026-W40", count: 3334 }],
    empty_days: ["2026-10-02"], interval_sec: 3600 },
  inputs: { files: 1, lines: 100001, events: 100000, failed_lines: 1, rejected_events: 0, timestamp_missing: 4, timestamp_invalid: 6,
    unsupported_files: 0, files_with_notes: 1, files_truncated: false,
    by_file: [{ name: "volume.csv", parser_id: "ko_fw_csv", status: "done", events: 100000, failed: 1,
      message: "구분자를 ';'로 인식했습니다. · 이 형식의 열 중 없는 열: 세션시간." }] },
  breakdown: { ...Object.fromEntries(["data_source", "src_ip", "dst_ip", "dst_port", "protocol"].map((k) => [k, EMPTY])),
    // Under a filter the alert card shows the filtered counts, like every other card.
    alert_name: { label: "장비 공격명", buckets: kind === "all" ? [{ key: "Synthetic Scan", count: 9 }, { key: "Vendor Label X", count: 2 }]
      : [{ key: "Synthetic Scan", count: 4 }, { key: "Vendor Label X", count: 1 }], other: 0, recorded: 11, not_recorded: 0 },
    enforcement_action: { label: "처리 결과", buckets: [{ key: "allowed", count: 94000, label: "허용" }, { key: "blocked", count: 6000, label: "차단" }],
      other: 0, recorded: 100000, not_recorded: 0 } },
  analysis: { run_id: "r1", version: 2, status, incomplete: [{ detector_id: "anomaly.peer", status: "partial", label: "일부만 처리" }] },
  method_note: "규칙 기반 집계입니다. 모델 판단이나 장기 정상 기준선 비교가 아닙니다.",
});
const alerts = { items: [{ alert_name: "Synthetic Scan", count: 9, registry: "confirmed", entries: [{ meaning: "경로 탐색" }] },
  { alert_name: "Vendor Label X", count: 2, registry: "needs_confirmation", entries: [] }], events_with_alert: 11, note: "장비의 주장입니다." };

// Load the lazy workbench route before timing UI assertions (setup, not behaviour).
beforeAll(async () => { await import("./Workbench"); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
beforeEach(() => { useInvStore.setState({ byInv: {} }); useInvTabs.setState({ tabs: [] }); });

describe("whole picture", () => {
  it("can leave a narrowed candidate scope to inspect all collected logs without losing the investigation", async () => {
    useInvStore.getState().set("i1", { filters: [{ field: "src_ip", op: "is", value: "192.0.2.9" }], time: { start: "2026-10-01T00:00:00Z" }, eventId: "old-event" });
    mockApi({ "POST /investigations/i1/scope-summary": [200, summary("filter")], "GET /investigations/i1/alert-names": [200, alerts] });
    renderUI(<ScopeSummary inv="i1" />);
    const region = await screen.findByRole("region", { name: "자료 현황" });
    expect(await within(region).findByText("100,000")).toBeTruthy();
    expect(within(region).getByText(/6,000건/)).toBeTruthy();
    fireEvent.click(within(region).getByRole("button", { name: "전체 로그 보기" }));
    expect(useInvStore.getState().byInv.i1).toMatchObject({ tab: "raw", filters: [], time: null, eventId: null });
  });

  it("keeps the full-log and statistics routes available if the summary aggregation fails", async () => {
    mockApi({ "POST /investigations/i1/scope-summary": [503, { detail: "집계 일시 중단" }] });
    renderUI(<ScopeSummary inv="i1" />);
    expect(await screen.findByText(/집계 일시 중단/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "전체 로그 통계" }));
    expect(useInvStore.getState().byInv.i1.tab).toBe("statistics");
  });
  it("states its basis, keeps the whole denominator under a filter and shows gaps, parse notes and alert registry", async () => {
    mockApi({ "POST /investigations/i1/scope-summary": [200, summary("filter")], "GET /investigations/i1/alert-names": [200, alerts] });
    renderUI(<ScopeSummary inv="i1" />);
    expect(await screen.findByText("집계 기준: 현재 필터 6,000건 (조사 전체 100,000건 중)")).toBeTruthy();
    expect(screen.getByText(/기록이 하나도 없는 날 1일: 2026-10-02/)).toBeTruthy();
    expect(screen.getByText(/시간 없음·해석 불가 10건/)).toBeTruthy();
    expect(screen.getByText(/조사 기간 밖 기록: 이전 0건, 이후 3건/)).toBeTruthy();
    expect(screen.getByText("⚠ 구분자를 ';'로 인식했습니다.")).toBeTruthy();
    expect(screen.getByText("⚠ 이 형식의 열 중 없는 열: 세션시간.")).toBeTruthy();
    expect(await screen.findByText("의미 확인 필요")).toBeTruthy();
    expect(screen.getByText("의미 확인됨(같은 장비·유효기간)")).toBeTruthy();
    expect(screen.getByText("anomaly.peer: 일부만 처리")).toBeTruthy();
    expect(screen.getByText(/장기 정상 기준선 비교가 아닙니다/)).toBeTruthy();
    // UX-04: the alert card follows the filter (4 of the whole 9), and says so.
    expect(screen.getByText(/현재 필터 기준 건수/)).toBeTruthy();
    expect(screen.getByText("4")).toBeTruthy();
  });

  it("never reports a running analysis as finished", async () => {
    // UX-05: a running run with no incomplete detector yet is still running, not "all finished".
    const running = { ...summary("all", "running"), analysis: { run_id: "r2", version: 3, status: "running", incomplete: [] } };
    mockApi({ "POST /investigations/i1/scope-summary": [200, running], "GET /investigations/i1/alert-names": [200, alerts] });
    renderUI(<ScopeSummary inv="i1" />);
    expect(await screen.findByText(/분석이 아직 진행 중입니다/)).toBeTruthy();
    expect(screen.queryByText(/모든 분석이 설정된 범위에서 끝났습니다/)).toBeNull();
  });
});

describe("internal golden set", () => {
  it("saves a prefilled draft directly, then edits with the version it was based on", async () => {
    const draft = { title: "가상 조사", scope: { org_unit: "가상 한빛금융", org_unit_id: "aff1", period_start: "2026-09-29T00:00:00+09:00", period_end: "2026-10-28T23:59:59+09:00" },
      initial_logs: [{ file: "fw.csv", parser: "ko_fw_csv", events: 90, failed: 0 }], initial_evidence_refs: [], observed_facts: ["경로 탐색 404 다수"],
      initial_judgement: { status: "insufficient_evidence", rationale: "", scope: "" }, questions: ["정기 점검인가?"],
      followups: [{ question: "정기 점검인가?", target: "출발지 198.51.100.23", period: "", reply: "", reply_scope_result: "", outcome: "open", remaining: [], evidence_refs: [] }],
      final_judgement: { status: "", rationale: "", scope: "" }, unresolved: ["정기 점검인가?: 회신·검증 미완료"], notes: "",
      lineage: { synthetic: false, source: "investigation", variant_group_id: "", split_group_id: "", split: "unassigned" } };
    let saved: any = null;
    const api = mockApi({
      "GET /auth/me": [200, ME],
      "GET /investigations/i1/internal-golden": () => [200, { record: saved }],
      "GET /investigations/i1/internal-golden/draft": [200, { content: draft }],
      "POST /investigations/i1/internal-golden": (call: any) => {
        saved = { id: "g1", version: (saved?.version || 0) + 1, content: call.body.content, versions: [{ version: (saved?.version || 0) + 1, change_note: call.body.change_note, created_at: "2026-10-29T00:00:00Z" }] };
        return [201, saved];
      },
    } as any);
    renderUI(<InternalGoldenPanel inv="i1" />);
    expect(await screen.findByText(/가명처리·별도 승인·직접 해시 확인 없이/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "조사 내용으로 초안 만들기" }));
    expect(await screen.findByText(/후속 증거와 회신/)).toBeTruthy();
    expect((screen.getByLabelText("추가 질문") as HTMLTextAreaElement).value).toBe("정기 점검인가?");
    expect(screen.getByText("출발지 198.51.100.23", { exact: false })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("최종 판단 상태"), { target: { value: "insufficient_evidence" } });
    fireEvent.change(screen.getByLabelText("최종 판단 근거"), { target: { value: "회신 없음" } });
    fireEvent.click(screen.getByRole("button", { name: "골든셋으로 저장" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/internal-golden")).toHaveLength(1));
    const first = api.find("POST", "/investigations/i1/internal-golden")[0].body;
    expect(first.expected_version).toBeNull();
    expect(first.content.final_judgement).toEqual({ status: "insufficient_evidence", rationale: "회신 없음", scope: "" });
    expect(first.content.questions).toEqual(["정기 점검인가?"]);
    fireEvent.click(await screen.findByRole("button", { name: "저장 (v2)" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/internal-golden")).toHaveLength(2));
    expect(api.find("POST", "/investigations/i1/internal-golden")[1].body.expected_version).toBe(1);
  });
});

describe("three work areas", () => {
  const inv = { id: "i1", display_id: "INV-1", title: "영역 검증", status: "in_progress", risk_level: "low", risk_score: 10, evidence: [],
    finding_counts: {}, org_unit: "가상 한빛금융", org_unit_id: "aff1", period_start: "2026-09-29T00:00:00+09:00", period_end: "2026-10-28T23:59:59+09:00" };
  beforeEach(() => {
    vi.stubGlobal("innerWidth", 1440);
    mockApi({
      "GET /auth/me": [200, ME], "GET /jobs": [200, []], "GET /investigations/i1": [200, inv],
      "POST /investigations/i1/query/aggregate": [200, { buckets: [], total: 0 }],
      "POST /investigations/i1/scope-summary": [200, summary()], "GET /investigations/i1/alert-names": [200, alerts],
      "POST /investigations/i1/context": [200, {}], "GET /investigations/i1/checks/marks": [200, { events: {}, findings: {} }],
      "GET /investigations/i1/internal-golden": [200, { record: null }],
    });
  });

  it("opens on the whole picture, groups the other views and keeps specialist views one click away", async () => {
    renderUI(<App />, { route: "/inv/i1" });
    expect(await screen.findByText("집계 기준: 조사 전체 100,000건", {}, { timeout: 5000 })).toBeTruthy();
    const scope = screen.getByRole("group", { name: "조사 범위" });
    expect(within(scope).getByText("가상 한빛금융")).toBeTruthy();
    expect(screen.getByRole("tab", { name: "장비·자료 의미" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: "HTTP" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "② 조사" }));
    expect(screen.getByRole("tab", { name: "조사 제안" })).toBeTruthy();
    expect(screen.queryByRole("tab", { name: "HTTP" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /전문 분석 8개 펼치기/ }));
    expect(screen.getByRole("tab", { name: "HTTP" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "③ 전체 로그" }));
    expect(screen.getByRole("tab", { name: "전체 로그·원문" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "로그 통계" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "④ 확인 및 판단" }));
    expect(screen.getByRole("tab", { name: "골든셋 저장" })).toBeTruthy();
  });

  it("adds a free search condition that is independent of the suggested candidates", async () => {
    renderUI(<App />, { route: "/inv/i1" });
    await screen.findByText("집계 기준: 조사 전체 100,000건", {}, { timeout: 5000 });
    fireEvent.click(screen.getByRole("button", { name: "로그 직접 검색" }));
    const search = screen.getByRole("search", { name: "로그 직접 검색" });
    fireEvent.change(within(search).getByLabelText("검색 필드"), { target: { value: "dst_port" } });
    fireEvent.change(within(search).getByLabelText("검색 값"), { target: { value: "4444" } });
    fireEvent.click(within(search).getByRole("button", { name: "조건 추가" }));
    await waitFor(() => expect(useInvStore.getState().get("i1").filters).toEqual([{ field: "dst_port", op: "is", value: 4444 }]));
    expect(useInvStore.getState().get("i1").tab).toBe("raw");
    expect(screen.getByText(/목적지 포트 = 4444/)).toBeTruthy();
  });
});
