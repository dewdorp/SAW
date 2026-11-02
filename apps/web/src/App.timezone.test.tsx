import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";
import { App } from "./App";
import { useInvStore, useInvTabs } from "./context/invContext";
import { setTz } from "./lib/format";
import { ME, mockApi, renderUI } from "./test/helpers";

// Keep the actual route, workbench and overview; only canvas rendering is irrelevant here.
vi.mock("./viz/EChart", () => ({
  EChart: ({ ariaLabel }: { ariaLabel?: string }) => <div role="img" aria-label={ariaLabel} />,
  TopBar: () => null,
  axisStyle: {},
  safeTooltip: () => () => "",
}));

const inv = {
  id: "i1", display_id: "INV-1", title: "시간대 합성 검증", status: "in_progress",
  risk_level: "low", risk_score: 10, evidence: [], finding_counts: {},
  time_start: "2026-10-04T17:30:09", time_end: "2026-10-04T18:49:55",
};
const bucket = { buckets: [] };
const overview = {
  summary: { files: 1, events: 592, time_range: ["2026-10-04T17:30:09Z", "2026-10-04T18:49:55Z"],
    findings: {}, unique_ip: 3, unique_uri: 4, parse_error_rate: 0, data_sources: [] },
  charts: { volume: { ...bucket, interval_sec: 60 }, size_trend: bucket, unique_ip_trend: bucket,
    status: bucket, top_src: bucket, top_uri: bucket, top_ua: bucket, top_asn: bucket, top_country: bucket, top_cloud: bucket },
  top_findings: [],
};

// Finish loading the actual lazy route before timing its UI assertions.
// Cold module transforms under concurrent suites are setup, not time-zone behavior.
beforeAll(async () => {
  await import("./pages/inv/Workbench");
});

const EMPTY = { label: "", buckets: [], other: 0, recorded: 0, not_recorded: 0 };
const SUMMARY = {
  scope: { org_unit: "가상 관계사", org_unit_id: "o1", period_start: null, period_end: null, period_declared: false, observed_start: null, observed_end: null, timezone: "Asia/Seoul" },
  basis: { kind: "all", all_events: 592, events: 592, note: "" },
  time: { with_timestamp: 592, without_timestamp: 0, outside_period: null, daily: [], weekly: [], empty_days: [], interval_sec: 3600 },
  inputs: { files: 1, lines: 593, events: 592, failed_lines: 0, rejected_events: 0, timestamp_missing: 0, timestamp_invalid: 0, unsupported_files: 0, files_with_notes: 0, by_file: [], files_truncated: false },
  breakdown: Object.fromEntries(["data_source", "enforcement_action", "alert_name", "src_ip", "dst_ip", "dst_port", "protocol"].map((k) => [k, EMPTY])),
  analysis: null, method_note: "규칙 기반 집계입니다.",
};

beforeEach(() => {
  vi.stubGlobal("innerWidth", 1440);
  setTz("KST");
  useInvStore.setState({ byInv: {} });
  useInvTabs.setState({ tabs: [] });
  mockApi({
    "GET /auth/me": [200, ME], "GET /jobs": [200, []],
    "GET /investigations/i1": [200, inv],
    "POST /investigations/i1/query/aggregate": [200, { ...bucket, total: 592 }],
    "POST /investigations/i1/overview": [200, overview],
    "GET /investigations/i1/network/overview": [200, { available: false }],
    "GET /investigations/i1/correlations": [200, []],
    "POST /investigations/i1/context": [200, {}],
    "GET /investigations/i1/checks/marks": [200, { events: {}, findings: {} }],
    "POST /investigations/i1/scope-summary": [200, SUMMARY],
    "GET /investigations/i1/alert-names": [200, { items: [], events_with_alert: 0, note: "" }],
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  setTz("KST");
});

it("updates workbench and overview when the time-zone button is toggled without resetting the view", async () => {
  renderUI(<App />, { route: "/inv/i1" });
  // The workbench opens on the whole picture; the traffic overview is one click away in the same area.
  expect(await screen.findByText(/집계 기준: 조사 전체 592건/, {}, { timeout: 5000 })).toBeTruthy();
  fireEvent.click(screen.getByRole("tab", { name: "트래픽 개요" }));
  await screen.findByText("분석 개요", {}, { timeout: 5000 });
  const header = screen.getByText("관측 기간").parentElement!;
  const summary = screen.getByText("분석 개요").parentElement!;
  const kst = "10-05-02:30:09 ~ 10-05-03:49:55";
  const utc = "10-04-17:30:09 ~ 10-04-18:49:55";
  expect(header.textContent).toContain(kst);
  expect(summary.textContent).toContain(kst);

  fireEvent.click(screen.getByRole("button", { name: "조사 안내·참고 숨기기" }));
  fireEvent.click(screen.getByTitle("표시 시간대 전환"));
  expect(screen.getByTitle("표시 시간대 전환").textContent).toContain("UTC");
  await waitFor(() => {
    expect(header.textContent).toContain(utc);
    expect(summary.textContent).toContain(utc);
  });
  expect(screen.getByRole("button", { name: "조사 안내·참고 보기" })).toBeTruthy();

  fireEvent.click(screen.getByTitle("표시 시간대 전환"));
  expect(screen.getByTitle("표시 시간대 전환").textContent).toContain("KST");
  await waitFor(() => {
    expect(header.textContent).toContain(kst);
    expect(summary.textContent).toContain(kst);
  });
  expect(screen.getByRole("button", { name: "조사 안내·참고 보기" })).toBeTruthy();
});


it("keeps analysis visible first in a narrow window while allowing evidence controls", async () => {
  vi.stubGlobal("innerWidth", 554);
  renderUI(<App />, { route: "/inv/i1" });
  await screen.findByText(/집계 기준: 조사 전체/);
  expect(screen.queryByRole("complementary", { name: "증거와 필터" })).toBeNull();
  expect(screen.queryByRole("complementary", { name: "컨텍스트" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "증거·필터 보기" }));
  expect(screen.getByRole("complementary", { name: "증거와 필터" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "트래픽 개요" })).toBeTruthy();
});
