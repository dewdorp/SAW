import { cleanup, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { OverviewTab } from "./OverviewTab";
vi.mock("../../viz/EChart", () => ({ EChart: ({ ariaLabel }: any) => <div role="img" aria-label={ariaLabel} />, TopBar: ({ title }: any) => <div>{title}</div>, axisStyle: {}, safeTooltip: () => () => "" }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); useInvStore.setState({ byInv: {} }); });
const overview = (sources: string[]) => ({ summary: { files: 1, events: 9, time_range: [null, null], unique_ip: 2, unique_uri: 0, findings: {}, parse_error_rate: 0, data_sources: sources.map(key => ({ key, count: 9 })) }, top_findings: [], charts: Object.fromEntries(["volume", "size_trend", "unique_ip_trend", "status", "top_src", "top_uri", "top_ua", "top_asn", "top_country", "top_cloud"].map(key => [key, { buckets: [], interval_sec: 60 }])) });
const start = (sources: string[], httpFields = false) => {
  const response = overview(sources);
  if (httpFields) {
    response.summary.unique_uri = 1;
    Object.assign(response.charts.status, { buckets: [{ key: 200, count: 3 }] });
    Object.assign(response.charts.top_uri, { buckets: [{ key: "/synthetic-http", count: 3 }] });
    Object.assign(response.charts.top_ua, { buckets: [{ key: "Synthetic Browser", count: 3 }] });
  }
  mockApi({ "POST /investigations/i1/overview": [200, response], "GET /investigations/i1/correlations": [200, []], "GET /investigations/i1/network/overview": [200, { available: false }] });
  renderUI(<OverviewTab inv="i1" />);
};
describe("overview source semantics", () => {
  it("uses neutral counters and excludes HTTP chart claims for firewall-only records", async () => {
    start(["connection"]);
    expect(await screen.findByText("기록 카운터 (의미는 장비 분석 참조)")).toBeTruthy();
    expect(screen.queryByText("HTTP 응답 상태 분포")).toBeNull();
    expect(screen.queryByText("응답 크기 추이")).toBeNull();
    expect(screen.queryByText("주요 URI 패턴")).toBeNull();
    expect(screen.queryByText("주요 User-Agent")).toBeNull();
    expect(screen.getByRole("img", { name: "record counters" })).toBeTruthy();
    expect(screen.queryByRole("img", { name: "response size" })).toBeNull();
  });
  it("keeps HTTP charts for pure HTTP sources but uses neutral counters for mixed sources", async () => {
    start(["web", "connection"]);
    expect(await screen.findByText("HTTP 응답 상태 분포")).toBeTruthy();
    expect(screen.getByText("기록 카운터 (의미는 장비 분석 참조)")).toBeTruthy();
    expect(screen.queryByRole("img", { name: "response size" })).toBeNull();
  });
  it("preserves response-size charts for HTTP-only records", async () => {
    start(["web"]);
    expect(await screen.findByText("응답 크기 추이")).toBeTruthy();
    expect(screen.getByRole("img", { name: "response size" })).toBeTruthy();
  });
});

it.each(["custom", "suricata", "connection"])("preserves normalized HTTP fields from %s without claiming response-counter semantics", async source => {
  start([source], true);
  expect(await screen.findByText("HTTP 응답 상태 분포")).toBeTruthy();
  expect(screen.getByText("주요 URI 패턴")).toBeTruthy();
  expect(screen.getByText("주요 User-Agent")).toBeTruthy();
  expect(screen.getByText(/고유 URI/)).toBeTruthy();
  expect(screen.getByText("기록 카운터 (의미는 장비 분석 참조)")).toBeTruthy();
  expect(screen.queryByRole("img", { name: "response size" })).toBeNull();
});
it("does not hide possible HTTP views solely because a source name is unknown", async () => {
  start(["custom"]);
  expect(await screen.findByText("주요 URI 패턴")).toBeTruthy();
});
