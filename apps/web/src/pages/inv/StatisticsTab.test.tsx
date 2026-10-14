import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { StatisticsTab, statisticsCsv } from "./StatisticsTab";

vi.mock("../../viz/EChart", () => ({ EChart: ({ onBrush, ariaLabel }: any) => onBrush ? <button onClick={() => onBrush([0, 0])}>구간 선택</button> : <div aria-label={ariaLabel} />, axisStyle: {}, safeTooltip: () => () => "" }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); useInvStore.setState({ byInv: {} }); });
const INV = "stats-inv";
const DATA = { scope: { investigation_id: INV, filters: [], time: null },
  summary: { matched_events: 100, time_start: "2026-10-14T00:00:00Z", time_end: "2026-10-14T01:00:00Z", timestamp_missing: 2 },
  table: { group_by: "src_ip", rows: [{ key: { src_ip: "192.0.2.1" }, count: 70, bytes_out_sum: 7000, bytes_out_known_events: 70,
    first_ts: "2026-10-14T00:00:00Z", last_ts: "2026-10-14T01:00:00Z", filter: [{ field: "src_ip", op: "is", value: "192.0.2.1" }] }],
    shown_events: 70, other_events: 20, missing_events: 10, limit: 20, approximate: true },
  timeline: { interval_sec: 60, buckets: [{ key: 1791936000, count: 98 }] } };

describe("Scoped statistics", () => {
  it("explains denominators, estimates and source bytes without declaring attacks", async () => {
    mockApi({ [`POST /investigations/${INV}/statistics`]: [200, DATA] });
    renderUI(<StatisticsTab inv={INV} />);
    expect(await screen.findByText("192.0.2.1")).toBeTruthy();
    expect(screen.getByText(/기타.*20/)).toBeTruthy();
    expect(screen.getByText(/분류 값 없음.*10/)).toBeTruthy();
    expect(screen.getByText(/상위 집계는 근삿값/)).toBeTruthy();
    expect(screen.getByText(/실제 전송량과 다를 수/)).toBeTruthy();
  });
  it("preserves the current query when drilling down to raw events", async () => {
    const time = { start: "2026-10-14T00:00:00Z", end: "2026-10-14T01:00:00Z" };
    const filters = [{ field: "data_source", op: "is" as const, value: "web" }];
    useInvStore.getState().set(INV, { filters, time });
    const api = mockApi({ [`POST /investigations/${INV}/statistics`]: [200, DATA] });
    renderUI(<StatisticsTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "192.0.2.1 원본 로그" }));
    expect(useInvStore.getState().get(INV)).toMatchObject({ tab: "raw", time,
      filters: [...filters, { field: "src_ip", op: "is", value: "192.0.2.1" }] });
    expect(api.calls[0].body).toMatchObject({ time, filters });
  });
  it("changes grouping and warns that duplicate filenames within an evidence bundle can merge", async () => {
    const api = mockApi({ [`POST /investigations/${INV}/statistics`]: [200, DATA] });
    renderUI(<StatisticsTab inv={INV} />);
    fireEvent.change(screen.getByLabelText("통계 기준"), { target: { value: "source_file" } });
    expect(await screen.findByText(/동명 파일은 합산/)).toBeTruthy();
    await waitFor(() => expect(api.calls.some(c => c.body.group_by === "source_file")).toBe(true));
  });
  it("intersects chart buckets with the already selected sub-second range", async () => {
    const time = { start: "2026-10-14T00:00:00.200Z", end: "2026-10-14T00:00:00.800Z" };
    useInvStore.getState().set(INV, { time });
    mockApi({ [`POST /investigations/${INV}/statistics`]: [200, { ...DATA,
      scope: { ...DATA.scope, time }, timeline: { interval_sec: 1, buckets: [{ key: Date.parse("2026-10-14T00:00:00Z") / 1000, count: 1 }] } }] });
    renderUI(<StatisticsTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "구간 선택" }));
    expect(useInvStore.getState().get(INV).time).toEqual(time);
  });
  it("shows an API failure without inventing zero statistics", async () => {
    mockApi({ [`POST /investigations/${INV}/statistics`]: [503, { detail: "statistics unavailable" }] });
    renderUI(<StatisticsTab inv={INV} />);
    expect(await screen.findByText(/statistics unavailable/)).toBeTruthy();
    expect(screen.queryByText("표시 합계 0")).toBeNull();
  });
});


describe("Statistics metric controls and safe displayed export", () => {
  it("adds pair and HTTP grouping and sends the selected metric order", async () => {
    const api = mockApi({ [`POST /investigations/${INV}/statistics`]: [200, DATA] });
    renderUI(<StatisticsTab inv={INV} />);
    await screen.findByText("192.0.2.1");
    fireEvent.change(screen.getByLabelText("통계 기준"), { target: { value: "src_dst" } });
    fireEvent.change(screen.getByLabelText("정렬 지표"), { target: { value: "http_error_count" } });
    await waitFor(() => expect(api.calls.some(c => c.body.group_by === "src_dst" && c.body.order_by === "http_error_count")).toBe(true));
    expect(await screen.findByRole("button", { name: "표시된 통계 CSV 내보내기" })).toBeTruthy();
    expect(screen.getByText(/표시된 상위 그룹만/)).toBeTruthy();
  });
  it("exports exact response scope, missing coverage and top-only limits safely", () => {
    const csv = statisticsCsv({ ...DATA,
      scope: { investigation_id: INV, filters: [{ field: "method", value: "POST" }], time: { start: "2026-10-14T00:00:00Z" } },
      table: { ...DATA.table, rows: [{ ...DATA.table.rows[0],
        key: { method: '\t =HYPERLINK("bad")\nnext' }, bytes_in_sum: null, http_status_known_events: 0, http_error_rate: null }] }
    });
    expect(csv).toContain("POST");
    expect(csv).toContain("2026-10-14T00:00:00Z");
    expect(csv).toContain("표시된 상위 그룹만");
    expect(csv).toContain("값 없음");
    expect(csv).toContain('\t =HYPERLINK(""bad"")\nnext');
    expect(csv).toContain("\"'");
    expect(csv).not.toContain("never-export-this-raw");
  });
});
