import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { MAX_LOADED, RawTab } from "./RawTab";

// The virtual list asks for the next page whenever its last visible row is near the end: render "everything visible"
// so the test drives paging the way endless scrolling would.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () => (count ? [{ index: count - 1, key: count - 1, start: 0 }] : []),
    getTotalSize: () => count * 24,
  }),
}));
afterEach(() => vi.unstubAllGlobals());

const INV = "inv-1";
const page = (n: number, size: number) => Array.from({ length: size }, (_, i) => ({ event_id: `e${n}-${i}`, timestamp: "2026-10-01T00:00:00Z", src_ip: "198.51.100.1" }));

describe("Raw events table", () => {
  it("holds one section in memory, moves to the next by cursor and releases the previous rows", async () => {
    const size = MAX_LOADED / 4;
    let n = 0;
    const api = mockApi({
      [`POST /investigations/${INV}/query/events`]: () => [200, { events: page(n++, size), next_cursor: `c${n}` }],
      [`POST /investigations/${INV}/query/aggregate`]: [200, { value: 50_000 }],
    });
    renderUI(<RawTab inv={INV} />);
    expect(await screen.findByText(/한 번에 20,000건씩 봅니다/)).toBeTruthy();
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/query/events`)).toHaveLength(4));
    await new Promise((r) => setTimeout(r, 50));
    expect(api.find("POST", `/investigations/${INV}/query/events`)).toHaveLength(4);   // endless data, bounded requests
    expect(screen.getByText(/조건에 맞는 전체 50,000건 · 화면 1~20,000번째/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "다음 20,000건 →" }));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/query/events`)[4].body.cursor).toBe("c4"));
    expect(await screen.findByText(/화면 20,001~/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "← 이전 20,000건" })).toBeTruthy();
  });

  it("exports the whole search on the server, not just the loaded rows", async () => {
    const api = mockApi({
      [`POST /investigations/${INV}/query/events`]: [200, { events: page(0, 3), next_cursor: "more" }],
      [`POST /investigations/${INV}/query/aggregate`]: [200, { value: 30_000 }],
      [`POST /investigations/${INV}/query/events/export`]: [200, "timestamp", { "x-saw-rows": "30000", "x-saw-total": "30000", "x-saw-truncated": "false" }],
    });
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => undefined }));
    renderUI(<RawTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "조건 전체 결과 CSV (서버, 가림)" }));
    expect(await screen.findByText("조건에 맞는 전체 30,000건을 내보냈습니다.")).toBeTruthy();
    const call = api.find("POST", `/investigations/${INV}/query/events/export`)[0];
    expect(call.body).toMatchObject({ filters: [], time: null });
    expect(call.body.columns.length).toBeGreaterThan(0);
  });

  it("shows no section notice when everything fits", async () => {
    mockApi({
      [`POST /investigations/${INV}/query/events`]: [200, { events: page(0, 3), next_cursor: null }],
      [`POST /investigations/${INV}/query/aggregate`]: [200, { value: 3 }],
    });
    renderUI(<RawTab inv={INV} />);
    expect(await screen.findByText(/조건에 맞는 전체 3건 · 화면 1~3번째/)).toBeTruthy();
    expect(screen.queryByText(/한 번에 20,000건씩/)).toBeNull();
  });

  it("shows records per day for the time column and narrows by a whole day, never filtering time by another field", async () => {
    // UX-08: the time column aggregated data_source and then built "timestamp is connection".
    const day = Date.parse("2026-10-01T00:00:00+09:00") / 1000;
    const api = mockApi({
      [`POST /investigations/${INV}/query/events`]: [200, { events: page(0, 3), next_cursor: null }],
      [`POST /investigations/${INV}/query/aggregate`]: [200, { buckets: [{ key: day, count: 5 }, { key: day + 3600, count: 2 }] }],
    });
    renderUI(<RawTab inv={INV} />);
    await screen.findByText(/화면 1~3번째/);
    const headers = screen.getAllByText("timestamp");
    fireEvent.click(headers[headers.length - 1]);
    expect(await screen.findByText("2026-10-01")).toBeTruthy();
    expect(screen.getByText("7")).toBeTruthy();
    expect(api.find("POST", `/investigations/${INV}/query/aggregate`).map((c) => c.body.agg)).toContainEqual({ type: "date_histogram", field: "timestamp", interval_sec: 3600 });
    expect(screen.queryByRole("button", { name: "포함" })).toBeNull();
    expect(screen.getByRole("button", { name: "이 날로 좁히기" })).toBeTruthy();
  });
});
