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
  it("stops loading at the memory bound and says how to see the rest", async () => {
    const size = MAX_LOADED / 4;
    let n = 0;
    const api = mockApi({ [`POST /investigations/${INV}/query/events`]: () => [200, { events: page(n++, size), next_cursor: `c${n}` }] });
    renderUI(<RawTab inv={INV} />);
    expect((await screen.findByRole("status")).textContent).toContain("까지만 불러옵니다");
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/query/events`)).toHaveLength(4));
    await new Promise((r) => setTimeout(r, 50));
    expect(api.find("POST", `/investigations/${INV}/query/events`)).toHaveLength(4);   // endless data, bounded requests
  });

  it("shows no notice when everything fits", async () => {
    mockApi({ [`POST /investigations/${INV}/query/events`]: [200, { events: page(0, 3), next_cursor: null }] });
    renderUI(<RawTab inv={INV} />);
    expect(await screen.findByText(/3건 불러옴/)).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("shows records per day for the time column and narrows by a whole day, never filtering time by another field", async () => {
    // UX-08: the time column aggregated data_source and then built "timestamp is connection".
    const day = Date.parse("2026-10-01T00:00:00+09:00") / 1000;
    const api = mockApi({
      [`POST /investigations/${INV}/query/events`]: [200, { events: page(0, 3), next_cursor: null }],
      [`POST /investigations/${INV}/query/aggregate`]: [200, { buckets: [{ key: day, count: 5 }, { key: day + 3600, count: 2 }] }],
    });
    renderUI(<RawTab inv={INV} />);
    await screen.findByText(/3건 불러옴/);
    const headers = screen.getAllByText("timestamp");
    fireEvent.click(headers[headers.length - 1]);
    expect(await screen.findByText("2026-10-01")).toBeTruthy();
    expect(screen.getByText("7")).toBeTruthy();
    expect(api.find("POST", `/investigations/${INV}/query/aggregate`)[0].body.agg).toEqual({ type: "date_histogram", field: "timestamp", interval_sec: 3600 });
    expect(screen.queryByRole("button", { name: "포함" })).toBeNull();
    expect(screen.getByRole("button", { name: "이 날로 좁히기" })).toBeTruthy();
  });
});
