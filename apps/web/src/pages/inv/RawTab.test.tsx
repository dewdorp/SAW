import { screen, waitFor } from "@testing-library/react";
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
    expect(await screen.findByText(/3 loaded/)).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });
});
