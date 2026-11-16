import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi } from "../../test/helpers";
import { SourceContextTab } from "./SourceContextTab";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

// UX-01: with both investigations cached, a selection made in A must not be saved while B is shown.
describe("switching investigations", () => {
  it("drops A's device selection when B is shown, so no profile can be saved to A's device from B", async () => {
    const api = mockApi({
      "GET /source-context/org-units": [200, []],
      "GET /source-context/investigations/A/devices": [200, [{ id: "devA", display_name: "A 방화벽" }]],
      "GET /source-context/investigations/B/devices": [200, [{ id: "devB", display_name: "B 방화벽" }]],
      "GET /source-context/devices/devA/profiles": [200, []],
      "GET /investigations/A": [200, { evidence: [] }],
      "GET /investigations/B": [200, { evidence: [] }],
      "POST /source-context/devices/devA/profiles": [201, { id: "p", version: 1 }],
    }) as any;
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 60_000 } } });
    const tree = (inv: string) => <QueryClientProvider client={qc}><MemoryRouter><SourceContextTab inv={inv} /></MemoryRouter></QueryClientProvider>;
    const view = render(tree("A"));
    await screen.findByRole("option", { name: "A 방화벽" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "devA" } });
    expect(await screen.findByRole("button", { name: "새 프로필 버전 저장" })).toBeTruthy();

    view.rerender(tree("B"));
    await screen.findByRole("option", { name: "B 방화벽" });
    await waitFor(() => expect(screen.queryByRole("button", { name: "새 프로필 버전 저장" })).toBeNull());
    expect((screen.getByLabelText("장비 선택") as HTMLSelectElement).value).toBe("");
    expect(api.find("POST", "/source-context/devices/devA/profiles")).toHaveLength(0);
  });

  it("prefills the Korean firewall export columns and leaves meanings unverified until confirmed", async () => {
    // F02: no column-by-column typing; what changes the analysis still needs the analyst's confirmation.
    const api = mockApi({
      "GET /source-context/org-units": [200, []],
      "GET /source-context/investigations/A/devices": [200, [{ id: "devA", display_name: "A 방화벽" }]],
      "GET /source-context/devices/devA/profiles": [200, []],
      "GET /investigations/A": [200, { evidence: [] }],
      "POST /source-context/devices/devA/profiles": [201, { id: "p", version: 1 }],
    }) as any;
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><MemoryRouter><SourceContextTab inv="A" /></MemoryRouter></QueryClientProvider>);
    await screen.findByRole("option", { name: "A 방화벽" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "devA" } });
    fireEvent.click(await screen.findByRole("button", { name: "한국형 FW 내보내기 기본값" }));
    fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
    await waitFor(() => expect(api.find("POST", "/source-context/devices/devA/profiles")).toHaveLength(1));
    const body = api.find("POST", "/source-context/devices/devA/profiles")[0].body;
    expect(body.source_fields).toMatchObject({ timestamp: "탐지시간", action: "대응", src_bytes: "송신바이트", dst_bytes: "수신바이트", duration: "세션시간" });
    expect(body.action_map).toEqual({ "허용": "allowed", "차단": "blocked" });
    expect(body.measurement_profile).toMatchObject({ counter_semantics: "total", verified: false });
    expect(body.time).toMatchObject({ role: "unknown", verified: false });
  });
});
