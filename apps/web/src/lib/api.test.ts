import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi } from "../test/helpers";
import { api, ApiError } from "./api";

afterEach(() => { vi.unstubAllGlobals(); document.cookie = "saw_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT"; });

describe("api client", () => {
  it("sends the CSRF cookie as a header on unsafe methods only", async () => {
    document.cookie = "saw_csrf=tok%2Fen";
    const m = mockApi({ "GET /x": [200, { ok: 1 }], "POST /x": [200, { ok: 2 }] });
    await api.get("/x");
    await api.post("/x", { a: 1 });
    expect(m.calls[0].headers["x-csrf-token"]).toBeUndefined();
    expect(m.calls[1].headers["x-csrf-token"]).toBe("tok/en");
    expect(m.calls[1].body).toEqual({ a: 1 });
  });

  it("raises ApiError with the server detail", async () => {
    mockApi({ "GET /bad": [409, { detail: "이 이벤트는 PCAP에서 추출된 것이 아닙니다" }] });
    const err = await api.get("/bad").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.message).toContain("PCAP");
  });

  it("announces an expired session (401) except on /auth/* calls", async () => {
    const seen = vi.fn();
    window.addEventListener("saw:unauthorized", seen);
    mockApi({ "GET /investigations": [401, { detail: "authentication required" }], "POST /auth/login": [401, { detail: "bad" }] });
    await api.get("/investigations").catch(() => undefined);
    await api.post("/auth/login", {}).catch(() => undefined);
    expect(seen).toHaveBeenCalledTimes(1);
    window.removeEventListener("saw:unauthorized", seen);
  });

  it("download() saves the attachment under the server file name", async () => {
    mockApi({ "GET /f": [200, "MZ...", { "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="abc_invoice.jpg.infected"' }] });
    const created = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }));
    const clicks: string[] = [];
    const orig = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function () { clicks.push(this.download); };
    await api.download("/f", "fallback.bin");
    HTMLAnchorElement.prototype.click = orig;
    expect(created).toHaveBeenCalled();
    expect(clicks).toEqual(["abc_invoice.jpg.infected"]);
  });

  it("download() surfaces JSON errors instead of saving them", async () => {
    mockApi({ "GET /f": [403, { detail: "missing permission investigation.write" }] });
    await expect(api.download("/f", "x")).rejects.toThrow("investigation.write");
  });
});
