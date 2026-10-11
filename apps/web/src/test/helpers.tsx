import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

export type Call = { method: string; url: string; body: any; headers: Record<string, string> };
type Reply = [status: number, body: unknown, headers?: Record<string, string>];
type Handler = (call: Call) => Reply | undefined;

function fakeResponse(status: number, body: unknown, headers: Record<string, string> = {}): any {
  const isText = typeof body === "string";
  const h: Record<string, string> = { "content-type": isText ? "text/plain" : "application/json", ...headers };
  const res = {
    ok: status >= 200 && status < 300, status, statusText: String(status),
    headers: { get: (k: string) => h[k.toLowerCase()] ?? null },
    json: async () => body,
    text: async () => (isText ? body : JSON.stringify(body)),
    blob: async () => new Blob([isText ? (body as string) : JSON.stringify(body)]),
    clone: () => res,
  };
  return res;
}

/** Fake SAW API: routes are "METHOD /path" (path without /api/v1, query string ignored) → handler or fixed reply. */
export function mockApi(routes: Record<string, Reply | Handler>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const method = (init.method || "GET").toUpperCase();
    const url = String(input).replace(/^\/api\/v1/, "");
    const path = url.split("?")[0];
    const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
    const call: Call = { method, url, body, headers: (init.headers as Record<string, string>) || {} };
    calls.push(call);
    const r = routes[`${method} ${path}`];
    const reply = typeof r === "function" ? r(call) : r;
    if (!reply) return fakeResponse(404, { detail: `no mock for ${method} ${path}` });
    return fakeResponse(reply[0], reply[1], reply[2]);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock, find: (method: string, path: string) => calls.filter((c) => c.method === method && c.url.split("?")[0] === path) };
}

export function renderUI(ui: ReactElement, { route = "/" }: { route?: string } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } });
  return { qc, ...render(<QueryClientProvider client={qc}><MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter></QueryClientProvider>) };
}

export const ME = {
  id: "u1", username: "analyst", display_name: "분석가", roles: ["analyst"],
  permissions: ["analyze.run", "investigation.read", "investigation.write"],
};
