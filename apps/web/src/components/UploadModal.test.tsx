import { fireEvent, screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { UploadModal } from "./UploadModal";

afterEach(() => vi.unstubAllGlobals());

function routes() {
  return mockApi({
    "GET /investigations": [200, [{ id: "inv9", display_id: "INV-9", title: "기존 조사" }]],
    "GET /source-context/org-units": [200, []],
    "GET /source-context/investigations/inv9/devices": [200, []],
    "POST /investigations": [201, { id: "new1" }],
    "POST /investigations/new1/evidence": [201, { id: "ev1" }],
    "POST /investigations/inv9/evidence": [201, { id: "ev2" }],
    "POST /uploads": [201, { id: "up1", part_size: 4 }],
    "PUT /uploads/up1/parts/1": [200, { ok: true }],
    "PUT /uploads/up1/parts/2": [200, { ok: true }],
    "POST /uploads/up1/complete": [200, { ok: true }],
    "POST /evidence/ev1/process": [200, { id: "job1" }],
    "POST /evidence/ev2/process": [200, { id: "job2" }],
  });
}

function pick(name: string, content: string) {
  const input = document.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files: [new File([content], name)] } });
}

const ui = (props: Partial<Parameters<typeof UploadModal>[0]> = {}) => (
  <Routes>
    <Route path="/" element={<UploadModal onClose={vi.fn()} {...props} />} />
    <Route path="/jobs/:id" element={<div>job page</div>} />
  </Routes>
);

describe("UploadModal", () => {
  it("creates a new investigation, uploads in parts, starts processing and opens the job", async () => {
    const api = routes();
    renderUI(ui({ kind: "pcap" }));
    expect((screen.getByRole("combobox", { name: /종류/ }) as HTMLSelectElement).value).toBe("pcap");
    fireEvent.change(screen.getByPlaceholderText("새 조사 제목 (선택)"), { target: { value: "침해 의심 캡처" } });
    pick("capture.pcap", "12345678");
    expect(screen.getByText("capture.pcap")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /업로드/ }));
    expect(await screen.findByText("job page")).toBeTruthy();
    const seq = api.calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.url}`);
    expect(seq).toEqual(["POST /investigations", "POST /investigations/new1/evidence", "POST /uploads", "PUT /uploads/up1/parts/1",
      "PUT /uploads/up1/parts/2", "POST /uploads/up1/complete", "POST /evidence/ev1/process"]);
    expect(api.find("POST", "/investigations")[0].body).toEqual({ title: "침해 의심 캡처" });
    expect(api.find("POST", "/investigations/new1/evidence")[0].body.kind).toBe("pcap");
  });

  it("adds evidence to an existing investigation without creating a new one", async () => {
    const api = routes();
    renderUI(ui({ invId: "inv9" }));
    expect(screen.queryByPlaceholderText("새 조사 제목 (선택)")).toBeNull();
    pick("access.log", "abc");
    fireEvent.click(screen.getByRole("button", { name: /업로드/ }));
    expect(await screen.findByText("job page")).toBeTruthy();
    expect(api.find("POST", "/investigations")).toHaveLength(0);
    expect(api.find("POST", "/evidence/ev2/process")).toHaveLength(1);
  });
});

it("pins the selected device profile, observed subject and collection scope before uploading", async () => {
  const contextApi = mockApi({
    "GET /investigations": [200, [{ id: "inv9", display_id: "INV-9", title: "기존 조사" }]],
    "GET /source-context/org-units": [200, [{ id: "org-a", display_name: "가상 A사" }]],
    "GET /source-context/investigations/inv9/devices": [200, [{ id: "dev1", display_name: "가상 FW" }]],
    "GET /source-context/devices/dev1/profiles": [200, [{ id: "p3", version: 3, profile: {} }]],
    "POST /investigations/inv9/evidence": [201, { id: "ev2" }], "POST /uploads": [201, { id: "up1", part_size: 4 }],
    "PUT /uploads/up1/parts/1": [200, {}], "POST /uploads/up1/complete": [200, {}], "POST /evidence/ev2/process": [200, { id: "job2" }],
  });
  renderUI(ui({ invId: "inv9" }));
  await screen.findByRole("option", { name: "가상 FW" });
  fireEvent.change(screen.getByLabelText("관측 장비"), { target: { value: "dev1" } });
  await screen.findByRole("option", { name: /v3/ });
  fireEvent.change(screen.getByLabelText("프로필 버전"), { target: { value: "p3" } });
  fireEvent.change(screen.getByLabelText("관측 대상 관계사"), { target: { value: "org-a" } });
  fireEvent.change(screen.getByLabelText("대상 귀속 상태"), { target: { value: "verified" } });
  fireEvent.change(screen.getByLabelText("귀속 확인 근거"), { target: { value: "합성 수집 명세 확인" } });
  fireEvent.change(screen.getByLabelText("수집 범위"), { target: { value: "blocked_only" } });
  pick("synthetic.csv", "abc"); fireEvent.click(screen.getByRole("button", { name: /업로드 및 분석/ }));
  expect(await screen.findByText("job page")).toBeTruthy();
  expect(contextApi.find("POST", "/investigations/inv9/evidence")[0].body.source_context).toEqual({ device_profile_version_id: "p3", subject: { org_unit_id: "org-a", status: "verified", basis: "합성 수집 명세 확인" }, collection: { scope: "blocked_only", filter: "", loss: "unknown" } });
});
it("blocks verified attribution without a basis before any evidence is created", async () => {
  const api = mockApi({ "GET /investigations": [200, []], "GET /source-context/org-units": [200, []], "GET /source-context/investigations/inv9/devices": [200, []] });
  renderUI(ui({ invId: "inv9" }));
  fireEvent.change(screen.getByLabelText("대상 귀속 상태"), { target: { value: "verified" } });
  pick("synthetic.csv", "abc"); fireEvent.click(screen.getByRole("button", { name: /업로드 및 분석/ }));
  expect(await screen.findByText(/관측 대상 관계사와 귀속 확인 근거/)).toBeTruthy();
  expect(api.find("POST", "/investigations/inv9/evidence")).toHaveLength(0);
});
it("creates a new investigation with an organization while keeping unconfigured context unknown", async () => {
  const api = routes();
  const fallback = api.fetchMock.getMockImplementation()!;
  api.fetchMock.mockImplementation(async (input: any, init?: any) => {
    if (String(input).includes("/source-context/org-units")) return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => [{ id: "org-a", display_name: "가상 A사" }] } as any;
    return fallback(input, init);
  });
  renderUI(ui());
  await screen.findByRole("option", { name: "가상 A사" });
  fireEvent.change(screen.getByLabelText("새 조사 관계사"), { target: { value: "org-a" } });
  expect(screen.getByText(/장비·프로필을 먼저 설정/)).toBeTruthy();
  pick("synthetic.csv", "abc"); fireEvent.click(screen.getByRole("button", { name: /업로드 및 분석/ }));
  expect(await screen.findByText("job page")).toBeTruthy();
  expect(api.find("POST", "/investigations")[0].body.org_unit_id).toBe("org-a");
  expect(api.find("POST", "/investigations/new1/evidence")[0].body).not.toHaveProperty("source_context");
});
