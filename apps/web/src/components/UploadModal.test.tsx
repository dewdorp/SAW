import { fireEvent, screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { UploadModal } from "./UploadModal";

afterEach(() => vi.unstubAllGlobals());

function routes() {
  return mockApi({
    "GET /investigations": [200, [{ id: "inv9", display_id: "INV-9", title: "기존 조사" }]],
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
