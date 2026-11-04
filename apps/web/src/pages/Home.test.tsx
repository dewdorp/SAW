import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { Home } from "./Home";
import { Investigations } from "./Investigations";

const INVS = [
  { id: "i1", display_id: "INV-1", title: "고객 API 대량 조회", status: "in_progress", risk_level: "critical", risk_score: 86,
    created_at: "2026-10-06T00:00:00Z", time_start: null, time_end: null, verdict: null, evidence: [{ kind: "pcap", size: 2048 }] },
  { id: "i2", display_id: "INV-2", title: "지난 사례", status: "closed", risk_level: "low", risk_score: 10,
    created_at: "2026-10-01T00:00:00Z", time_start: null, time_end: null, verdict: "attack", evidence: [] },
];

beforeEach(() => mockApi({
  "GET /investigations": [200, INVS], "GET /jobs": [200, [{ id: "job-1234567", kind: "ingest", state: "PARSING" }]],
  "GET /findings/recent": [200, [{ id: "f1", investigation_id: "i1", title: "Potential Web Shell Upload and Use", risk_level: "critical", display_id: "F-1" }]],
  "POST /investigations": [201, { id: "new1" }],
}));
afterEach(() => vi.unstubAllGlobals());

describe("Home", () => {
  it("opens built-in practice even when the installation has no investigations", async () => {
    mockApi({ "GET /investigations": [200, []], "GET /jobs": [200, []], "GET /findings/recent": [200, []] });
    renderUI(<Home />);
    expect(await screen.findByText("아직 조사가 없습니다")).toBeTruthy();
    expect(screen.getByRole("link", { name: "분석 사례집" }).getAttribute("href")).toBe("/casebook");
  });

  it("summarises open work in stat tiles", async () => {
    renderUI(<Home />);
    expect(await screen.findByText("Potential Web Shell Upload and Use")).toBeTruthy();
    const stats = document.querySelector(".stats") as HTMLElement;
    const tile = (label: string) => within(stats).getByText(label).parentElement!.querySelector(".stat-value")!.textContent;
    expect(tile("진행 중인 조사")).toBe("1");
    expect(tile("높은 위험 조사")).toBe("1");
    expect(tile("처리 중인 작업")).toBe("1");
    expect(screen.getByText("파싱 중")).toBeTruthy();
  });

  it("previews what was pasted and enables analysis", () => {
    renderUI(<Home />);
    const btn = screen.getByRole("button", { name: /분석 \(Ctrl\+Enter\)/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "GET /api/customer?id=1%27 HTTP/1.1\n10.0.0.1 hxxps://evil[.]com" } });
    for (const chip of ["HTTP 요청", "IPv4 ×1", "URL", "URL 인코딩"]) expect(screen.getByText(chip)).toBeTruthy();
    expect(btn.disabled).toBe(false);
  });

  it("starts an NDR or firewall upload using the supported auto kind", () => {
    renderUI(<Home />);
    fireEvent.click(screen.getByRole("button", { name: "NDR·FW 로그 분석" }));
    const dialog = screen.getByRole("dialog", { name: "증거 업로드" });
    expect((within(dialog).getByLabelText("자료 종류") as HTMLSelectElement).value).toBe("auto");
    expect(within(dialog).getByRole("button", {name:"원본 파일 선택"})).toBeTruthy();
  });

  it("opens the upload dialog from a file quick-start card", () => {
    renderUI(<Home />);
    fireEvent.click(screen.getByRole("button", { name: /PCAP/ }));
    expect(document.querySelector(".modal")).toBeTruthy();
  });
});

describe("Investigations list", () => {
  it("shows Korean status/verdict/evidence and creates a new investigation", async () => {
    const api = mockApi({ "GET /investigations": [200, INVS], "POST /investigations": [201, { id: "new1" }],
      "GET /source-context/org-units": [200, [{ id: "org-a", display_name: "가상 A사" }]] });
    renderUI(<Investigations />);
    const row = (await screen.findByText("고객 API 대량 조회")).closest("tr")!;
    expect(within(row).getByText("분석 중")).toBeTruthy();
    expect(within(row).getByText(/PCAP 2/)).toBeTruthy();
    expect(screen.getByText("종결 · 공격")).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText(/새 조사 제목/), { target: { value: "새 사건" } });
    fireEvent.change(await screen.findByLabelText("새 조사 관계사"), { target: { value: "org-a" } });
    fireEvent.change(screen.getByLabelText("조사 시작일"), { target: { value: "2026-10-01" } });
    fireEvent.change(screen.getByLabelText("조사 종료일"), { target: { value: "2026-10-31" } });
    fireEvent.click(screen.getByRole("button", { name: "새 조사 만들기" }));
    await vi.waitFor(() => expect(api.find("POST", "/investigations")[0].body).toEqual({ title: "새 사건", org_unit_id: "org-a",
      period_start: "2026-10-01T00:00:00+09:00", period_end: "2026-10-31T23:59:59+09:00" }));
  });
});
