import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GoldenCandidateButton } from "../components/GoldenCandidateButton";
import { mockApi, renderUI } from "../test/helpers";
import { GoldenCandidates } from "./GoldenCandidates";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const w26 = { id: "c1", source_kind: "casebook", source_id: "W26", source_version: "a".repeat(64), title: "공유 폴더의 대량 확장자 변경",
  origin_label: "합성 예제", org_label: "합성 예제(사례집)", note: "", split: "unassigned", status: "candidate", status_label: "후보",
  golden_version: null, created_at: "2026-11-04T01:00:00Z", link: "/casebook?worked=W26" };
const inv = { ...w26, id: "c2", source_kind: "investigation", source_id: "inv-1", title: "시험 조사", origin_label: "실제 조사",
  org_label: "가상 관계사", link: "/inv/inv-1", status: "saved", status_label: "골든셋 저장됨", golden_version: 1 };

describe("golden-set candidates", () => {
  it("one click puts a case in the inbox, and a second click keeps one candidate", async () => {
    let created = true;
    const api = mockApi({ "GET /knowledge/golden-candidates": [200, { items: [] }],
      "POST /knowledge/golden-candidates": () => { const r = [201, { item: w26, created }]; created = false; return r as any; } });
    renderUI(<GoldenCandidateButton sourceKind="casebook" sourceId="W26" />);
    fireEvent.click(await screen.findByRole("button", { name: "골든 후보로 담기" }));
    expect(await screen.findByText("골든 후보에 담았습니다.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "골든 후보로 담기" }));
    expect(await screen.findByText("이미 담긴 후보입니다. 한 건으로 유지합니다.")).toBeTruthy();
    expect(api.find("POST", "/knowledge/golden-candidates")[0].body).toEqual({ source_kind: "casebook", source_id: "W26" });
    expect(screen.getByRole("link", { name: "후보함 열기" }).getAttribute("href")).toBe("/golden-candidates");
  });

  it("lists title, origin, affiliate, date and status; saves only the chosen ones; exports only saved ones", async () => {
    const api = mockApi({ "GET /knowledge/golden-candidates": [200, { items: [w26, inv] }],
      "POST /knowledge/golden-candidates/save": [200, { items: [{ ...w26, status: "saved" }] }] });
    renderUI(<GoldenCandidates />);
    expect(await screen.findByText("공유 폴더의 대량 확장자 변경")).toBeTruthy();
    expect(screen.getByRole("cell", { name: "합성 예제" })).toBeTruthy();
    expect(screen.getByRole("cell", { name: "실제 조사" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "사례로 돌아가기" }).getAttribute("href")).toBe("/casebook?worked=W26");
    expect(screen.getByRole("link", { name: "조사로 돌아가기" }).getAttribute("href")).toBe("/inv/inv-1");
    fireEvent.click(screen.getByLabelText("선택: 공유 폴더의 대량 확장자 변경"));
    expect((screen.getByRole("button", { name: "선택한 저장본 내보내기" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "선택한 후보를 골든셋으로 저장" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/golden-candidates/save")).toHaveLength(1));
    expect(api.find("POST", "/knowledge/golden-candidates/save")[0].body).toEqual({ ids: ["c1"] });
  });

  it("removing asks first and keeps the source", async () => {
    const api = mockApi({ "GET /knowledge/golden-candidates": [200, { items: [w26] }], "DELETE /knowledge/golden-candidates/c1": [204, ""] });
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    renderUI(<GoldenCandidates />);
    fireEvent.click(await screen.findByRole("button", { name: "후보함에서 빼기" }));
    expect(api.find("DELETE", "/knowledge/golden-candidates/c1")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "후보함에서 빼기" }));
    await waitFor(() => expect(api.find("DELETE", "/knowledge/golden-candidates/c1")).toHaveLength(1));
    expect(confirm.mock.calls[0][0]).toContain("원본과 저장한 골든 버전은 남습니다");
    expect(await screen.findByText(/원본 조사·로그와 저장한 골든 버전은 그대로입니다/)).toBeTruthy();
  });
});
