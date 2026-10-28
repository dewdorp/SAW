import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Investigations } from "./Investigations";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const records = [{ id: "ia", title: "가상 A 조사", display_id: "INV-A", evidence: [], org_unit_id: "oa", org_unit: "가상 A사" }, { id: "ib", title: "가상 B 조사", display_id: "INV-B", evidence: [], org_unit_id: "ob", org_unit: "가상 B사" }];
const routes = (extra = {}) => ({ "GET /auth/me": [200, ME], "GET /investigations": [200, records], "GET /source-context/org-units": [200, [{ id: "oa", display_name: "가상 A사" }, { id: "ob", display_name: "가상 B사" }]], ...extra }) as any;
const ui = <Routes><Route path="/" element={<Investigations />} /><Route path="/inv/:id" element={<div>created workbench</div>} /></Routes>;
describe("organization investigation entry", () => {
  it("filters by organization and creates a service-free investigation with its stable organization ID", async () => {
    const api = mockApi(routes({ "POST /investigations": [201, { id: "new1" }] })); renderUI(ui);
    await screen.findByText("INV-A");
    fireEvent.change(screen.getByLabelText("관계사 필터"), { target: { value: "oa" } });
    expect(screen.queryByText("INV-B")).toBeNull();
    fireEvent.change(screen.getByLabelText("새 조사 관계사"), { target: { value: "ob" } });
    fireEvent.change(screen.getByPlaceholderText(/새 조사 제목/), { target: { value: "서비스 미지정 FW 조사" } });
    // One affiliate + one period: creation stays disabled until the period is chosen.
    expect((screen.getByRole("button", { name: "새 조사 만들기" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("조사 시작일"), { target: { value: "2026-09-29" } });
    fireEvent.change(screen.getByLabelText("조사 종료일"), { target: { value: "2026-10-28" } });
    fireEvent.click(screen.getByRole("button", { name: "새 조사 만들기" }));
    expect(await screen.findByText("created workbench")).toBeTruthy();
    expect(api.find("POST", "/investigations")[0].body).toEqual({ title: "서비스 미지정 FW 조사", org_unit_id: "ob", period_start: "2026-09-29T00:00:00+09:00", period_end: "2026-10-28T23:59:59+09:00" });
  });
  it("allows only affiliate managers to register an organization and selects the new organization", async () => {
    const api = mockApi(routes({ "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "org.manage"] }], "POST /source-context/org-units": [201, { id: "oc", display_name: "가상 C사" }] }));
    renderUI(ui);
    fireEvent.change(await screen.findByLabelText("새 관계사 이름"), { target: { value: "가상 C사" } });
    fireEvent.click(screen.getByRole("button", { name: "관계사 등록" }));
    await waitFor(() => expect((screen.getByLabelText("새 조사 관계사") as HTMLSelectElement).value).toBe("oc"));
    expect(api.find("POST", "/source-context/org-units")[0].body).toEqual({ display_name: "가상 C사" });
  });
  it("hides organization registration for an ordinary analyst", async () => {
    mockApi(routes()); renderUI(ui); await screen.findByText("INV-A");
    expect(screen.queryByLabelText("새 관계사 이름")).toBeNull();
    expect(screen.queryByRole("button", { name: "관계사 등록" })).toBeNull();
  });
});
