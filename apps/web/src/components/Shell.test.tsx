import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Shell } from "./Shell";

beforeEach(() => {
  localStorage.clear();
  mockApi({ "GET /jobs": [200, [{ id: "j1" }, { id: "j2" }]], "GET /investigations": [200, [{ id: "i1", display_id: "INV-1", title: "고객 API 대량 조회" }]] });
});
afterEach(() => vi.unstubAllGlobals());

const app = () => document.querySelector(".app")!;

describe("Shell (sidebar layout)", () => {
  it("shows three analyst menus plus tools and settings, and hides admin without permission", async () => {
    renderUI(<Shell me={ME}><div>content</div></Shell>);
    const nav = screen.getByLabelText("주 메뉴");
    const links = within(nav).getAllByRole("link").map((a) => [a.textContent, a.getAttribute("href")]);
    expect(links).toEqual([["헌팅", "/"], ["시나리오", "/scenarios"], ["자산·업무", "/assets"], ["도구·설정", "/settings"]]);
    expect(within(nav).queryByText("관리·감사")).toBeNull();
    expect(await screen.findByText("작업 2")).toBeTruthy(); // active jobs stay visible in the top bar
    expect(document.querySelector(".sb-user small")!.textContent).toBe("분석가"); // role in Korean
  });

  it("shows the admin menu for administrators", () => {
    renderUI(<Shell me={{ ...ME, roles: ["admin"], permissions: ["admin.users", "audit.read"] }}><div /></Shell>);
    expect(screen.getByText("관리·감사")).toBeTruthy();
  });

  it("keeps the hunt menu active on a hunt workbench and names old addresses", () => {
    renderUI(<Shell me={ME}><div /></Shell>, { route: "/inv/abc" });
    const nav = within(screen.getByLabelText("주 메뉴"));
    expect(nav.getByRole("link", { name: "헌팅" }).className).toContain("active");
    expect(document.querySelector(".crumb")!.textContent).toBe("헌팅 작업대");
    fireEvent.click(nav.getByRole("link", { name: "시나리오" }));
    expect(document.querySelector(".crumb")!.textContent).toBe("시나리오");
  });

  it("finds and opens the casebook through menu search", async () => {
    renderUI(<Shell me={ME}><div /></Shell>);
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const dialog = within(await screen.findByRole("dialog", { name: "Command palette" }));
    fireEvent.change(dialog.getByPlaceholderText("메뉴 또는 조사 이름 검색…"), { target: { value: "분석 사례집" } });
    fireEvent.click(dialog.getByText("분석 사례집"));
    expect(document.querySelector(".crumb")!.textContent).toBe("분석 사례집");
    expect(screen.queryByRole("dialog", { name: "Command palette" })).toBeNull();
  });

  it("auto-collapses on the investigation workbench, and remembers an explicit choice", () => {
    const { unmount } = renderUI(<Shell me={ME}><div /></Shell>, { route: "/inv/abc" });
    expect(app().classList.contains("collapsed")).toBe(true);
    fireEvent.click(screen.getByLabelText("메뉴 접기/펼치기"));
    expect(app().classList.contains("collapsed")).toBe(false);
    expect(localStorage.getItem("saw.sidebar")).toBe("open");
    unmount();
    renderUI(<Shell me={ME}><div /></Shell>, { route: "/inv/abc" });
    expect(app().classList.contains("collapsed")).toBe(false);
  });

  it("is expanded elsewhere by default", () => {
    renderUI(<Shell me={ME}><div /></Shell>, { route: "/knowledge" });
    expect(app().classList.contains("collapsed")).toBe(false);
    expect(document.querySelector(".crumb")!.textContent).toBe("SOC 지식");
  });

  it("opens the search palette with Ctrl+K and finds investigations by name", async () => {
    renderUI(<Shell me={ME}><div /></Shell>);
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const input = await screen.findByPlaceholderText("메뉴 또는 조사 이름 검색…");
    fireEvent.change(input, { target: { value: "대량" } });
    expect(await screen.findByText("조사 INV-1 고객 API 대량 조회")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByPlaceholderText("메뉴 또는 조사 이름 검색…")).toBeNull();
  });

  it("opens the password dialog from the sidebar", () => {
    renderUI(<Shell me={ME}><div /></Shell>);
    fireEvent.click(screen.getByTitle("비밀번호 변경"));
    expect(screen.getByRole("dialog", { name: "비밀번호 변경" })).toBeTruthy();
  });
});
