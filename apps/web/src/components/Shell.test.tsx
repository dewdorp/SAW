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
  it("shows grouped Korean menus and hides admin without permission", async () => {
    renderUI(<Shell me={ME}><div>content</div></Shell>);
    const nav = screen.getByLabelText("주 메뉴");
    for (const label of ["홈", "빠른 분석", "조사 목록", "작업 상태", "위협 헌팅", "케이스", "SOC 지식", "탐지 룰"]) {
      expect(within(nav).getByText(label)).toBeTruthy();
    }
    expect(within(nav).queryByText("관리·감사")).toBeNull();
    expect(await within(nav).findByText("2")).toBeTruthy(); // active jobs badge
    expect(document.querySelector(".sb-user small")!.textContent).toBe("분석가"); // role in Korean
  });

  it("shows the admin menu for administrators", () => {
    renderUI(<Shell me={{ ...ME, roles: ["admin"], permissions: ["admin.users", "audit.read"] }}><div /></Shell>);
    expect(screen.getByText("관리·감사")).toBeTruthy();
  });

  it("opens the casebook from the sidebar", () => {
    renderUI(<Shell me={ME}><div /></Shell>, { route: "/inv/abc" });
    const link = within(screen.getByLabelText("주 메뉴")).getByRole("link", { name: "분석 사례집" });
    expect(link.getAttribute("href")).toBe("/casebook");
    fireEvent.click(link);
    expect(document.querySelector(".crumb")!.textContent).toBe("분석 사례집");
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
