import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { PasswordDialog } from "./PasswordDialog";

afterEach(() => vi.unstubAllGlobals());

const fill = (cur: string, nw: string, again: string) => {
  fireEvent.change(screen.getByPlaceholderText("현재 비밀번호"), { target: { value: cur } });
  fireEvent.change(screen.getByPlaceholderText(/새 비밀번호 \(12자/), { target: { value: nw } });
  fireEvent.change(screen.getByPlaceholderText("새 비밀번호 확인"), { target: { value: again } });
};

describe("PasswordDialog", () => {
  it("blocks submission until the new password is confirmed", () => {
    mockApi({});
    renderUI(<PasswordDialog onClose={vi.fn()} />);
    fill("old", "N3w!Passw0rd-x", "N3w!Passw0rd-y");
    expect(screen.getByText("새 비밀번호가 일치하지 않습니다.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "변경" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("posts current and new password, then confirms other sessions were signed out", async () => {
    const m = mockApi({ "POST /auth/password": [200, { ok: true }] });
    renderUI(<PasswordDialog onClose={vi.fn()} />);
    fill("old", "N3w!Passw0rd-x", "N3w!Passw0rd-x");
    fireEvent.click(screen.getByRole("button", { name: "변경" }));
    expect(await screen.findByText(/다른 곳에 로그인된 세션은 모두 종료/)).toBeTruthy();
    expect(m.find("POST", "/auth/password")[0].body).toEqual({ current_password: "old", new_password: "N3w!Passw0rd-x" });
  });

  it("shows the policy error from the server", async () => {
    mockApi({ "POST /auth/password": [400, { detail: "password must be at least 12 characters" }] });
    renderUI(<PasswordDialog onClose={vi.fn()} />);
    fill("old", "short", "short");
    fireEvent.click(screen.getByRole("button", { name: "변경" }));
    expect((await screen.findByRole("alert")).textContent).toContain("12 characters");
  });
});
