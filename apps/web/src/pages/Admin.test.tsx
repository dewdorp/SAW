import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { Admin } from "./Admin";

const ADMIN = { id: "a1", username: "admin", display_name: "관리자", roles: ["admin"], permissions: ["admin.users", "audit.read"] };
const USERS = [{ id: "u7", username: "kim", display_name: "김분석", roles: ["analyst"], status: "active", mfa_enabled: true }];
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function setup() {
  return mockApi({
    "GET /admin/users": [200, USERS], "GET /admin/audit": [200, []], "GET /admin/audit/verify": [200, { ok: true, first_broken_id: null }],
    "POST /admin/users/u7/mfa-reset": [200, { ok: true, username: "kim" }],
    "POST /admin/users/u7/password": [200, { ok: true, username: "kim" }],
  });
}

describe("Audit log check", () => {
  it("says in plain words when the newest entries are missing", async () => {
    mockApi({ "GET /admin/users": [200, USERS], "GET /admin/audit": [200, []],
      "GET /admin/audit/verify": [200, { ok: false, reason: "tail", first_broken_id: 41, entries: 40, expected_entries: 43 }] });
    renderUI(<Admin me={ADMIN} />);
    expect(await screen.findByText(/최근 기록이 사라짐 \(있어야 할 43건 중 40건만 남음\)/)).toBeTruthy();
  });
});

describe("Admin user management", () => {
  it("resets MFA only after confirmation", async () => {
    const api = setup();
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    renderUI(<Admin me={ADMIN} />);
    const row = (await screen.findByText("kim")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "MFA 재설정" }));
    expect(api.find("POST", "/admin/users/u7/mfa-reset")).toHaveLength(0);
    fireEvent.click(within(row).getByRole("button", { name: "MFA 재설정" }));
    await vi.waitFor(() => expect(api.find("POST", "/admin/users/u7/mfa-reset")).toHaveLength(1));
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("sets a temporary password and tells the admin to hand it over safely", async () => {
    const api = setup();
    vi.spyOn(window, "prompt").mockReturnValue("Temp!0rary-Pass1");
    renderUI(<Admin me={ADMIN} />);
    fireEvent.click(within((await screen.findByText("kim")).closest("tr")!).getByRole("button", { name: "임시 비밀번호" }));
    expect(await screen.findByText(/임시 비밀번호가 설정되었습니다 \(kim\)/)).toBeTruthy();
    expect(api.find("POST", "/admin/users/u7/password")[0].body).toEqual({ password: "Temp!0rary-Pass1" });
  });

  it("does nothing when the temporary password prompt is cancelled", async () => {
    const api = setup();
    vi.spyOn(window, "prompt").mockReturnValue(null);
    renderUI(<Admin me={ADMIN} />);
    fireEvent.click(within((await screen.findByText("kim")).closest("tr")!).getByRole("button", { name: "임시 비밀번호" }));
    expect(api.find("POST", "/admin/users/u7/password")).toHaveLength(0);
  });
});
