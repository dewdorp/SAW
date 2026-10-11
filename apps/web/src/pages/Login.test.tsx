import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { Login } from "./Login";

vi.mock("qrcode", () => ({ default: { toCanvas: vi.fn(() => Promise.resolve()) } }));
afterEach(() => vi.unstubAllGlobals());

function typePw(user = "analyst", pw = "secret-pass") {
  fireEvent.change(screen.getByPlaceholderText("사용자 ID"), { target: { value: user } });
  fireEvent.change(screen.getByPlaceholderText("비밀번호"), { target: { value: pw } });
  fireEvent.click(screen.getByRole("button", { name: "로그인" }));
}

describe("Login + MFA", () => {
  it("asks for the 6-digit code after the password, accepts digits only, then finishes", async () => {
    const m = mockApi({ "POST /auth/login": [200, { state: "mfa_required", csrf_token: "c" }], "POST /auth/mfa/verify": [200, { state: "ok" }] });
    const done = vi.fn();
    renderUI(<Login onDone={done} />);
    expect((screen.getByRole("button", { name: "로그인" }) as HTMLButtonElement).disabled).toBe(true);
    typePw();
    const code = await screen.findByPlaceholderText("6자리 코드");
    fireEvent.change(code, { target: { value: "12a3-45 6" } });
    expect((code as HTMLInputElement).value).toBe("123456");
    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    await waitFor(() => expect(done).toHaveBeenCalled());
    expect(m.find("POST", "/auth/mfa/verify")[0].body).toEqual({ code: "123456" });
  });

  it("shows QR enrollment with the manual key grouped by 4", async () => {
    mockApi({ "POST /auth/login": [200, { state: "mfa_enroll", provisioning_uri: "otpauth://totp/SAW:analyst?secret=ABCDEFGHIJKLMNOP&issuer=SAW" }] });
    renderUI(<Login onDone={vi.fn()} />);
    typePw();
    expect((await screen.findByLabelText("MFA 등록 QR 코드")).tagName).toBe("CANVAS");
    expect(screen.getByText("ABCD EFGH IJKL MNOP")).toBeTruthy();
  });

  it("shows the server error and lets the user go back", async () => {
    mockApi({ "POST /auth/login": [200, { state: "mfa_required" }], "POST /auth/mfa/verify": [401, { detail: "invalid code" }] });
    const done = vi.fn();
    renderUI(<Login onDone={done} />);
    typePw();
    fireEvent.change(await screen.findByPlaceholderText("6자리 코드"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("invalid code"));
    expect(done).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("← 다시 로그인"));
    expect(screen.getByPlaceholderText("사용자 ID")).toBeTruthy();
  });

  it("explains a reused code in Korean and returns to the password step when the account is locked", async () => {
    const replies = ["MFA code already used", "account locked"];
    mockApi({ "POST /auth/login": [200, { state: "mfa_required" }], "POST /auth/mfa/verify": () => [401, { detail: replies.shift() }] });
    renderUI(<Login onDone={vi.fn()} />);
    typePw();
    const code = await screen.findByPlaceholderText("6자리 코드");
    fireEvent.change(code, { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("이미 사용한 인증 코드"));
    expect((code as HTMLInputElement).value).toBe("");
    fireEvent.change(code, { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    expect(await screen.findByPlaceholderText("사용자 ID")).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain("계정이 잠시 잠겼습니다");
  });

  it("goes straight in when MFA is not required", async () => {
    mockApi({ "POST /auth/login": [200, { state: "ok" }] });
    const done = vi.fn();
    renderUI(<Login onDone={done} />);
    typePw();
    await waitFor(() => expect(done).toHaveBeenCalled());
  });
});
