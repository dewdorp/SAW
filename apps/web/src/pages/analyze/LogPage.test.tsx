import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { LogPage } from "./LogPage";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const CASE = { id: "WL02", server: "Nginx", title: "로그인 API 무차별 대입 뒤 성공", format: "ncsa_combined", lines: 3, bytes: 300,
  scenario: "한 출발지가 로그인 API에 84번 실패한 뒤 한 번 성공했습니다.", look_for: ["실패 비율"], expected: ["web.credential_attack"],
  normal_possibility: "사내 자동화 시험일 수 있습니다." };
const TEXT = ['203.0.113.45 - - [03/Nov/2026:09:31:00 +0900] "POST /api/v1/auth/login HTTP/1.1" 401 64 "-" "python-requests/2.32.3"',
  '203.0.113.45 - - [03/Nov/2026:09:31:02 +0900] "POST /api/v1/auth/login HTTP/1.1" 401 64 "-" "python-requests/2.32.3"',
  '203.0.113.45 - - [03/Nov/2026:09:33:50 +0900] "POST /api/v1/auth/login HTTP/1.1" 200 182 "-" "python-requests/2.32.3"'].join("\n");
const finding = { detector_id: "web.credential_attack", state: "found", category: "web.credential_attack", category_ko: "로그인 무차별 시도",
  title: "Possible Password Guessing / Brute Force", title_ko: "비밀번호 무차별 대입 가능성", explanation: "203.0.113.45에서 웹 로그인 시도 85건, 실패율 99%.",
  risk_score: 52, risk_level: "medium", confidence: "high", time_start: "2026-11-03T00:31:00Z", time_end: "2026-11-03T00:33:50Z", total_events: 85,
  metrics: [{ label: "시도", value: 85, unit: "" }, { label: "실패 비율", value: 0.988, unit: "" }],
  checks: [{ label: "실패 비율이 높음", passed: true, value: "99%" }, { label: "서로 다른 계정이 많음", passed: null, value: "로그에 계정 이름 없음" }],
  entities: ["ip:203.0.113.45"], line_nos: [1, 3], next_checks: ["로그인에 성공한 계정이 있는지 확인"], attack: ["T1110.001"] };
const result = (findings: any[]) => ({ parser: "nginx_combined", confidence: 0.95, candidates: [], events: 3, failed: 0, failure_samples: [], time_range: null,
  top_src_ip: [], top_uri_template: [], top_status: [], top_user_agent: [], patterns: [], suspicious: [], sample_events: [],
  format_ko: "NCSA combined/common 형식 (Nginx·Apache·Tomcat·WebtoB·JEUS 등 공통)",
  web: { events: 3, findings, sources: [{ src_ip: "203.0.113.45", requests: 3, status: { "4xx": 2, "2xx": 1 }, distinct_paths: 1,
    clients: [{ kind: "script", kind_ko: "스크립트·도구", count: 3 }], attack_syntax_lines: [], first: "2026-11-03T00:31:00Z", last: "2026-11-03T00:33:50Z" }],
    errors: [], status: { "4xx": 2, "2xx": 1 } } });

describe("web server log paste", () => {
  it("loads a case, analyses it, compares with the expected result and shows the pasted evidence lines", async () => {
    const api = mockApi({ "GET /parsers": [200, []], "GET /analyze/log/web-cases": [200, { items: [CASE] }],
      "GET /analyze/log/web-cases/WL02": [200, { id: "WL02", text: TEXT }], "POST /analyze/log": [200, result([finding])] });
    renderUI(<LogPage />);
    fireEvent.click(await screen.findByRole("button", { name: "이 사례 넣기" }));
    expect(await screen.findByText("비밀번호 무차별 대입 가능성")).toBeTruthy();
    expect(screen.getByText("기대한 결과와 같음")).toBeTruthy();
    expect(screen.getByText(/NCSA combined\/common 형식/)).toBeTruthy();
    expect(screen.getByText("로그에 계정 이름 없음")).toBeTruthy();
    expect(screen.getByText("로그인에 성공한 계정이 있는지 확인")).toBeTruthy();
    expect(api.find("POST", "/analyze/log")[0].body.text).toBe(TEXT);
    fireEvent.click(screen.getByRole("button", { name: /근거 줄 보기/ }));
    const lines = screen.getByTestId("evidence-lines").textContent!;
    expect(lines).toContain("09:31:00");
    expect(lines).toContain("09:33:50");
    expect(lines).not.toContain("09:31:02");  // only the lines the result points at
  });

  it("says plainly when nothing crossed a threshold, and that this is not a safety verdict", async () => {
    mockApi({ "GET /parsers": [200, []], "GET /analyze/log/web-cases": [200, { items: [{ ...CASE, expected: [] }] }],
      "GET /analyze/log/web-cases/WL02": [200, { id: "WL02", text: TEXT }], "POST /analyze/log": [200, result([])] });
    renderUI(<LogPage />);
    fireEvent.click(await screen.findByRole("button", { name: "이 사례 넣기" }));
    await waitFor(() => expect(screen.getByTestId("no-findings")).toBeTruthy());
    expect(screen.getByTestId("no-findings").textContent).toContain("안전하다는 확인은 아닙니다");
    expect(screen.getByText("기대한 결과와 같음")).toBeTruthy();
  });

  it("editing the pasted text drops the case comparison", async () => {
    mockApi({ "GET /parsers": [200, []], "GET /analyze/log/web-cases": [200, { items: [CASE] }],
      "GET /analyze/log/web-cases/WL02": [200, { id: "WL02", text: TEXT }], "POST /analyze/log": [200, result([finding])] });
    renderUI(<LogPage />);
    fireEvent.click(await screen.findByRole("button", { name: "이 사례 넣기" }));
    await screen.findByTestId("case-card");
    fireEvent.change(screen.getByLabelText("로그 붙여넣기"), { target: { value: TEXT + "\nextra" } });
    expect(screen.queryByTestId("case-card")).toBeNull();
  });
});
