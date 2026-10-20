import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { SourceContextTab } from "./SourceContextTab";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const routes = (extra = {}) => ({
  "GET /source-context/org-units": [200, [{ id: "org-a", display_name: "가상 A사" }]],
  "GET /source-context/investigations/i1/devices": [200, [{ id: "dev1", display_name: "가상 FW-01" }]],
  "GET /source-context/devices/dev1/profiles": [200, [{ id: "p1", version: 1, sha256: "abc", profile: { vendor: "가상 제조사" } }]],
  "GET /investigations/i1": [200, { evidence: [{ id: "e1", title: "가상 증거" }] }],
  "GET /source-context/evidence/e1/context": [200, { sha256: "frozen-sha", snapshot: { subject: { status: "unknown" }, profile: { vendor: "당시 제조사" } } }],
  ...extra,
}) as any;
describe("source context registry", () => {
  it("creates a device and selects its version list", async () => {
    const api = mockApi(routes({ "POST /source-context/investigations/i1/devices": [201, { id: "dev2", display_name: "가상 FW-02" }], "GET /source-context/devices/dev2/profiles": [200, []] }));
    renderUI(<SourceContextTab inv="i1" />);
    fireEvent.change(screen.getByLabelText("새 장비 이름"), { target: { value: "가상 FW-02" } });
    fireEvent.click(screen.getByRole("button", { name: "장비 등록" }));
    await waitFor(() => expect(api.find("GET", "/source-context/devices/dev2/profiles")).toHaveLength(1));
    expect(api.find("POST", "/source-context/investigations/i1/devices")[0].body).toEqual({ display_name: "가상 FW-02" });
  });
  it("saves a new conservative profile and never rewrites an evidence snapshot", async () => {
    const api = mockApi(routes({ "POST /source-context/devices/dev1/profiles": [201, { id: "p2", version: 2 }] }));
    renderUI(<SourceContextTab inv="i1" />);
    await screen.findByRole("option", { name: "가상 FW-01" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
    expect(await screen.findByText("당시 제조사")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("제조사"), { target: { value: "새 제조사" } });
    fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
    await waitFor(() => expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(1));
    expect(api.find("POST", "/source-context/devices/dev1/profiles")[0].body).toMatchObject({ vendor: "새 제조사", action_verified: false, measurement_profile: { verified: false, counter_semantics: "unknown" }, time: { verified: false } });
    expect(api.calls.filter(c => c.method !== "GET" && c.url.includes("/evidence/"))).toHaveLength(0);
  });
  it("keeps invalid advanced JSON as a draft and rejects it only on submit", async () => {
    const api = mockApi(routes()); renderUI(<SourceContextTab inv="i1" />);
    await screen.findByRole("option", { name: "가상 FW-01" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
    fireEvent.change(screen.getByLabelText("고급 프로필 JSON"), { target: { value: "{" } });
    expect(screen.queryByRole("alert")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
    expect(await screen.findByText(/JSON 형식/)).toBeTruthy();
    expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(0);
  });
  it("requires explicit basis and acknowledgement for verified semantics", async () => {
    const api = mockApi(routes()); renderUI(<SourceContextTab inv="i1" />);
    await screen.findByRole("option", { name: "가상 FW-01" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
    fireEvent.click(screen.getByLabelText("카운터 의미 검증됨"));
    fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
    expect(await screen.findByText(/검증 근거와 확인 동의/)).toBeTruthy();
    expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(0);
  });
  it("labels the synthetic template and surfaces save rejection", async () => {
    mockApi(routes({ "POST /source-context/devices/dev1/profiles": [422, { detail: "가상 필드 의미 재확인" }] }));
    renderUI(<SourceContextTab inv="i1" />);
    await screen.findByRole("option", { name: "가상 FW-01" });
    fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
    fireEvent.click(screen.getByRole("button", { name: "합성 FW 필드 예제 채우기" }));
    expect(screen.getByText(/실제 제조사 매핑으로 검증되지 않은 합성 예제/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
    expect(await screen.findByText(/가상 필드 의미 재확인/)).toBeTruthy();
  });
});

it("rejects advanced JSON boolean coercion that would bypass verification acknowledgement", async () => {
  const api = mockApi(routes()); renderUI(<SourceContextTab inv="i1" />);
  await screen.findByRole("option", { name: "가상 FW-01" });
  fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
  fireEvent.change(screen.getByLabelText("고급 프로필 JSON"), { target: { value: JSON.stringify({ measurement_profile: { verified: "true", basis: "합성 명세" } }) } });
  fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
  expect(await screen.findByText(/검증 여부는 true 또는 false/)).toBeTruthy();
  expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(0);
});

it("uses only accepted source semantics in the synthetic field template", async () => {
  const api = mockApi(routes({ "POST /source-context/devices/dev1/profiles": [201, { id: "p2", version: 2 }] }));
  renderUI(<SourceContextTab inv="i1" />);
  await screen.findByRole("option", { name: "가상 FW-01" });
  fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
  fireEvent.click(screen.getByRole("button", { name: "합성 FW 필드 예제 채우기" }));
  fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
  await waitFor(() => expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(1));
  expect(api.find("POST", "/source-context/devices/dev1/profiles")[0].body.source_fields).toEqual({ timestamp: "timestamp", session_id: "session_id", record_kind: "record_kind", action: "action", src_bytes: "src_bytes", dst_bytes: "dst_bytes", duration: "duration" });
  expect(screen.queryByLabelText("출발지 IP 필드")).toBeNull();
});

it("shows frozen semantic cards with readable labels before collapsed raw context", async () => {
  mockApi(routes({ "GET /source-context/evidence/e1/context": [200, { id: "cx1", sha256: "frozen-sha", created_at: "2026-10-20T00:00:00Z", snapshot: {
    investigation_org_unit_id: "org-a", subject: { org_unit_id: "org-a", status: "verified", basis: "합성 수집 명세" },
    observer: { device_id: "dev1", device_profile_version_id: "p1", network: "합성 업무망" },
    profile: { vendor: "당시 제조사", measurement_profile: { counter_semantics: "cumulative", direction: "src_to_dst", unit: "bytes", verified: true }, action_verified: false, time: { role: "occurred", timezone: "Asia/Seoul", verified: true } },
    collection: { scope: "blocked_only", loss: "unknown" },
  } }] }));
  renderUI(<SourceContextTab inv="i1" />);
  const summary = await screen.findByRole("region", { name: "가상 증거 원천 맥락" });
  expect(await within(summary).findByText("가상 A사")).toBeTruthy();
  expect(await within(summary).findByText("가상 FW-01")).toBeTruthy();
  expect(await within(summary).findByText(/프로필 v1/)).toBeTruthy();
  expect(within(summary).getByText("합성 업무망")).toBeTruthy();
  expect(within(summary).getByText("누적")).toBeTruthy();
  expect(within(summary).getByText("출발지 → 목적지")).toBeTruthy();
  expect(within(summary).getByText("바이트")).toBeTruthy();
  expect(within(summary).getByText("차단 기록만 수집")).toBeTruthy();
  expect(within(summary).getByText("손실 여부 미확인")).toBeTruthy();
  const raw = within(summary).getByText("원천 맥락 구조·무결성 상세").closest("details")!;
  expect(raw.open).toBe(false);
  expect(raw.textContent).toContain("frozen-sha");
});

it.each([
  ["second", "초"], ["seconds", "초"], ["s", "초"],
  ["millisecond", "밀리초"], ["milliseconds", "밀리초"], ["ms", "밀리초"],
  ["microsecond", "마이크로초"], ["microseconds", "마이크로초"], ["us", "마이크로초"],
  ["nanosecond", "나노초"], ["nanoseconds", "나노초"], ["ns", "나노초"],
])("labels recorded time precision %s and keeps known loss state neutral", async (precision, label) => {
  mockApi(routes({ "GET /source-context/evidence/e1/context": [200, { sha256: "alias-sha", snapshot: { profile: { time: { role: "occurred", timezone: "UTC", precision, verified: true } }, collection: { loss: "known" } } }] }));
  renderUI(<SourceContextTab inv="i1" />);
  const time = await screen.findByRole("region", { name: "시각 의미" });
  expect(within(time).getByText(label)).toBeTruthy();
  expect(screen.getByText("손실 상태 확인됨(크기 미기록)")).toBeTruthy();
  expect(screen.queryByText("손실 확인됨")).toBeNull();
});

it.each([["second", "초"], ["ms", "밀리초"], ["subseconds", "초 미만"], ["vendor-tick", "해석 미확인"]])("preserves exact copied profile precision %s in the visible draft and next version", async (precision, label) => {
  const api = mockApi(routes({
    "GET /source-context/devices/dev1/profiles": [200, [{ id: "p1", version: 1, profile: { time: { role: "occurred", timezone: "UTC", precision, verified: true, basis: "합성 원천 사전" } } }]],
    "POST /source-context/devices/dev1/profiles": [201, { id: "p2", version: 2 }],
  }));
  renderUI(<SourceContextTab inv="i1" />);
  await screen.findByRole("option", { name: "가상 FW-01" });
  fireEvent.change(screen.getByLabelText("장비 선택"), { target: { value: "dev1" } });
  fireEvent.click(await screen.findByText(/^v1 ·/));
  fireEvent.click(screen.getByRole("button", { name: "v1을 새 초안으로 복사" }));
  const select = screen.getByLabelText("시각 정밀도") as HTMLSelectElement;
  expect(select.value).toBe(precision);
  expect(select.selectedOptions[0].textContent).toContain(label);
  fireEvent.click(screen.getByLabelText("원천 필드 사전과 수집 조건을 확인했으며 입력한 검증 근거에 동의합니다"));
  fireEvent.click(screen.getByRole("button", { name: "새 프로필 버전 저장" }));
  await waitFor(() => expect(api.find("POST", "/source-context/devices/dev1/profiles")).toHaveLength(1));
  expect(api.find("POST", "/source-context/devices/dev1/profiles")[0].body.time).toEqual({ role: "occurred", timezone: "UTC", precision, verified: true, basis: "합성 원천 사전" });
  expect(api.calls.filter(call => call.method !== "GET" && call.url.includes("/evidence/"))).toHaveLength(0);
});
