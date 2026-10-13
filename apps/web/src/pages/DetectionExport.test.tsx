import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router-dom";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Detections } from "./Detections";

const UI = <Routes><Route path="/detections/*" element={<Detections />} /></Routes>;
const catalog = { detectors: [], signatures: [], scenarios: [], network_rules: [], can_switch: false };
beforeEach(() => { URL.createObjectURL = vi.fn(() => "blob:synthetic"); URL.revokeObjectURL = vi.fn(); vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {}); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("rule export and help", () => {
  it("explains internal approved Sigma execution and separate manual deployment", async () => {
    mockApi({ "GET /auth/me": [200, ME] });
    renderUI(UI, { route: "/detections/help" });
    expect(await screen.findByText("룰 등록부터 탐지까지")).toBeTruthy();
    expect(screen.getByText(/작성자와 다른/)).toBeTruthy();
    expect(screen.getByText("일치 예제와 정상 예제 등록")).toBeTruthy();
    expect(screen.getByText(/외부 SIEM/)).toBeTruthy();
  });
  it("downloads the whole shipped catalog with the requested format", async () => {
    const calls = mockApi({ "GET /detection-catalog": [200, catalog], "GET /detection-catalog/export": [200, { schema: "saw.detection-catalog.v1" }] });
    renderUI(UI, { route: "/detections/catalog" });
    fireEvent.click(await screen.findByRole("button", { name: "전체 기본 룰 YAML 다운로드" }));
    await waitFor(() => expect(calls.find("GET", "/detection-catalog/export")[0]?.url).toBe("/detection-catalog/export?format=yaml"));
    expect(screen.getByText(/검색 필터와 관계없이/)).toBeTruthy();
  });
  it("shows export failures instead of announcing a successful download", async () => {
    mockApi({ "GET /detection-catalog": [200, catalog], "GET /detection-catalog/export": [400, { detail: "내보내기 범위 제한" }] });
    renderUI(UI, { route: "/detections/catalog" });
    fireEvent.click(await screen.findByRole("button", { name: "전체 기본 룰 JSON 다운로드" }));
    expect(await screen.findByText(/내보내기 범위 제한/)).toBeTruthy();
  });
  it("creates a constrained example with both matching and benign tests", async () => {
    const calls = mockApi({ "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "detection.write"] }], "GET /detections": [200, []],
      "POST /detections": [201, { id: "example-rule" }], "GET /detections/example-rule": [404, { detail: "synthetic editor" }] });
    renderUI(UI, { route: "/detections" });
    fireEvent.click(await screen.findByRole("button", { name: "새 Sigma 룰" }));
    await waitFor(() => expect(calls.find("POST", "/detections")).toHaveLength(1));
    const body = calls.find("POST", "/detections")[0].body;
    expect(body.logic).toContain("/saw-demo/restricted-export");
    expect(body.threshold.count_gte).toBe(5);
    expect(body.test_events[0].event.method).toBe("POST");
    expect(body.test_events.map((x: any) => x.expected)).toEqual(["match", "no_match"]);
  });
  it("downloads current user rules without changing approval status", async () => {
    const calls = mockApi({ "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "knowledge.read"] }], "GET /detections": [200, []], "GET /detections/export": [200, { rules: [] }] });
    renderUI(UI, { route: "/detections" });
    fireEvent.click(await screen.findByRole("button", { name: "현재 룰 묶음 JSON 다운로드" }));
    await waitFor(() => expect(calls.find("GET", "/detections/export")).toHaveLength(1));
    expect(calls.calls.filter(x => x.method !== "GET")).toHaveLength(0);
  });
});
