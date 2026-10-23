import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes, useNavigate } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { useInvStore, useInvTabs } from "../../context/invContext";
import { ME, mockApi, renderUI } from "../../test/helpers";
import { Workbench } from "./Workbench";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useInvStore.setState({ byInv: {} });
  useInvTabs.setState({ tabs: [] });
});

const run = (id: string, version: number) => ({
  id, version, status: "complete", scope: {}, summary: {}, created_at: "2026-10-23T00:00:00Z",
  input_sha256: "synthetic-input", findings: [], executions: [],
});
const inv = (id: string) => ({
  id, display_id: id, title: "합성 " + id, status: "closed", risk_level: "low", risk_score: 0,
  evidence: [], finding_counts: {}, org_unit: null, time_start: null, time_end: null,
});
const report = (id: string, version: number) => ({
  id, version, content_sha256: id + "-hash", created_at: "2026-10-23T00:00:00Z",
  content: { schema_version: "saw.report.v2", scope: { kind: "investigation" }, limits: [] },
});

function Navigation() {
  const navigate = useNavigate();
  return <><button onClick={() => navigate("/inv/i2")}>다른 합성 조사로 이동</button>
    <Routes><Route path="/inv/:id" element={<Workbench />} /></Routes></>;
}

function example() {
  useInvStore.getState().set("i1", { tab: "analysis-history" });
  useInvStore.getState().set("i2", { tab: "analysis-history" });
  const routes: any = {
    "GET /auth/me": [200, ME],
    "GET /source-context/org-units": [200, []],
    "GET /investigations/i1/analysis-runs": (c: any) => [200, c.url.includes("before_version=3")
      ? { runs: [run("run-a2", 2)], next_before_version: null }
      : { runs: [run("run-a3", 3)], next_before_version: 3 }],
    "GET /investigations/i1/report-versions": (c: any) => [200, c.url.includes("before_version=3")
      ? { reports: [report("report-a2", 2)], next_before_version: null }
      : { reports: [report("report-a3", 3)], next_before_version: 3 }],
    "GET /investigations/i1/report-versions/report-a2": [200, report("report-a2", 2)],
    "GET /investigations/i1/analysis-runs/run-a3": [200, run("run-a3", 3)],
    "GET /investigations/i1/analysis-runs/run-a2": [200, run("run-a2", 2)],
    "GET /investigations/i2/analysis-runs": [200, { runs: [run("run-b1", 1)], next_before_version: null }],
    "GET /investigations/i2/analysis-runs/run-b1": [200, run("run-b1", 1)],
    "GET /investigations/i2/report-versions": [200, { reports: [report("report-b1", 1)], next_before_version: null }],
  };
  for (const id of ["i1", "i2"]) {
    routes["GET /investigations/" + id] = [200, inv(id)];
    routes["GET /source-context/investigations/" + id + "/devices"] = [200, []];
    routes["POST /investigations/" + id + "/query/aggregate"] = [200, { buckets: [], total: 0 }];
  }
  const api = mockApi(routes);
  const rendered = renderUI(<Navigation />, { route: "/inv/i1" });
  // A cached destination must not accidentally remount through the loading branch.
  rendered.qc.setQueryDefaults(["inv", "i2"], { gcTime: 300000, staleTime: 60000 });
  rendered.qc.setQueryData(["inv", "i2"], inv("i2"));
  return { api, ...rendered };
}

it("clears paged reports and selected analysis when moving to another cached investigation", async () => {
  const { api } = example();
  fireEvent.click(await screen.findByRole("button", { name: "이전 분석 더 보기" }));
  await screen.findByRole("option", { name: /v2/ });
  fireEvent.change(screen.getByLabelText("분석 실행 선택"), { target: { value: "run-a2" } });
  await waitFor(() => expect(screen.getByText(/실행 v2 · 완료/)).toBeTruthy());
  fireEvent.click(screen.getByRole("button", { name: "이전 보고서 더 보기" }));
  fireEvent.click(await screen.findByRole("button", { name: "보고서 v2 상세" }));
  await screen.findByRole("heading", { name: "정확한 저장 보고서 v2" });
  fireEvent.click(screen.getByRole("button", { name: "다른 합성 조사로 이동" }));
  await screen.findByRole("link", { name: "저장 보고서 v1" });
  expect(screen.getByLabelText("분석 실행 선택")).toHaveProperty("value", "run-b1");
  expect(screen.queryByRole("link", { name: "저장 보고서 v3" })).toBeNull();
  expect(screen.queryByRole("link", { name: "저장 보고서 v2" })).toBeNull();
  expect(screen.queryByRole("option", { name: /v2/ })).toBeNull();
  expect(screen.queryByRole("heading", { name: "정확한 저장 보고서 v2" })).toBeNull();
  expect(api.find("GET", "/investigations/i2/analysis-runs/run-a2")).toHaveLength(0);
  expect(api.find("GET", "/investigations/i2/report-versions/report-a2")).toHaveLength(0);
});

it("closes the prior investigation export scope when moving to another cached investigation", async () => {
  example();
  fireEvent.click(await screen.findByRole("button", { name: "선택 실행 HTML·Excel 내보내기" }));
  expect(await screen.findByRole("dialog", { name: "불변 보고서 내보내기 범위" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "다른 합성 조사로 이동" }));
  await screen.findByRole("link", { name: "저장 보고서 v1" });
  expect(screen.queryByRole("dialog", { name: "불변 보고서 내보내기 범위" })).toBeNull();
  fireEvent.click(await screen.findByRole("button", { name: "선택 실행 HTML·Excel 내보내기" }));
  expect(await screen.findByRole("dialog", { name: "불변 보고서 내보내기 범위" })).toHaveProperty("textContent", expect.stringContaining("run-b1"));
});
