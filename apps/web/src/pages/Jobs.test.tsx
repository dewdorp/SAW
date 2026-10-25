import { fireEvent, screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { fmtEta, JobDetail } from "./Jobs";

class FakeEventSource {
  addEventListener() { /* no live updates in tests */ }
  close() { /* nothing */ }
  onerror: (() => void) | null = null;
}

afterEach(() => vi.unstubAllGlobals());

describe("job progress", () => {
  it("formats remaining time in Korean", () => {
    expect(fmtEta(20)).toBe("1분 이내");
    expect(fmtEta(600)).toBe("약 10분 남음");
    expect(fmtEta(3 * 3600 + 15 * 60)).toBe("약 3시간 15분 남음");
    expect(fmtEta(undefined)).toBe("");
  });

  it("shows byte progress, speed and ETA while parsing a large file", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    mockApi({"GET /auth/me":[200,ME],
      "GET /jobs/j1": [200, {
        id: "j1", investigation_id: "inv1", evidence_id: "ev1", state: "PARSING", events_done: 120000, events_total_est: 900000,
        current_item: "qsearch.csv", created_at: "2026-10-09T00:00:00Z",
        stages: { extract: { pct: 100, done: true }, parse: { pct: 13.4, eps: 3100, eta_sec: 1500 }, index: { pct: 13.4 } },
        files: [{ id: "f1", parent_file_id: null, size: 637_000_000, status: "parsing", display_name: "qsearch.csv" }],
      }],
      "GET /parsers": [200, []],
    });
    renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail />} /></Routes>, { route: "/jobs/j1" });
    expect(await screen.findByText("약 25분 남음")).toBeTruthy();
    expect(screen.getByText("초당 3,100건")).toBeTruthy();
    expect(screen.getByText("● 파싱 중")).toBeTruthy();
    expect(screen.getAllByText("13.4%")).toHaveLength(2); // parse + index bars
  });

  it("shows where every line of the file went (coverage)", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    mockApi({"GET /auth/me":[200,ME],
      "GET /jobs/j2": [200, {
        id: "j2", investigation_id: "inv1", evidence_id: "ev1", state: "COMPLETED", events_done: 900,
        created_at: "2026-10-09T00:00:00Z", stages: { parse: { pct: 100, done: true } },
        files: [{ id: "f1", parent_file_id: null, size: 1000, status: "degraded", name: "fw.csv", parser_id: "csv",
          events_parsed: 900, events_failed: 3, error_samples: [{ line_no: 7, reason: "column count mismatch", raw: "x,y" }],
          coverage: { lines: 1006, events: 900, continuation_lines: 0, skipped_lines: 1, blank_lines: 102, failed_lines: 3 } }],
      }],
      "GET /parsers": [200, []],
    });
    renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail />} /></Routes>, { route: "/jobs/j2" });
    expect(await screen.findByText(/처리 범위/)).toBeTruthy();
    expect(screen.getByText("1,006")).toBeTruthy();
    expect(screen.getByText("99.67%")).toBeTruthy(); // (900 + 1) / (1006 - 102)
    expect(screen.getByText("⚠ 일부 실패")).toBeTruthy();
    expect(screen.getByText(/fw.csv:7 column count mismatch/)).toBeTruthy();
  });
});


it("opens the newly queued reprocessing job while preserving previous results", async () => {
  vi.stubGlobal("EventSource", FakeEventSource);
  const api = mockApi({
    "GET /auth/me": [200, ME],
    "GET /jobs/old-job": [200, {
      id: "old-job", investigation_id: "inv1", evidence_id: "ev1", kind: "ingest", state: "COMPLETED",
      stages: {}, files: [{id:"f1", name:"synthetic.csv", type:"text", size:100, status:"done", parser_id:"csv", events_parsed:1}],
    }],
    "GET /parsers": [200, [{id:"csv", name:"CSV"}]],
    "POST /evidence/ev1/files/f1/parser": [200, {ok:true, job_id:"new-job"}],
  });
  renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/><Route path="/jobs/new-job" element={<div>새 재처리 작업</div>}/></Routes>, {route:"/jobs/old-job"});
  expect(await screen.findByText("다른 파서로 다시 처리")).toBeTruthy();
  expect(screen.getByText(/기존 결과와 분석 이력은 보존합니다\. 새 결과 저장을 확인하면 최신 결과로 전환합니다\. 전환 전 실패하거나 취소되면 기존 결과를 유지합니다\. 전환 후 탐지 분석만 실패하거나 취소될 수 있으며, 이때 저장된 새 결과는 유지됩니다\./)).toBeTruthy();
  expect(await screen.findByRole("option", {name:"csv"})).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox"), {target:{value:"csv"}});
  expect(await screen.findByText("새 재처리 작업")).toBeTruthy();
  expect(api.find("POST", "/evidence/ev1/files/f1/parser")[0].body).toEqual({parser_id:"csv"});
});

it.each(["PARSING", "COMPLETED"])("shows only executed phases for reprocessing %s", async (state) => {
  vi.stubGlobal("EventSource", FakeEventSource);
  const done = state === "COMPLETED";
  mockApi({
    "GET /auth/me": [200, ME],
    "GET /jobs/reprocess": [200, {id:"reprocess", investigation_id:"inv1", evidence_id:"ev1",
      kind:"reprocess", state, files:[], stages:{parse:{done,pct:done?100:25},index:{done,pct:done?100:0},analyze:{done}}}],
    "GET /parsers": [200, []],
  });
  renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/></Routes>, {route:"/jobs/reprocess"});
  expect(await screen.findByText("파싱")).toBeTruthy();
  expect(screen.getByText("색인")).toBeTruthy();
  expect(screen.getByText("분석")).toBeTruthy();
  expect(screen.queryByText("업로드")).toBeNull();
  expect(screen.queryByText("압축 해제")).toBeNull();
  expect(screen.getByText("보관된 원본으로 다시 처리합니다. 업로드와 압축 해제는 반복하지 않습니다.")).toBeTruthy();
  if(done) expect(screen.getAllByText("✓")).toHaveLength(3);
  else { expect(screen.getByText("25%")).toBeTruthy(); expect(screen.queryByText("✓")).toBeNull(); }
});
