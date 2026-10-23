import { screen } from "@testing-library/react";
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
