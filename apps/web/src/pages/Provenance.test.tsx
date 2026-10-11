import { fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Provenance } from "./Provenance";

afterEach(() => vi.unstubAllGlobals());

const RUN = { id: "r1", finished_at: "2026-10-09T01:00:00Z", actor: "analyst", actor_id: "u1", investigation: "INV-1", investigation_id: "i1",
  investigation_title: "사건 A", file_name: "fw.csv", input_size: 2048, input_sha256: "a".repeat(64), parser_id: "u:waf-x@1", parser_version: "1",
  parser_digest: "b".repeat(64), settings_digest: "c".repeat(64), run_digest: "d".repeat(64), events: 33, failed: 0, status: "done", draft_parser: true };

describe("processing records", () => {
  it("lists my runs with fingerprints and verifies one against the audit log", async () => {
    const api = mockApi({
      "GET /auth/me": [200, ME],
      "GET /processing-runs": [200, [RUN]],
      "GET /processing-runs/r1/verify": [200, { ok: true }],
    });
    renderUI(<Provenance />);
    expect(await screen.findByText("fw.csv")).toBeTruthy();
    expect(screen.getByText("초안")).toBeTruthy();
    expect(screen.getByText("aaaaaaaaaaaa")).toBeTruthy();
    expect(screen.queryByText("통합 보기")).toBeNull();  // analysts have no consolidated view
    fireEvent.click(screen.getByRole("button", { name: "검증" }));
    expect(await screen.findByText("일치")).toBeTruthy();
    expect(api.find("GET", "/processing-runs")[0].url).toContain("scope=mine");
  });

  it("an auditor opens the consolidated view with consistency warnings", async () => {
    mockApi({
      "GET /auth/me": [200, { ...ME, roles: ["admin"], permissions: ["admin.users", "audit.read"] }],
      "GET /processing-runs/summary": [200, { days: 90, runs: 3, inputs: 2,
        by_user: [{ actor: "analyst", actor_id: "u1", runs: 2, files: 1, events: 60, draft_runs: 1 }],
        by_parser: [{ parser_id: "csv", parser_version: "1.0.0", runs: 1, settings_variants: 1, analysts: ["analyst"] }],
        warnings: { same_input_different_settings: [{ input_sha256: "a".repeat(64), settings_variants: 2, runs: [{ ...RUN, file_name: "(비공개).csv" }] }],
          parser_definition_changed: [], draft_parser_runs: [RUN] } }],
      "GET /processing-runs": [200, [{ ...RUN, file_name: "(비공개).csv", investigation_title: undefined, investigation_id: undefined }]],
    });
    renderUI(<Provenance />);
    expect(await screen.findByText(/같은 입력 파일을 서로 다른 설정으로 처리/)).toBeTruthy();
    expect(screen.getByText("분석가별")).toBeTruthy();
    expect(await screen.findByText("(비공개).csv")).toBeTruthy();
  });
});
