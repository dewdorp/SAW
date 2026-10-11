import { fireEvent, screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Parsers } from "./Parsers";

afterEach(() => vi.unstubAllGlobals());

const META = { parsers: [], targets: ["timestamp_raw", "src_ip", "dst_ip", "dst_port"], data_sources: ["custom", "waf"] };
const SUGGEST = {
  spec: { format: "delimited", delimiter: "|", has_header: true, mapping: { 일시: "timestamp_raw" }, data_source: "waf",
    detect: { header_contains: ["일시", "공격자"] }, drop: ["cookie"] },
  columns: ["일시", "공격자", "상세"], notes: ["민감할 수 있는 열을 저장하지 않도록 제안했습니다: cookie"],
};
const PREVIEW = {
  detect_score: 0.995, auto_detect: true, coverage: { lines: 3, events: 2, skipped_lines: 1, failed_lines: 0 },
  rows: [{ line_no: 2, fields: { timestamp: "2026-10-03T08:38:47.000Z", src_ip: "198.51.100.7" } }], failures: [],
};

const ui = (
  <Routes>
    <Route path="/parsers/*" element={<Parsers />} />
    <Route path="/jobs/:id" element={<div>job page</div>} />
  </Routes>
);

describe("parser wizard", () => {
  it("starts from the uploaded file, suggests, previews, saves and re-processes the file", async () => {
    const api = mockApi({
      "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "parser.manage"] }],
      "GET /parser-library": [200, META],
      "GET /evidence/e1/files/f1/sample": [200, { file: "waf_x.txt", encoding: "cp949", lines: ["일시|공격자|상세", "20261003173847|198.51.100.7|a=1"] }],
      "POST /parser-library/suggest": [200, SUGGEST],
      "POST /parser-library/preview": [200, PREVIEW],
      "POST /parser-library": [201, { id: "u:waf-x", pinned_id: "u:waf-x@1", slug: "waf-x", version: 1, status: "draft" }],
      "POST /evidence/e1/files/f1/parser": [200, { ok: true }],
    });
    renderUI(ui, { route: "/parsers/new?ev=e1&file=f1&job=j1" });
    expect(await screen.findByText(/작업 화면에서 왔습니다/)).toBeTruthy();
    await vi.waitFor(() => expect((screen.getByPlaceholderText(/로그 몇 줄/) as HTMLTextAreaElement).value).toContain("일시|공격자"));
    fireEvent.click(screen.getByRole("button", { name: "자동 제안" }));
    expect(await screen.findByText(/저장하지 않도록 제안/)).toBeTruthy();
    expect(screen.getByText("공격자")).toBeTruthy();  // column row in the mapping table
    const cookieRow = screen.getByText("cookie").closest("tr")!;
    expect((cookieRow.querySelectorAll("input[type=checkbox]")[0] as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "미리보기" }));
    expect(await screen.findByText("이 샘플에서 자동 감지됨")).toBeTruthy();
    expect(screen.getByText("198.51.100.7")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "초안으로 저장하고 이 파일 다시 처리" }));
    expect(await screen.findByText("job page")).toBeTruthy();
    const saved = api.find("POST", "/parser-library")[0].body;
    expect(saved.name).toBe("waf_x");
    expect(saved.spec.delimiter).toBe("|");
    expect(saved.spec.drop).toEqual(["cookie"]);
    expect(api.find("POST", "/evidence/e1/files/f1/parser")[0].body).toEqual({ parser_id: "u:waf-x@1" });  // own draft, pinned
  });

  it("shows draft / pending / shared states and lets a different reviewer approve or reject", async () => {
    const api = mockApi({
      "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "parser.manage", "parser.approve"] }],
      "GET /parser-library": [200, { ...META, parsers: [
        { id: "u:waf-x", pinned_id: "u:waf-x@2", slug: "waf-x", name: "웹방화벽 X", version: 2, status: "pending", can_review: true, mine: false,
          note: "정책명 가림", created_by: "kim", created_at: "2026-10-09T00:00:00Z", spec: { format: "delimited", data_source: "waf", detect: { header_contains: ["일시"] } } },
        { id: "u:waf-x", pinned_id: "u:waf-x@1", slug: "waf-x", name: "웹방화벽 X", version: 1, status: "active", can_review: false, mine: false,
          created_by: "kim", reviewed_by: "lee", created_at: "2026-10-08T00:00:00Z", reviewed_at: "2026-10-08T01:00:00Z",
          spec: { format: "delimited", data_source: "waf", detect: { header_contains: ["일시"] } } },
        { id: "u:my-fw", pinned_id: "u:my-fw@1", slug: "my-fw", name: "내 방화벽", version: 1, status: "draft", mine: true,
          created_by: "analyst", created_at: "2026-10-09T00:00:00Z", spec: { format: "kv", data_source: "zeek_conn", detect: {} } }] }],
      "POST /parser-library/waf-x/versions/2/review": [200, { status: "active" }],
      "POST /parser-library/my-fw/versions/1/share": [200, { status: "pending" }],
    });
    renderUI(ui, { route: "/parsers" });
    expect(await screen.findByText("승인 대기")).toBeTruthy();
    expect(screen.getByText("공용 · 사용 중")).toBeTruthy();
    expect(screen.getByText("내 초안", { selector: "span.tag" })).toBeTruthy();
    expect(screen.getByText(/승인을 기다리는 파서 1건/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "승인" }));
    await vi.waitFor(() => expect(api.find("POST", "/parser-library/waf-x/versions/2/review")[0].body).toEqual({ approve: true, note: "" }));
    fireEvent.click(screen.getByRole("button", { name: "공용 요청" }));
    await vi.waitFor(() => expect(api.find("POST", "/parser-library/my-fw/versions/1/share")).toHaveLength(1));
    expect(screen.getByRole("button", { name: "끄기" })).toBeTruthy();  // approver can switch the shared one off
  });
});
