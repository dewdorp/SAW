import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { FindingDetail } from "./FindingsTab";

vi.mock("../../viz/EChart", () => ({ EChart: () => <div data-testid="chart" />, axisStyle: {}, safeTooltip: () => () => "", TopBar: () => null }));
afterEach(() => vi.unstubAllGlobals());

const INV = "inv-1";
const FINDING = {
  id: "f1", display_id: "F-1035", title: "Potential Web Shell Upload and Use", risk_level: "critical", risk_score: 86,
  risk_factors: [{ name: "behavior_severity", value: 0.95 }], confidence: "high", claim: "INFERRED", status: "new",
  time_start: null, time_end: null, detector: { id: "pcap.webshell", version: "1.0.0" },
  metrics: [{ name: "later_requests", label: "Requests to uploaded path", observed: 3, claim: "DERIVED" }],
  checks: [{ label: "Uploaded path requested afterwards", passed: true, value: "3건", claim: "DERIVED" }],
  entities: ["ip:203.0.113.66"], attack: [{ technique_id: "T1505.003", name: "Web Shell", confidence: "high", condition: "업로드 후 사용", claim: "INFERRED" }],
  evidence_refs: { claim: "OBSERVED" }, counter_evidence: [], fp_matches: [],
  explanation_md: "203.0.113.66 → 10.20.1.15 서버측 스크립트 `shell.jsp` 업로드, 이후 3회 요청.\n\n### 확인·대응 권고 (분석가 판단 후 수행)\n- 웹 서버에서 업로드 파일 존재 여부 확인\n- 웹 서버 계정의 프로세스 실행 이력 확인",
  feedback: [{ verdict: "valid", comment: "확인함", at: null, claim: "VERDICT" }],
};

describe("Finding detail", () => {
  it("separates the explanation from the analyst recommendations and labels every claim", async () => {
    mockApi({
      [`GET /investigations/${INV}/findings/f1`]: [200, FINDING],
      [`POST /investigations/${INV}/findings/f1/events`]: [200, { events: [], total: 4 }],
      "GET /cases": [200, []],
    });
    renderUI(<FindingDetail inv={INV} id="f1" />);
    expect(await screen.findByRole("heading", { name: "Potential Web Shell Upload and Use" })).toBeTruthy();
    const advice = screen.getByText("확인·대응 권고 (분석가 판단 후 수행)").closest(".panel") as HTMLElement;
    expect(within(advice).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "웹 서버에서 업로드 파일 존재 여부 확인", "웹 서버 계정의 프로세스 실행 이력 확인"]);
    expect(screen.getByText(/shell.jsp/).textContent).not.toContain("확인·대응 권고");
    const claims = [...document.querySelectorAll(".claim")].map((e) => e.textContent);
    for (const c of ["추론", "계산", "관측", "판정"]) expect(claims).toContain(c);
    expect(screen.getByText("신뢰도 높음 ⓘ")).toBeTruthy();
  });

  it("records the analyst verdict with a comment", async () => {
    const api = mockApi({
      [`GET /investigations/${INV}/findings/f1`]: [200, { ...FINDING, feedback: [] }],
      [`POST /investigations/${INV}/findings/f1/events`]: [200, { events: [], total: 0 }],
      [`POST /investigations/${INV}/findings/f1/feedback`]: [200, { ok: true, status: "false_positive" }],
      "GET /cases": [200, []],
    });
    renderUI(<FindingDetail inv={INV} id="f1" />);
    fireEvent.change(await screen.findByPlaceholderText("판단 근거 (선택)"), { target: { value: "정상 배포 작업" } });
    fireEvent.click(screen.getByRole("button", { name: "오탐" }));
    await vi.waitFor(() => expect(api.find("POST", `/investigations/${INV}/findings/f1/feedback`)[0].body)
      .toEqual({ verdict: "false_positive", comment: "정상 배포 작업" }));
  });
});
