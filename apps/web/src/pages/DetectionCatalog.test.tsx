import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router-dom";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Detections } from "./Detections";

afterEach(() => vi.unstubAllGlobals());

const SIGNATURE = {
  id: "exposure.config", title: "설정 파일 접근", group: "exposure", group_title: "정보 노출",
  stage: "RECONNAISSANCE", severity: 0.7, confidence: "medium", attack: ["T1190"], cve: "CVE-2099-0001",
  where: "uri", success: "only", explain: "응답 내용에서 실제 설정값이 전달되었는지 확인합니다.",
  checks: ["서버 응답 본문을 확인합니다."], examples: ["/config-example.json", { uri: "/sample-config", status: 200 }],
  enabled: true, note: "", updated_by: "", updated_at: null,
};
const TOOL = { ...SIGNATURE, id: "tool.example", title: "예시 탐색 도구", group: "tool", group_title: "공격 도구",
  attack: ["T1595"], cve: "", where: "ua", success: "ignore", explain: "도구 이름은 정당한 점검에도 쓰일 수 있습니다.",
  examples: ["<img src=x onerror=alert(1)>"], enabled: false, note: "허가된 점검 장비에서 사용", updated_by: "senior1",
  updated_at: "2026-10-10T03:00:00Z" };
const CATALOG = {
  can_switch: false,
  signatures: [SIGNATURE, TOOL],
  detectors: [{ id: "web.scan", title: "웹 경로 탐색", stage: "RECONNAISSANCE", data_sources: ["web", "waf"] }],
  scenarios: [{ id: "flow.example", title: "탐색 뒤 실행 흔적", severity: 0.8, attack: ["T1059"],
    explain: "순서와 같은 개체 근거를 함께 확인합니다.", checks: ["원본 탐지 근거를 확인합니다."],
    steps: [{ name: "탐색", stages: ["RECONNAISSANCE"], categories: [], success: false },
      { name: "실행 흔적", stages: [], categories: ["exec"], success: true }] }],
};
const ui = <Routes><Route path="/detections/*" element={<Detections />} /></Routes>;
const start = (route = "/detections/catalog") => renderUI(ui, { route });
const selectSignature = async (title = SIGNATURE.title) => fireEvent.click(await screen.findByRole("button", { name: `규칙 보기: ${title}` }));

describe("shipped detection catalog", () => {
  it("opens the shipped catalog from the detection menu and keeps candidate and coverage links", async () => {
    mockApi({ "GET /detections": [200, []], "GET /detection-catalog": [200, CATALOG] });
    start("/detections");
    fireEvent.click(screen.getByRole("link", { name: "기본 탐지 목록" }));
    expect(await screen.findByRole("button", { name: `규칙 보기: ${SIGNATURE.title}` })).toBeTruthy();
    expect(screen.getByRole("link", { name: "탐지 룰 후보" }).getAttribute("href")).toBe("/detections");
    expect(screen.getByRole("link", { name: "ATT&CK 커버리지" }).getAttribute("href")).toBe("/detections/coverage");
  });

  it("combines text, group and switch filters without silently showing other groups", async () => {
    mockApi({ "GET /detection-catalog": [200, CATALOG] });
    start();
    await screen.findByRole("button", { name: `규칙 보기: ${SIGNATURE.title}` });
    fireEvent.change(screen.getByLabelText("시그니처 묶음"), { target: { value: "tool" } });
    expect(screen.queryByRole("button", { name: `규칙 보기: ${SIGNATURE.title}` })).toBeNull();
    fireEvent.change(screen.getByLabelText("기본 탐지 검색"), { target: { value: "cve-2099-0001" } });
    expect(screen.getByText("조건에 맞는 기본 탐지가 없습니다.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("시그니처 묶음"), { target: { value: "" } });
    expect(screen.getByRole("button", { name: `규칙 보기: ${SIGNATURE.title}` })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("시그니처 상태"), { target: { value: "disabled" } });
    expect(screen.getByText("조건에 맞는 기본 탐지가 없습니다.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("기본 탐지 검색"), { target: { value: "t1595" } });
    expect(screen.getByRole("button", { name: `규칙 보기: ${TOOL.title}` })).toBeTruthy();
  });

  it("shows explanations, mixed examples and ATT&CK as text for read-only users", async () => {
    mockApi({ "GET /detection-catalog": [200, CATALOG] });
    start();
    await selectSignature();
    const detail = within(screen.getByRole("region", { name: "시그니처 상세" }));
    expect(detail.getByText(SIGNATURE.explain)).toBeTruthy();
    expect(detail.getByText(SIGNATURE.checks[0])).toBeTruthy();
    expect(detail.getByText("T1190")).toBeTruthy();
    expect(detail.getByText("/config-example.json")).toBeTruthy();
    expect(detail.getByText(/"uri": "\/sample-config"/)).toBeTruthy();
    expect(detail.queryByRole("button", { name: "시그니처 끄기" })).toBeNull();
    await selectSignature(TOOL.title);
    const toolDetail = screen.getByRole("region", { name: "시그니처 상세" });
    expect(within(toolDetail).getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(toolDetail.querySelector("img")).toBeNull();
    expect(within(toolDetail).getByText(TOOL.note)).toBeTruthy();
  });

  it("opens exact signature policy target without a legacy immediate switch", async () => {
    const api = mockApi({ "GET /detection-catalog": [200, { ...CATALOG, can_switch: true }] });
    start(); await selectSignature();
    expect(screen.getByRole("link", { name: "설정 변경" }).getAttribute("href")).toBe("/detections/policies/signature%3Aexposure.config");
    expect(screen.queryByRole("button", { name: "시그니처 끄기" })).toBeNull();
    expect(within(screen.getByRole("region", { name: "시그니처 상세" })).getByText(/초안·선택 시험·독립 승인·SAW 적용/)).toBeTruthy();
    expect(api.calls.filter(call => call.method !== "GET")).toHaveLength(0);
  });
  it("shows code detectors and ordered scenarios without treating a success signal as a verdict", async () => {
    mockApi({ "GET /detection-catalog": [200, CATALOG] });
    start();
    await screen.findByRole("button", { name: /기본 탐지기/ });
    fireEvent.click(screen.getByRole("button", { name: /기본 탐지기/ }));
    expect(screen.getByText("웹 경로 탐색")).toBeTruthy();
    expect(screen.getByText("web.scan")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /공격 흐름/ }));
    expect(screen.getByText("탐색 뒤 실행 흔적")).toBeTruthy();
    expect(screen.getByText("성공 신호 필요 · 개별 탐지 근거 확인")).toBeTruthy();
    expect(screen.getByText(/HTTP 2xx 응답만으로 공격 성공을 확정할 수 없습니다/)).toBeTruthy();
    expect(screen.getByText(/차단된 공격 시도도 차단 여부만으로 오탐으로 분류하지 않습니다/)).toBeTruthy();
  });

  it("reports a catalog fetch failure instead of presenting an empty successful catalog", async () => {
    mockApi({ "GET /detection-catalog": [503, { detail: "탐지 목록을 불러올 수 없습니다." }] });
    start();
    expect((await screen.findByRole("alert")).textContent).toContain("탐지 목록을 불러올 수 없습니다.");
    expect(screen.queryByText("조건에 맞는 기본 탐지가 없습니다.")).toBeNull();
  });

  it("keeps the creator's existing Sigma approval unavailable", async () => {
    mockApi({
      "GET /auth/me": [200, { ...ME, permissions: ["detection.approve"] }],
      "GET /detections/d1": [200, {
        id: "d1", display_id: "DET-1", version: 1, status: "test", created_by: ME.username, source: null,
        current: { title: "작성한 규칙", format: "sigma", logic: "title: Example", severity: "medium",
          threshold: {}, false_positive: "", attack: [], created_by: ME.username, reviewed_by: "" },
        test_runs: [], deployments: [], versions: [],
      }],
    });
    start("/detections/d1");
    expect(await screen.findByText("작성자와 다른 Senior/Manager가 승인해야 합니다.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Approve \(4-eyes/ })).toBeNull();
  });

  it("shows optional NDR policies and site criteria as read-only settings", async () => {
    const api = mockApi({ "GET /detection-catalog": [200, { ...CATALOG, can_switch: true, network_rules: [{
      id: "ndr.large_transfer", kind: "outbound_volume", enabled: false, title: "내부에서 외부로 큰 전송",
      stage: "ACTIONS_ON_OBJECTIVES", severity: 0.7, attack: ["T1041"], window_seconds: 600,
      min_connections: 3, min_bytes: 50000000, explain: "전송 목적과 승인된 작업 여부를 확인합니다.",
      checks: ["전송 대상과 시간 구간을 확인합니다."],
      site: { internal_cidrs: ["192.0.2.0/24"], home_countries: ["KR"], allowed_ports: [443],
        baseline_note: "시험용 승인 포트 기준", admin_ports: [22, 3389], timezone: "Asia/Seoul",
        work_start_hour: 9, work_end_hour: 18, work_days: [0, 1, 2, 3, 4] },
      limits: { max_events: 20000, max_groups: 1000, max_findings: 100, max_samples: 10 },
    }] }] });
    start();
    fireEvent.click(await screen.findByRole("button", { name: /NDR 연결 정책/ }));
    expect(screen.getByText("내부에서 외부로 큰 전송")).toBeTruthy();
    expect(screen.getByText("꺼짐")).toBeTruthy();
    expect(screen.getByText("전송 목적과 승인된 작업 여부를 확인합니다.")).toBeTruthy();
    expect(screen.getByText("192.0.2.0/24")).toBeTruthy();
    expect(screen.getByText("시험용 승인 포트 기준")).toBeTruthy();
    expect(screen.getByText(/600초/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "NDR 장비 관측 정책 변경" }).getAttribute("href")).toBe("/detections/policies/ndr.observation");
    expect(screen.queryByRole("button", { name: "시그니처 켜기" })).toBeNull();
    expect(api.calls.filter((call) => call.method !== "GET")).toHaveLength(0);
    fireEvent.change(screen.getByLabelText("기본 탐지 검색"), { target: { value: "t1041" } });
    expect(screen.getByText("내부에서 외부로 큰 전송")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("기본 탐지 검색"), { target: { value: "no matching policy" } });
    expect(screen.getByText("조건에 맞는 기본 탐지가 없습니다.")).toBeTruthy();
  });

  it("handles an older catalog without the optional NDR policy field", async () => {
    mockApi({ "GET /detection-catalog": [200, CATALOG] });
    start();
    fireEvent.click(await screen.findByRole("button", { name: /NDR 연결 정책/ }));
    expect(screen.getByText("조건에 맞는 기본 탐지가 없습니다.")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows a supplied scenario time bound as a matching condition", async () => {
    mockApi({ "GET /detection-catalog": [200, { ...CATALOG,
      scenarios: [{ ...CATALOG.scenarios[0], max_span_seconds: 900, entity_role: "source", strict_order: true }],
    }] });
    start();
    fireEvent.click(await screen.findByRole("button", { name: /공격 흐름/ }));
    expect(screen.getByText("최대 연결 구간: 900초")).toBeTruthy();
  });

  it("translates the stages returned by built-in detectors", async () => {
    mockApi({ "GET /detection-catalog": [200, { ...CATALOG, detectors: [
      { id: "recon", title: "탐지 1", stage: "RECON", data_sources: ["web"] },
      { id: "exec", title: "탐지 2", stage: "EXECUTION", data_sources: ["web"] },
      { id: "persist", title: "탐지 3", stage: "PERSISTENCE", data_sources: ["web"] },
      { id: "data", title: "탐지 4", stage: "DATA_ACCESS", data_sources: ["web"] },
      { id: "auth", title: "탐지 5", stage: "AUTHENTICATION", data_sources: ["web"] },
    ] }] });
    start();
    fireEvent.click(await screen.findByRole("button", { name: /기본 탐지기/ }));
    for (const label of ["정찰", "명령 실행", "지속성 확보", "자료 접근", "인증"]) {
      expect(screen.getByText(label)).toBeTruthy();
    }
  });

  it("moves keyboard focus to the selected signature details", async () => {
    mockApi({ "GET /detection-catalog": [200, CATALOG] });
    start();
    await selectSignature();
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "시그니처 상세" }));
    await selectSignature(TOOL.title);
    expect(document.activeElement).toBe(screen.getByRole("region", { name: "시그니처 상세" }));
  });
});
