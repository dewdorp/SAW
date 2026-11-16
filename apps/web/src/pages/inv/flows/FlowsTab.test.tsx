import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../../test/helpers";
import { FlowsTab } from "./FlowsTab";
import { RememberDialog } from "./RememberDialog";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const flow = { key: "f1", host: "portal.example.test", link: "session", link_text: "세션 쿠키 JSESSIONID의 값이 같음", session_ref: "9f938959", accounts: [], attempted_accounts: ["U20"],
  src_ips: ["10.20.1.44"], start: "2026-10-20T00:05:00Z", end: "2026-10-20T00:05:12Z", requests: 4, summary: "인증 시도 이후 회원정보 조회 요청이 관측되었습니다. 인증은 실패로 확인됐고, 동일 세션 9f938959입니다.",
  sequence: ["인증 화면 접근", "인증 시도", "회원정보 조회"], flags: ["lookup_after_failed_auth", "device_block_vs_success", "http_200_but_failed"], devices: [{ event_id: "w1" }], ddos_interval_ids: ["D1"],
  attention: 8, step_count: 4, judgement: null, conformance: [] };
const quiet = { ...flow, key: "f2", summary: "계정 U17의 인증 시도 성공 이후 동일 세션 aaaa1111에서 본인 대상 회원정보 조회이(가) 1회 수행되었습니다. 연결 근거는 세션 일치와 계정 일치입니다.", flags: [], devices: [], ddos_interval_ids: [], attention: 0 };
const run = (extra: any = {}) => ({ run: { id: "r1", version: 3, status: "complete", reason: "ingest", finished_at: "2026-10-21T01:00:00Z", knowledge: {}, changes: { first_run: true },
  result: { counts: { records_read: 180, labeled: 150, sessions_confirmed: 46, sessions_candidate: 0, duplicates: 1, no_time: 0 }, completeness: { flows_total: 2, note: "" }, flows: [flow, quiet], conflicts: [],
    ddos: [{ id: "D1", event_id: "d1", host: "portal.example.test", target_ip: "10.40.1.10", start: "2026-10-20T00:04:00Z", end_raw: "2026-10-20 09:07:00", vector: "SYN Flood", metric: "pps", unit: "packets/s", value: "185000",
      interval_seconds: "60", detection_state: "detected", mitigation_state: "mitigating", requests: 9, server_errors: 0 }],
    discovery: { baseline: { note: "처음 관측된 전이는 '처음 보임'일 뿐 공격이라는 뜻이 아니고" }, transitions: [{ host: "portal.example.test", from: "회원정보 조회", to: "미등록 GET /export/all.do", count: 1, sessions: 1,
      first: "2026-10-20T00:26:13Z", median_gap_seconds: 3, explained_by_registered_flow: false, unregistered_step: true, example_event_ids: ["e9"] }] },
    unregistered: [{ host: "portal.example.test", method: "GET", path: "/export/all.do", count: 1, first: "2026-10-20T00:26:13Z", last: "2026-10-20T00:26:13Z", example_event_id: "e9", suggestion: null }],
    services: [{ host: "portal.example.test", requests: 180, labeled: 150, activities: [{ meaning: "회원정보 조회", count: 70 }], link: { session_cookie: "JSESSIONID", text: "세션 쿠키 JSESSIONID로 요청을 연결합니다." } }],
    time: { note: "발생 시각 순으로 정렬했습니다.", basis: "기록의 발생 시각(수집·업로드 시각 아님)" }, side: { app_events: 90, alerts: 2, ddos_intervals: 1 } }, ...extra.run },
  stale: extra.stale || { stale: false, reasons: [] }, knowledge_items: 5 });
const detail = { ...flow, run: { id: "r1", version: 3 }, steps_omitted: 0, confirmed: ["10-20 09:05:04 이 요청의 HTTP 응답은 200이지만 인증 결과는 실패입니다."], inferred: ["이 흐름의 시간대에 같은 서비스의 DDoS 관측 구간이 있습니다. 집계 자료이므로 이 흐름의 행위로 연결하지 않았습니다."],
  unknown: ["장비 차단 기록과 가까운 시각의 요청 처리 기록이 있습니다. 같은 요청인지 확인되지 않았습니다."], next_checks: ["인증 실패 뒤 조회가 실제로 처리됐는지 확인"],
  steps: [{ event_id: "e1", time: "2026-10-20T00:05:04Z", meaning: "인증 시도", role: "auth_attempt", method: "POST", path: "/auth.html", status_code: 200, outcome: "failure", outcome_basis: "애플리케이션 기록 login의 result = fail (요청 ID 일치)", knowledge: { id: "k2", version: 1 }, account: "U20", account_note: "시도한 계정(인증 성공이 확인된 계정이 아님)" },
    { event_id: "e2", time: "2026-10-20T00:05:09Z", meaning: "회원정보 조회", role: "lookup", method: "GET", path: "/memberinfo", status_code: 403, outcome: "unknown", outcome_basis: "결과 확인 기준에 맞는 기록이 없습니다.", knowledge: { id: "k3", version: 2 }, auth_context_text: "앞선 인증 시도가 실패로 확인됨(성공 기록 없음)", object: "U99", object_relation: "other" }],
  devices: [{ event_id: "w1", step_event_id: "e2", source: "waf", time: "2026-10-20T00:05:09Z", alert_name: "Parameter Tampering", device: "waf-syn-01", rule_id: "942100", rule_version: "4", device_action: "block", http_status: 403, link: "same_request", link_basis: "요청 ID 일치", signature: { registered: false } }],
  network: { records: 1, pairs: [{ allowed: 1, blocked: 0, filters: [], time: {} }], text: "통신이 있었다는 근거이며, 같은 요청이라는 근거는 아닙니다." },
  knowledge_used: [{ id: "k3", title: "회원정보 조회 — 모든 메서드 /memberinfo", applied_version: 2, current_version: 3, status: "active" }], judgements: [] };

describe("business flows", () => {
  it("shows what was observed, why it was linked, what is unknown and what to check, without calling it an attack", async () => {
    mockApi({ "GET /investigations/i1/flows": [200, run()], "GET /investigations/i1/flows/runs/r1/flow": [200, detail] });
    renderUI(<FlowsTab inv="i1" />);
    expect(await screen.findByText(/HTTP 요청 180건 중/)).toBeTruthy();
    expect(screen.getByText("전체 검사 완료")).toBeTruthy();
    // Only the flow that needs a look is listed first; the matching one is one click away.
    expect(screen.getByRole("button", { name: /인증은 실패로 확인됐고/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /계정 U17/ })).toBeNull();
    expect(screen.getByText("DDoS 구간과 같은 시간대").getAttribute("title")).toContain("이 흐름의 행위로 연결하지 않았습니다");
    fireEvent.click(screen.getByRole("button", { name: /인증은 실패로 확인됐고/ }));
    expect(await screen.findByText("확인되지 않은 것")).toBeTruthy();
    expect(screen.getByText("다음에 확인할 것")).toBeTruthy();
    expect(screen.getByText(/HTTP 응답은 200이지만 인증 결과는 실패/)).toBeTruthy();
    expect(screen.getByText("시도한 계정(인증 성공이 확인된 계정이 아님)")).toBeTruthy();
    expect(screen.getByText("계정과 다름")).toBeTruthy();
    expect(screen.getByText("해석 미등록")).toBeTruthy();  // a similar-name meaning is never borrowed
    expect(screen.getByText(/장비 탐지, 장비 조치, HTTP 응답, 업무 결과는 서로 다른 값입니다/)).toBeTruthy();
    expect(screen.getByText("현재 v3")).toBeTruthy();  // the run keeps the version that was applied
    fireEvent.click(screen.getByRole("button", { name: /^전체 2$/ }));
    expect(screen.getByRole("button", { name: /계정 U17/ })).toBeTruthy();
    const ddos = screen.getByLabelText("DDoS 구간 표");
    expect(within(ddos).getByText("SYN Flood")).toBeTruthy();
    expect(screen.getByText(/특정 계정·세션의 행위로 연결하지 않았습니다/)).toBeTruthy();
    expect(screen.getByText(/공격이라는 뜻이 아니고/)).toBeTruthy();
  });

  it("says when the result is out of date and re-analyses with the reason, keeping the earlier run", async () => {
    const api = mockApi({ "GET /investigations/i1/flows": [200, run({ stale: { stale: true, reasons: ["지식이 바뀌었습니다(회원정보 조회)."] } })],
      "POST /investigations/i1/flows/run": [200, { id: "r2", version: 4 }] });
    renderUI(<FlowsTab inv="i1" />);
    expect(await screen.findByText("이 결과는 최신이 아닙니다.")).toBeTruthy();
    expect(screen.getByText(/이전 결과\(v3\)는 그대로 남습니다/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "최신 지식으로 다시 분석" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/flows/run")[0].body).toEqual({ reason: "knowledge_changed" }));
  });

  it("a failed run is shown as failed, and a partial one as partial", async () => {
    mockApi({ "GET /investigations/i1/flows": [200, { ...run(), run: { ...run().run, status: "failed", result: { error: "ValueError" } } }] });
    renderUI(<FlowsTab inv="i1" />);
    expect(await screen.findByText(/결과 없음이 아니라 실행 실패입니다/)).toBeTruthy();
    cleanup();
    mockApi({ "GET /investigations/i2/flows": [200, { ...run(), run: { ...run().run, status: "partial" } }] });
    renderUI(<FlowsTab inv="i2" />);
    expect(await screen.findByText(/처리 한도 때문에 일부만 검사했습니다/)).toBeTruthy();
  });

  it("remembers a meaning from a sentence, previews the records it covers and keeps the judgement apart", async () => {
    const saved = vi.fn();
    const api = mockApi({
      "POST /knowledge/flow-items/extract": [200, { drafts: [{ kind: "activity", from_text: "/memberinfo는 사용자정보 조회 기능이다", content: { host: "portal.example.test", method: "", path: "/memberinfo", match: "exact", params: [],
        meaning: "사용자정보 조회 기능", role: "lookup", object_param: "", outcomes: [], note: "" } }], judgement: { verdict: "normal" } }],
      "POST /investigations/i1/flow-knowledge/preview": [200, { matches: 70, host_records: 180, partial: false, samples: [{ event_id: "e2", method: "GET", path: "/memberinfo", status_code: 200 }], not_matched_examples: [] }],
      "POST /investigations/i1/flows/remember": (call) => call.body.items[0].allow_conflict ? [201, { saved: [{}], judgement: {}, run: {} }]
        : [409, { detail: "같은 범위에 다른 내용이 이미 등록되어 있습니다.", conflicts: [{ id: "k9", title: "공지사항 조회 — 모든 메서드 /memberinfo", version: 1 }] }] });
    renderUI(<RememberDialog inv="i1" seed={{ host: "portal.example.test", method: "GET", path: "/memberinfo", eventIds: ["e2"] }} onClose={() => {}} onSaved={saved} />);
    fireEvent.change(screen.getByPlaceholderText(/auth.html은 인증 관련 기능/), { target: { value: "/memberinfo는 사용자정보 조회 기능이다. 이번 요청은 정상" } });
    fireEvent.click(screen.getByRole("button", { name: "문장에서 뽑기" }));
    expect(await screen.findByDisplayValue("사용자정보 조회 기능")).toBeTruthy();
    expect(await screen.findByText("이 조사에서 적용될 기록 70건")).toBeTruthy();
    expect((screen.getByLabelText("이번 사건의 판단") as HTMLSelectElement).value).toBe("normal");
    expect(screen.getByText(/같은 주소·IP의 다른 요청을 계속 정상으로 처리하지 않습니다/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "기억하고 다시 분석" }));
    expect(await screen.findByText(/공지사항 조회 — 모든 메서드 \/memberinfo/)).toBeTruthy();
    expect(screen.getByText(/어느 쪽도 자동 적용되지 않고/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "상충 상태로 저장" }));
    await waitFor(() => expect(saved).toHaveBeenCalled());
    const body = api.find("POST", "/investigations/i1/flows/remember")[1].body;
    expect(body.items[0].content.meaning).toBe("사용자정보 조회 기능");
    expect(body.items[0].evidence).toEqual({ investigation_id: "i1", event_ids: ["e2"], source: "event" });
    expect(body.judgement).toEqual({ verdict: "normal", note: "/memberinfo는 사용자정보 조회 기능이다. 이번 요청은 정상", event_ids: ["e2"] });
  });
});
