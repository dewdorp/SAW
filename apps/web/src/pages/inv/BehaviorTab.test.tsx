import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { BehaviorTab } from "./BehaviorTab";

vi.mock("../../viz/EChart", () => ({ EChart: ({ ariaLabel, option, onClick }: any) => <><div role="img" aria-label={ariaLabel} data-description={option.aria?.label?.description} />{onClick && <button onClick={() => onClick({ dataIndex: 0 })}>첫 구간 선택</button>}</>, axisStyle: {}, safeTooltip: () => () => "" }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); useInvStore.setState({ byInv: {} }); });
const INV = "behavior-inv";
const scope = { filters: [{ field: "data_source", op: "is" as const, value: "waf" }], time: { start: "2026-10-16T00:00:00Z", end: "2026-10-16T00:10:00Z" }, ips: ["192.0.2.1"], role: "src" };
const ids = ["requests_10s", "paths_60s", "status404_60s", "repeats_60s", "ua_600s"];
const labels = ["요청 수", "서로 다른 경로", "404 응답", "반복 요청", "서로 다른 UA"];
const dto = { id: "br-1", version: 1, created_at: "2026-10-16T01:00:00Z", created_by: "analyst", result_sha256: "a".repeat(64), result: {
  schema: "saw.behavior.result.v1", scope, methodology: { version: "saw-web-behavior/1.0" },
  profile: { id: "theori-reference-v1", label: "WhitepaperReference", thresholds: { requests_10s: 30 } },
  source_manifest: { files: [{ id: "file-1" }] },
  observations: {
    summary: { count: 31, first: scope.time.start, last: "2026-10-16T00:00:09Z", unique_paths: 9, methods: { GET: 31 }, status_codes: { "404": 17 }, actions: { allowed: 31 }, user_agents: null, services: ["app.test:443"] },
    quality: { user_agent: { present: 0, recorded_empty: 0, not_collected: 31, unknown: 0 }, timestamp_precision: { seconds: 31 } },
    timeline: { interval_seconds: 10, timezone: "UTC", coverage_label: "수집 WAF 이벤트", buckets: [{ start: scope.time.start, end_exclusive: "2026-10-16T00:00:10Z", count: 31, status404: 17, blocked: 0, allowed: 31, ua_values: null }], annotations: [] },
    metrics: ids.map((id, i) => ({ id, label: labels[i], value: i === 4 ? null : 31 - i, window_seconds: [10, 60, 60, 60, 600][i], data_state: i === 4 ? "not_collected" : "available", result: i === 4 ? "unavailable" : "threshold_met", reference_threshold: [30, 30, 15, 20, 2][i], applied_threshold: [30, 30, 15, 20, 2][i], excluded_count: 0, eligible_count: i === 4 ? 0 : 31, partial_window: true, evidence_ids: i === 4 ? [] : ["e1", "e2"], window: i === 4 ? null : { start: scope.time.start, end_exclusive: "2026-10-16T00:00:10Z", src_ip: "192.0.2.1", service: "app.test:443" } })),
    indicators: [{ id: "tool", label: "도구 문자열", state: "observed", count: 1, source: "user_agent", verification: "문자열 일치", conditions: ["필드 수집"], evidence_ids: ["e1"], limits: ["실행 여부 확인 불가"] }],
    followups: [{ id: "origin", target: "웹 서버", needed_data: ["처리 로그"], items: ["처리 결과 확인"], conditions: ["허용 요청 관측"] }],
    limits: ["수집 연속성 미확인"], execution: { scanned: 31, processed: 31, truncated: false }
  },
  selected_evidence: [{ event_id: "e1", event: { method: "GET", uri: "/a?q=1", timestamp: scope.time.start }, sha256: "b".repeat(64) }, { event_id: "e2", event: { method: "GET", uri: "/a?q=2", timestamp: "2026-10-16T00:00:01Z" }, sha256: "c".repeat(64) }]
}};
const routes = (extra = {}) => ({
  [`GET /investigations/${INV}/behavior`]: [200, { results: [{ id: dto.id, version: dto.version, created_at: dto.created_at }] }],
  [`GET /investigations/${INV}/behavior/br-1`]: [200, dto],
  [`GET /investigations/${INV}/checks`]: [200, { checks: [], me: "u1" }],
  ...extra,
}) as any;

describe("Saved behavior analysis", () => {
  it("does not invent a preview or zero values before a calculation", async () => {
    mockApi({ [`GET /investigations/${INV}/behavior`]: [200, { results: [] }] });
    renderUI(<BehaviorTab inv={INV} />);
    expect(await screen.findByText(/저장된 분석 결과가 없습니다/)).toBeTruthy();
    expect(screen.queryByRole("img", { name: "행위 관측 시계열" })).toBeNull();
  });
  it("submits current filters, time, selected and multiple IPs with local controls", async () => {
    useInvStore.getState().set(INV, { filters: scope.filters, time: scope.time, selection: { type: "ip", value: "192.0.2.1" } });
    const api = mockApi({ [`GET /investigations/${INV}/behavior`]: [200, { results: [] }],
      [`POST /investigations/${INV}/behavior`]: [202, { id: "j1", state: "QUEUED" }], "GET /jobs/j1": [200, { id: "j1", state: "ANALYZING", events_done: 12 }], "POST /jobs/j1/cancel": [200, { state: "CANCELLED" }] });
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.change(screen.getByLabelText("분석 IP"), { target: { value: "192.0.2.1, 192.0.2.2" } });
    fireEvent.change(screen.getByLabelText("IP 역할"), { target: { value: "either" } });
    fireEvent.change(screen.getByLabelText("요청 수 기준"), { target: { value: "40" } });
    fireEvent.click(screen.getByRole("button", { name: "행위 분석 실행" }));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/behavior`)).toHaveLength(1));
    expect(api.find("POST", `/investigations/${INV}/behavior`)[0].body).toMatchObject({ ...scope, ips: ["192.0.2.1", "192.0.2.2"], role: "either", profile: { thresholds: { requests_10s: 40 } } });
    fireEvent.click(await screen.findByRole("button", { name: "분석 취소" }));
    await waitFor(() => expect(api.find("POST", "/jobs/j1/cancel")).toHaveLength(1));
  });
  it("renders saved measurements, missing fields, reference labels and report link", async () => {
    mockApi(routes());
    renderUI(<BehaviorTab inv={INV} />);
    expect(await screen.findByText("수집 WAF 이벤트")).toBeTruthy();
    expect(screen.getByText("WhitepaperReference")).toBeTruthy();
    const row = screen.getByRole("row", { name: /서로 다른 UA.*미수집/ });
    expect(within(row).getByText("—")).toBeTruthy();
    expect(screen.getAllByText(/부분 시간창/).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "저장 결과 보고서" }).getAttribute("href")).toBe(`/api/v1/investigations/${INV}/behavior/br-1/report`);
    expect(screen.getByText(/실행 여부 확인 불가/)).toBeTruthy();
  });
  it("drills down by saved evidence IDs without replaying query filters", async () => {
    useInvStore.getState().set(INV, { filters: [{ field: "method", op: "is", value: "POST" }], time: null });
    mockApi(routes());
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "요청 수 표본 원문" }));
    expect(useInvStore.getState().get(INV)).toMatchObject({ tab: "raw", time: null, filters: [{ field: "event_id", op: "in", value: ["e1", "e2"] }] });
  });
  it("compares only saved selected evidence and original frozen query scope", async () => {
    const api = mockApi(routes({ [`POST /investigations/${INV}/diff`]: [200, { requests: [], transitions: [] }] }));
    renderUI(<BehaviorTab inv={INV} />);
    await screen.findByText("수집 WAF 이벤트");
    fireEvent.click(screen.getByLabelText("요청 비교 선택 e1"));
    fireEvent.click(screen.getByLabelText("요청 비교 선택 e2"));
    fireEvent.click(screen.getByRole("button", { name: "선택 요청 비교" }));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/diff`)).toHaveLength(1));
    expect(api.find("POST", `/investigations/${INV}/diff`)[0].body).toEqual({ ...scope, event_ids: ["e1", "e2"], behavior_result_id: "br-1", result_sha256: dto.result_sha256 });
  });
  it("records analyst text through Check with a pinned behavior result attachment", async () => {
    const api = mockApi(routes({ [`POST /investigations/${INV}/checks`]: [201, { id: "c1" }] }));
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "분석가 확인 기록" }));
    fireEvent.change(screen.getByLabelText("행위 답변 상태"), { target: { value: "answered" } });
    fireEvent.change(screen.getByLabelText("근거"), { target: { value: "승인된 점검 범위를 확인함" } });
    fireEvent.click(screen.getByRole("button", { name: "확인 기록 저장" }));
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/checks`)).toHaveLength(1));
    const body = api.find("POST", `/investigations/${INV}/checks`)[0].body;
    expect(body.behavior).toMatchObject({ result_id: "br-1", result_sha256: dto.result_sha256, metric_ids: ids, answer_status: "answered" });
    expect(body.note).toBe("승인된 점검 범위를 확인함");
    expect(body.behavior).not.toHaveProperty("metrics");
    expect(body.scope).toMatchObject({ coverage: "selected", checked: 2, event_ids: ["e1", "e2"] });
  });
  it("selects another saved version as a comparison without claiming a normal baseline", async () => {
    const second = { ...dto, id: "br-2", version: 2 };
    mockApi(routes({ [`GET /investigations/${INV}/behavior`]: [200, { results: [{ id: "br-1", version: 1 }, { id: "br-2", version: 2 }] }], [`GET /investigations/${INV}/behavior/br-2`]: [200, second] }));
    renderUI(<BehaviorTab inv={INV} />);
    await screen.findByText("수집 WAF 이벤트");
    fireEvent.change(screen.getByLabelText("비교 대상"), { target: { value: "br-2" } });
    expect(await screen.findByText("비교 대상 v2")).toBeTruthy();
    expect(screen.queryByText("정상 기준선")).toBeNull();
  });
});

describe("Behavior provenance and qualifying windows", () => {
  it("shows per-file coverage and distinguishes missing source metadata", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.source_manifest = { evidence: [{ evidence_id: "source-1", files: [
      { id: "f1", display_name: "synthetic.log", parser_id: "web", parse_status: "done", events_parsed: 31, events_failed: 2, timezone: null }
    ] }] };
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    const row = await screen.findByRole("row", { name: /synthetic.log.*web.*완료.*31.*2.*미기록/ });
    expect(row).toBeTruthy();
  });
  it("shows the UA qualifying window separately from its global maximum", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.observations.metrics[4] = { ...detailed.result.observations.metrics[4],
      value: 5, data_state: "available", result: "threshold_met", window: { start: scope.time.start, end_exclusive: "2026-10-16T00:10:00Z" },
      status404_in_window: 0, required_status404: 2,
      qualifying_window: { start: "2026-10-16T02:00:00Z", end_exclusive: "2026-10-16T02:10:00Z", value: 2, status404: 2, src_ip: "192.0.2.1", service: "app.test:443", evidence_ids: ["e1", "e2"] } };
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    expect(await screen.findByText(/동반 조건 충족 구간/)).toBeTruthy();
    const row = screen.getByRole("row", { name: /서로 다른 UA.*5.*동반 조건 충족/ });
    expect(within(row).getByText(/UA 2.*404 2/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "서로 다른 UA 동반 조건 구간" }));
    expect(screen.getByText(/\[2026-10-16T02:00:00Z, 2026-10-16T02:10:00Z\)/)).toBeTruthy();
  });
});

it("uses Korean verification labels and a chart description that preserves missing observations", async () => {
  const detailed = structuredClone(dto) as any;
  detailed.result.observations.timeline.buckets[0].blocked = null;
  detailed.result.observations.indicators[0].verification = "conditional_code_derived";
  mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
  renderUI(<BehaviorTab inv={INV} />);
  await screen.findByText("수집 WAF 이벤트");
  expect(screen.getByText(/코드에서 확인한 조건부 문자열/)).toBeTruthy();
  const description = screen.getByRole("img", { name: "행위 관측 시계열" }).getAttribute("data-description");
  expect(description).toContain("차단 미수집");
  expect(description).not.toContain("NaN");
});

describe("Frozen evidence raw navigation", () => {
  it("omits masked URI filters and current scope while retaining only saved metric evidence IDs", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.scope.filters = [{ field: "uri", op: "is", value: "/api?token=[가림]" }];
    detailed.result.observations.metrics[0].evidence_ids = ["e1", "e2", "not-saved"];
    useInvStore.getState().set(INV, { filters: [{ field: "method", op: "is", value: "POST" }],
      time: { start: "2030-01-01T00:00:00Z" }, selection: { type: "ip", value: "192.0.2.99" } });
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "요청 수 표본 원문" }));
    expect(useInvStore.getState().get(INV)).toMatchObject({ tab: "raw", time: null, selection: null,
      filters: [{ field: "event_id", op: "in", value: ["e1", "e2"] }] });
  });
  it("keeps a peak selection within its saved partition evidence", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.selected_evidence.push({ event_id: "other-service", event: {
      timestamp: scope.time.start, src_ip: "192.0.2.99", hostname: "other.test", dst_port: 80 } });
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "요청 수 최대 구간" }));
    fireEvent.click(screen.getByRole("button", { name: "선택 구간 표본 원문" }));
    expect(useInvStore.getState().get(INV).filters).toEqual([{ field: "event_id", op: "in", value: ["e1", "e2"] }]);
  });
  it("selects a chart bucket using frozen timestamps and an exclusive microsecond end", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.observations.timeline.buckets = [{ start: "2026-10-16T00:00:00.000100Z",
      end_exclusive: "2026-10-16T00:00:00.000500Z", count: 2 }];
    detailed.result.selected_evidence = [
      { event_id: "before", event: { timestamp: "2026-10-16T00:00:00.000099Z" } },
      { event_id: "start", event: { timestamp: "2026-10-16T00:00:00.000100Z" } },
      { event_id: "inside", event: { timestamp: "2026-10-16T00:00:00.000499Z" } },
      { event_id: "end", event: { timestamp: "2026-10-16T00:00:00.000500Z" } },
    ];
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "첫 구간 선택" }));
    fireEvent.click(screen.getByRole("button", { name: "선택 구간 표본 원문" }));
    expect(useInvStore.getState().get(INV)).toMatchObject({ time: null,
      filters: [{ field: "event_id", op: "in", value: ["start", "inside"] }] });
  });
});

describe("Versioned conditional followup questions", () => {
  it("renders the saved question, allowed actions, resolution and prohibited conclusions", async () => {
    const detailed = structuredClone(dto) as any;
    detailed.result.observations.followups[0] = {
      ...detailed.result.observations.followups[0], condition: "허용 응답이 관측된 경우",
      question_version: "saw-web-behavior-questions/1.0", question: "승인된 서버 로그에 처리 결과가 남아 있는가?",
      allowed_actions: ["보존된 처리 로그를 읽기 전용으로 대조"],
      resolution_criteria: ["동일 요청 ID의 처리 결과와 담당자 확인이 일치"],
      if_unresolved: "추가 자료 요청 후 후속확인 상태 유지",
      forbidden_claims: ["성공 응답만으로 침해 성공을 단정하지 않음"]
    };
    mockApi(routes({ [`GET /investigations/${INV}/behavior/br-1`]: [200, detailed] }));
    renderUI(<BehaviorTab inv={INV} />);
    expect(await screen.findByText("saw-web-behavior-questions/1.0")).toBeTruthy();
    for (const text of ["승인된 서버 로그에 처리 결과가 남아 있는가?", "보존된 처리 로그를 읽기 전용으로 대조",
      "동일 요청 ID의 처리 결과와 담당자 확인이 일치", "추가 자료 요청 후 후속확인 상태 유지", "성공 응답만으로 침해 성공을 단정하지 않음"]) {
      expect(screen.getByText(text)).toBeTruthy();
    }
  });
  it("keeps older saved followups readable and explicitly marks missing metadata", async () => {
    mockApi(routes());
    renderUI(<BehaviorTab inv={INV} />);
    await screen.findByText("수집 WAF 이벤트");
    expect(screen.getByText(/질문 버전.*미기록/)).toBeTruthy();
    expect(screen.getAllByText("이 저장 결과에는 미기록").length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText("처리 결과 확인")).toBeTruthy();
  });
});
