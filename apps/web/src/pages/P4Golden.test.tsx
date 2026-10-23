import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Knowledge } from "./Knowledge";
import { GoldenCases, GoldenReview } from "./Golden";

const sha = (letter: string) => letter.repeat(64);
const yes = { enabled: true, reasons: [] };
const no = { enabled: false, reasons: ["independent_reviewer_required"] };
const perms = ["knowledge.read", "knowledge.write", "knowledge.approve", "golden.release.create", "golden.release.approve", "golden.evaluate.read"];
const capture = { schema: "saw.experience.golden-capture.v1", check_revisions: [{ check_id: "c1", revision_id: "cr1", revision: 1, payload_sha256: sha("c") }], analysis_runs: [{ id: "run1", sha256: sha("a"), scope_sha256: sha("b") }], followup_versions: [], source_investigation_ids: ["i1"], contributor_ids: ["author"] };
const exp = { id: "e1", rev: 2, status: "approved", analyst_id: "author", source_investigation_id: "i1", data: { golden_capture: capture } };
const answers = { schema: "saw.golden.answers.v2", detection_truth: { status: "available", case_versions: [{ id: "truth1", sha256: sha("d") }], units: [{ case_version_id: "truth1", unit_id: "w1", unit_kind: "window", event_ids: [], filters: [], time: null, detection_truth: "expected_match", investigation_truth: "approved_activity", basis: "승인된 합성 작업도 탐지 조건에 해당" }], matching_policy: {}, duplicate_policy: "exact", limits: [] }, investigation_truth: { behavior: "분산 관측", impact: "미확인", reason: "FW만 수집", evidence_refs: [], required_facts_actions: [], followups: [], no_followups_reason: "", forbidden_claims: ["침해 성공"], limits: [] }, later_confirmed_facts: [], analyst_records: [] };
const golden = { analysis_run_ref:{id:"run1",sha256:sha("a"),scope_sha256:sha("b")}, id: "g1", version: 1, experience_id: "e1", experience_rev: 2, title: "합성 사례", status: "adopted", split: "dev", content_sha256: sha("a"), schema_version: "saw.golden.v2", can_edit: true, can_review: true, answers_access: { available: true, requires_holdout_attempt: false }, answers, input: { cutoff: { as_of: "2026-10-20T00:00:00Z" } }, applicability: { mode: "interpretation_only", reasons: [] }, validation: { state: "not_requested", reasons: [] }, export_eligibility: { external_release: yes, internal_evaluator: yes }, manifest: [] };
const profiles = [{ id: "pp1", kind: "pseudonymization", profile_key: "scoped", version: 1, payload_sha256: sha("b"), implementation: "scoped-identities/1", payload: {}, capabilities: [], limits: [] }, { id: "mp1", kind: "model_conversion", profile_key: "native", version: 1, payload_sha256: sha("c"), implementation: "golden-native/1", payload: {}, capabilities: [], limits: [] }];
const release = { id: "rel1", current_version_id: "rv1", pending_job: null, state: "awaiting_review", approval: null, eligibility: { preview: yes, approve: yes, download: no, revoke: no, new_version: yes }, versions: [{ id: "rv1", revision: 1, payload_sha256: sha("d"), state: "awaiting_review" }], version: { id: "rv1", revision: 1, payload_sha256: sha("d"), request_sha256: sha("e"), schema_version: "saw.golden.release.v2", purpose: "external_development", purpose_text: "합성 개발", recipient: { name: "담당자", organization: "합성 연구실" }, usage_conditions: ["합성 자료만 사용"], expires_at: "2027-01-01T00:00:00Z", examples: [{ version_id: "g1", content_sha256: sha("a") }], split: "dev", artifact_kind: "dev", projection: "v2", profiles: { pseudonymization: { id: "pp1", sha256: sha("b") }, model_conversion: { id: "mp1", sha256: sha("c") } }, applicability: { mode: "interpretation_only", reasons: [], validations: [] }, artifact: { sha256: sha("f"), size_bytes: 123, media_type: "application/zip" }, manifest: { files: [], file_count: 0, uncompressed_bytes: 0 } } };
const preview = { release_id: "rel1", version_id: "rv1", payload_sha256: sha("d"), artifact_sha256: sha("f"), manifest: release.version.manifest, validation: { passed: true, checks: [] }, samples: [{ path: "README.md", content_text: "<script>secret()</script>", bytes_total: 30, preview_bytes: 20, truncated: true }], omitted: { files: 2, bytes: 10 }, limits: [] };
function setup(extra: Record<string, any> = {}, route = "/knowledge/releases/rel1") {
  const api = mockApi({ "GET /auth/me": [200, { ...ME, permissions: perms }], "GET /knowledge/golden": [200, [golden]], "GET /knowledge/golden/profiles": [200, { items: profiles, next_cursor: null }], "GET /knowledge/golden/releases": [200, { items: [release], next_cursor: null }], "GET /knowledge/golden/releases/rel1": [200, release], "GET /knowledge/golden/releases/rel1/versions/rv1": [200, release], "GET /knowledge/golden/releases/rel1/versions/rv1/preview": [200, preview], ...extra });
  const ui=renderUI(<Routes><Route path="/knowledge/*" element={<Knowledge />} /></Routes>, { route });
  return {...api,ui};
}
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("P4 Golden exact contracts", () => {
  it("prepares explicit v2 using only saved Experience pins and selected truth versions", async () => {
    const api = mockApi({ "GET /auth/me": [200, { ...ME, permissions: perms }], "GET /knowledge/golden/experience/e1": [200, { experience_id: "e1", versions: [] }], "GET /detection-cases": [200, { items: [{ id: "truth1", title: "합성 정답", version: 1 }], next_cursor: null }], "POST /knowledge/golden/experience/e1/prepare": [201, golden] });
    renderUI(<GoldenReview experience={exp} onChoice={() => {}} />);
    fireEvent.change(await screen.findByLabelText("고정 분석 실행"), { target: { value: "run1" } });
    fireEvent.click(await screen.findByLabelText("정답 버전 합성 정답 v1"));
    fireEvent.click(screen.getByRole("button", { name: "조사 기록에서 채택 초안 만들기" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/golden/experience/e1/prepare")).toHaveLength(1));
    expect(api.find("POST", "/knowledge/golden/experience/e1/prepare")[0].body).toEqual({ expected_experience_rev: 2, schema_version: "saw.golden.v2", check_ids: ["c1"], analysis_run_id: "run1", truth_case_version_ids: ["truth1"] });
  });
  it("separates the two v2 truth axes and never submits answer edits as review_answers", async () => {
    const changed = vi.fn();
    const api = mockApi({ "GET /auth/me": [200, { ...ME, permissions: perms }], "GET /knowledge/golden/experience/e1": [200, { versions: [{ ...golden, status: "draft" }] }], "GET /detection-cases": [200, { items: [] }], "PATCH /knowledge/golden/g1": [200, { ...golden, id: "g2" }] });
    renderUI(<GoldenReview experience={exp} onChoice={changed} />);
    expect(await screen.findByText("탐지 기대: 일치")).toBeTruthy();
    expect(screen.getByText("조사 판단: 승인된 활동")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("후속확인이 불필요한 이유"), { target: { value: "범위 밖 사항을 한계로 기록함" } });
    fireEvent.click(screen.getByRole("button", { name: "새 초안으로 저장" }));
    await waitFor(() => expect(api.find("PATCH", "/knowledge/golden/g1")).toHaveLength(1));
    const body = api.find("PATCH", "/knowledge/golden/g1")[0].body;
    expect(body.answers.investigation_truth.no_followups_reason).toBe("범위 밖 사항을 한계로 기록함");
    expect(body.answers.detection_truth.units[0].unit_kind).toBe("window");
    expect(changed.mock.calls.every(call => !call[0].payload?.review_answers)).toBe(true);
  });
  it("removes holdout answer labels, search fields and previous split selection", async () => {
    const api = mockApi({ "GET /auth/me": [200, { ...ME, permissions: perms }], "GET /knowledge/golden": call => [200, call.url.includes("split=holdout") ? [{ ...golden, split: "holdout", title: "SECRET TITLE", category: "SECRET CATEGORY", verdict: "SECRET VERDICT", content_sha256: sha("9"), input_sha256: sha("8"), answers_access: { available: false, requires_holdout_attempt: true } }] : [golden]] });
    const ui = renderUI(<GoldenCases />);
    fireEvent.change(await screen.findByLabelText("사례명 검색"), { target: { value: "attack" } });
    fireEvent.change(screen.getByLabelText("정답 사례 용도"), { target: { value: "holdout" } });
    await screen.findByLabelText("비공개 사례 g1 v1 선택");
    expect(ui.container.innerHTML).not.toMatch(/SECRET|9999999999|합성 사례/);
    expect(screen.queryByLabelText("사례명 검색")).toBeNull();
    expect(api.find("GET", "/knowledge/golden").at(-1)?.url).not.toContain("q=");
  });
});

describe("P4 governed release", () => {
  it("requires explicit preview and exact artifact receipt before approval; stale preserves reason and clears acknowledgements", async () => {
    const api = setup({ "POST /knowledge/golden/releases/rel1/versions/rv1/approve": [409, { detail: "release_changed" }] });
    await screen.findByText("반출 버전 1");
    expect(api.find("GET", "/knowledge/golden/releases/rel1/versions/rv1/preview")).toHaveLength(0);
    expect((screen.getByRole("button", { name: "반출 승인" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "실제 파일 미리보기" }));
    expect(await screen.findByText("<script>secret()</script>")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("검토 사유"), { target: { value: "정확한 파일과 한계 검토" } });
    for (const label of ["파일 미리보기 확인", "재제공 권리 확인", "수신처와 목적 확인", "한계 수용 확인"]) fireEvent.click(screen.getByLabelText(label));
    fireEvent.click(screen.getByRole("button", { name: "반출 승인" }));
    await screen.findByText(/release_changed/);
    expect(api.find("POST", "/knowledge/golden/releases/rel1/versions/rv1/approve")[0].body).toEqual({ expected_current_version_id: "rv1", expected_payload_sha256: sha("d"), expected_artifact_sha256: sha("f"), expected_decision_id: null, decision: "approve", reason: "정확한 파일과 한계 검토", confirmations: { preview_reviewed: true, redistribution_rights: true, recipient_and_purpose: true, limits_accepted: true } });
    expect((screen.getByLabelText("검토 사유") as HTMLInputElement).value).toBe("정확한 파일과 한계 검토");
    expect((screen.getByLabelText("파일 미리보기 확인") as HTMLInputElement).checked).toBe(false);
  });
  it("honours server action denial even for an approver permission and does not fetch preview", async () => {
    const api = setup({ "GET /knowledge/golden/releases/rel1": [200, { ...release, eligibility: { ...release.eligibility, preview: no, approve: no } }] });
    await screen.findByText("반출 버전 1");
    expect((screen.getByRole("button", { name: "실제 파일 미리보기" }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "반출 승인" }) as HTMLButtonElement).disabled).toBe(true);
    expect(api.find("GET", "/knowledge/golden/releases/rel1/versions/rv1/preview")).toHaveLength(0);
  });
  it("pins exact selected profiles, case digest and purpose in a release request", async () => {
    const api = setup({ "POST /knowledge/golden/releases": [202, { release_id: "rel1", job_id: "job1" }], "GET /jobs/job1": [200, { id: "job1", kind: "golden_export", state: "QUEUED", stages: { golden_export: { release_id: "rel1", actions: {} } } }] }, "/knowledge/releases/new");
    fireEvent.click(await screen.findByLabelText("반출 선택 합성 사례 v1"));
    fireEvent.change(screen.getByLabelText("가명처리 프로필"), { target: { value: "pp1" } });
    fireEvent.change(screen.getByLabelText("변환 프로필"), { target: { value: "mp1" } });
    for (const [label, value] of [["반출 목적 설명", "합성 개발 검증"], ["수신자", "담당자"], ["수신 기관", "연구실"], ["사용 조건", "합성 검증에 한함"], ["재제공 권리 근거", "직접 만든 합성 자료"]]) fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.change(screen.getByLabelText("만료 시각"), { target: { value: "2027-01-01T00:00" } });
    fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));
    fireEvent.click(screen.getByRole("button", { name: "반출 파일 생성 요청" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/golden/releases")).toHaveLength(1));
    expect(api.find("POST", "/knowledge/golden/releases")[0].body).toMatchObject({ schema_version: "saw.golden.release.v2", expected_current_version_id: null, purpose: "external_development", examples: [{ version_id: "g1", content_sha256: sha("a") }], split: "dev", artifact_kind: "dev", projection: "v2", pseudonymization_profile: { id: "pp1", sha256: sha("b") }, model_conversion_profile: { id: "mp1", sha256: sha("c") }, applicability_request: { mode: "interpretation_only", complete_scopes: [] } });
  });
  it("does not fetch holdout answers on route visit and records operator reported results before explicit answer read", async () => {
    let attempt: any = { id: "ha1", release_version_id: "rv1", target: { kind: "model", name: "합성 대상", version: "1", artifact_sha256: sha("a") }, purpose_text: "합성 평가", status: "input_accessed", input_access: { count: 1 }, result: { status: "not_submitted", artifact_sha256: null, summary: null }, answers_access: { count: 0 }, eligibility: { download_input: yes, record_result: yes, read_answers: no }, limits: ["operator_declared"] };
    const api = setup({ "GET /knowledge/golden/holdout-attempts/ha1": () => [200, attempt], "POST /knowledge/golden/holdout-attempts/ha1/result": (call:any) => { attempt = { ...attempt, status: "result_recorded", result: { status: "operator_reported", ...call.body }, eligibility: { ...attempt.eligibility, read_answers: yes } }; return [200, attempt]; }, "GET /knowledge/golden/holdout-attempts/ha1/answers": [200, '{"truth":"bounded answer"}'] }, "/knowledge/holdout-attempts/ha1");
    await screen.findByText("합성 대상");
    expect(api.find("GET", "/knowledge/golden/holdout-attempts/ha1/answers")).toHaveLength(0);
    expect((screen.getByRole("button", { name: "내부 평가자 정답 열람" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("결과 파일 SHA256"), { target: { value: sha("e") } });
    fireEvent.change(screen.getByLabelText("직접 실행한 결과 요약"), { target: { value: "운영자가 별도 도구에서 확인함" } });
    fireEvent.click(screen.getByRole("button", { name: "사용자 보고 결과 등록" }));
    await screen.findByText("사용자가 보고한 결과");
    expect(api.find("POST", "/knowledge/golden/holdout-attempts/ha1/result")[0].body).toEqual({ expected_result_sha256: null, artifact_sha256: sha("e"), summary: "운영자가 별도 도구에서 확인함" });
    fireEvent.click(screen.getByRole("button", { name: "내부 평가자 정답 열람" }));
    await waitFor(() => expect(api.find("GET", "/knowledge/golden/holdout-attempts/ha1/answers")).toHaveLength(1));
  });
});

describe("P4 action boundaries", () => {
  it("clears redistribution acknowledgement after changing release purpose", async () => {
    setup({}, "/knowledge/releases/new");
    await screen.findByLabelText("반출 목적 설명");
    fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));
    fireEvent.change(screen.getByLabelText("반출 목적 설명"), { target: { value: "수정한 목적" } });
    expect((screen.getByLabelText("재제공 권리를 확인했습니다") as HTMLInputElement).checked).toBe(false);
  });
  it("keeps evaluator permission distinct from ordinary knowledge approval", async () => {
    mockApi({ "GET /auth/me": [200, { ...ME, permissions: ["knowledge.read", "knowledge.approve"] }], "GET /knowledge/golden": [200, [golden]] });
    renderUI(<GoldenCases />);
    await screen.findByText("합성 사례");
    expect(screen.queryByRole("button", { name: "평가자 정답 JSONL" })).toBeNull();
  });
  it("limits exact selection to one hundred examples", async () => {
    mockApi({ "GET /auth/me": [200, { ...ME, permissions: perms }], "GET /knowledge/golden": [200, Array.from({ length: 101 }, (_,i) => ({ ...golden, id: "g"+i, title: "사례"+i }))] });
    renderUI(<GoldenCases />);
    const checks = await screen.findAllByRole("checkbox");
    checks.slice(0,100).forEach(c => fireEvent.click(c));
    expect((checks[100] as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText("선택 100/100")).toBeTruthy();
  });
  it("does not create a browser download when exact approved bytes are denied", async () => {
    const create = vi.fn(); vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() }));
    setup({ "GET /knowledge/golden/releases/rel1": [200, { ...release, state: "approved", eligibility: { ...release.eligibility, download: yes } }], "GET /knowledge/golden/releases/rel1/versions/rv1/download": [403, { detail: "source_access_revoked" }] });
    fireEvent.click(await screen.findByRole("button", { name: "승인된 정확한 파일 내려받기" }));
    await screen.findByText(/source_access_revoked/);
    expect(create).not.toHaveBeenCalled();
  });
  it("rejects a preview receipt for different sealed bytes", async () => {
    setup({ "GET /knowledge/golden/releases/rel1/versions/rv1/preview": [200, { ...preview, artifact_sha256: sha("0") }] });
    fireEvent.click(await screen.findByRole("button", { name: "실제 파일 미리보기" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "실제 파일 미리보기" }) as HTMLButtonElement).disabled).toBe(false));
    expect((screen.getByLabelText("파일 미리보기 확인") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "반출 승인" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("uses the exact previous decision to revoke and then blocks downloads", async () => {
    let row:any = { ...release, state: "approved", approval: { id: "dec1", decision: "approve", reason: "기존 승인" }, eligibility: { ...release.eligibility, download: yes, revoke: yes } };
    const api=setup({ "GET /knowledge/golden/releases/rel1": () => [200,row], "POST /knowledge/golden/releases/rel1/versions/rv1/revoke": () => { row={...row,state:"revoked",approval:{id:"dec2",decision:"revoke"},eligibility:{...row.eligibility,download:no,revoke:no}};return [200,row]; } });
    fireEvent.change(await screen.findByLabelText("검토 사유"),{target:{value:"권리 변경으로 철회"}});
    fireEvent.click(screen.getByRole("button",{name:"반출 승인 철회"}));
    await screen.findByText("반출 철회됨");
    expect(api.find("POST","/knowledge/golden/releases/rel1/versions/rv1/revoke")[0].body).toEqual({expected_decision_id:"dec1",reason:"권리 변경으로 철회"});
    expect((screen.getByRole("button",{name:"승인된 정확한 파일 내려받기"}) as HTMLButtonElement).disabled).toBe(true);
  });
  it("appends a strict profile version with the selected latest CAS",async()=>{
    const api=setup({"POST /knowledge/golden/profiles":[201,{...profiles[0],id:"pp2",version:2}]}, "/knowledge/profiles");
    fireEvent.click((await screen.findAllByRole("button",{name:"이 버전 기준 새 버전 작성"}))[0]);
    fireEvent.click(screen.getByRole("button",{name:"프로필 버전 저장"}));
    await screen.findByText(/프로필 v2 저장됨/);
    expect(api.find("POST","/knowledge/golden/profiles")[0].body).toEqual({kind:"pseudonymization",profile_key:"scoped",expected_latest_id:"pp1",implementation:"scoped-identities/1",payload:{schema:"saw.pseudonymization-profile.v1",version:1,identity_scope:"org_network",identity_mapping:"scoped_injective/1",time_transform:"none",free_text:"drop_unapproved",metadata:"allowlist_v2"}});
  });
  it("pins a holdout case with input digest only",async()=>{
    const hidden={...golden,split:"holdout",title:"DO NOT DISPLAY",content_sha256:sha("9"),input_sha256:sha("8")};
    const api=setup({"GET /knowledge/golden":[200,[hidden]],"POST /knowledge/golden/releases":[409,{detail:"synthetic_stop_after_request"}]},"/knowledge/releases/new");
    fireEvent.change(await screen.findByLabelText("반출 용도"),{target:{value:"holdout"}});
    fireEvent.click(await screen.findByLabelText("반출 선택 비공개 사례 g1 v1"));
    fireEvent.change(screen.getByLabelText("가명처리 프로필"),{target:{value:"pp1"}});
    fireEvent.change(screen.getByLabelText("변환 프로필"),{target:{value:"mp1"}});
    for(const [label,value] of [["반출 목적 설명","합성 평가"],["수신자","담당자"],["수신 기관","연구실"],["사용 조건","일회 평가"],["재제공 권리 근거","직접 생성"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});
    fireEvent.change(screen.getByLabelText("만료 시각"),{target:{value:"2027-01-01T00:00"}});
    fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));
    fireEvent.click(screen.getByRole("button",{name:"반출 파일 생성 요청"}));
    await screen.findByText(/synthetic_stop_after_request/);
    const body=api.find("POST","/knowledge/golden/releases")[0].body;
    expect(body).toMatchObject({purpose:"external_evaluation",artifact_kind:"holdout_input",examples:[{version_id:"g1",input_sha256:sha("8")}]});
    expect(JSON.stringify(body)).not.toContain("content_sha256");
    expect(screen.queryByText(/DO NOT DISPLAY/)).toBeNull();
  });
});

it("keeps the approved Experience scope hash when a newer working revision exists",async()=>{
 const approved={...exp,rev:3,approved_rev:2,approved:exp.data,data:{golden_capture:{...capture,analysis_runs:[{id:"new-run",sha256:sha("7"),scope_sha256:sha("6")}]}}};
 const api=setup({"GET /experiences/e1":[200,approved],"POST /knowledge/golden/releases":[409,{detail:"scope_request_captured"}]},"/knowledge/golden");
 fireEvent.click(await screen.findByLabelText("버전 1 합성 사례 선택"));
 fireEvent.click(screen.getByRole("link",{name:"선택 버전으로 반출 패키지 작성"}));
 fireEvent.change(await screen.findByLabelText("자료 용도"),{target:{value:"full_recalculation"}});
 const select=await screen.findByLabelText("합성 사례 v1 고정 실행");
 await waitFor(()=>expect((select as HTMLSelectElement).options.length).toBe(2));
 fireEvent.change(select,{target:{value:"run1"}});
 fireEvent.change(screen.getByLabelText("가명처리 프로필"),{target:{value:"pp1"}});
 fireEvent.change(screen.getByLabelText("변환 프로필"),{target:{value:"mp1"}});
 for(const [label,value] of [["반출 목적 설명","전체 재계산"],["수신자","담당자"],["수신 기관","연구실"],["사용 조건","합성용"],["재제공 권리 근거","직접 생성"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});
 fireEvent.change(screen.getByLabelText("만료 시각"),{target:{value:"2027-01-01T00:00"}});
 fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));
 fireEvent.click(screen.getByRole("button",{name:"반출 파일 생성 요청"}));
 await screen.findByText(/scope_request_captured/);
 expect(api.find("POST","/knowledge/golden/releases")[0].body.applicability_request).toEqual({mode:"full_recalculation",complete_scopes:[{golden_version_id:"g1",analysis_run_id:"run1",scope_sha256:sha("b")}]});
});

it("preserves release inputs but clears rights after conflict and reuses the same idempotency key only for unchanged requests",async()=>{
 const api=setup({"POST /knowledge/golden/releases":[409,{detail:"release_changed"}]},"/knowledge/releases/new");
 fireEvent.click(await screen.findByLabelText("반출 선택 합성 사례 v1"));
 fireEvent.change(screen.getByLabelText("가명처리 프로필"),{target:{value:"pp1"}});
 fireEvent.change(screen.getByLabelText("변환 프로필"),{target:{value:"mp1"}});
 for(const [label,value] of [["반출 목적 설명","최초 목적"],["수신자","담당자"],["수신 기관","연구실"],["사용 조건","합성용"],["재제공 권리 근거","직접 생성"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});
 fireEvent.change(screen.getByLabelText("만료 시각"),{target:{value:"2027-01-01T00:00"}});
 fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));
 fireEvent.click(screen.getByRole("button",{name:"반출 파일 생성 요청"}));
 await screen.findByText(/release_changed/);
 expect((screen.getByLabelText("반출 목적 설명") as HTMLTextAreaElement).value).toBe("최초 목적");
 expect((screen.getByLabelText("재제공 권리를 확인했습니다") as HTMLInputElement).checked).toBe(false);
 fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));fireEvent.click(screen.getByRole("button",{name:"반출 파일 생성 요청"}));
 await waitFor(()=>expect(api.find("POST","/knowledge/golden/releases")).toHaveLength(2));
 expect(api.find("POST","/knowledge/golden/releases")[1].body.idempotency_key).toBe(api.find("POST","/knowledge/golden/releases")[0].body.idempotency_key);
 await waitFor(()=>expect((screen.getByLabelText("재제공 권리를 확인했습니다") as HTMLInputElement).checked).toBe(false));
 fireEvent.change(screen.getByLabelText("반출 목적 설명"),{target:{value:"변경 목적"}});
 fireEvent.click(screen.getByLabelText("재제공 권리를 확인했습니다"));fireEvent.click(screen.getByRole("button",{name:"반출 파일 생성 요청"}));
 await waitFor(()=>expect(api.find("POST","/knowledge/golden/releases")).toHaveLength(3));
 expect(api.find("POST","/knowledge/golden/releases")[2].body.idempotency_key).not.toBe(api.find("POST","/knowledge/golden/releases")[0].body.idempotency_key);
});
it("allows an exact older profile from the next cursor page without replacing an earlier selection",async()=>{
 const api=setup({"GET /knowledge/golden/profiles":(call:any)=>[200,call.url.includes("cursor=older")?{items:[{...profiles[0],id:"pp-old",version:0,payload_sha256:sha("7")}],next_cursor:null}:{items:profiles,next_cursor:"older"}]},"/knowledge/releases/new");
 await screen.findByRole("option",{name:/pp1/});
 fireEvent.change(screen.getByLabelText("가명처리 프로필"),{target:{value:"pp1"}});
 fireEvent.click(await screen.findByRole("button",{name:"가명처리 프로필 더 보기"}));
 await screen.findByRole("option",{name:/pp-old/});
 expect((screen.getByLabelText("가명처리 프로필") as HTMLSelectElement).value).toBe("pp1");
 expect(api.find("GET","/knowledge/golden/profiles").some(c=>c.url.includes("cursor=older"))).toBe(true);
});
it("does not retain preview or review input after navigating to a different release",async()=>{
 const second={...release,id:"rel2",current_version_id:"rv2",version:{...release.version,id:"rv2",revision:2},versions:[]};
 const api=setup({"GET /knowledge/golden/releases":[200,{items:[second],next_cursor:null}],"GET /knowledge/golden/releases/rel2":[200,second]});
 fireEvent.click(await screen.findByRole("button",{name:"실제 파일 미리보기"}));await screen.findByText("<script>secret()</script>");
 fireEvent.change(screen.getByLabelText("검토 사유"),{target:{value:"첫 파일 전용 의견"}});
 fireEvent.click(screen.getByLabelText("파일 미리보기 확인"));
 fireEvent.click(screen.getByRole("link",{name:"반출 목록"}));
 fireEvent.click(await screen.findByRole("link",{name:"반출 rel2"}));
 await screen.findByText("반출 버전 2");
 expect((screen.getByLabelText("검토 사유") as HTMLInputElement).value).toBe("");
 expect((screen.getByLabelText("파일 미리보기 확인") as HTMLInputElement).checked).toBe(false);
 expect(screen.queryByText("<script>secret()</script>")).toBeNull();
 expect(api.find("GET","/knowledge/golden/releases/rel2/versions/rv2/preview")).toHaveLength(0);
});

it("clears selected exact versions when the signed-in principal changes",async()=>{
 mockApi({"GET /auth/me":[200,{...ME,permissions:perms}],"GET /knowledge/golden":[200,[golden]]});
 const ui=renderUI(<GoldenCases/>);fireEvent.click(await screen.findByLabelText("버전 1 합성 사례 선택"));
 expect(screen.getByText("선택 1/100")).toBeTruthy();
 await act(async()=>{ui.qc.setQueryData(["me"],{...ME,id:"another-user",permissions:perms});});
 await waitFor(()=>expect(screen.getByText("선택 0/100")).toBeTruthy());
 expect(screen.queryByRole("link",{name:"선택 버전으로 반출 패키지 작성"})).toBeNull();
});

describe("P4 review repairs",()=>{
 it("refreshes server eligibility after first preview while preserving the exact receipt",async()=>{
  let viewed=false;
  const initial={...release,eligibility:{...release.eligibility,approve:no}};
  const api=setup({"GET /knowledge/golden/releases/rel1":[200,initial],"GET /knowledge/golden/releases/rel1/versions/rv1":()=>[200,{...release,eligibility:{...release.eligibility,approve:viewed?yes:no}}],"GET /knowledge/golden/releases/rel1/versions/rv1/preview":()=>{viewed=true;return [200,preview];},"POST /knowledge/golden/releases/rel1/versions/rv1/approve":[200,release]});
  expect((await screen.findByLabelText("파일 미리보기 확인") as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button",{name:"실제 파일 미리보기"}));
  await waitFor(()=>expect((screen.getByLabelText("파일 미리보기 확인") as HTMLInputElement).disabled).toBe(false));
  expect(api.find("GET","/knowledge/golden/releases/rel1/versions/rv1")).toHaveLength(1);
  expect(screen.getByText("<script>secret()</script>")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("검토 사유"),{target:{value:"첫 파일 검토 완료"}});
  for(const label of ["파일 미리보기 확인","재제공 권리 확인","수신처와 목적 확인","한계 수용 확인"])fireEvent.click(screen.getByLabelText(label));
  fireEvent.click(screen.getByRole("button",{name:"반출 승인"}));
  await waitFor(()=>expect(api.find("POST","/knowledge/golden/releases/rel1/versions/rv1/approve")).toHaveLength(1));
 });
 it("allows server-authorized decline without preview or approval acknowledgements",async()=>{
  const api=setup({"GET /knowledge/golden/releases/rel1":[200,{...release,eligibility:{...release.eligibility,approve:no,preview:no,decline:yes}}],"POST /knowledge/golden/releases/rel1/versions/rv1/approve":[200,release]});
  fireEvent.change(await screen.findByLabelText("검토 사유"),{target:{value:"수신처 제한 미충족"}});
  expect((screen.getByRole("button",{name:"반출 반려"}) as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(screen.getByRole("button",{name:"반출 반려"}));
  await waitFor(()=>expect(api.find("POST","/knowledge/golden/releases/rel1/versions/rv1/approve")).toHaveLength(1));
  expect(api.find("POST","/knowledge/golden/releases/rel1/versions/rv1/approve")[0].body).toMatchObject({decision:"decline",reason:"수신처 제한 미충족",expected_current_version_id:"rv1",expected_payload_sha256:sha("d"),expected_artifact_sha256:sha("f"),expected_decision_id:null,confirmations:{}});
  expect(api.find("GET","/knowledge/golden/releases/rel1/versions/rv1/preview")).toHaveLength(0);
 });
 it("honours explicit decline denial even when approval is allowed",async()=>{
  setup({"GET /knowledge/golden/releases/rel1":[200,{...release,eligibility:{...release.eligibility,decline:no}}]});
  fireEvent.click(await screen.findByRole("button",{name:"실제 파일 미리보기"}));
  await screen.findByText("<script>secret()</script>");
  fireEvent.change(screen.getByLabelText("검토 사유"),{target:{value:"사유"}});
  expect((screen.getByRole("button",{name:"반출 반려"}) as HTMLButtonElement).disabled).toBe(true);
 });
 it("uses P2 before pagination and retains exact truth versions across pages",async()=>{
  const api=mockApi({"GET /auth/me":[200,{...ME,permissions:perms}],"GET /knowledge/golden/experience/e1":[200,{versions:[]}],"GET /detection-cases":c=>[200,c.url.includes("before=older%2Fpage")?{items:[{id:"truth101",title:"이전 정답",version:3}],next_cursor:null}:{items:[{id:"truth1",title:"새 정답",version:1}],next_cursor:"older/page"}],"POST /knowledge/golden/experience/e1/prepare":[201,golden]});
  renderUI(<GoldenReview experience={exp} onChoice={()=>{}}/>);
  fireEvent.click(await screen.findByLabelText("정답 버전 새 정답 v1"));
  fireEvent.click(screen.getByRole("button",{name:"다음 정답 사례"}));
  fireEvent.click(await screen.findByLabelText("정답 버전 이전 정답 v3"));
  fireEvent.click(screen.getByRole("button",{name:"조사 기록에서 채택 초안 만들기"}));
  await waitFor(()=>expect(api.find("POST","/knowledge/golden/experience/e1/prepare")).toHaveLength(1));
  expect(api.find("POST","/knowledge/golden/experience/e1/prepare")[0].body.truth_case_version_ids).toEqual(["truth1","truth101"]);
  expect(api.find("GET","/detection-cases")[1].url).toContain("before=older%2Fpage");
  expect(api.find("GET","/detection-cases")[1].url).not.toContain("&cursor=");
 });
 it("does not restore another principal's Golden navigation selection",async()=>{
  let allowed=true;
  const api=setup({"GET /knowledge/golden":()=>[200,allowed?[golden]:[]]},"/knowledge/golden");
  fireEvent.click(await screen.findByLabelText("버전 1 합성 사례 선택"));
  fireEvent.click(screen.getByRole("link",{name:"선택 버전으로 반출 패키지 작성"}));
  await screen.findByText("고정 선택 버전");
  allowed=false;
  await act(async()=>{api.ui.qc.setQueryData(["me"],{...ME,id:"another-user",permissions:perms});});
  await waitFor(()=>expect(screen.getByText("선택 0/100")).toBeTruthy());
  expect(api.ui.container.textContent).not.toContain("합성 사례");
  expect(api.ui.container.textContent).not.toContain(sha("a"));
 });
 it("discards a same-principal Golden selection after source access is denied",async()=>{
  let denied=false;
  const api=setup({"GET /knowledge/golden":()=>denied?[403,{detail:"source_denied"}]:[200,[golden]]},"/knowledge/golden");
  fireEvent.click(await screen.findByLabelText("버전 1 합성 사례 선택"));
  fireEvent.click(screen.getByRole("link",{name:"선택 버전으로 반출 패키지 작성"}));
  await screen.findByText("고정 선택 버전");
  denied=true;
  await act(async()=>{await api.ui.qc.invalidateQueries({queryKey:["goldens","release"]});});
  await screen.findByText(/source_denied/);
  expect(screen.getByText("선택 0/100")).toBeTruthy();
  expect(api.ui.container.textContent).not.toContain("합성 사례");
  expect(api.ui.container.textContent).not.toContain(sha("a"));
 });
 it("does not restore another principal's holdout release seed",async()=>{
  let allowed=true;const holdout={...release,state:"approved",version:{...release.version,split:"holdout"}};
  const api=setup({"GET /knowledge/golden/releases/rel1":[200,holdout],"GET /knowledge/golden/releases/rel1/versions/rv1":()=>allowed?[200,holdout]:[403,{detail:"release_denied"}],"GET /knowledge/golden/releases":()=>[200,{items:allowed?[holdout]:[],next_cursor:null}]});
  fireEvent.click(await screen.findByRole("link",{name:"이 정확한 입력 파일로 평가 시도 등록"}));
  await screen.findByText("고정 파일 SHA256 "+sha("f"));
  allowed=false;
  await act(async()=>{api.ui.qc.setQueryData(["me"],{...ME,id:"another-user",permissions:perms});});
  await waitFor(()=>expect(screen.queryByText("고정 파일 SHA256 "+sha("f"))).toBeNull());
  expect((screen.getByLabelText("승인된 비공개 평가 입력") as HTMLSelectElement).value).toBe("");
  expect(api.ui.container.textContent).not.toContain("rv1");
 });
 it("clears a holdout selection when its exact version becomes inaccessible",async()=>{
  let denied=false;const holdout={...release,state:"approved",version:{...release.version,split:"holdout"}};
  const api=setup({"GET /knowledge/golden/releases/rel1":[200,holdout],"GET /knowledge/golden/releases/rel1/versions/rv1":()=>denied?[404,{detail:"release_hidden"}]:[200,holdout],"GET /knowledge/golden/releases":[200,{items:[holdout],next_cursor:null}]});
  fireEvent.click(await screen.findByRole("link",{name:"이 정확한 입력 파일로 평가 시도 등록"}));
  await screen.findByText("고정 파일 SHA256 "+sha("f"));denied=true;
  await act(async()=>{await api.ui.qc.invalidateQueries({queryKey:["golden-release"]});});
  await screen.findByText(/release_hidden/);
  expect(screen.queryByText("고정 파일 SHA256 "+sha("f"))).toBeNull();
  expect((screen.getByRole("button",{name:"평가 시도 등록 요청"}) as HTMLButtonElement).disabled).toBe(true);
 });
});

it("offers only the exact Golden run pin even when Experience captured additional runs",async()=>{
 const expanded={...exp,data:{golden_capture:{...capture,analysis_runs:[...capture.analysis_runs,{id:"run2",sha256:sha("2"),scope_sha256:sha("3")}]}}};
 const api=setup({"GET /experiences/e1":[200,expanded]},"/knowledge/releases/new");
 fireEvent.click(await screen.findByLabelText("반출 선택 합성 사례 v1"));
 fireEvent.change(screen.getByLabelText("자료 용도"),{target:{value:"full_recalculation"}});
 const select=await screen.findByLabelText("합성 사례 v1 고정 실행");
 await waitFor(()=>expect(Array.from((select as HTMLSelectElement).options).map(o=>o.value)).toEqual(["","run1"]));
 expect(api.find("GET","/experiences/e1")).toHaveLength(0);
});
it("explains missing exact run pins and links to a new v2 capture instead of offering Experience runs",async()=>{
 const api=setup({"GET /knowledge/golden":[200,[{...golden,analysis_run_ref:null}]],"GET /experiences/e1":[200,exp]},"/knowledge/releases/new");
 fireEvent.click(await screen.findByLabelText("반출 선택 합성 사례 v1"));
 fireEvent.change(screen.getByLabelText("자료 용도"),{target:{value:"full_recalculation"}});
 expect(await screen.findByText("이 정답 버전에는 범위 해시가 고정된 분석 실행이 없어 전체 재계산을 요청할 수 없습니다.")).toBeTruthy();
 expect(screen.getByRole("link",{name:"새 v2 캡처 만들기"}).getAttribute("href")).toBe("/knowledge/exp/e1");
 expect(api.find("GET","/experiences/e1")).toHaveLength(0);
});


describe("P4 browser label semantics",()=>{
 it("shows a saved valid profile's separate approval constraint without a blocked status",async()=>{
  let rows=[{...profiles[0],limits:["profile_is_not_export_authorization"]}];
  setup({"GET /knowledge/golden/profiles":()=>[200,{items:rows,next_cursor:null}],"POST /knowledge/golden/profiles":()=>{rows=[{...rows[0],id:"pp2",version:2}];return [201,rows[0]];}}, "/knowledge/profiles");
  fireEvent.click(await screen.findByRole("button",{name:"이 버전 기준 새 버전 작성"}));
  fireEvent.click(screen.getByRole("button",{name:"프로필 버전 저장"}));
  await screen.findByText(/프로필 v2 저장됨/);
  expect(await screen.findByText("프로필은 변환 규칙을 정의합니다. 반출 승인은 패키지별로 별도로 필요합니다.")).toBeTruthy();
  expect(screen.queryByText("현재 조건에서 작업할 수 없습니다.")).toBeNull();
  expect((screen.getByRole("button",{name:"프로필 버전 저장"}) as HTMLButtonElement).disabled).toBe(false);
 });
 it("explains author review and approval requirements separately from representative and preview limits",async()=>{
  const row={...release,eligibility:{preview:yes,approve:{enabled:false,reasons:["golden_independent_preview_approval_required"]},decline:{enabled:false,reasons:["golden_independent_decline_required"]},download:{enabled:false,reasons:["golden_active_release_approval_required"]},revoke:{enabled:false,reasons:["golden_approved_release_required"]},new_version:yes},version:{...release.version,applicability:{mode:"interpretation_only",reasons:["representative_input"]}}};
  setup({"GET /knowledge/golden/releases/rel1":[200,row],"GET /knowledge/golden/releases/rel1/versions/rv1":[200,row],"GET /knowledge/golden/releases/rel1/versions/rv1/preview":[200,{...preview,limits:["bounded_plain_text_preview","pseudonymization_is_not_anonymization"]}]});
  await screen.findByText("대표 근거가 포함된 해석용 자료입니다. 전체 범위 재계산에는 별도 검증이 필요합니다.");
  expect(screen.getByText("승인하려면 반출 요건을 충족한 현재 버전과 미리보기를 확인한 독립 검토자가 필요합니다.")).toBeTruthy();
  expect(screen.getByText("반려는 반출 검토 권한이 있는 독립 검토자가 만료·철회되지 않은 현재 버전에서 진행합니다.")).toBeTruthy();
  expect(screen.getByText("내려받으려면 반출 권한과 유효한 독립 승인이 필요합니다.")).toBeTruthy();
  expect(screen.getByText("철회하려면 반출 검토 권한과 현재 승인 결정이 필요합니다.")).toBeTruthy();
  fireEvent.click(screen.getByRole("button",{name:"실제 파일 미리보기"}));
  await screen.findByText("미리보기는 크기가 제한된 텍스트 표본입니다. 생략된 파일과 바이트 수를 함께 확인하세요.");
  expect(screen.getByText("가명처리 후에도 재식별 가능성이 있어 익명화를 보장하지 않습니다.")).toBeTruthy();
  for(const name of ["반출 승인","반출 반려","승인된 정확한 파일 내려받기","반출 승인 철회"])expect((screen.getByRole("button",{name}) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByText("현재 조건에서 작업할 수 없습니다.")).toBeNull();
 });
 it("explains preview and new-version eligibility without changing server action denial",async()=>{
  setup({"GET /knowledge/golden/releases/rel1":[200,{...release,eligibility:{...release.eligibility,preview:{enabled:false,reasons:["golden_preview_permission_required"]},new_version:{enabled:false,reasons:["golden_release_build_pending_or_permission"]}}}]});
  await screen.findByText("실제 파일 미리보기는 이 버전의 작성자 또는 반출 검토 권한이 있는 사용자에게 제공됩니다.");
  expect(screen.getByText("새 버전은 반출 작성 권한이 있고 진행 중인 파일 생성 작업이 없을 때 요청할 수 있습니다.")).toBeTruthy();
  expect((screen.getByRole("button",{name:"실제 파일 미리보기"}) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button",{name:"새 반출 버전 작성"}) as HTMLButtonElement).disabled).toBe(true);
 });
 it("distinguishes declared holdout target limits from input, result and evaluator requirements",async()=>{
  setup({"GET /knowledge/golden/holdout-attempts/ha1":[200,{id:"ha1",release_id:"rel1",release_version_id:"rv1",target:{name:"합성 대상",version:"1",artifact_sha256:sha("a")},status:"reserved",input_access:{count:0},answers_access:{count:0},result:{status:"not_submitted"},eligibility:{download_input:{enabled:false,reasons:["golden_holdout_input_unavailable"]},record_result:{enabled:false,reasons:["golden_holdout_result_unavailable"]},read_answers:{enabled:false,reasons:["golden_holdout_result_and_evaluator_required"]}},limits:["target_identity_operator_declared","operator_report_is_not_model_execution"]}]}, "/knowledge/holdout-attempts/ha1");
  await screen.findByText("대상 이름·버전·파일 해시는 사용자가 기재한 값이며 실제 대상 파일의 검증 결과는 아닙니다.");
  expect(screen.getByText("결과는 사용자가 별도 환경에서 실행한 내용의 보고입니다. SAW의 모델 실행·품질 평가를 뜻하지 않습니다.")).toBeTruthy();
  expect(screen.getByText("입력은 이 평가 시도의 작성자가 유효한 반출 승인과 반복 평가 요건을 충족할 때 내려받을 수 있습니다.")).toBeTruthy();
  expect(screen.getByText("결과는 이 평가 시도의 작성자가 입력을 받은 뒤 정답 열람 전에 한 번 등록할 수 있습니다.")).toBeTruthy();
  expect(screen.getByText("정답 열람에는 결과 등록과 내부 평가자 권한이 필요합니다.")).toBeTruthy();
  expect(screen.queryByText("현재 조건에서 작업할 수 없습니다.")).toBeNull();
  for(const name of ["이 평가 시도의 입력 내려받기","사용자 보고 결과 등록","내부 평가자 정답 열람"])expect((screen.getByRole("button",{name}) as HTMLButtonElement).disabled).toBe(true);
 });
 it("keeps unknown reason content behind the safe fallback",async()=>{
  setup({"GET /knowledge/golden/profiles":[200,{items:[{...profiles[0],limits:["UNKNOWN_PRIVATE_EXCEPTION_TEXT"]}],next_cursor:null}]},"/knowledge/profiles");
  await screen.findByText("현재 조건에서 작업할 수 없습니다.");
  expect(screen.queryByText("UNKNOWN_PRIVATE_EXCEPTION_TEXT")).toBeNull();
 });
});


describe("P4 actual NDJSON answer responses",()=>{
 it.each([
  ["one record",JSON.stringify({schema:"saw.golden.answers.v2",example_id:"g1",content_sha256:sha("a"),answers:{text:"합성 <script>window.syntheticSecret=1</script>"}})+"\n"],
  ["multiple records",JSON.stringify({schema:"saw.golden.answers.v2",example_id:"g1",content_sha256:sha("a"),answers:{text:"합성 <img src=x onerror=synthetic()>"}})+"\n"+JSON.stringify({schema:"saw.golden.answers.v2",example_id:"g2",content_sha256:sha("b"),answers:{text:"두 번째 합성 정답"}})+"\n"],
 ])("renders %s as escaped raw text only after explicit evaluator action",async(_name,raw)=>{
  const attempt={id:"ha1",release_id:"rel1",release_version_id:"rv1",target:{name:"합성 대상",version:"1",artifact_sha256:sha("a")},status:"result_recorded",input_access:{count:1},answers_access:{count:0},result:{status:"operator_reported",artifact_sha256:sha("b"),summary:"운영자가 별도 실행한 합성 결과"},eligibility:{download_input:yes,record_result:no,read_answers:yes},limits:[]};
  const mock=setup({"GET /knowledge/golden/holdout-attempts/ha1":[200,attempt]},"/knowledge/holdout-attempts/ha1");
  const original=mock.fetchMock.getMockImplementation()!;
  const answerReads=vi.fn(async()=>new Response(raw,{status:200,headers:{"content-type":"application/x-ndjson; charset=utf-8"}}));
  mock.fetchMock.mockImplementation((url,init)=>String(url).endsWith("/holdout-attempts/ha1/answers")?answerReads():original(url,init));
  const read=await screen.findByRole("button",{name:"내부 평가자 정답 열람"});
  expect(answerReads).not.toHaveBeenCalled();
  await act(async()=>{fireEvent.mouseOver(read);});
  expect(answerReads).not.toHaveBeenCalled();
  fireEvent.click(read);
  await waitFor(()=>expect(mock.ui.container.querySelector("pre")?.textContent).toBe(raw));
  expect(answerReads).toHaveBeenCalledTimes(1);
  expect(mock.ui.container.querySelector("pre script, pre img")).toBeNull();
  expect(screen.getByText("비공개 평가 시도")).toBeTruthy();
  expect(screen.getByRole("button",{name:"내부 평가자 정답 열람"})).toBeTruthy();
 });
});
