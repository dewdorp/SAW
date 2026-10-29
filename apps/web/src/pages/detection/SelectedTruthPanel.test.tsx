import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { SelectedTruthPanel } from "./SelectedTruthPanel";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const source = { id: "cv1", case_id: "case1", title: "합성 승인 점검", version: 1, sha256: "truth-hash", investigation_id: "i1", scope: { filters: [] }, units: [{ unit_id: "scan-1", unit_kind: "window", detection_truth: "expected_match", investigation_truth: "approved_activity", basis: "합성 승인서" }, { unit_id: "normal-1", unit_kind: "event", detection_truth: "expected_no_match", investigation_truth: "normal", event_ids: ["event-2"], basis: "합성 평상 요청" }] };
const result = { id: "t1", version: 2, passed: true, scope: { method: "selected_truth_v1", subject: { version_id: "v2" } }, proof: { proof_sha256: "proof-h", rule_policy_sha256: "rp-h" }, result: { execution: "complete", units: [{ case_version_id: "cv1", unit_id: "scan-1", unit_kind: "window", status: "complete", detection_truth: "expected_match", investigation_truth: "approved_activity", prediction: false, reference_prediction: true, input_count: 4, matching_event_ids: [] }, { case_version_id: "cv1", unit_id: "normal-1", unit_kind: "event", status: "insufficient_data", detection_truth: "expected_no_match", investigation_truth: "normal", prediction: null, reference_prediction: null, input_count: 0, matching_event_ids: [] }], metrics: { tp: 0, fp: 0, fn: 1, tn: 0, labeled: 1, unlabeled: 0, precision: { numerator: 0, denominator: 0, value: null }, recall: { numerator: 0, denominator: 1, value: 0 } }, limits: {} } };
const setup = (extra = {}) => mockApi({ "GET /investigations": [200, [{ id: "i1", display_id: "INV-1", title: "합성 조사" }]], "GET /source-context/org-units": [200, []], "GET /detection-cases": [200, { items: [source], next_cursor: null }], ...extra } as any);
const ui = (onResult = vi.fn()) => <SelectedTruthPanel testPath="/detections/d1/test" version={{ id: "v2", version: 2, payload_sha256: "h2" }} versions={[{ id: "v1", version: 1, payload_sha256: "h1" }]} onResult={onResult} />;
describe("selected unit truth tests", () => {
  it("requires explicit units and sends exact case/rule/reference pins without interpreting approved activity as no-match", async () => {
    const api = setup({ "POST /detections/d1/test": [200, result] }); renderUI(ui());
    expect((screen.getByRole("button", { name: "선택 단위 시험 실행" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1"));
    fireEvent.change(screen.getByLabelText("비교 기준 룰 버전"), { target: { value: "v1" } });
    fireEvent.click(screen.getByRole("button", { name: "선택 단위 시험 실행" }));
    await screen.findByText("선택 정답 시험 결과");
    expect(api.find("POST", "/detections/d1/test")[0].body).toEqual({ method: "selected_truth_v1", version_id: "v2", payload_sha256: "h2", reference_version_id: "v1", units: [{ case_version_id: "cv1", unit_id: "scan-1" }], context_scope: { kind: "group" } });
    expect(screen.getAllByText("승인 활동").length).toBeGreaterThan(0);
  });
  it("shows misses and insufficient data units with null precision instead of true negatives", async () => {
    setup({ "POST /detections/d1/test": [200, result] }); renderUI(ui());
    fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1"));
    fireEvent.click(screen.getByRole("button", { name: "선택 단위 시험 실행" }));
    expect(await screen.findByText("계산 불가 (분모 0)")).toBeTruthy();
    expect(screen.getByRole("row", { name: /scan-1.*적중 기대.*승인 활동.*미적중/ })).toBeTruthy();
    expect(screen.getByRole("row", { name: /normal-1.*비적중 기대.*정상.*자료 부족.*미확인/ })).toBeTruthy();
    expect(screen.getByText("TN 0")).toBeTruthy();
  });
  it("creates a bounded window case with separate detector truth and human judgment", async () => {
    const api = setup({ "POST /detection-cases": [201, source] }); renderUI(ui());
    fireEvent.click(screen.getByRole("button", { name: "새 정답 사례 만들기" }));
    fireEvent.change(screen.getByLabelText("사례 제목"), { target: { value: "합성 점검 구간" } });
    await screen.findAllByRole("option", { name: "INV-1 합성 조사" });
    fireEvent.change(screen.getByLabelText("사례 원천 조사"), { target: { value: "i1" } });
    fireEvent.change(screen.getByLabelText("판정 단위"), { target: { value: "window" } });
    fireEvent.change(screen.getByLabelText("탐지 적중 정답"), { target: { value: "expected_match" } });
    fireEvent.change(screen.getByLabelText("분석가 판단"), { target: { value: "approved_activity" } });
    fireEvent.change(screen.getByLabelText("정답 근거"), { target: { value: "합성 승인 명세" } });
    fireEvent.click(screen.getByRole("button", { name: "새 사례 버전 저장" }));
    await waitFor(() => expect(api.find("POST", "/detection-cases")).toHaveLength(1));
    expect(api.find("POST", "/detection-cases")[0].body).toMatchObject({ title: "합성 점검 구간", investigation_id: "i1", filters: [], units: [{ unit_id: "unit-1", unit_kind: "window", detection_truth: "expected_match", investigation_truth: "approved_activity", basis: "합성 승인 명세" }] });
  });
  it("rejects mixed accuracy units locally and preserves their selection", async () => {
    const api = setup(); renderUI(ui());
    fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1")); fireEvent.click(screen.getByLabelText("선택 합성 승인 점검 v1 normal-1"));
    fireEvent.click(screen.getByRole("button", { name: "선택 단위 시험 실행" }));
    expect(await screen.findByText(/같은 종류의 판정 단위/)).toBeTruthy(); expect(api.find("POST", "/detections/d1/test")).toHaveLength(0);
  });
  it("pins the current active reference explicitly for approval comparison", async () => {
    const api = setup({ "POST /detections/d1/test": [200, result] }); renderUI(<SelectedTruthPanel testPath="/detections/d1/test" version={{ id: "v2", version: 2, payload_sha256: "h2" }} versions={[{ id: "v1", version: 1, payload_sha256: "h1" }]} activeVersionId="v1" onResult={vi.fn()} />);
    fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1")); fireEvent.click(screen.getByRole("button", { name: "선택 단위 시험 실행" }));
    await waitFor(()=>expect(api.find("POST", "/detections/d1/test")).toHaveLength(1)); expect(api.find("POST", "/detections/d1/test")[0].body.reference_version_id).toBe("v1");
  });  it("preserves selected units and shows rejection without manufacturing a result", async () => {
    setup({ "POST /detections/d1/test": [409, { detail: "truth_version_changed" }] }); renderUI(ui());
    fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1")); fireEvent.click(screen.getByRole("button", { name: "선택 단위 시험 실행" }));
    expect(await screen.findByText(/truth_version_changed/)).toBeTruthy();
    expect((screen.getByLabelText("선택 합성 승인 점검 v1 scan-1") as HTMLInputElement).checked).toBe(true);
    expect(screen.queryByText("선택 정답 시험 결과")).toBeNull();
  });
  it("keeps the original case affiliation when revising labels under a different test policy scope",async()=>{
    const scoped={...source,scope:{filters:[],org_unit_id:"original-org",device_id:"original-device"}};const api=setup({"GET /detection-cases":[200,{items:[scoped]}],"POST /detection-cases/case1/versions":[201,{...scoped,id:"cv2",version:2}]});renderUI(ui());fireEvent.click((await screen.findAllByRole("button",{name:"합성 승인 점검 새 버전"}))[0]);fireEvent.click(screen.getByRole("button",{name:"새 사례 버전 저장"}));await waitFor(()=>expect(api.find("POST","/detection-cases/case1/versions")).toHaveLength(1));expect(api.find("POST","/detection-cases/case1/versions")[0].body).toMatchObject({org_unit_id:"original-org",device_id:"original-device"});
  });  it.each(["investigation","organization"])("clears a dependent selected device when its %s changes",async(change)=>{
    const api=setup({"GET /investigations":[200,[{id:"i1",display_id:"I1",title:"First"},{id:"i2",display_id:"I2",title:"Second"}]],"GET /source-context/org-units":[200,[{id:"o1",display_name:"Org One"},{id:"o2",display_name:"Org Two"}]],"GET /source-context/investigations/i1/devices":[200,[{id:"dev1",display_name:"Device One"}]],"GET /source-context/investigations/i2/devices":[200,[{id:"dev2",display_name:"Device Two"}]],"POST /detections/d1/test":[409,{detail:"hidden scope"}]});renderUI(ui());fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1"));fireEvent.change(screen.getByLabelText("시험 정책 범위"),{target:{value:"device"}});await screen.findByRole("option",{name:"Org One"});fireEvent.change(screen.getByLabelText("시험 관계사"),{target:{value:"o1"}});fireEvent.change(screen.getByLabelText("장비 소속 조사"),{target:{value:"i1"}});await screen.findByRole("option",{name:"Device One"});fireEvent.change(screen.getByLabelText("시험 장비"),{target:{value:"dev1"}});
    if(change==="investigation"){fireEvent.change(screen.getByLabelText("장비 소속 조사"),{target:{value:"i2"}});await screen.findByRole("option",{name:"Device Two"});}else fireEvent.change(screen.getByLabelText("시험 관계사"),{target:{value:"o2"}});
    expect((screen.getByLabelText("시험 장비")as HTMLSelectElement).value).toBe("");fireEvent.click(screen.getByRole("button",{name:"선택 단위 시험 실행"}));await screen.findByText(/분석 장비를 선택하세요/);expect(api.find("POST","/detections/d1/test")).toHaveLength(0);
  });
  it("keeps test device selection separate from editing a truth case source investigation",async()=>{
    const api=setup({"GET /source-context/org-units":[200,[{id:"o1",display_name:"Org One"}]],"GET /source-context/investigations/i1/devices":[200,[{id:"dev1",display_name:"Device One"}]],"POST /detections/d1/test":[409,{detail:"expected exact selected test scope"}]});renderUI(ui());fireEvent.click(await screen.findByLabelText("선택 합성 승인 점검 v1 scan-1"));fireEvent.change(screen.getByLabelText("시험 정책 범위"),{target:{value:"device"}});await screen.findByRole("option",{name:"Org One"});fireEvent.change(screen.getByLabelText("시험 관계사"),{target:{value:"o1"}});fireEvent.change(screen.getByLabelText("장비 소속 조사"),{target:{value:"i1"}});await screen.findByRole("option",{name:"Device One"});fireEvent.change(screen.getByLabelText("시험 장비"),{target:{value:"dev1"}});fireEvent.click(screen.getByRole("button",{name:"새 정답 사례 만들기"}));expect((screen.getByLabelText("장비 소속 조사")as HTMLSelectElement).value).toBe("i1");fireEvent.click(screen.getByRole("button",{name:"선택 단위 시험 실행"}));await waitFor(()=>expect(api.find("POST","/detections/d1/test")).toHaveLength(1));expect(api.find("POST","/detections/d1/test")[0].body.context_scope).toEqual({kind:"device",org_unit_id:"o1",device_id:"dev1"});
  });});
