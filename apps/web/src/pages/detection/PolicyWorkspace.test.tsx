import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { PolicyWorkspace } from "./PolicyWorkspace";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const spec = { id: "fw.observation", version: "1", title: "합성 방화벽 명세", engine: { version: "fw/1" }, parameters: [{ key: "enabled", type: "boolean", label: "사용", default: true, unit: "boolean" }, { key: "deny_allow_window_seconds", type: "integer", label: "거부 후 허용 기간", default: 300, minimum: 0, maximum: 1000, unit: "seconds" }], defaults: { enabled: true, deny_allow_window_seconds: 300 }, grouping: ["network"], window: { kind: "fixed_utc", boundary: "[start,end)" }, prerequisites: ["검증된 측정 단위"], examples: [], benign_examples: [], follow_up: [], limits: {} };
const setup = (extra = {}) => mockApi({ "GET /auth/me": [200, { permissions: ["detection.write", "detection.approve"] }], "GET /detector-specs": [200, { items: [spec] }], "GET /detector-specs/fw.observation": [200, spec], "GET /detector-specs/fw.observation/effective": [200, { spec, effective: { values: spec.defaults, per_value_source: {}, layers: [] } }], "GET /detection-policies": [200, { items: [], next_cursor: null }], "GET /source-context/org-units": [200, [{ id: "org-a", display_name: "동일 이름" }, { id: "org-b", display_name: "동일 이름" }]], ...extra } as any);
describe("governed policy drafts", () => {
 it("keeps false, zero and explicit empty exclusions distinct from inheritance without applying", async () => {
  const api = setup({ "POST /detection-policies/drafts": [409, { detail: "draft_changed" }] }); renderUI(<PolicyWorkspace detectorId="fw.observation" />);
  await screen.findByText("합성 방화벽 명세");
  fireEvent.change(screen.getByLabelText("사용 설정 방식"), { target: { value: "set" } });
  fireEvent.click(screen.getByLabelText("사용 값"));
  fireEvent.change(screen.getByLabelText("거부 후 허용 기간 설정 방식"), { target: { value: "set" } });
  fireEvent.change(screen.getByLabelText("거부 후 허용 기간 값"), { target: { value: "0" } });
  fireEvent.change(screen.getByLabelText("예외 적용 방식"), { target: { value: "set" } });
  fireEvent.change(screen.getByLabelText("정책 변경 사유"), { target: { value: "합성 기준 검토" } });
  fireEvent.click(screen.getByRole("button", { name: "정책 초안 버전 저장" }));
  await screen.findByText(/draft_changed/);
  expect(api.find("POST", "/detection-policies/drafts")[0].body).toEqual({ detector_id: "fw.observation", scope: { kind: "group" }, expected_draft_version_id: null, base_version_id: null, changes: { set: { enabled: false, deny_allow_window_seconds: 0 }, inherit: [] }, exclusions: { mode: "set", values: [] }, reason: "합성 기준 검토" });
  expect((screen.getByLabelText("거부 후 허용 기간 값") as HTMLInputElement).value).toBe("0");
  expect(api.calls.filter(row => row.url.endsWith("/activate"))).toHaveLength(0);
 });
 it("retains incomplete JSON and rejects empty numeric overrides before mutation", async () => {
  const api = setup(); renderUI(<PolicyWorkspace detectorId="fw.observation" />); await screen.findByText("합성 방화벽 명세");
  fireEvent.change(screen.getByLabelText("정책 편집 방식"), { target: { value: "json" } }); fireEvent.change(screen.getByLabelText("상위 값 덮어쓰기 JSON"), { target: { value: '{"enabled":' } });
  fireEvent.change(screen.getByLabelText("정책 변경 사유"), { target: { value: "합성" } }); fireEvent.click(screen.getByRole("button", { name: "정책 초안 버전 저장" }));
  await screen.findByText(/JSON 형식을 확인/); expect((screen.getByLabelText("상위 값 덮어쓰기 JSON") as HTMLTextAreaElement).value).toBe('{"enabled":'); expect(api.find("POST", "/detection-policies/drafts")).toHaveLength(0);
 });
 it("does not lose JSON false and zero when returning to typed controls", async () => {
  setup(); renderUI(<PolicyWorkspace detectorId="fw.observation" />); await screen.findByText("합성 방화벽 명세");
  fireEvent.change(screen.getByLabelText("정책 편집 방식"), { target: { value: "json" } }); fireEvent.change(screen.getByLabelText("상위 값 덮어쓰기 JSON"), { target: { value: '{"enabled":false,"deny_allow_window_seconds":0}' } });
  fireEvent.change(screen.getByLabelText("정책 편집 방식"), { target: { value: "form" } });
  expect((screen.getByLabelText("사용 값") as HTMLInputElement).checked).toBe(false); expect((screen.getByLabelText("거부 후 허용 기간 값") as HTMLInputElement).value).toBe("0");
 }); it("pins stable organization ID even when display names collide", async () => {
  const api = setup({ "POST /detection-policies/drafts": [409, { detail: "draft_changed" }] }); renderUI(<PolicyWorkspace detectorId="fw.observation" />); await screen.findByText("합성 방화벽 명세");
  fireEvent.change(screen.getByLabelText("정책 범위"), { target: { value: "org" } }); await screen.findAllByRole("option", { name: /동일 이름/ }); fireEvent.change(screen.getByLabelText("정책 관계사"), { target: { value: "org-b" } });
  await waitFor(() => expect((screen.getByRole("button", { name: "정책 초안 버전 저장" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.change(screen.getByLabelText("정책 변경 사유"), { target: { value: "분리된 기준" } }); fireEvent.click(screen.getByRole("button", { name: "정책 초안 버전 저장" }));
  await waitFor(() => expect(api.find("POST", "/detection-policies/drafts")).toHaveLength(1)); expect(api.find("POST", "/detection-policies/drafts")[0].body.scope).toEqual({ kind: "org", org_unit_id: "org-b" });
 });
 it("tests the immutable current policy rather than a higher unselected allocation and pins the active reference",async()=>{
  const p1={id:"p1",version:1,payload_sha256:"ph1"};const p2={id:"p2",version:2,payload_sha256:"ph2"};const binding={id:"binding1",current:{...p1,payload:{overrides:{enabled:false},exclusions_override:null}},pointers:{draft:null,approved:p1,active:p1,latest:p2,activation_revision:1},versions:[p1,p2],eligibility:{approve:false,activate:false,rollback:false},test_runs:[]};
  const api=setup({"GET /detection-policies":[200,{items:[{id:"binding1"}]}],"GET /detection-policies/binding1":[200,binding],"GET /investigations":[200,[]],"GET /detection-cases":[200,{items:[{id:"cv1",case_id:"c1",title:"합성 구간",version:1,units:[{unit_id:"u1",unit_kind:"window",detection_truth:"expected_no_match",investigation_truth:"normal"}]}]}],"POST /detection-policies/binding1/test":[409,{detail:"input_changed"}]});renderUI(<PolicyWorkspace detectorId="fw.observation"/>);fireEvent.click(await screen.findByLabelText("선택 합성 구간 v1 u1"));fireEvent.click(screen.getByRole("button",{name:"선택 단위 시험 실행"}));await screen.findByText(/input_changed/);expect(api.find("POST","/detection-policies/binding1/test")[0].body).toMatchObject({version_id:"p1",payload_sha256:"ph1",reference_version_id:"p1",context_scope:{kind:"group"}});
 }); it("uses the registered Sigma runtime target rather than the shared documentation spec ID",async()=>{
  const sigma={...spec,id:"sigma",title:"합성 등록 Sigma"};const api=setup({"GET /detector-specs/sigma.approved%3Arule1":[200,sigma],"GET /detector-specs/sigma.approved%3Arule1/effective":[200,{spec:sigma,effective:{values:sigma.defaults,per_value_source:{},layers:[]}}],"POST /detection-policies/drafts":[409,{detail:"draft_changed"}]});renderUI(<PolicyWorkspace detectorId="sigma.approved:rule1"/>);await screen.findByText("합성 등록 Sigma");fireEvent.change(screen.getByLabelText("정책 변경 사유"),{target:{value:"실제 룰 설정"}});fireEvent.click(screen.getByRole("button",{name:"정책 초안 버전 저장"}));await screen.findByText(/draft_changed/);expect(api.find("POST","/detection-policies/drafts")[0].body.detector_id).toBe("sigma.approved:rule1");
 }); it("uses organization plus observing device in policy lookup without equating equipment ownership with observed subject",async()=>{
  const api=setup({"GET /investigations":[200,[{id:"device-owner-inv",display_id:"OWNER",title:"공동 관측 장비",org_unit_id:"equipment-owner"}]],"GET /source-context/investigations/device-owner-inv/devices":[200,[{id:"shared-observer",display_name:"공동 관측 장비"}]]});renderUI(<PolicyWorkspace detectorId="fw.observation"/>);await screen.findByText("합성 방화벽 명세");fireEvent.change(screen.getByLabelText("정책 범위"),{target:{value:"device"}});await screen.findAllByRole("option",{name:/동일 이름/});fireEvent.change(screen.getByLabelText("정책 관계사"),{target:{value:"org-a"}});await screen.findByRole("option",{name:"OWNER 공동 관측 장비"});fireEvent.change(screen.getByLabelText("장비 소속 조사"),{target:{value:"device-owner-inv"}});await screen.findByRole("option",{name:/공동 관측 장비 · shared-observer/});fireEvent.change(screen.getByLabelText("정책 장비"),{target:{value:"shared-observer"}});await waitFor(()=>expect(api.find("GET","/detection-policies").some(call=>new URLSearchParams(call.url.split("?")[1]).get("scope_key")==="device:org-a:shared-observer")).toBe(true));
  fireEvent.change(screen.getByLabelText("정책 관계사"),{target:{value:"org-b"}});fireEvent.change(screen.getByLabelText("장비 소속 조사"),{target:{value:"device-owner-inv"}});fireEvent.change(screen.getByLabelText("정책 장비"),{target:{value:"shared-observer"}});await waitFor(()=>expect(api.find("GET","/detection-policies").some(call=>new URLSearchParams(call.url.split("?")[1]).get("scope_key")==="device:org-b:shared-observer")).toBe(true));
 });});
