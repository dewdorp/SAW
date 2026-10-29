import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Detections } from "./Detections";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const v1 = { id: "v1", version: 1, payload_sha256: "h1" };
const v2 = { id: "v2", version: 2, payload_sha256: "h2" };
const dto = { id: "d1", display_id: "DET-1", version: 2, status: "draft", created_by: "original", source: null, pointers: { latest: v2, draft: v2, approved: v1, active: v1, activation_revision: 3, active_approval_id: "a1" }, eligibility: { approve: false, activate: true, rollback: true, reasons: { approve: ["contributor"] } }, current: { title: "합성 규칙", description: "", data_source: "web", format: "sigma", logic: "title: Synthetic", severity: "medium", confidence: "medium", threshold: { count_gte: 5, timespan_sec: 600, group_by: ["src_ip"] }, exceptions: [], false_positive: "", attack: [], test_events: [], created_by: "editor", reviewed_by: "" }, test_runs: [], deployments: [], versions: [v1, v2] };
const routes = (extra = {}) => ({ "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "detection.write", "detection.approve"] }], "GET /detections/d1": [200, dto], "GET /investigations": [200, []], "GET /detection-cases": [200, { items: [], next_cursor: null }], "GET /source-context/org-units": [200, []], ...extra }) as any;
const start = () => renderUI(<Routes><Route path="/detections/*" element={<Detections />} /></Routes>, { route: "/detections/d1" });
describe("governed detection editor", () => {
  it("shows latest, approved and active separately without activating a draft", async () => {
    const api = mockApi(routes()); start();
    const pointers = await screen.findByRole("region", { name: "룰 버전 상태" });
    expect(within(pointers).getByText("최신 초안 v2")).toBeTruthy();
    expect(within(pointers).getByText("승인본 v1")).toBeTruthy();
    expect(within(pointers).getByText("활성본 v1")).toBeTruthy();
    expect(api.calls.filter(c => c.method !== "GET")).toHaveLength(0);
  });
  it("keeps incomplete JSON unchanged and rejects it only when saving", async () => {
    const api = mockApi(routes()); start();
    fireEvent.change(await screen.findByLabelText("임계값 편집 방식"), { target: { value: "json" } });
    fireEvent.change(screen.getByLabelText("임계값 JSON"), { target: { value: "{" } });
    expect((screen.getByLabelText("임계값 JSON") as HTMLTextAreaElement).value).toBe("{");
    expect(screen.queryByText(/임계값 JSON 형식/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "새 초안 버전 저장" }));
    expect(await screen.findByText(/임계값 JSON 형식/)).toBeTruthy();
    expect(api.find("PATCH", "/detections/d1")).toHaveLength(0);
  });
  it("posts numeric threshold and exact draft/base pointers", async () => {
    const api = mockApi(routes({ "PATCH /detections/d1": [200, dto] })); start();
    fireEvent.change(await screen.findByLabelText("최소 일치 수"), { target: { value: "40" } });
    fireEvent.change(screen.getByLabelText("집계 기간 (초)"), { target: { value: "300" } });
    fireEvent.change(screen.getByLabelText("그룹 필드"), { target: { value: "src_ip, dst_ip" } });
    fireEvent.change(screen.getByLabelText("고유값 필드"), { target: { value: "dst_port" } });
    fireEvent.click(screen.getByRole("button", { name: "새 초안 버전 저장" }));
    await waitFor(() => expect(api.find("PATCH", "/detections/d1")).toHaveLength(1));
    expect(api.find("PATCH", "/detections/d1")[0].body).toMatchObject({ expected_draft_version_id: "v2", base_version_id: "v2", threshold: { count_gte: 40, timespan_sec: 300, group_by: ["src_ip", "dst_ip"], distinct_field: "dst_port" }, exceptions: [] });
    expect(api.find("POST", "/detections/d1/activate")).toHaveLength(0);
  });
  it("retains advanced JSON and the active version on a server conflict", async () => {
    const api = mockApi(routes({ "PATCH /detections/d1": [409, { detail: "draft_version_conflict" }] })); start();
    fireEvent.change(await screen.findByLabelText("임계값 편집 방식"), { target: { value: "json" } });
    const text = '{ "count_gte": 9, "timespan_sec": 60, "group_by": [] }';
    fireEvent.change(screen.getByLabelText("임계값 JSON"), { target: { value: text } });
    fireEvent.click(screen.getByRole("button", { name: "새 초안 버전 저장" }));
    expect(await screen.findByText(/draft_version_conflict/)).toBeTruthy();
    expect((screen.getByLabelText("임계값 JSON") as HTMLTextAreaElement).value).toBe(text);
    expect(screen.getByText("활성본 v1")).toBeTruthy();
    expect(api.find("POST", "/detections/d1/approve")).toHaveLength(0);
  });
  it("uses server contributor eligibility instead of only checking the original username", async () => {
    mockApi(routes()); start();
    expect(await screen.findByText(/contributor/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "선택 시험으로 승인" })).toBeNull();
  });
  it("retains threshold semantics when switching between typed and JSON drafts", async () => {
    const api = mockApi(routes({ "PATCH /detections/d1": [409, { detail: "draft_changed" }] })); start(); await screen.findByLabelText("최소 일치 수");
    fireEvent.change(screen.getByLabelText("최소 일치 수"), { target: { value: "9" } }); fireEvent.change(screen.getByLabelText("임계값 편집 방식"), { target: { value: "json" } });
    expect(JSON.parse((screen.getByLabelText("임계값 JSON") as HTMLTextAreaElement).value).count_gte).toBe(9);
    fireEvent.change(screen.getByLabelText("임계값 JSON"), { target: { value: '{"count_gte":12,"timespan_sec":900,"group_by":["dst_ip"]}' } }); fireEvent.change(screen.getByLabelText("임계값 편집 방식"), { target: { value: "form" } });
    expect((screen.getByLabelText("최소 일치 수") as HTMLInputElement).value).toBe("12"); fireEvent.click(screen.getByRole("button", { name: "새 초안 버전 저장" })); await waitFor(()=>expect(api.find("PATCH", "/detections/d1")).toHaveLength(1));expect(api.find("PATCH", "/detections/d1")[0].body.threshold.count_gte).toBe(12);
  });  it("preserves a dirty JSON draft and its original CAS pin during a background refetch", async () => {
    let remote=dto;const api=mockApi(routes({"GET /detections/d1":()=>[200,remote],"PATCH /detections/d1":[409,{detail:"draft_changed"}]}));const {qc}=start();await screen.findByLabelText("임계값 편집 방식");fireEvent.change(screen.getByLabelText("임계값 편집 방식"),{target:{value:"json"}});fireEvent.change(screen.getByLabelText("임계값 JSON"),{target:{value:'{"count_gte":8,"timespan_sec":600}'}});
    remote={...dto,version:3,pointers:{...dto.pointers,draft:{id:"v3",version:3,payload_sha256:"h3"},latest:{id:"v3",version:3,payload_sha256:"h3"}}};await qc.invalidateQueries({queryKey:["detection","d1"]});expect((screen.getByLabelText("임계값 JSON")as HTMLTextAreaElement).value).toContain('"count_gte":8');fireEvent.click(screen.getByRole("button",{name:"새 초안 버전 저장"}));await screen.findByText(/draft_changed/);expect(api.find("PATCH","/detections/d1")[0].body.expected_draft_version_id).toBe("v2");
  });
  it("loads an immutable historical version and creates a new draft based on that exact ID",async()=>{
    const api=mockApi(routes({"GET /detections/d1/versions/v1":[200,{id:"d1",version:{...dto.current,...v1,title:"과거 합성 규칙"},approvals:[]}],"PATCH /detections/d1":[409,{detail:"draft_changed"}]}));start();await screen.findByLabelText("과거 룰 버전");fireEvent.change(screen.getByLabelText("과거 룰 버전"),{target:{value:"v1"}});await screen.findAllByText("과거 합성 규칙");fireEvent.click(screen.getByRole("button",{name:"선택 과거 버전을 새 초안으로 편집"}));fireEvent.click(screen.getByRole("button",{name:"새 초안 버전 저장"}));await screen.findByText(/draft_changed/);expect(api.find("PATCH","/detections/d1")[0].body).toMatchObject({base_version_id:"v1",expected_draft_version_id:"v2",title:"과거 합성 규칙"});
  });  it("exports the explicitly selected saved version and records only the approved external version",async()=>{
    const api=mockApi(routes({"GET /detections/d1/export":[200,"saved rule"],"POST /detections/d1/deployed":[200,dto]}));start();await screen.findByLabelText("내보낼 저장 버전");fireEvent.change(screen.getByLabelText("내보낼 저장 버전"),{target:{value:"v1"}});fireEvent.click(screen.getByRole("button",{name:"generic"}));await screen.findByText("saved rule");expect(api.find("GET","/detections/d1/export")[0].url).toBe("/detections/d1/export?fmt=generic&version_id=v1");fireEvent.change(screen.getByLabelText("외부 배포 승인 버전"),{target:{value:"v1"}});fireEvent.change(screen.getByLabelText("외부 수동 배포 대상"),{target:{value:"합성 외부 장비"}});fireEvent.click(screen.getByRole("button",{name:"외부 수동 배포 사실 기록"}));await waitFor(()=>expect(api.find("POST","/detections/d1/deployed")).toHaveLength(1));expect(api.find("POST","/detections/d1/deployed")[0].body).toEqual({version_id:"v1",target:"합성 외부 장비",note:""});expect(api.find("POST","/detections/d1/activate")).toHaveLength(0);
  });  it("preserves both legacy replay method labels without promoting selected truth into the legacy dropdown",async()=>{
    mockApi(routes({"GET /detections/d1":[200,{...dto,test_runs:[{id:"old-replay",version:1,passed:true,scope:{},method:"legacy_historical_replay",proof:null,result:{method:"legacy_historical_replay",hits:3,scanned:9,investigations:1,tp:1,fp:0,unlabeled:0}},{id:"old-verdict",version:1,passed:true,scope:{method:"legacy_investigation_verdict"},proof:null,result:{hits:0}},{id:"selected-only",version:2,passed:false,scope:{method:"selected_truth_v1"},result:{execution:"insufficient_data"},proof:null}]}]}));start();const dropdown=await screen.findByLabelText("기존 시험 선택");expect(within(dropdown).getByRole("option",{name:/old-replay/})).toBeTruthy();expect(within(dropdown).getByRole("option",{name:/old-verdict/})).toBeTruthy();expect(within(dropdown).queryByRole("option",{name:/selected-only/})).toBeNull();fireEvent.change(dropdown,{target:{value:"old-replay"}});expect(screen.getByText(/일치 3.*검사 9/)).toBeTruthy();
  });});
