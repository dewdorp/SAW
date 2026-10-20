import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { GovernanceActions } from "./GovernanceActions";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const version = { id: "v2", version: 2, payload_sha256: "h2" };
const data = { pointers: { draft: version, latest: version, approved: version, approved_approval_id: "a2", active: { id: "v1", version: 1, payload_sha256: "h1" }, active_approval_id: "a1", activation_revision: 3 }, eligibility: { approve: true, activate: true, rollback: true, reasons: {} }, rollback_targets: [{ version_id: "v1", version: 1, payload_sha256: "h1", approval_id: "a1" }] };
const selectedTest = { id: "t2", passed: true, scope: { method: "selected_truth_v1", subject: { version_id: "v2" } }, result: { execution: "complete" }, proof: { proof_sha256: "proof2", rule_policy_sha256: "rp2" } };
const ui = (changes = {}) => <GovernanceActions path="/detections/d1" data={data} version={version} selectedTest={selectedTest} permissions={["detection.approve"]} onChange={vi.fn()} {...changes} />;
describe("exact governance actions", () => {
  it("approves only the explicitly selected proof without activating", async () => {
    const api = mockApi({ "POST /detections/d1/approve": [200, data] }); renderUI(ui());
    fireEvent.change(screen.getByLabelText("승인·적용 사유"), { target: { value: "합성 검증 근거 확인" } });
    fireEvent.click(screen.getByRole("button", { name: "선택 시험으로 승인" }));
    await waitFor(() => expect(api.find("POST", "/detections/d1/approve")).toHaveLength(1));
    expect(api.find("POST", "/detections/d1/approve")[0].body).toEqual({ version_id: "v2", payload_sha256: "h2", test_run_id: "t2", rule_policy_sha256: "rp2", expected_proof_sha256: "proof2", expected_draft_version_id: "v2", reason: "합성 검증 근거 확인" });
    expect(api.find("POST", "/detections/d1/activate")).toHaveLength(0);
  });
  it("applies and rolls back with exact approval and active revision", async () => {
    const api = mockApi({ "POST /detections/d1/activate": [200, data], "POST /detections/d1/rollback": [200, data] }); renderUI(ui());
    fireEvent.change(screen.getByLabelText("승인·적용 사유"), { target: { value: "합성 적용과 복구 확인" } });
    fireEvent.click(screen.getByRole("button", { name: "승인본 SAW에 적용" }));
    await waitFor(() => expect(api.find("POST", "/detections/d1/activate")).toHaveLength(1));
    expect(api.find("POST", "/detections/d1/activate")[0].body).toEqual({ approval_id: "a2", version_id: "v2", expected_active_version_id: "v1", expected_activation_revision: 3, reason: "합성 적용과 복구 확인" });
    fireEvent.change(screen.getByLabelText("복구할 승인 버전"), { target: { value: "v1" } });
    fireEvent.click(screen.getByRole("button", { name: "선택 승인본으로 복구" }));
    await waitFor(() => expect(api.find("POST", "/detections/d1/rollback")).toHaveLength(1));
    expect(api.find("POST", "/detections/d1/rollback")[0].body).toMatchObject({ approval_id: "a1", version_id: "v1", expected_active_version_id: "v1", expected_activation_revision: 3 });
  });
  it("refuses null or stale proof even when a reviewer has general permission", () => {
    mockApi({}); renderUI(ui({ selectedTest: { ...selectedTest, proof: null } }));
    expect(screen.queryByRole("button", { name: "선택 시험으로 승인" })).toBeNull();
    expect(screen.getByText(/현재 승인 증명 없음/)).toBeTruthy();
  });
  it("preserves the entered reason and reports an active pointer conflict", async () => {
    mockApi({ "POST /detections/d1/activate": [409, { detail: "activation_revision_conflict" }] }); renderUI(ui());
    fireEvent.change(screen.getByLabelText("승인·적용 사유"), { target: { value: "합성 적용 사유" } });
    fireEvent.click(screen.getByRole("button", { name: "승인본 SAW에 적용" }));
    expect(await screen.findByText(/activation_revision_conflict/)).toBeTruthy();
    expect((screen.getByLabelText("승인·적용 사유") as HTMLTextAreaElement).value).toBe("합성 적용 사유");
    expect(screen.queryByText("SAW 적용 완료")).toBeNull();
  });
  it("preserves the server-pinned organization scope when approving a selected rule proof",async()=>{
    const api=mockApi({"POST /detections/d1/approve":[200,data]});renderUI(ui({selectedTest:{...selectedTest,proof:{...selectedTest.proof,context_scope:{kind:"org",org_unit_id:"stable-org"}}}}));fireEvent.change(screen.getByLabelText("승인·적용 사유"),{target:{value:"원천 범위 독립 검토"}});fireEvent.click(screen.getByRole("button",{name:"선택 시험으로 승인"}));await waitFor(()=>expect(api.find("POST","/detections/d1/approve")).toHaveLength(1));expect(api.find("POST","/detections/d1/approve")[0].body.context_scope).toEqual({kind:"org",org_unit_id:"stable-org"});
  });});
