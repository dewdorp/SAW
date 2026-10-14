import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CheckDialog, MarkBadges } from "../../components/Checks";
import { CloseDialog } from "./CloseDialog";
import { mockApi, renderUI } from "../../test/helpers";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const scope = { target_type: "entity", target_key: "ip:203.0.113.10", role: "either", filters: [], time: null, as_of: null, methodology_version: "soc-guidance/1.0" };
const guidance = { methodology_version: "soc-guidance/1.0", rule_id: "A", scope, title: "허용된 요청의 처리 결과 확인", data_states: [] };

describe("Guidance response reuses confirmation records", () => {
  it("records followup and source state without making an infection verdict", async () => {
    const api = mockApi({ "POST /investigations/i/checks": [201, { id: "c1" }] });
    const props: any = { inv: "i", target: { type: "entity", key: scope.target_key, label: "203.0.113.10" }, guidance, onClose: vi.fn() };
    renderUI(<CheckDialog {...props} />);
    fireEvent.change(screen.getByLabelText("답변 상태"), { target: { value: "follow_up" } });
    fireEvent.change(screen.getByLabelText("근거"), { target: { value: "WAS 처리 결과가 없어 실제 영향은 미확인" } });
    fireEvent.change(screen.getByLabelText("확인할 대상"), { target: { value: "웹 운영 담당자" } });
    fireEvent.change(screen.getByLabelText("필요 자료"), { target: { value: "해당 시각 WAS 로그" } });
    fireEvent.change(screen.getByLabelText("후속 확인 항목"), { target: { value: "허용된 두 요청의 실제 처리 결과" } });
    fireEvent.click(screen.getByRole("button", { name: "확인 기록 저장" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i/checks")).toHaveLength(1));
    const body = api.find("POST", "/investigations/i/checks")[0].body;
    expect(body.guidance).toMatchObject({ rule_id: "A", scope, answer_status: "follow_up", answer: "WAS 처리 결과가 없어 실제 영향은 미확인", follow_up: { target: "웹 운영 담당자", needed_data: ["해당 시각 WAS 로그"], items: ["허용된 두 요청의 실제 처리 결과"] } });
    expect(body.judgement).toBe("undetermined");
    expect(body.guidance).not.toHaveProperty("queries");
    expect(body.shared).toBe(false);
  });

  it("keeps guidance when editing a prior response and does not show unresolved work as verified", async () => {
    const api = mockApi({ "PUT /investigations/i/checks/c1": [200, {}] });
    const old = { ...guidance, answer_status: "follow_up", follow_up: { target: "담당자", needed_data: ["WAS"], items: ["처리 결과"], priority: "normal" } };
    renderUI(<CheckDialog inv="i" target={{ type: "entity", key: scope.target_key, label: "IP" }} edit={{ id: "c1", questions: ["success"], judgement: "undetermined", note: "추가 확인 필요", guidance: old }} onClose={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("근거"), { target: { value: "응답 보존 요청 완료; 영향은 미확인" } });
    fireEvent.click(screen.getByRole("button", { name: "변경 저장" }));
    await waitFor(() => expect(api.find("PUT", "/investigations/i/checks/c1")).toHaveLength(1));
    expect(api.find("PUT", "/investigations/i/checks/c1")[0].body.guidance.answer_status).toBe("follow_up");
  });

  it("renders followup marks distinctly from completed verification", () => {
    const mark: any = { id: "c1", questions: ["impact"], judgement: "undetermined", author: "check", kind: "direct", coverage: "one", shared: false, source_state: "", guidance_status: "follow_up" };
    renderUI(<MarkBadges own={[mark]} />);
    expect(screen.getByText(/후속확인/)).toBeTruthy();
    expect(screen.queryByText("✓판단 불가")).toBeNull();
  });
});

describe("Closure reuses analyst records", () => {
  it("prefills recorded work and keeps attack nature separate from unknown impact", async () => {
    const api = mockApi({
      "GET /investigations/i/closing-check": [200, { items: [] }],
      "GET /investigations/i/guidance/closure-draft": [200, { methodology_version: "soc-guidance/1.0", behavior_assessment: "공격 시도 관측", impact_assessment: "실제 영향 미확인", check_ids: ["c1"], scopes: [], evidence: [], limits: ["WAS 처리 결과 미수집"], follow_up: [{ target: "웹 운영 담당자", needed_data: ["WAS 로그"], items: ["실제 처리 결과"], priority: "normal" }] }],
      "POST /investigations/i/close": [200, {}],
    });
    renderUI(<CloseDialog inv={{ id: "i", display_id: "INV-SYNTH" }} onClose={vi.fn()} />);
    await waitFor(() => expect((screen.getByLabelText("행위 판단") as HTMLTextAreaElement).value).toBe("공격 시도 관측"));
    expect((screen.getByLabelText("실제 영향 판단") as HTMLTextAreaElement).value).toBe("실제 영향 미확인");
    expect((screen.getByLabelText("범위 제한") as HTMLTextAreaElement).value).toContain("WAS 처리 결과 미수집");
    expect(screen.queryByLabelText("WAF 차단 여부 확인")).toBeNull();
    fireEvent.click(screen.getByLabelText("공격"));
    fireEvent.change(screen.getByLabelText("판정 사유"), { target: { value: "공격 시도 관측. 실제 침해는 미확인." } });
    fireEvent.click(screen.getByRole("button", { name: "종결" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i/close")).toHaveLength(1));
    expect(api.find("POST", "/investigations/i/close")[0].body).toMatchObject({ behavior_assessment: "공격 시도 관측", impact_assessment: "실제 영향 미확인", checks: [], follow_up: [] });
  });
});


it("can resolve an earlier empty-evidence followup using newly available scoped records", async () => {
  const api = mockApi({
    "POST /investigations/i/guidance/preview": [200, { queries: [{ evidence_refs: ["new-evidence"] }] }],
    "PUT /investigations/i/checks/c1": [200, {}],
  });
  const old = { ...guidance, answer_status: "follow_up", follow_up: { target: "담당자", needed_data: ["WAS"], items: ["처리 결과"], priority: "normal" } };
  renderUI(<CheckDialog inv="i" target={{ type: "entity", key: scope.target_key, label: "IP" }} edit={{ id: "c1", evidence: [], note: "처리 결과 확인", guidance: old }} onClose={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("답변 상태"), { target: { value: "answered" } });
  fireEvent.click(await screen.findByLabelText("근거 선택 new-evidence"));
  fireEvent.click(screen.getByRole("button", { name: "변경 저장" }));
  await waitFor(() => expect(api.find("PUT", "/investigations/i/checks/c1")).toHaveLength(1));
  expect(api.find("POST", "/investigations/i/guidance/preview")[0].body).toEqual(scope);
  expect(api.find("PUT", "/investigations/i/checks/c1")[0].body).toMatchObject({ evidence: ["new-evidence"], guidance: { scope, answer_status: "answered" } });
});
