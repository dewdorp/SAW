import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Knowledge } from "./Knowledge";

afterEach(() => vi.unstubAllGlobals());
const EXP = { id: "e1", display_id: "EXP-1", status: "review", rev: 1, analyst_id: "author",
  analyst: "작성자", source_investigation_id: "i1", data: { title: "합성 사례", category: "attack",
    final_verdict: "unknown", reason: "처리 결과 미확인" }, fp_conflicts: { matches: 0 } };
const G = { id: "g1", experience_id: "e1", experience_rev: 1, version: 1, status: "draft",
  content_sha256: "a".repeat(64), can_review: true, can_edit: true, methodology_version: "soc-guidance/1.0",
  manifest: [{ sha256: "b".repeat(64), kind: "observation", size_bytes: 20 }],
  answers: { required_facts_actions: [{ text: "허용 2건 확인", evidence_refs: ["b".repeat(64)] }],
    judgement: { behavior: "공격 시도", impact: "미확인", reason: "WAS 미수집", evidence_refs: ["b".repeat(64)] },
    followups: ["처리 결과 요청"], forbidden_claims: ["전부 차단"], analyst_records: [] } };
function show(routes: Record<string, any> = {}, route = "/knowledge/exp/e1") {
  let currentExp = EXP;
  let currentG = G;
  const api = mockApi({
    "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "knowledge.read", "knowledge.write", "knowledge.approve"] }],
    "GET /experiences/e1": () => [200, currentExp], "GET /experiences/e1/revisions": [200, []],
    "GET /knowledge/golden/experience/e1": () => [200, { versions: [currentG] }],
    "POST /experiences/e1/approve": (call) => { currentExp = { ...EXP, status: "approved" }; if (call.body.golden) currentG = { ...G, status: "adopted" }; return [200, currentExp]; }, ...routes });
  renderUI(<Routes><Route path="/knowledge/*" element={<Knowledge />} /></Routes>, { route });
  return api;
}
describe("golden review in existing experience", () => {

  it("requires a new reviewed draft after changing the analyst judgement", async () => {
    show();
    await screen.findByText("정답 사례 채택");
    fireEvent.change(screen.getByLabelText("정답 사례 결정"), { target: { value: "adopt" } });
    fireEvent.change(screen.getByLabelText("침해·영향 확인 내용"), { target: { value: "침해 성공" } });
    for (const label of ["필수 사실과 조사 항목 확인", "판단과 근거 확인", "후속확인 확인", "금지 주장 확인"])
      fireEvent.click(screen.getByLabelText(label));
    expect((screen.getByRole("button", { name: "경험 승인" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/판단·근거를 변경했습니다/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "새 초안으로 저장" })).toBeTruthy();
  });

  it("requires four confirmations only when golden adoption is chosen and submits one approval", async () => {
    const api = show();
    expect(await screen.findByText("정답 사례 채택")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("정답 사례 결정"), { target: { value: "adopt" } });
    const approve = screen.getByRole("button", { name: "경험 승인" });
    expect((approve as HTMLButtonElement).disabled).toBe(true);
    for (const label of ["필수 사실과 조사 항목 확인", "판단과 근거 확인", "후속확인 확인", "금지 주장 확인"])
      fireEvent.click(screen.getByLabelText(label));
    expect((approve as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(approve);
    await waitFor(() => expect(api.find("POST", "/experiences/e1/approve")).toHaveLength(1));
    const payload = api.find("POST", "/experiences/e1/approve")[0].body;
    expect(payload.golden.version_id).toBe("g1");
    expect(payload.golden.confirmations.forbidden_claims).toBe(true);
    expect(api.find("POST", "/knowledge/golden/g1/review")).toHaveLength(0);
    expect(await screen.findByText("채택됨")).toBeTruthy();
  });
  it("keeps experience approval independent from golden adoption", async () => {
    const api = show();
    fireEvent.click(await screen.findByRole("button", { name: "경험 승인" }));
    await waitFor(() => expect(api.find("POST", "/experiences/e1/approve")).toHaveLength(1));
    expect(api.find("POST", "/experiences/e1/approve")[0].body.golden).toBeUndefined();
    expect(await screen.findByText(/approved/, { selector: "span.tag" })).toBeTruthy();
  });
  it("shows source authorization failure without offering candidate preparation", async () => {
    show({ "GET /knowledge/golden/experience/e1": [403, { detail: "investigation.read" }] });
    expect(await screen.findByText(/원본 조사에 접근할 권한이 필요/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "조사 기록에서 채택 초안 만들기" })).toBeNull();
  });
});


describe("golden export in SOC knowledge list", () => {
  it("keeps evaluator download separate and sends the selected immutable version with its split", async () => {
    const createObjectURL = vi.fn(() => "blob:golden-test");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const api = show({
      "GET /experiences": [200, []],
      "GET /knowledge/golden": [200, [{ ...G, title: "합성", status: "adopted", split: "dev", category: "operational", verdict: "unknown" }]],
      "POST /knowledge/golden/export": [200, "separate evaluator jsonl", { "content-disposition": 'attachment; filename="evaluator-answer.jsonl"' }],
    }, "/knowledge");
    fireEvent.click(await screen.findByLabelText("정답 사례 보기"));
    expect(await screen.findByText("운영·정보 부족 · 미확인")).toBeTruthy();
    fireEvent.click(screen.getByLabelText("버전 1 합성 선택"));
    fireEvent.click(screen.getByRole("button", { name: "평가자 정답 JSONL" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled());
    expect(api.find("POST", "/knowledge/golden/export")[0].body).toEqual({
      version_ids: ["g1"], split: "dev", format: "jsonl", audience: "evaluator" });
    click.mockRestore();
  });
});
