import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { ReviewInbox, ReviewPanel } from "./Reviews";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const INV = "inv-1";
const R = (o: object) => ({ id: "r1", investigation_id: INV, subject_type: "finding", subject_id: "f1", subject_ko: "탐지를 정상·오탐으로 낮춤", subject_label: "F-1001 Possible API Enumeration",
  conclusion: "위험도 high 탐지를 '오탐'으로 평가함", scope_note: "", limits: [], evidence: [], required: true, status: "needed", status_ko: "검토자 지정 필요", stale: false, open: true, latest: true,
  requested_by: "kim", requested_by_id: "u1", reviewer: "", reviewer_id: null, outcome_note: "", created_at: "2026-10-10T00:00:00Z", ...o });
const PEOPLE = [{ id: "u2", name: "박선임", username: "park", senior: true }];

describe("Review requests", () => {
  it("fills an open need by choosing a reviewer and stating the conclusion", async () => {
    const api = mockApi({ [`GET /investigations/${INV}/reviews`]: [200, { reviews: [R({})], me: "u1" }], "GET /reviews/reviewers": [200, PEOPLE],
      [`POST /investigations/${INV}/reviews`]: [201, R({ status: "requested" })] });
    renderUI(<ReviewPanel inv={INV} />);
    expect(await screen.findByText("검토자 지정 필요")).toBeTruthy();
    expect(screen.getByText(/끝나지 않은 것 1건/)).toBeTruthy();
    fireEvent.click(screen.getByText("검토자 지정해 요청"));
    const send = (await screen.findByRole("button", { name: "검토 요청 보내기" })) as HTMLButtonElement;
    expect(send.disabled).toBe(true);                                       // nobody chosen yet
    await screen.findByText(/박선임/);
    fireEvent.change(screen.getByLabelText("검토자"), { target: { value: "u2" } });
    fireEvent.change(screen.getByLabelText("검토받을 결론"), { target: { value: "02~03시 요청은 정산 배치로 판단" } });
    fireEvent.click(send);
    await waitFor(() => expect(api.find("POST", `/investigations/${INV}/reviews`)).toHaveLength(1));
    expect(api.find("POST", `/investigations/${INV}/reviews`)[0].body).toMatchObject({
      subject_type: "finding", subject_id: "f1", reviewer_id: "u2", conclusion: "02~03시 요청은 정산 배치로 판단" });
  });

  it("makes the reviewer say how far they agree before saving an answer", async () => {
    const asked = R({ status: "requested", status_ko: "검토 대기", reviewer: "park", reviewer_id: "u2", limits: ["표본만 본 확인 1건"],
      investigation: { id: INV, display_id: "INV-1", title: "A 조사" } });
    const api = mockApi({ "GET /reviews/inbox": [200, { to_review: [asked], returned: [] }], "GET /auth/me": [200, { id: "u2", username: "park" }],
      "POST /reviews/r1/decide": [200, {}] });
    renderUI(<ReviewInbox />);
    expect(await screen.findByText(/요청받은 것 1건/)).toBeTruthy();
    expect(await screen.findByText(/자료의 한계: 표본만 본 확인 1건/)).toBeTruthy();   // the reviewer sees the gaps without asking
    const save = (await screen.findByRole("button", { name: "검토 결과 저장" })) as HTMLButtonElement;
    fireEvent.click(screen.getByLabelText("결론 범위가 너무 넓음"));
    expect(save.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("검토 의견"), { target: { value: "03시 이후 요청은 확인되지 않음" } });
    fireEvent.click(save);
    await waitFor(() => expect(api.find("POST", "/reviews/r1/decide")[0].body).toEqual({ outcome: "too_broad", note: "03시 이후 요청은 확인되지 않음" }));
  });

  it("shows an approval that no longer covers the conclusion", async () => {
    mockApi({ [`GET /investigations/${INV}/reviews`]: [200, { reviews: [R({ status: "approved", status_ko: "근거가 결론을 지지함", stale: true, open: true, reviewer: "park", reviewer_id: "u2", outcome_note: "원본 30건 확인" })], me: "u1" }] });
    renderUI(<ReviewPanel inv={INV} />);
    expect(await screen.findByText("결론이 바뀜 — 다시 검토 필요")).toBeTruthy();
    expect(screen.getByText("보완해서 다시 요청")).toBeTruthy();
  });
});
