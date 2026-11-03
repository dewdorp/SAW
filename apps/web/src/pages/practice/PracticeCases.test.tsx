import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PracticeCases, type PracticePack, type PracticeStage } from "./PracticeCases";

afterEach(cleanup);

function stage(id: string, title: string): PracticeStage {
  return {
    id, title, observation: `관측 내용 ${id}`,
    evidence: [{ id: `행 ${id}`, source: "FW", summary: `근거 ${id}`, fields: { dst_port: 443 } }],
    question: `지금 할 수 있는 판단은? ${id}`,
    options: [
      { id: "A", text: "추가 대조가 필요합니다", explanation: `대상과 시간이 근거입니다 ${id}` },
      { id: "B", text: "이미 전체가 확인됐습니다", explanation: `전체 대상 근거는 없습니다 ${id}` },
    ],
    correctId: "A", rationale: `이 범위에서 가능한 결론 ${id}`, nextCheck: "대상 목록을 대조합니다",
  };
}
const pack: PracticePack = {
  version: "test",
  cases: [
    { id: "C001", title: "웹 서비스 접촉", sources: ["NDR", "FW"], initial: stage("I1", "처음 자료"),
      followups: [stage("F1", "추가 자료 1"), stage("F2", "추가 자료 2")] },
    { id: "C002", title: "통신 시각 비교", sources: ["NDR", "FW"], initial: stage("I2", "처음 자료"), followups: [] },
  ],
};
const loadPack = async () => pack;
async function openFirst() {
  render(<PracticeCases loadPack={loadPack} />);
  fireEvent.click(await screen.findByRole("button", { name: /C001.*웹 서비스 접촉/ }));
}

describe("가상 로그 예제", () => {
  it("원문을 바로 열 수 있고 명시적으로 해설을 열기 전에는 정답·후속 증거가 나오지 않는다", async () => {
    await openFirst();
    expect(screen.getByText("근거 I1")).toBeTruthy();
    expect(screen.getByRole("link", { name: "NDR 전체 CSV" }).getAttribute("href")).toBe("/practice-data/v1/C001/ndr.csv");
    expect(screen.getByRole("link", { name: "FW 전체 CSV" }).hasAttribute("download")).toBe(true);
    expect(screen.queryByText("근거 F1")).toBeNull();
    fireEvent.click(screen.getByRole("radio", { name: "이미 전체가 확인됐습니다" }));
    expect(screen.queryByText("전체 대상 근거는 없습니다 I1")).toBeNull();
    expect(screen.queryByText("이 범위에서 가능한 결론 I1")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "정답·해설 보기" }));
    expect(screen.getByText("내 선택: 오답")).toBeTruthy();
    expect(screen.getByText("전체 대상 근거는 없습니다 I1")).toBeTruthy();
    expect(screen.getByText("대상과 시간이 근거입니다 I1")).toBeTruthy();
  });

  it("각 추가 자료는 독립적이고, 초기 판단과 다른 단계의 선택이 서로 섞이지 않는다", async () => {
    await openFirst();
    fireEvent.click(screen.getByRole("radio", { name: "이미 전체가 확인됐습니다" }));
    fireEvent.click(screen.getByRole("button", { name: "정답·해설 보기" }));
    fireEvent.change(screen.getByLabelText("검토할 자료"), { target: { value: "1" } });
    expect(screen.getByText("근거 F1")).toBeTruthy();
    expect(screen.queryByText("근거 F2")).toBeNull();
    expect(screen.queryByText("내 선택: 오답")).toBeNull();
    expect((screen.getByRole("radio", { name: "이미 전체가 확인됐습니다" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole("radio", { name: "추가 대조가 필요합니다" }));
    fireEvent.click(screen.getByRole("button", { name: "정답·해설 보기" }));
    expect(screen.getByText("내 선택: 정답")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("검토할 자료"), { target: { value: "2" } });
    expect(screen.queryByText("내 선택: 정답")).toBeNull();
    expect(screen.queryByText("근거 F1")).toBeNull();
    fireEvent.change(screen.getByLabelText("검토할 자료"), { target: { value: "0" } });
    expect(screen.getByText("내 선택: 오답")).toBeTruthy();
  });

  it("답을 고르지 않아도 해설을 읽을 수 있고, 다른 사례·다시 풀기에 이전 정답을 넘기지 않는다", async () => {
    await openFirst();
    fireEvent.click(screen.getByRole("button", { name: "정답·해설 보기" }));
    expect(screen.getByText("이 범위에서 가능한 결론 I1")).toBeTruthy();
    expect(screen.queryByText(/내 선택: (오답|정답)/)).toBeNull();
    fireEvent.change(screen.getByLabelText("연습할 예제"), { target: { value: "C002" } });
    expect(screen.getByText("근거 I2")).toBeTruthy();
    expect(screen.queryByText("이 범위에서 가능한 결론 I1")).toBeNull();
    expect(screen.queryByText("이 범위에서 가능한 결론 I2")).toBeNull();
    fireEvent.click(screen.getByRole("radio", { name: "추가 대조가 필요합니다" }));
    fireEvent.click(screen.getByRole("button", { name: "정답·해설 보기" }));
    fireEvent.click(screen.getByRole("button", { name: "처음부터 다시 풀기" }));
    expect(screen.queryByText("이 범위에서 가능한 결론 I2")).toBeNull();
    expect((screen.getByRole("radio", { name: "추가 대조가 필요합니다" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "예제 목록" }));
    expect(screen.getByRole("button", { name: /C001.*웹 서비스 접촉/ })).toBeTruthy();
  });

  it("업데이트 후 예제 자산을 못 읽으면 빈 목록 대신 오류와 재시도를 제공한다", async () => {
    const load = vi.fn().mockRejectedValueOnce(new Error("chunk missing")).mockResolvedValueOnce(pack);
    render(<PracticeCases loadPack={load} />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "다시 불러오기" }));
    expect(await screen.findByRole("button", { name: /C001.*웹 서비스 접촉/ })).toBeTruthy();
  });
});
