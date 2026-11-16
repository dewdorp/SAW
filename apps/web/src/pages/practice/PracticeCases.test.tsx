import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PracticeCases } from "./PracticeCases";
import type { PracticePack } from "./casebookData";
import { notesFor } from "./caseNotes";
import data from "./practice-cases.json";
import workedIndex from "../../../public/reference-data/platform-cases/index.json";
import worked60 from "../../../public/reference-data/platform-cases/W60.json";

const pack = data as unknown as PracticePack;
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
function visit(path = "/casebook", loadPack = async () => pack) {
  return render(<MemoryRouter initialEntries={[path]}><PracticeCases loadPack={loadPack} /></MemoryRouter>);
}

describe("분석 사례집", () => {
  it("기존 C 사례에서 플랫폼 사례를 열고 W60 직접 링크와 조사 복귀 경로를 유지한다", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string) => {
      const body = input.endsWith("/index.json") ? workedIndex
        : input.endsWith("/W60.json") ? worked60 : null;
      return new Response(JSON.stringify(body), { status: body ? 200 : 404,
        headers: { "content-type": "application/json" } });
    }));
    visit("/casebook?case=C010&worked=W60&investigation=inv_77");
    expect(await screen.findByRole("heading", { name: /C010.*같은 포트/ })).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "다른 사례" }), { target: { value: "C011" } });
    expect(await screen.findByRole("heading", { name: /C011/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "플랫폼 분석 사례 보기" }));
    expect(await screen.findByRole("heading", { name: `W60 · ${worked60.title}` })).toBeTruthy();
    expect(screen.getByText(/전체 60건 중 60건/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "실제 조사로 돌아가기" }).getAttribute("href")).toBe("/inv/inv_77");
    expect(screen.getByRole("link", { name: "이 사례 원본 ZIP 받기" }).getAttribute("href"))
      .toBe("/reference-data/platform-cases/W60.zip");
    expect(screen.queryByRole("heading", { name: /C011/ })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "분석 사례집" }).closest("[tabindex='-1']"));
  });

  it("직접 링크에서 증거·질문·정상 대안·범위가 있는 초기 결론을 즉시 읽는다", async () => {
    visit("/practice?case=C010&investigation=inv_77");
    expect(await screen.findByRole("heading", { name: /C010.*같은 포트/ })).toBeTruthy();
    expect(screen.getByText(/목적지 주소 8개·목적지 포트 1종, 허용 12건·차단 12건/)).toBeTruthy();
    expect(screen.getByText(/자산 인벤토리 작업도 한 원천/)).toBeTruthy();
    expect(screen.getByText("분석가가 확인할 질문과 자료")).toBeTruthy();
    expect(screen.getByRole("link", { name: "실제 조사로 돌아가기" }).getAttribute("href")).toBe("/inv/inv_77");
    expect(screen.queryByRole("radio")).toBeNull();
    expect(screen.queryByText(/정답|오답|채점/)).toBeNull();
    expect(screen.getByRole("link", { name: "가상 NDR 전체 CSV" }).getAttribute("href")).toBe("/practice-data/v1/C010/ndr.csv");
    expect(screen.getByRole("link", { name: "가상 FW 전체 CSV" }).getAttribute("download")).toBe("가상-C010-fw.csv");
    fireEvent.click(screen.getByRole("button", { name: "남은 대표 근거 2개 모두 보기" }));
    const row = screen.getByText("근거 위치: fw.csv:165").closest("details")!;
    fireEvent.click(row.querySelector("summary")!);
    expect(row.open).toBe(true);
    expect(within(row).getByText("목적지 포트 (dst_port)")).toBeTruthy();
  });

  it("분석을 여는 즉시 서술형 근거를 보여 준다", async () => {
    visit("/casebook?case=C001");
    expect(await screen.findByRole("heading", { name: "판단에 사용한 근거" })).toBeTruthy();
    expect(screen.queryByText(pack.cases[0].initial.question)).toBeNull();
  });

  it("같은 초기 사실을 유지하며 서로 다른 회신 하나씩만 대조한다", async () => {
    visit("/casebook?case=C010");
    const switches = await screen.findByRole("group", { name: "후속 자료별 분석 예시" });
    const buttons = within(switches).getAllByRole("button");
    expect(buttons).toHaveLength(4);
    for (let i = 0; i < buttons.length; i++) {
      fireEvent.click(buttons[i]);
      const region = screen.getByRole("region", { name: "선택한 후속 자료의 분석" });
      const stage = pack.cases[9].followups[i];
      expect(within(region).getByText(stage.options.find(o => o.id === stage.correctId)!.text)).toBeTruthy();
      expect(within(region).getByText(`근거 위치: ${stage.evidence[0].id}`)).toBeTruthy();
      expect(within(region).queryByText(`근거 위치: ${pack.cases[9].followups[(i + 1) % 4].evidence[0].id}`)).toBeNull();
      expect(screen.getByText(/목적지 주소 8개·목적지 포트 1종, 허용 12건·차단 12건/)).toBeTruthy();
    }
  });

  it("목록 검색·사례 전환·복귀를 지원하고 안전하지 않은 조사 경로는 무시한다", async () => {
    visit("/casebook?case=unknown&investigation=..%2Fadmin");
    expect(await screen.findByText(/해당 번호의 사례를 찾을 수 없습니다/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: "실제 조사로 돌아가기" })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "C010" } });
    fireEvent.click(screen.getByRole("button", { name: /C010.*같은 포트/ }));
    fireEvent.change(screen.getByRole("combobox", { name: "다른 사례" }), { target: { value: "C003" } });
    expect(screen.getByRole("heading", { name: /C003.*로그인/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "사례 목록" }));
    expect((screen.getByRole("searchbox") as HTMLInputElement).value).toBe("C010");
    expect(screen.getByRole("button", { name: /C010.*같은 포트/ })).toBeTruthy();
  });

  it("100개 사례 전체에 주제별 정상 대안·판별 질문과 네 가지 독립 회신을 제공한다", () => {
    expect(pack.cases).toHaveLength(100);
    for (const c of pack.cases) {
      expect(notesFor(c.title)?.every(Boolean)).toBe(true);
      expect(c.followups).toHaveLength(4);
      for (const s of [c.initial, ...c.followups]) {
        expect(s.evidence.length).toBeGreaterThan(0);
        expect(s.options.find(o => o.id === s.correctId)?.text).toBeTruthy();
        expect(s.rationale).toBeTruthy();
        expect(s.nextCheck).toBeTruthy();
      }
    }
  });

  it("대량 사례의 분석 기록과 원본을 목록에서 바로 연다", async () => {
    visit();
    expect((await screen.findByRole("link", { name: "63일 분석 과정 보기" })).getAttribute("href")).toBe("/reference-data/long-window.html");
    expect(screen.getByRole("link", { name: "63일 원본 로그 받기" }).getAttribute("href")).toBe("/reference-data/long-window-sample.zip");
  });

  it("자료 로드 실패에서 다시 시도한다", async () => {
    const loader = vi.fn().mockRejectedValueOnce(new Error("failed")).mockResolvedValue(pack);
    visit("/casebook", loader);
    expect(await screen.findByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "다시 불러오기" }));
    expect(await screen.findByRole("searchbox")).toBeTruthy();
  });
});
