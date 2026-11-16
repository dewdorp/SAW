import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { PlatformCases } from "./PlatformCases";

afterEach(cleanup);
it("재생 기록에서 선정 근거, 원문 행, 대조 자료와 판단을 읽고 다른 사례를 연다", async () => {
  const index = [{ id: "W01", title: "웹 요청", classification: "공격 시도" }, { id: "W02", title: "주기 접속", classification: "정상 업무" }];
  const steps = Array.from({ length: 5 }, (_, i) => ({ action: `화면 ${i}`, finding: `관측 ${i}`, image: i === 1 ? "shots/W01-candidate.png" : undefined, rows: i === 2 ? [{ src_ip: "198.51.100.41" }] : [] }));
  const load = vi.fn(async (filename: string) => filename === "index.json" ? index : { ...index.find(c => filename === `${c.id}.json`), steps });
  render(<PlatformCases loadJson={load} assetUrl={file => `/offline/${file}`} />);
  await screen.findByRole("heading", { name: "W01 · 웹 요청" }, { timeout: 10000 });
  expect(screen.getByRole("link", { name: /원본 ZIP/ }).getAttribute("download")).toBe("W01.zip");
  fireEvent.click(screen.getByRole("button", { name: /다음 · SAW 계산/ }));
  const img = screen.getByRole("img", { name: /W01.*실행 화면/ });
  expect(img.closest("details")?.open).toBe(true);
  expect(img.getAttribute("src")).toBe("/offline/shots/W01-candidate.png");
  fireEvent.click(screen.getByRole("button", { name: /다음 · 원문 필터/ }));
  expect(screen.getByRole("cell", { name: "198.51.100.41" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /다음 · 추가 자료/ }));
  expect(screen.getByText("관측 3")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /다음 · 판단 예시/ }));
  expect(screen.getByText("판단 분류 · 공격 시도")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /W02.*주기 접속/ }));
  await screen.findByRole("heading", { name: "W02 · 주기 접속" }, { timeout: 10000 });
  expect(screen.getByRole("heading", { name: "조사 범위" })).toBeTruthy();
});

it("목록을 검색하고 범주와 페이지를 바꾸면 보이는 사례에서 조사를 다시 시작한다", async () => {
  const index = Array.from({ length: 60 }, (_, i) => ({
    id: `W${String(i + 1).padStart(2, "0")}`, title: i === 59 ? "원격 실행" : `연결 ${i + 1}`,
    category: i === 59 ? "내부 이동" : "웹", classification: i === 59 ? "침해 확인" : "보류",
    route: i < 6 ? "candidate" : "pivot"
  }));
  const steps = Array.from({ length: 5 }, (_, i) => ({ action: `화면 ${i}`, finding: `관측 ${i}` }));
  const load = vi.fn(async (name: string) => name === "index.json" ? index : { ...index.find(c => name === c.id + ".json"), steps });
  const download = vi.fn();
  render(<PlatformCases loadJson={load} assetUrl={f => "/offline/" + f} onDownload={download} />);
  await screen.findByRole("heading", { name: "W07 · 연결 7" });
  expect(screen.getByText("전체 60건 중 60건 · 1–9번째")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /다음 · 경보 단서/ }));
  expect(screen.getByRole("heading", { name: "경보 단서로 1차 조회" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "다음 페이지" }));
  await screen.findByRole("heading", { name: "W10 · 연결 10" });
  expect(screen.getByRole("heading", { name: "조사 범위" })).toBeTruthy();
  const input = screen.getByRole("searchbox", { name: "사례 검색" });
  fireEvent.change(input, { target: { value: " w60  침해 확인 " } });
  expect(screen.queryByRole("heading", { name: "W10 · 연결 10" })).toBeNull();
  await screen.findByRole("heading", { name: "W60 · 원격 실행" });
  fireEvent.click(screen.getByRole("button", { name: /원본 ZIP/ }));
  expect(download).toHaveBeenCalledWith("W60");
  fireEvent.change(input, { target: { value: "내부 실행" } });
  expect(screen.getByText("전체 60건 중 1건 · 1–1번째")).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: "사례 범주" }), { target: { value: "웹" } });
  expect(screen.getByText("조건에 맞는 사례가 없습니다.")).toBeTruthy();
  expect(screen.queryByRole("heading", { name: "W60 · 원격 실행" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "필터 초기화" }));
  await screen.findByRole("heading", { name: "W01 · 연결 1" });
  fireEvent.change(screen.getByRole("combobox", { name: "사례 범주" }), { target: { value: "내부 이동" } });
  await screen.findByRole("heading", { name: "W60 · 원격 실행" });
});

it("후보함에서 연 사례는 그 사례의 페이지로 바로 열리고 골든 후보 담기 단추가 있다", async () => {
  const index = Array.from({ length: 60 }, (_, i) => ({ id: `W${String(i + 1).padStart(2, "0")}`, title: `사례 ${i + 1}`, classification: "침해 확인", route: "pivot" }));
  const steps = Array.from({ length: 5 }, (_, i) => ({ action: `화면 ${i}`, finding: `관측 ${i}` }));
  const load = vi.fn(async (name: string) => name === "index.json" ? index : { ...index.find(c => name === c.id + ".json"), steps });
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ items: [] }), { headers: { "content-type": "application/json" } })));
  render(<MemoryRouter><PlatformCases loadJson={load} assetUrl={f => "/offline/" + f} initialCase="W26" candidates /></MemoryRouter>);
  await screen.findByRole("heading", { name: "W26 · 사례 26" });
  expect(screen.getByText("전체 60건 중 60건 · 19–27번째")).toBeTruthy();
  expect(screen.getByRole("button", { name: "골든 후보로 담기" })).toBeTruthy();
  vi.unstubAllGlobals();
});
