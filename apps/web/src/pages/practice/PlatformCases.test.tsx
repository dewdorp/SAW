import { cleanup, fireEvent, render, screen } from "@testing-library/react";
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
