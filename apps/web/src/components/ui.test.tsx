import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Badge, Claim, EmptyState, PageHeader, Stat } from "./ui";

describe("shared UI", () => {
  it("claim badges name the kind of knowledge, with an explanation", () => {
    render(<div><Claim type="OBSERVED" /><Claim type="DERIVED" /><Claim type="INFERRED" /><Claim type="VERDICT" /><Claim type="BOGUS" /><Claim /></div>);
    const labels = [...document.querySelectorAll(".claim")].map((e) => e.textContent);
    expect(labels).toEqual(["관측", "계산", "추론", "판정"]);
    expect(screen.getByText("추론").getAttribute("title")).toContain("가설");
    expect(document.querySelector(".claim.c-observed")).toBeTruthy();
  });

  it("page header renders eyebrow, title, description and actions", () => {
    render(<PageHeader eyebrow="빠른 분석" title="로그 분석" desc="형식을 자동 판별" actions={<button>실행</button>} />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("로그 분석");
    expect(screen.getByText("빠른 분석").className).toBe("eyebrow");
    expect(screen.getByText("형식을 자동 판별")).toBeTruthy();
    expect(screen.getByRole("button", { name: "실행" })).toBeTruthy();
  });

  it("stat tiles are clickable only when they have an action", () => {
    const go = vi.fn();
    render(<div><Stat label="심각" value={3} tone="critical" onClick={go} /><Stat label="연결" value="1,718" sub="HTTP 12" /></div>);
    fireEvent.click(screen.getByRole("button"));
    expect(go).toHaveBeenCalledOnce();
    expect(screen.getAllByRole("button")).toHaveLength(1);
    expect(document.querySelector(".stat.critical .stat-value")!.textContent).toBe("3");
  });

  it("badges and empty states render text content", () => {
    render(<div><Badge tone="bad">위장 · pe</Badge><EmptyState title="해당 파일 없음">설명</EmptyState></div>);
    expect(document.querySelector(".badge.bad")!.textContent).toBe("위장 · pe");
    expect(screen.getByRole("heading", { name: "해당 파일 없음" })).toBeTruthy();
  });
});
