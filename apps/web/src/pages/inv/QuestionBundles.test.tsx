import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { QuestionBundles } from "./QuestionBundles";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
beforeEach(() => { useInvStore.setState({ byInv: {} }); });

const item = { title: "내부 서버 10.20.1.10가 외부 클라이언트 198.51.100.50에게 보낸 응답 96.0MB — 외부 반출 후보",
  observed: "응답 96MB", basis: { threshold_bytes: 1 }, records: 12, filters: [{ field: "src_ip", op: "is", value: "198.51.100.50" }],
  unknown: ["실제 데이터 종류"], normal_possibilities: ["정상 백업"], next_questions: ["승인된 업무였는지"], entities: [], time: {} };
const data = { version: "question-bundles/1", sensitivity: "normal", note: "판정이 아닙니다. 정상이라는 뜻이 아닙니다.",
  thresholds: { paths: 30, bytes: 52428800, periodic_min: 8, periodic_cv: 0.15, targets: 10, ports: 10 },
  bundles: [{ id: "web_attack", title: "A. 웹 공격", status: "insufficient_data", missing: ["HTTP 요청 기록"], items: [] },
    { id: "transfer", title: "B. 대량 반출", status: "found", items: [item] },
    { id: "periodic", title: "C. 반복 통신", status: "looked_none", items: [] }] };

describe("question bundles", () => {
  it("separates no data from nothing found, and turns an item into its logs and a check", async () => {
    const events = Array.from({ length: 12 }, (_, i) => ({ event_id: `e${i}` }));
    const api = mockApi({
      "GET /investigations/i1/question-bundles": [200, data],
      "POST /investigations/i1/query/events": [200, { events }],
      "POST /investigations/i1/checks": [201, { id: "c1" }],
    }) as any;
    renderUI(<QuestionBundles inv="i1" />);
    expect(await screen.findByText("자료 부족 — 판단 불가")).toBeTruthy();
    expect(screen.getByText("이 기준에서는 보이지 않음 (정상 판정 아님)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "관련 로그 보기" }));
    expect(useInvStore.getState().byInv.i1.tab).toBe("raw");
    expect(useInvStore.getState().byInv.i1.filters).toEqual(item.filters);
    fireEvent.click(screen.getByRole("button", { name: "확인 기록으로 남기고 확인 요청 작성" }));
    await waitFor(() => expect(api.find("POST", "/investigations/i1/checks")).toHaveLength(1));
    const body = api.find("POST", "/investigations/i1/checks")[0].body;
    expect(body.target_type).toBe("set");
    expect(body.scope).toMatchObject({ coverage: "all", loaded: 12 });
    expect(body.evidence).toHaveLength(12);
  });
});
