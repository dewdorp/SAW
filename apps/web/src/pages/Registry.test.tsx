import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ME, mockApi, renderUI } from "../test/helpers";
import { Registry } from "./Registry";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("alert-name registry", () => {
  it("records what an alert observes, cannot prove, needs next and which questions it feeds", async () => {
    const api = mockApi({
      "GET /auth/me": [200, { ...ME, permissions: [...ME.permissions, "signature.manage"] }],
      "GET /source-context/org-units": [200, []],
      "GET /knowledge/device-signatures": [200, { items: [] }],
      "POST /knowledge/device-signatures": [201, { id: "s1" }],
    });
    renderUI(<Registry />);
    fireEvent.click(await screen.findByRole("button", { name: "새 공격명 등록" }));
    fireEvent.change(screen.getByLabelText("장비 원래 공격명"), { target: { value: "SYNTH-SQLI-PROBE" } });
    fireEvent.change(screen.getByLabelText("분석가가 확인한 의미"), { target: { value: "요청 값에 SQL 구문 형태" } });
    fireEvent.change(screen.getByLabelText("연결할 조사 질문"), { target: { value: "q02, Q09" } });
    fireEvent.change(screen.getByLabelText("이 공격명이 관측하는 것 (한 줄에 하나)"), { target: { value: "요청 값의 구문 형태" } });
    fireEvent.change(screen.getByLabelText("이 공격명만으로 입증하지 못하는 것 (한 줄에 하나)"), { target: { value: "DB에서 실행됐는지\n데이터가 나갔는지" } });
    fireEvent.change(screen.getByLabelText("장비 처리값 (한 줄에 하나, 예: block, alert)"), { target: { value: "block" } });
    fireEvent.click(screen.getByRole("button", { name: "등록" }));
    await waitFor(() => expect(api.find("POST", "/knowledge/device-signatures")).toHaveLength(1));
    expect(api.find("POST", "/knowledge/device-signatures")[0].body).toMatchObject({
      original_name: "SYNTH-SQLI-PROBE", linked_questions: ["Q02", "Q09"], observes: ["요청 값의 구문 형태"],
      cannot_prove: ["DB에서 실행됐는지", "데이터가 나갔는지"], action_values: ["block"], followup_data: [] });
  });
});
