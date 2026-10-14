import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../test/helpers";
import { ContentPackages } from "./ContentPackages";

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
const digest = "a".repeat(64);
const entry = { kind: "sigma", source_id: "demo", source_version: 1, content: { title: "합성 규칙", logic: "synthetic" }, fixtures: [] };
const doc = { schema: "saw.content-package/1", package_id: "demo-pack", revision: 1, requires: { content_engine: "saw-content-v1" }, payload_sha256: digest, entries: [entry] };
const base = { id: "p1", package_id: "demo-pack", revision: 1, digest, status: "staged", imported_by: "writer",
  document: doc, baseline: [], test_result: {}, receipt: {}, can_apply: false, can_rollback: false };
const preview = { digest, package_id: "demo-pack", revision: 1, integrity: "sha256_verified", origin: "not_authenticated",
  changes: [{ kind: "sigma", source_id: "demo", source_version: 1, action: "add", before: null, after: entry.content }] };

describe("offline content packages", () => {
  it("keeps verification separate from staging and invalidates an edited preview", async () => {
    const calls = mockApi({ "GET /content-packages": [200, { packages: [] }], "POST /content-packages/verify": [200, preview],
      "POST /content-packages/stage": [201, base], "GET /content-packages/p1": [200, base] });
    renderUI(<ContentPackages />);
    fireEvent.change(await screen.findByLabelText("콘텐츠 JSON"), { target: { value: JSON.stringify(doc) } });
    fireEvent.click(screen.getByRole("button", { name: "파일 검증·변경 미리보기" }));
    expect(await screen.findByText(/발행자 신원은 인증되지/)).toBeTruthy();
    expect(calls.find("POST", "/content-packages/stage")).toHaveLength(0);
    expect(screen.getByRole("button", { name: "반입 초안 저장" })).toHaveProperty('disabled', false);
    fireEvent.change(screen.getByLabelText("콘텐츠 JSON"), { target: { value: JSON.stringify(doc) + " " } });
    expect(screen.getByRole("button", { name: "반입 초안 저장" })).toHaveProperty('disabled', true);
    fireEvent.click(screen.getByRole("button", { name: "파일 검증·변경 미리보기" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "반입 초안 저장" })).toHaveProperty('disabled', false));
    fireEvent.click(screen.getByRole("button", { name: "반입 초안 저장" }));
    expect(await screen.findByText("반입한 사람: writer")).toBeTruthy();
    expect(calls.calls.some(c => c.url.endsWith("/apply"))).toBe(false);
  });

  it("requires passing tests, a distinct reviewer, and an explicit reason to apply", async () => {
    let selected = { ...base, test_result: { passed: true, kind: "package_fixture", results: [] }, can_apply: true };
    const calls = mockApi({ "GET /content-packages": [200, { packages: [selected] }], "GET /content-packages/p1": () => [200, selected],
      "POST /content-packages/p1/apply": () => { selected = { ...selected, status: "applied", can_apply: false }; return [200, selected]; } });
    renderUI(<ContentPackages />);
    fireEvent.click(await screen.findByRole("button", { name: "demo-pack r1" }));
    const apply = await screen.findByRole("button", { name: "승인·적용" });
    expect(apply).toHaveProperty('disabled', true);
    fireEvent.change(screen.getByLabelText("검토·되돌리기 사유"), { target: { value: "합성 예제와 변경 범위를 검토함" } });
    fireEvent.click(apply);
    await waitFor(() => expect(calls.find("POST", "/content-packages/p1/apply")).toHaveLength(1));
    expect(calls.find("POST", "/content-packages/p1/apply")[0].body).toEqual({ digest, reason: "합성 예제와 변경 범위를 검토함" });
  });

  it("hides apply authority for the importer and shows failed synthetic fixtures", async () => {
    const failed = { ...base, test_result: { passed: false, kind: "package_fixture",
      results: [{ source_id: "demo", name: "normal fixture", expected: "no_match", passed: false }] } };
    mockApi({ "GET /content-packages": [200, { packages: [failed] }], "GET /content-packages/p1": [200, failed] });
    renderUI(<ContentPackages />);
    fireEvent.click(await screen.findByRole("button", { name: "demo-pack r1" }));
    expect(await screen.findByText("normal fixture")).toBeTruthy();
    expect(screen.getByRole("button", { name: "승인·적용" })).toHaveProperty('disabled', true);
    expect(screen.getByText(/과거 조사 재생 시험/)).toBeTruthy();
  });

  it("shows drift and refuses rollback after the live state changed", async () => {
    const applied = { ...base, status: "applied", can_rollback: true };
    const calls = mockApi({ "GET /content-packages": [200, { packages: [applied] }], "GET /content-packages/p1": [200, applied],
      "GET /content-packages/p1/rollback-preview": [200, { digest, can_rollback: false, changes: [{ source_id: "demo", action: "restore", drift: true }] }] });
    renderUI(<ContentPackages />);
    fireEvent.click(await screen.findByRole("button", { name: "demo-pack r1" }));
    fireEvent.click(await screen.findByRole("button", { name: "되돌리기 영향 확인" }));
    expect(await screen.findByText(/이후 변경 있음/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "확인한 이전 승인본으로 되돌리기" })).toHaveProperty('disabled', true);
    expect(calls.calls.some(c => c.method === "POST")).toBe(false);
  });

  it("explains why the prior rule author cannot approve a rollback", async () => {
    const blocked = "직전 룰 작성자는 자기 룰의 복구를 승인할 수 없습니다. 다른 검토자가 필요합니다.";
    const applied = { ...base, status: "applied", can_rollback: false, rollback_blocked_reasons: [blocked] };
    mockApi({ "GET /content-packages": [200, { packages: [applied] }], "GET /content-packages/p1": [200, applied],
      "GET /content-packages/p1/rollback-preview": [200, { digest, can_rollback: false, rollback_blocked_reasons: [blocked],
        changes: [{ source_id: "demo", action: "restore", drift: false }] }] });
    renderUI(<ContentPackages />);
    fireEvent.click(await screen.findByRole("button", { name: "demo-pack r1" }));
    expect(await screen.findByText(blocked)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "되돌리기 영향 확인" }));
    const rollback = await screen.findByRole("button", { name: "확인한 이전 승인본으로 되돌리기" });
    fireEvent.change(screen.getByLabelText("검토·되돌리기 사유"), { target: { value: "합성 복구 검토" } });
    expect(rollback).toHaveProperty("disabled", true);
    expect(screen.getByText(blocked)).toBeTruthy();
  });

});
