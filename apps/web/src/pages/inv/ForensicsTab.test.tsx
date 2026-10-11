import { fireEvent, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { api } from "../../lib/api";
import { mockApi, renderUI } from "../../test/helpers";
import { ForensicsTab } from "./ForensicsTab";

vi.mock("../../viz/EChart", () => ({ EChart: () => <div data-testid="chart" />, axisStyle: {}, safeTooltip: () => () => "" }));
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

const INV = "inv-1";
const SUMMARY = {
  captures: [{ file_id: "f1", name: "incident.pcap", engine: "pcap(builtin)", sha256: "ab".repeat(32), note: "",
    summary: { packets: 820, decoded: 820, undecoded: 0, duplicates: 2, ip_bytes: 59000, files_extracted: 11, extracted_bytes: 40000,
      first_ts: 1760000000, last_ts: 1760000600, services: { http: 12, ftp: 1 }, top_talkers: [{ ip: "203.0.113.66", bytes: 30000 }] } }],
  verdict: { level: "high", text: "침해 정황 의심 — 높음 이상 탐지가 있습니다. 근거를 확인하고 판단하세요." },
  severity: { critical: 3, high: 2, medium: 4, low: 1, info: 0 },
  counts: { connections: 40, http: 12, dns: 25, tls: 0, files: 14, masquerade: 1, auth: 8, ids_alerts: 0 },
  file_categories: [{ key: "executable", count: 1 }, { key: "web", count: 5 }],
  auth_outcomes: [], traffic: { buckets: [{ key: 1760000000, count: 10 }] },
  findings: [{ id: "fw", title: "Potential Web Shell Upload and Use", risk_level: "critical", time_start: null }],
};
const FILES = [
  { event_id: "e1", sha256: "c".repeat(64), md5: "m", sha1: "s", filename: "invoice.jpg", kind: "pe", category: "executable", masquerade: true,
    declared_type: "image/jpeg", size: 10500, entropy: 7.99, tx: "45.77.12.34", rx: "10.20.5.33", extracted: true, risky: true, source: "HTTP" },
  { event_id: "e2", sha256: "d".repeat(64), filename: "index.html", kind: "html", category: "web", masquerade: false, size: 400,
    entropy: 4.1, tx: "10.20.1.15", rx: "203.0.113.66", extracted: true, risky: false, source: "HTTP" },
];
const CREDS = [
  { event_id: "a1", protocol: "ftp", user: "ftpadmin", outcome: "success", src_ip: "203.0.113.66", dst_ip: "10.20.1.21", dst_port: 21,
    password_length: 8, password_weak: true, password_equals_user: true },
  { event_id: "a2", protocol: "smtp", user: "kim", outcome: "failure", src_ip: "10.20.5.33", dst_ip: "10.20.1.25", dst_port: 25,
    password_length: 11, password_weak: false, password_equals_user: false },
];
const routes = () => mockApi({
  [`GET /investigations/${INV}/forensics/summary`]: [200, SUMMARY],
  [`GET /investigations/${INV}/forensics/files`]: [200, FILES],
  [`GET /investigations/${INV}/forensics/credentials`]: [200, CREDS],
  [`GET /investigations/${INV}/forensics/certificates`]: [200, { tls_sessions: 9, with_certificate: 9, certificates: [
    { dst_ip: "45.77.12.34", dst_port: 443, external: true, server_names: ["update.example.com"], subject_cn: "localhost", issuer_cn: "localhost",
      not_before: "2026-10-02T09:00:00+00:00", not_after: "2026-11-01T09:00:00+00:00", self_signed: true, name_mismatch: true,
      expired_at_use: false, key: "rsa-1024", sha1: "aa".repeat(20), sha256: "bb".repeat(32), sessions: 3 },
    { dst_ip: "52.79.10.20", dst_port: 443, external: true, server_names: ["www.example.com"], subject_cn: "www.example.com", issuer_cn: "Example Root CA",
      not_before: "2026-03-17T09:00:00+00:00", not_after: "2027-03-17T09:00:00+00:00", self_signed: false, name_mismatch: false,
      expired_at_use: false, key: "rsa-2048", sha1: "cc".repeat(20), sha256: "dd".repeat(32), sessions: 3 }] }],
});

describe("PCAP forensics tab", () => {
  it("leads with the verdict and severity tiles, then the findings", async () => {
    routes();
    renderUI(<ForensicsTab inv={INV} />);
    expect((await screen.findByText(/침해 정황 의심/)).closest(".notice")!.className).toContain("high");
    const stats = document.querySelector(".stats") as HTMLElement;
    expect(within(stats).getByText("심각").parentElement!.textContent).toContain("3");
    expect(within(stats).getByText("위장 의심 1")).toBeTruthy();
    expect(screen.getByText("Potential Web Shell Upload and Use")).toBeTruthy();
    expect(screen.getByText("실행 파일 1")).toBeTruthy();
    expect(screen.getByTestId("chart")).toBeTruthy();
  });

  it("clicking a finding opens it in the findings tab", async () => {
    routes();
    renderUI(<ForensicsTab inv={INV} />);
    fireEvent.click(await screen.findByText("Potential Web Shell Upload and Use"));
    expect(useInvStore.getState().get(INV)).toMatchObject({ tab: "findings", findingId: "fw" });
  });

  it("lists risky extracted files by default and downloads them through the audited endpoint", async () => {
    routes();
    const dl = vi.spyOn(api, "download").mockResolvedValue({} as Response);
    renderUI(<ForensicsTab inv={INV} />);
    fireEvent.click(await screen.findByText("추출 파일", { selector: "button" }));
    expect(await screen.findByText("invoice.jpg")).toBeTruthy();
    expect(screen.queryByText("index.html")).toBeNull();
    expect(screen.getByText("위장 · pe").className).toContain("bad");
    fireEvent.click(screen.getByTitle("파일 다운로드 (감사 기록)"));
    await vi.waitFor(() => expect(dl).toHaveBeenCalledWith(`/investigations/${INV}/forensics/files/${"c".repeat(64)}/download`, "c".repeat(64)));
    fireEvent.click(screen.getByLabelText(/위험 유형만/));
    expect(await screen.findByText("index.html")).toBeTruthy();
  });

  it("shows cleartext authentications without any password value", async () => {
    routes();
    renderUI(<ForensicsTab inv={INV} />);
    fireEvent.click(await screen.findByText("평문 인증", { selector: "button" }));
    const row = (await screen.findByText("ftpadmin")).closest("tr")!;
    expect(within(row).getByText("성공")).toBeTruthy();
    expect(within(row).getByText("취약")).toBeTruthy();
    expect(within(row).getByText(/계정명과 동일/)).toBeTruthy();
    expect(screen.getByText("11자")).toBeTruthy();
    expect(screen.getByText(/비밀번호를 저장하지 않습니다/)).toBeTruthy();
  });

  it("lists server certificates with their anomalies", async () => {
    routes();
    renderUI(<ForensicsTab inv={INV} />);
    fireEvent.click(await screen.findByText("TLS 인증서", { selector: "button" }));
    const bad = (await screen.findByText("update.example.com")).closest("tr")!;
    expect(within(bad).getByText("자체 서명")).toBeTruthy();
    expect(within(bad).getByText("이름 불일치")).toBeTruthy();
    expect(within(bad).getByText("약한 키")).toBeTruthy();
    const ok = screen.getByText("Example Root CA").closest("tr")!;
    expect(within(ok).getByText("없음")).toBeTruthy();
    expect(screen.getByText(/TLS 1.3은 인증서가 암호화/)).toBeTruthy();
  });

  it("shows capture details", async () => {
    routes();
    renderUI(<ForensicsTab inv={INV} />);
    fireEvent.click(await screen.findByText("캡처 정보", { selector: "button" }));
    expect(screen.getByText("incident.pcap")).toBeTruthy();
    expect(screen.getByText("중복 프레임 제외").parentElement!.textContent).toContain("2");
    expect(screen.getByText("http 12")).toBeTruthy();
  });

  it("explains what to do when there is no PCAP evidence", async () => {
    mockApi({ [`GET /investigations/${INV}/forensics/summary`]: [200, { ...SUMMARY, captures: [] }] });
    renderUI(<ForensicsTab inv={INV} />);
    expect(await screen.findByText("PCAP 증거가 없습니다")).toBeTruthy();
  });
});
