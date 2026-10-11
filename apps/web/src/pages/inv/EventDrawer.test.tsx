import { fireEvent, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useInvStore } from "../../context/invContext";
import { mockApi, renderUI } from "../../test/helpers";
import { EventDrawer } from "./EventDrawer";

const INV = "inv-1";
const EVENT = { event_id: "ev1", data_source: "zeek_http", src_ip: "203.0.113.66", src_port: 40100, dst_ip: "10.20.1.15", dst_port: 80,
  source_file: "incident.pcap:http.log", raw_ref: { line_no: 1 }, parser: "zeek_json", parser_version: "1.0.0", raw_visual: "{}" };

beforeEach(() => useInvStore.getState().set(INV, { eventId: "ev1" }));
afterEach(() => { vi.unstubAllGlobals(); useInvStore.getState().set(INV, { eventId: null }); });

describe("Event drawer — session stream", () => {
  it("shows reassembled client and server text separately, never as HTML", async () => {
    const xss = "<img src=x onerror=alert(1)>";
    mockApi({
      [`GET /investigations/${INV}/events/ev1`]: [200, { event: EVENT, masked_kinds: [], related_findings: [], can_unmask: false }],
      [`GET /investigations/${INV}/forensics/sessions/ev1/stream`]: [200, {
        client: "203.0.113.66:40100", server: "10.20.1.15:80", packets: 8, client_bytes: 88, server_bytes: 81, missed_bytes: 12, truncated: false,
        client_view: { mode: "text", text: `GET /item?q=${xss} HTTP/1.1\r\nCookie: ●●●●`, masked: ["auth_header"] },
        server_view: { mode: "hex", text: "00000000  4d 5a 90 00", masked: [] } }],
    });
    renderUI(<EventDrawer inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: "⇄ 스트림 보기" }));
    const dlg = await screen.findByRole("dialog", { name: "세션 스트림" });
    expect(await screen.findByText(/GET \/item\?q=/)).toBeTruthy();
    expect(dlg.querySelector("img")).toBeNull();
    expect(screen.getByText("서버 → 클라이언트 (HEX)")).toBeTruthy();
    expect(screen.getByText("누락 12 B")).toBeTruthy();
    expect(screen.getByText("마스킹: auth_header")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "닫기" }));
    expect(screen.queryByRole("dialog", { name: "세션 스트림" })).toBeNull();
  });

  it("explains why packets cannot be extracted for uploaded Zeek logs", async () => {
    mockApi({
      [`GET /investigations/${INV}/events/ev1`]: [200, { event: EVENT, masked_kinds: [], related_findings: [], can_unmask: false }],
      [`GET /investigations/${INV}/network/sessions/ev1/pcap`]: [409, { detail: "이 이벤트는 PCAP에서 추출된 것이 아닙니다" }],
    });
    renderUI(<EventDrawer inv={INV} />);
    fireEvent.click(await screen.findByRole("button", { name: /세션 PCAP/ }));
    expect(await screen.findByText(/PCAP에서 추출된 것이 아닙니다/)).toBeTruthy();
  });

  it("warns when the session has missing packets", async () => {
    const gappy = { ...EVENT, ext: { zeek: { capture_gap: true } } };
    mockApi({ [`GET /investigations/${INV}/events/ev1`]: [200, { event: gappy, masked_kinds: [], related_findings: [], can_unmask: false }] });
    renderUI(<EventDrawer inv={INV} />);
    expect((await screen.findByRole("alert")).textContent).toContain("패킷 빠짐");
  });

  it("uses Korean tab names", async () => {
    mockApi({ [`GET /investigations/${INV}/events/ev1`]: [200, { event: EVENT, masked_kinds: [], related_findings: [], can_unmask: false }] });
    renderUI(<EventDrawer inv={INV} />);
    for (const t of ["정규화", "원본", "엔티티", "관련 탐지", "전후 로그"]) expect(await screen.findByRole("button", { name: t })).toBeTruthy();
  });

  it("links an NDR event to the captured session and opens its packets", async () => {
    const NDR = { ...EVENT, data_source: "web", parser: "ndr_meta_csv", source_file: "qsearch.csv", method: "GET", uri: "/login.do" };
    mockApi({
      [`GET /investigations/${INV}/events/ev1`]: [200, { event: NDR, masked_kinds: [], related_findings: [], can_unmask: false }],
      [`GET /investigations/${INV}/network/linked/ev1`]: [200, { pcap_session: true, groups: [
        { relation: "same_session", data_source: "zeek_http", count: 1, events: [{ event_id: "p1", timestamp: "2026-10-03T08:38:47Z",
          src_ip: "203.0.113.66", src_port: 40100, dst_ip: "10.20.1.15", dst_port: 80, method: "GET", uri: "/login.do", status_code: 200, source_file: "incident.pcap" }] },
        { relation: "same_request", data_source: "web", count: 1, events: [{ event_id: "w1", timestamp: "2026-10-03T08:38:47Z",
          src_ip: "203.0.113.66", dst_ip: null, method: "GET", uri: "/login.do", status_code: 200, source_file: "access.log" }] }] }],
    });
    renderUI(<EventDrawer inv={INV} />);
    expect(await screen.findByRole("button", { name: "⇄ 스트림 보기" })).toBeTruthy();  // NDR row, packets from the PCAP
    fireEvent.click(await screen.findByRole("button", { name: "연결된 기록 2" }));
    expect(await screen.findByText("같은 세션")).toBeTruthy();
    expect(screen.getByText("같은 요청")).toBeTruthy();
    expect(screen.getByText(/원본 패킷이 있어/)).toBeTruthy();
    fireEvent.click(screen.getByText("incident.pcap"));
    expect(useInvStore.getState().get(INV).eventId).toBe("p1");
  });

  it("hides packet buttons for log events whose session was not captured", async () => {
    mockApi({
      [`GET /investigations/${INV}/events/ev1`]: [200, { event: { ...EVENT, data_source: "web" }, masked_kinds: [], related_findings: [], can_unmask: false }],
      [`GET /investigations/${INV}/network/linked/ev1`]: [200, { pcap_session: false, groups: [] }],
    });
    renderUI(<EventDrawer inv={INV} />);
    expect(await screen.findByText(/연결된 기록/)).toBeTruthy();
    await vi.waitFor(() => expect(screen.queryByRole("button", { name: "⇄ 스트림 보기" })).toBeNull());
  });
});
