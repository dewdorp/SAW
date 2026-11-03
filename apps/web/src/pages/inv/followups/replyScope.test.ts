import { describe, expect, it } from "vitest";
import { blankScope, parseConnections, replyScopeBody } from "./FollowUpFields";

describe("reply connections", () => {
  it("reads one connection per line in either written form", () => {
    expect(parseConnections("10.31.1.30 → 10.31.0.30:443\n10.31.1.30, 10.31.0.31, 3389\n10.31.1.30 -> 10.31.0.32:미기록")).toEqual([
      { src_ip: "10.31.1.30", dst_ip: "10.31.0.30", dst_port: 443 },
      { src_ip: "10.31.1.30", dst_ip: "10.31.0.31", dst_port: 3389 },
      { src_ip: "10.31.1.30", dst_ip: "10.31.0.32", dst_port: null }]);
    expect(() => parseConnections("10.31.1.30 → 10.31.0.30:99999")).toThrow(/0~65535/);
    expect(() => parseConnections("10.31.1.30")).toThrow(/형식/);
  });
  it("sends the stated connections with the reply scope so a matching reply can match", () => {
    const body = replyScopeBody({ ...blankScope(), src: "10.31.1.30", conns: "10.31.1.30 → 10.31.0.30:443" });
    expect(body?.connections).toEqual([{ src_ip: "10.31.1.30", dst_ip: "10.31.0.30", dst_port: 443 }]);
    expect(replyScopeBody({ ...blankScope(), conns: "10.31.1.30 → 10.31.0.30:443" })).not.toBeNull();
  });
});
