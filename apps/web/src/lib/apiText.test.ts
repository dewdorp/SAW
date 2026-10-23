import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("api.text response contract", () => {
  it.each([
    ["single NDJSON record", "application/x-ndjson", '{"schema":"saw.golden.answers.v2","answers":{"text":"합성 <script>x</script>"}}\n'],
    ["multiple NDJSON records", "application/x-ndjson; charset=utf-8", '{"example_id":"g1","answers":{"truth":"합성"}}\r\n{"example_id":"g2","answers":{"truth":"둘째"}}\r\n'],
    ["JSON export preview", "application/json", '{\n  "rule": "synthetic", "enabled": false\n}\n'],
    ["Markdown case export", "text/markdown; charset=utf-8", "# 합성 사례\n\n공백과 줄바꿈 유지\n"],
    ["YAML detection export", "application/yaml", "title: synthetic\ndetection:\n  condition: selection\n"],
    ["empty text", "text/plain", ""],
  ])("returns exact raw text for %s", async (_name, contentType, raw) => {
    const fetchMock=vi.fn(async () => new Response(raw, {status:200,headers:{"content-type":contentType}}));
    vi.stubGlobal("fetch",fetchMock);
    await expect(api.text("/synthetic-export")).resolves.toBe(raw);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/synthetic-export",expect.objectContaining({method:"GET",credentials:"same-origin",headers:{}}));
  });

  it("keeps normal JSON API decoding unchanged", async () => {
    vi.stubGlobal("fetch",vi.fn(async () => new Response('{"items":[{"id":"synthetic"}]}',{headers:{"content-type":"application/json"}})));
    await expect(api.get("/items")).resolves.toEqual({items:[{id:"synthetic"}]});
  });

  it.each([
    [403,"application/json",'{"detail":"정답 열람 권한 없음"}',"정답 열람 권한 없음"],
    [409,"application/problem+json",'{"title":"합성 상태 충돌"}',"합성 상태 충돌"],
    [503,"text/plain","synthetic service unavailable","synthetic service unavailable"],
  ])("preserves an HTTP %s error for a text request", async (status, contentType, body, detail) => {
    vi.stubGlobal("fetch",vi.fn(async () => new Response(body,{status,headers:{"content-type":contentType}})));
    const error=await api.text("/synthetic-export").catch(value=>value);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({status,detail,message:detail});
  });

  it("keeps unauthorized events and JSON errors for text requests while excluding auth routes", async () => {
    const dispatch=vi.spyOn(window,"dispatchEvent");
    vi.stubGlobal("fetch",vi.fn(async () => new Response('{"detail":"synthetic session expired"}',{status:401,headers:{"content-type":"application/json"}})));
    await expect(api.text("/synthetic-export")).rejects.toMatchObject({status:401,detail:"synthetic session expired"});
    expect(dispatch.mock.calls.filter(([event])=>event.type==="saw:unauthorized")).toHaveLength(1);
    await expect(api.text("/auth/synthetic")).rejects.toMatchObject({status:401,detail:"synthetic session expired"});
    expect(dispatch.mock.calls.filter(([event])=>event.type==="saw:unauthorized")).toHaveLength(1);
  });
});
