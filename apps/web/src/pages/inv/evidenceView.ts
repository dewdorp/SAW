import type { Filter } from "../../context/invContext";
import { fmtTime } from "../../lib/format";

export type LogProfile = "common" | "http" | "network";
export type ColumnMode = "auto" | LogProfile | "custom";
export const PRESETS: Record<LogProfile, string[]> = {
  common: ["timestamp", "data_source", "src_ip", "dst_ip", "dst_port", "protocol", "source_file"],
  http: ["timestamp", "src_ip", "dst_ip", "method", "hostname", "uri", "status_code", "bytes_in", "bytes_out"],
  network: ["timestamp", "src_ip", "dst_ip", "dst_port", "enforcement_action", "protocol", "bytes_out", "bytes_in"],
};
export const PROFILE_NAMES: Record<LogProfile, string> = {common: "공통 열", http: "NDR·HTTP 열", network: "FW·연결 열"};
const LABEL: Record<string,string> = {
  timestamp: "시각", data_source: "로그 종류", src_ip: "출발지 IP", src_cloud: "출발지 클라우드", method: "요청 방식", hostname: "요청 호스트",
  uri: "요청 경로", uri_template: "경로 유형", status_code: "HTTP 응답", user_agent: "요청 프로그램", ua_class: "프로그램 분류",
  domain: "도메인", dst_ip: "목적지 IP", dst_port: "목적지 포트", src_port: "출발지 포트", protocol: "프로토콜",
  enforcement_action: "처리 결과", user: "계정", tags: "태그", source_file: "원본 파일", bytes_out: "바이트(out)", bytes_in: "바이트(in)",
};
export const ALL_COLS = Object.keys(LABEL);
export function columnLabel(c: string, p: LogProfile = "common"): string {
  if(c === "bytes_in" && p !== "common") return p === "http" ? "요청 바이트" : "수신 바이트";
  if(c === "bytes_out" && p !== "common") return p === "http" ? "응답 바이트" : "송신 바이트";
  return LABEL[c] || c;
}
export const profileOf = (s: unknown): LogProfile => ["web","http","waf","zeek_http"].includes(String(s)) ? "http" :
  ["firewall","connection","zeek_conn"].includes(String(s)) ? "network" : "common";

// Use an explicit restriction or a complete source distribution. The first loaded page is not a census.
export function profileForScope(filters: Filter[], inventory?: {buckets?: {key: unknown}[]; other?: number}): LogProfile {
  let names: string[] | undefined;
  const restricted = filters.filter(f => f.field === "data_source");
  for (const f of restricted) {
    const vs = f.op === "is" ? [String(f.value)] : f.op === "in" && Array.isArray(f.value) ? f.value.map(String) : undefined;
    if (vs) names = names ? names.filter(s => vs.includes(s)) : vs;
  }
  if (!names && inventory?.buckets?.length && inventory.other === 0) names = inventory.buckets.map(b => String(b.key));
  for (const f of restricted) {
    const vs = f.op === "is_not" ? [String(f.value)] : f.op === "not_in" && Array.isArray(f.value) ? f.value.map(String) : undefined;
    if (vs && names) names = names.filter(s => !vs.includes(s));
  }
  const kinds = new Set((names || []).map(profileOf));
  return kinds.size === 1 ? [...kinds][0] : "common";
}
export function displayField(c: string, val: unknown): string {
  if(val == null || val === "" || (Array.isArray(val) && !val.length)) return "—";
  if(c === "timestamp") return fmtTime(val as string);
  if(c === "data_source") return ({firewall:"방화벽",connection:"연결",web:"웹",waf:"WAF",ips:"IPS",ddos:"DDoS",zeek_conn:"Zeek 연결",zeek_http:"Zeek HTTP"} as Record<string,string>)[String(val)] || String(val);
  if(c === "enforcement_action") return ({allowed:"허용",blocked:"차단",unknown:"미확인",detected:"탐지"} as Record<string,string>)[String(val)] || String(val);
  if((c === "bytes_in" || c === "bytes_out") && /^\d+$/.test(String(val))) return String(val).replace(/\B(?=(\d{3})+(?!\d))/g, ",") + " B";
  return Array.isArray(val) ? val.join(" · ") : String(val);
}

export type ColumnPref = {mode: ColumnMode; custom: string[]};
const LEGACY_DEFAULT = ["timestamp", "data_source", "src_ip", "method", "uri", "status_code", "bytes_out", "user_agent"];
const allowed = (v: unknown): string[] => Array.isArray(v) ? [...new Set(v.filter((k): k is string => typeof k === "string" && ALL_COLS.includes(k)))] : [];
export function readColumnPref(): ColumnPref {
  const fallback: ColumnPref = {mode:"auto", custom:[]};
  try {
    const v = JSON.parse(localStorage.getItem("saw.rawview.v1") || "null");
    const custom = allowed(v?.custom);
    if (v && ["auto","common","http","network","custom"].includes(v.mode) && (v.mode !== "custom" || custom.length)) return {mode:v.mode,custom};
    const old = allowed(JSON.parse(localStorage.getItem("saw.rawcols") || "null"));
    // v0.2.3 automatically persisted its HTTP default, even when the analyst never chose it.
    return old.length && old.join() !== LEGACY_DEFAULT.join() ? {mode:"custom",custom:old} : fallback;
  } catch { return fallback; }
}
