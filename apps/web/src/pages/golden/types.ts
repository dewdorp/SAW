export type Eligibility = { enabled: boolean; reasons: string[] };
export type Ref = { id: string; sha256: string };
export type Page<T> = { items: T[]; next_cursor: string | null };
export type Profile = { id: string; kind: "pseudonymization" | "model_conversion"; profile_key: string; version: number; payload_sha256: string; implementation: string; payload: Record<string, unknown>; capabilities: string[]; limits: string[] };
export type Capture = { schema: string; captured_at: string; check_revisions: {check_id: string; revision_id: string; revision: number; payload_sha256: string}[]; followup_versions: {followup_id: string; version_id: string; revision: number; payload_sha256: string}[]; analysis_runs: (Ref & {scope_sha256: string})[]; source_investigation_ids: string[]; contributor_ids: string[] };
export type GoldenSelection = {version_id: string; content_sha256: string} | {version_id: string; input_sha256: string};
export const TERMINAL = ["COMPLETED", "FAILED", "CANCELLED"];
export const ROOT = "/knowledge/golden";
export const HASH = /^[a-f0-9]{64}$/;
export const lines = (value: string) => value.split("\n").map(v => v.trim()).filter(Boolean);
export function hiddenHoldout(g: any) { return g?.status === "adopted" && g?.split === "holdout"; }
export function safeCaseLabel(g: any) { return hiddenHoldout(g) ? `비공개 사례 ${g.id} v${g.version}` : `${g.title || g.id} v${g.version}`; }
export function exactSelection(g: any): GoldenSelection {
  const key = hiddenHoldout(g) ? "input_sha256" : "content_sha256";
  if (!HASH.test(g?.[key] || "")) throw new Error("정확한 사례 해시가 없습니다. 목록을 다시 확인하세요.");
  return key === "input_sha256" ? {version_id:g.id,input_sha256:g[key]} : {version_id:g.id,content_sha256:g[key]};
}

export const principalKey = (me:any) => JSON.stringify([me?.id,me?.permissions]);
