import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { Me } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";

type Kind = "investigation" | "evidence" | "case";
type Target = { target_type: Kind; target_id: string; display_id: string; status: string; files?: number; bytes?: number; legal_hold?: boolean };
type Preview = Target & { confirmation: string; fingerprint: string; counts: Record<string, number>; retained: string[];
  blockers: string[]; blocker_details: { code: string; message: string }[]; scope_note: string };
type Receipt = { id: string; target_type: Kind; target_id: string; state: string; step: string;
  counts: Record<string, number>; retained: string[]; error_code: string };
const KINDS = { investigation: "조사 전체", evidence: "증거 묶음 · 포함 파일 전체", case: "케이스 폐기" };
const COUNTS: Record<string, string> = { investigations: "삭제할 조사", cases: "폐기할 케이스", evidence_bundles: "증거 묶음",
  files: "등록 파일", objects: "원본·파생 저장 파일", bytes: "정리할 바이트", events: "색인 이벤트", invalidated_findings: "무효화할 분석 결과",
  notes: "조사 노트", retained_custody: "보존할 인계 기록", retained_processing_runs: "보존할 처리 기록", retained_snapshots: "보존할 케이스 스냅샷" };
const STEP: Record<string, string> = { planned: "삭제 계획 저장됨", events_removed: "색인 정리 확인됨", objects_removed: "파일 정리 확인됨", completed: "완료" };
function Counts({ values }: { values: Record<string, number> }) {
  return <dl className="kv">{Object.entries(values).map(([name, count]) => <div key={name}><dt>{COUNTS[name] || name}</dt><dd>{count.toLocaleString()}</dd></div>)}</dl>;
}
export function AdminData({ me }: { me: Me }) {
  const canManage = me.permissions.includes("admin.data.delete");
  const qc = useQueryClient();
  const [kind, setKind] = useState<Kind>("investigation");
  const [offset, setOffset] = useState(0);
  const [impact, setImpact] = useState<Preview | null>(null);
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [result, setResult] = useState<Receipt | null>(null);
  const list = useQuery<{ items: Target[]; deletions: Receipt[]; has_more: boolean }>({ queryKey: ["admin-data", kind, offset],
    queryFn: () => api.get(`/admin/data?target_type=${kind}&offset=${offset}&limit=30`), enabled: canManage });
  const reset = () => { setImpact(null); setReason(""); setConfirmation(""); setResult(null); };
  const inspect = useMutation({ mutationFn: (target: Target) => api.post<Preview>("/admin/data/deletion-preview", {
    target_type: target.target_type, target_id: target.target_id }), onSuccess: (data) => { setImpact(data); setReason(""); setConfirmation(""); } });
  const done = (data: Receipt) => { setResult(data); setImpact(null); setConfirmation("");
    qc.invalidateQueries({ queryKey: ["admin-data"] }); qc.invalidateQueries({ queryKey: ["investigations"] }); qc.invalidateQueries({ queryKey: ["cases"] }); };
  const remove = useMutation({ mutationFn: () => api.post<Receipt>("/admin/data/deletions", {
    target_type: impact!.target_type, target_id: impact!.target_id, reason: reason.trim(), confirmation,
    preview_fingerprint: impact!.fingerprint }), onSuccess: done,
    onError: () => { setImpact(null); setConfirmation(""); } });
  const retry = useMutation({ mutationFn: (id: string) => api.post<Receipt>(`/admin/data/deletions/${id}/retry`), onSuccess: done });
  if (!canManage) return <div className="page"><p>데이터 관리 권한이 필요합니다.</p></div>;
  const busy = inspect.isPending || remove.isPending || retry.isPending;
  const receipts = list.data?.deletions || [];
  return <div className="page col">
    <PageHeader eyebrow="관리" title="데이터 관리" desc="원문을 열지 않고 조사·증거 묶음·케이스를 정리합니다. 관리자에게 분석 원문 열람 권한을 추가하지 않습니다." />
    <Panel title="삭제 범위를 먼저 확인하세요">
      <p>활성 데이터 정리이며 완전 소거가 아닙니다. 감사·인계·처리 이력, 폐기 케이스의 스냅샷·리비전, 별도 백업과 이미 내보낸 파일은 보존됩니다.</p>
      <p className="small">증거 묶음은 압축 내부 파일을 포함한 전체 업로드입니다. 일부 파일만 삭제하는 기능은 제공하지 않습니다. 증거 삭제 후 이 조사의 자동 분석 결과는 무효화되며 남은 자료를 재분석해야 합니다.</p>
      <p className="small">법적 보존·진행 작업·공유 근거는 자동 해제하지 않습니다. 차단 사유를 확인하고 해당 업무 화면 또는 보존 책임자에게 처리하세요.</p>
    </Panel>
    <Panel title="정리할 대상">
      <label>대상 종류 <select className="input" value={kind} disabled={busy} onChange={(e) => { setKind(e.target.value as Kind); setOffset(0); reset(); }}>{Object.entries(KINDS).map(([key, title]) => <option key={key} value={key}>{title}</option>)}</select></label>
      {list.isLoading && <Loading />}
      <ErrorBox error={list.error} />
      <table className="t"><thead><tr><th>ID</th><th>상태</th><th>파일·보존</th><th>작업</th></tr></thead><tbody>
        {(list.data?.items || []).map((item) => <tr key={item.target_id}><td className="mono">{item.display_id}</td><td>{item.status}</td>
          <td>{item.files !== undefined ? `${item.files}개 · ${(item.bytes || 0).toLocaleString()}바이트` : "—"}{item.legal_hold && " · 법적 보존"}</td>
          <td><button className="btn sm" disabled={busy} onClick={() => { reset(); inspect.mutate(item); }}>삭제 영향 확인</button></td></tr>)}
      </tbody></table>
      {list.isSuccess && !list.data.items.length && <p>해당하는 활성 대상이 없습니다.</p>}
      <div className="row"><button className="btn sm" disabled={!offset || busy} onClick={() => { setOffset(Math.max(0, offset - 30)); reset(); }}>이전</button>
        <span className="small">{offset + 1}번부터 · 최대 30개</span><button className="btn sm" disabled={!list.data?.has_more || busy} onClick={() => { setOffset(offset + 30); reset(); }}>다음</button></div>
    </Panel>
    <ErrorBox error={inspect.error || remove.error || retry.error} />
    {impact && <Panel title="삭제 영향 미리보기">
      <p><strong>{KINDS[impact.target_type]} · {impact.confirmation}</strong></p><p>{impact.scope_note}</p>
      <Counts values={impact.counts} /><h3>보존되는 항목</h3><ul>{impact.retained.map((text) => <li key={text}>{text}</li>)}</ul>
      {!!impact.blockers.length && <div role="alert"><strong>지금은 삭제할 수 없습니다.</strong><ul>{impact.blocker_details.map((b) => <li key={b.code}>{b.message}</li>)}</ul></div>}
      <label>삭제 사유<textarea aria-label="삭제 사유" className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} placeholder="정리 목적을 5자 이상 입력하세요" /></label>
      <label>대상 ID 확인<input aria-label="대상 ID 확인" className="input mono" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} placeholder={impact.confirmation} autoComplete="off" /></label>
      <p className="small">위 ID를 정확히 입력하세요. 실행 후 원본·색인을 되돌리려면 별도 백업 복원이 필요합니다. 케이스는 활성 목록에서 폐기하고 스냅샷·리비전은 보존합니다.</p>
      <button className="btn" disabled={busy || !!impact.blockers.length || reason.trim().length < 5 || confirmation !== impact.confirmation} onClick={() => remove.mutate()}>{remove.isPending ? "정리 중…" : "확인한 범위 삭제"}</button>
    </Panel>}
    {result && <div role={result.state === "COMPLETED" ? "status" : "alert"} className="panel">
      <strong>{result.state === "COMPLETED" ? "정리 완료 · 보존 항목은 유지됩니다." : "미완료 · 삭제가 끝나지 않았습니다. 영수증에서 재시도하세요."}</strong><p className="mono">영수증 {result.id}</p>
    </div>}
    <Panel title="최근 삭제 영수증">
      <p className="small">미완료 작업의 조사에는 접근과 새 분석을 막습니다. 실패를 확인한 뒤 재시도하면 이미 정리된 단계부터 이어갑니다.</p>
      {receipts.map((r) => <article key={r.id} className="panel"><div className="row wrap"><strong>{r.state === "COMPLETED" ? "정리 완료" : r.state === "FAILED" ? "미완료 · 재시도 필요" : "진행 중"}</strong><span>{STEP[r.step] || r.step}</span></div>
        <p className="mono small">{r.target_id} · 영수증 {r.id}</p>{r.error_code && <p className="small">오류 코드: {r.error_code}</p>}
        <Counts values={r.counts} />{r.state !== "COMPLETED" && <button className="btn sm" disabled={busy} onClick={() => retry.mutate(r.id)}>삭제 재시도</button>}
      </article>)}
      {!receipts.length && <p>삭제 영수증이 없습니다.</p>}
    </Panel>
  </div>;
}
