import { ActivationHistory } from "./ActivationHistory";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";
import type { VersionRef } from "./RuleEditor";
export function GovernanceActions({ path, data, version, selectedTest, permissions, onChange, disabled = false }: { path: string; data: any; version: VersionRef; selectedTest: any; permissions: string[]; onChange: () => void; disabled?: boolean }) {
  const [reason, setReason] = useState(""); const [rollback, setRollback] = useState("");
  const pointers = data.pointers;
  const reviewer = permissions.includes("detection.approve");
  const validProof = selectedTest?.passed === true && selectedTest.scope?.method === "selected_truth_v1" && selectedTest.scope?.subject?.version_id === version.id && selectedTest.result?.execution === "complete" && selectedTest.proof?.proof_sha256 && selectedTest.proof?.rule_policy_sha256;
  const mutation = useMutation({ mutationFn: ({ action, body }: { action: string; body: any }) => api.post(`${path}/${action}`, body), onSuccess: onChange });
  const base = () => ({ expected_active_version_id: pointers.active?.id || null, expected_activation_revision: pointers.activation_revision, reason: reason.trim() });
  const canAct = !!reason.trim() && !disabled && !mutation.isPending;
  const approve = () => mutation.mutate({ action: "approve", body: { version_id: version.id, payload_sha256: version.payload_sha256, test_run_id: selectedTest.id, rule_policy_sha256: selectedTest.proof.rule_policy_sha256, expected_proof_sha256: selectedTest.proof.proof_sha256, expected_draft_version_id: pointers.draft?.id || null, ...((selectedTest.proof.context_scope || selectedTest.scope.context_scope || selectedTest.scope.pin?.context_scope) ? { context_scope: selectedTest.proof.context_scope || selectedTest.scope.context_scope || selectedTest.scope.pin.context_scope } : {}), reason: reason.trim() } });
  const apply = () => mutation.mutate({ action: "activate", body: { approval_id: pointers.approved_approval_id, version_id: pointers.approved.id, ...base() } });
  const target = (data.rollback_targets || []).find((row: any) => row.version_id === rollback);
  return <><section className="panel pb col" aria-label="독립 승인·SAW 적용" style={{ gap: 8 }}><h4>독립 승인·SAW 적용</h4>
    <p className="small muted">기여자가 아닌 검토자의 승인과 SAW 적용은 별도 동작입니다. 복구는 과거 승인본을 가리키는 새 적용 이력입니다.</p>
    {Object.entries(data.eligibility?.reasons || {}).map(([action, values]: any) => values.length ? <div className="small muted" key={action}>{action}: {values.join(" · ")}</div> : null)}
    {!validProof && <div className="small muted">현재 승인 증명 없음 — 선택 시험·정답·입력·정책 버전을 확인하고 재시험하세요.</div>}
    {disabled && <div className="small muted">저장하지 않은 편집이 있습니다. 새 초안을 저장하고 다시 시험하세요.</div>}
    {reviewer && pointers && <><label>승인·적용 사유 <textarea className="input" value={reason} onChange={event => setReason(event.target.value)} maxLength={1000} /></label>
      <div className="row wrap">{data.eligibility?.approve && validProof && <button className="btn primary" disabled={!canAct} onClick={approve}>선택 시험으로 승인</button>}
        {data.eligibility?.activate && pointers.approved && pointers.approved_approval_id && <button className="btn primary" disabled={!canAct} onClick={apply}>승인본 SAW에 적용</button>}
      </div>
      {data.eligibility?.rollback && (data.rollback_targets || []).length > 0 && <div className="row wrap"><label>복구할 승인 버전 <select className="input" value={rollback} onChange={event => setRollback(event.target.value)}><option value="">복구 대상 선택</option>{data.rollback_targets.map((row: any) => <option key={`${row.version_id}:${row.approval_id}`} value={row.version_id}>v{row.version} · {row.version_id}</option>)}</select></label><button className="btn" disabled={!canAct || !target} onClick={() => mutation.mutate({ action: "rollback", body: { approval_id: target.approval_id, version_id: target.version_id, ...base() } })}>선택 승인본으로 복구</button></div>}
    </>}
    {!reviewer && <span className="small muted">조회만 가능합니다. 독립 승인·적용 권한이 필요합니다.</span>}
    <ErrorBox error={mutation.error} />{mutation.error && <div className="small muted">입력한 사유와 기존 활성본은 유지됩니다. 충돌한 버전·원천 접근 권한을 확인하세요.</div>}
    {mutation.isSuccess && <div role="status">{mutation.variables.action === "approve" ? "승인 완료 (활성본은 별도 적용 필요)" : mutation.variables.action === "activate" ? "SAW 적용 완료" : "복구 적용 이력 저장 완료"}</div>}
  </section>{pointers&&<ActivationHistory key={`${path}:${pointers.activation_revision}`} path={path} revision={pointers.activation_revision}/>}</>;
}
