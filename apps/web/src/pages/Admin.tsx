import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { Me } from "../App";
import { ErrorBox, Panel } from "../components/common";
import { Integrations } from "./Integrations";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

const ROLES = ["admin", "soc_manager", "senior_analyst", "analyst", "viewer"];

// Why the audit log failed its check, in words an administrator can act on.
function auditProblem(v: { reason?: string | null; first_broken_id?: number | null; entries?: number; expected_entries?: number }): string {
  if (v.reason === "tail") return `✗ 최근 기록이 사라짐 (있어야 할 ${v.expected_entries}건 중 ${v.entries}건만 남음)`;
  if (v.reason === "anchor") return `✗ 이전 점검 때 있던 기록이 없어졌거나 바뀜 (#${v.first_broken_id ?? "?"}) — 백업에서 복원한 직후라면 정상일 수 있음`;
  return `✗ 기록이 바뀌었거나 중간이 빠짐 (#${v.first_broken_id})`;
}

export function Admin({ me }: { me: Me }) {
  const qc = useQueryClient();
  const canUsers = me.permissions.includes("admin.users");
  const canAudit = me.permissions.includes("audit.read");
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get("/admin/users"), enabled: canUsers });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api.get("/admin/audit?limit=200"), enabled: canAudit });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: () => api.get("/admin/audit/verify"), enabled: canAudit });
  const [nu, setNu] = useState({ username: "", password: "", display_name: "", roles: ["analyst"] });
  const setPw = useMutation({ mutationFn: (v: { id: string; password: string }) => api.post(`/admin/users/${v.id}/password`, { password: v.password }) });
  const resetMfa = useMutation({ mutationFn: (id: string) => api.post(`/admin/users/${id}/mfa-reset`), onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }) });
  const create = useMutation({ mutationFn: () => api.post("/admin/users", nu), onSuccess: () => { setNu({ username: "", password: "", display_name: "", roles: ["analyst"] }); qc.invalidateQueries({ queryKey: ["users"] }); } });
  return (
    <div className="page col">
      <PageHeader eyebrow="관리" title="관리·감사" desc="사용자·MFA·감사 로그·연동을 관리합니다. 관리자 계정은 분석 데이터에 접근하지 않습니다." />
      {me.permissions.includes("ai.models.manage") && <Panel title="로컬 모델"><p className="small">CPU 합성 시험용 모델의 반입 검증과 선택을 관리합니다. 운영 품질은 미채택 상태입니다.</p><Link className="btn" to="/admin/local-models">로컬 모델 관리 열기</Link></Panel>}
      {canUsers && (
        <Panel title="Users (MFA 필수 · 직무분리: Admin은 분석 데이터 기본 접근 없음)">
          <table className="t"><thead><tr><th>username</th><th>name</th><th>roles</th><th>status</th><th>MFA</th><th /></tr></thead>
            <tbody>{(users.data || []).map((u: any) => <tr key={u.id}><td className="mono">{u.username}</td><td>{u.display_name}</td><td>{u.roles.join(", ")}</td><td>{u.status}</td><td>{u.mfa_enabled ? "✓ 등록됨" : "등록 대기 (다음 로그인 시 QR)"}</td>
              <td><button className="btn sm" onClick={() => { if (confirm(`${u.username}의 MFA를 재설정합니까? 기존 세션이 종료되고 다음 로그인 때 QR 등록을 다시 합니다.`)) resetMfa.mutate(u.id); }}>MFA 재설정</button>{" "}
                <button className="btn sm" onClick={() => { const pw = prompt(`${u.username}의 임시 비밀번호 (12자 이상, 3종류 이상 문자). 기존 세션이 모두 종료됩니다. 사용자는 로그인 후 '비밀번호'에서 바로 변경해야 합니다.`); if (pw) setPw.mutate({ id: u.id, password: pw }); }}>임시 비밀번호</button></td></tr>)}</tbody></table>
          <ErrorBox error={setPw.error} />{setPw.isSuccess && <div className="small">임시 비밀번호가 설정되었습니다 ({setPw.data.username}). 안전한 경로로 전달하세요.</div>}
          <div className="row wrap" style={{ marginTop: 8 }}>
            <input className="input" placeholder="username" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} />
            <input className="input" placeholder="display name" value={nu.display_name} onChange={(e) => setNu({ ...nu, display_name: e.target.value })} />
            <input className="input" type="password" placeholder="초기 비밀번호 (≥12)" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} />
            <select className="input" value={nu.roles[0]} onChange={(e) => setNu({ ...nu, roles: [e.target.value] })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
            <button className="btn primary" onClick={() => create.mutate()}>추가</button>
          </div>
          <ErrorBox error={create.error || resetMfa.error} />
        </Panel>
      )}
      {me.permissions.includes("admin.connectors") && <Integrations />}
      {canAudit && (
        <Panel title="Audit Log (append-only, hash chain)" right={verify.data ? <span className={`tag ${verify.data.ok ? "ok" : "bad"}`}>{verify.data.ok ? `✓ 변조 없음 (${verify.data.entries ?? 0}건)` : auditProblem(verify.data)}</span> : null}>
          <div className="scroll" style={{ maxHeight: 520 }}>
            <table className="t"><thead><tr><th>#</th><th>at</th><th>actor</th><th>action</th><th>target</th><th>outcome</th><th>detail</th></tr></thead>
              <tbody>{(audit.data || []).map((e: any) => <tr key={e.id}><td className="num">{e.id}</td><td className="small">{fmtTime(e.at)}</td><td>{e.actor}</td><td className="mono">{e.action}</td><td className="small mono">{e.target_type} {String(e.target_id).slice(0, 8)}</td><td>{e.outcome}</td><td className="small mono ellipsis" style={{ maxWidth: 320 }}>{JSON.stringify(e.detail)}</td></tr>)}</tbody></table>
          </div>
        </Panel>
      )}
    </div>
  );
}
