import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

const lines = (v: string) => v.split("\n").map((x) => x.trim()).filter(Boolean);
type Form = { vendor: string; product: string; original_name: string; signature_id: string; rule_version: string; valid_from: string; valid_to: string;
  status: string; meaning: string; description: string; example_logs: string; benign_cases: string; false_positive_cases: string; checks: string;
  log_source: string; action_values: string; observes: string; cannot_prove: string; followup_data: string; linked_questions: string; scope_note: string };
const LISTS = ["example_logs", "benign_cases", "false_positive_cases", "checks", "action_values", "observes", "cannot_prove", "followup_data", "linked_questions"] as const;
const blank = (): Form => ({ vendor: "", product: "", original_name: "", signature_id: "", rule_version: "", valid_from: "", valid_to: "", status: "confirmed",
  meaning: "", description: "", example_logs: "", benign_cases: "", false_positive_cases: "", checks: "",
  log_source: "", action_values: "", observes: "", cannot_prove: "", followup_data: "", linked_questions: "", scope_note: "" });
const toForm = (x: any): Form => ({ ...blank(), ...Object.fromEntries(Object.entries(x).filter(([k]) => k in blank() && typeof x[k] === "string")),
  ...Object.fromEntries(LISTS.map((k) => [k, (x[k] || []).join("\n")])) });
// Questions may be typed "Q01, Q09" on one line.
const body = (f: Form) => ({ ...f, ...Object.fromEntries(LISTS.map((k) => [k, k === "linked_questions" ? lines(f[k].replace(/[,\s]+/g, "\n")).map((q) => q.toUpperCase()) : lines(f[k])])) });

function Affiliates({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const create = useMutation({ mutationFn: () => api.post("/source-context/org-units", { display_name: name.trim() }), onSuccess: () => { setName(""); qc.invalidateQueries({ queryKey: ["org-units"] }); } });
  return (
    <Panel title="관계사">
      <div className="small muted">조사는 관계사 한 곳과 조사 기간을 단위로 합니다. 같은 사설 IP라도 관계사가 다르면 다른 장비로 취급하며 결과를 합치지 않습니다.</div>
      {orgs.isLoading && <Loading />}
      <ul className="small">{(orgs.data || []).map((o: any) => <li key={o.id}>{o.display_name} <span className="mono muted">{o.id}</span></li>)}</ul>
      {canManage && <div className="row wrap"><input className="input" aria-label="새 관계사 이름" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn sm" disabled={!name.trim() || create.isPending} onClick={() => create.mutate()}>관계사 추가</button></div>}
      <ErrorBox error={orgs.error || create.error} />
    </Panel>
  );
}

function SignatureForm({ initial, onDone }: { initial?: any; onDone: () => void }) {
  const [f, setF] = useState<Form>(initial ? toForm(initial) : blank());
  const set = (k: keyof Form, v: string) => setF({ ...f, [k]: v });
  const save = useMutation({ mutationFn: () => initial ? api.put(`/knowledge/device-signatures/${initial.id}`, { ...body(f), expected_version: initial.version }) : api.post("/knowledge/device-signatures", body(f)), onSuccess: onDone });
  const fixed = !!initial;
  const text = (k: keyof Form, label: string, rows = 2) => <label className="col small">{label}<textarea className="input" rows={rows} value={f[k]} onChange={(e) => set(k, e.target.value)} /></label>;
  return (
    <section className="panel pb col" aria-label={initial ? "공격명 수정" : "공격명 등록"} style={{ gap: 6 }}>
      <div className="row wrap">
        {(["vendor", "product", "original_name", "signature_id"] as (keyof Form)[]).map((k) => <label key={k} className="small">{({ vendor: "벤더", product: "제품", original_name: "장비 원래 공격명", signature_id: "시그니처 ID" } as any)[k]}
          <input className="input" disabled={fixed} value={f[k]} onChange={(e) => set(k, e.target.value)} /></label>)}
      </div>
      {fixed && <div className="small muted">장비·제품·원래 공격명·시그니처 ID는 바꿀 수 없습니다. 다른 이름이면 새로 등록하세요(비슷한 이름을 같은 의미로 묶지 않습니다).</div>}
      <div className="row wrap">
        <label className="small">룰 버전<input className="input" value={f.rule_version} onChange={(e) => set("rule_version", e.target.value)} /></label>
        <label className="small">적용 시작<input className="input" value={f.valid_from} onChange={(e) => set("valid_from", e.target.value)} placeholder="예: 2026-10-01" /></label>
        <label className="small">적용 끝<input className="input" value={f.valid_to} onChange={(e) => set("valid_to", e.target.value)} /></label>
        <label className="small">상태<select className="input" value={f.status} onChange={(e) => set("status", e.target.value)}><option value="confirmed">의미 확인됨</option><option value="needs_confirmation">확인 필요</option></select></label>
      </div>
      {text("meaning", "분석가가 확인한 의미")}
      {text("description", "설명")}
      {text("example_logs", "관련 로그 예시 (한 줄에 하나, 가상·가명 예시만)", 3)}
      {text("benign_cases", "알려진 정상 사례 (한 줄에 하나)")}
      {text("false_positive_cases", "알려진 오탐 사례 (한 줄에 하나)")}
      {text("checks", "판단할 때 확인할 사항 (한 줄에 하나)", 3)}
      <div className="row wrap">
        <label className="small">로그 원천<input className="input" value={f.log_source} onChange={(e) => set("log_source", e.target.value)} placeholder="예: WAF 차단 로그" /></label>
        <label className="small">연결할 조사 질문<input className="input" value={f.linked_questions} onChange={(e) => set("linked_questions", e.target.value)} placeholder="예: Q01, Q09" /></label>
      </div>
      {text("action_values", "장비 처리값 (한 줄에 하나, 예: block, alert)")}
      {text("observes", "이 공격명이 관측하는 것 (한 줄에 하나)")}
      {text("cannot_prove", "이 공격명만으로 입증하지 못하는 것 (한 줄에 하나)")}
      {text("followup_data", "필요한 후속 자료 (한 줄에 하나)")}
      {text("scope_note", "특정 관계사 예외 (공통 의미와 구분해 적기)")}
      <ErrorBox error={save.error} />
      <div className="row"><button className="btn primary" disabled={!f.original_name.trim() || save.isPending} onClick={() => save.mutate()}>{initial ? `저장 (v${initial.version + 1})` : "등록"}</button><button className="btn" onClick={onDone}>닫기</button></div>
    </section>
  );
}

export function Registry() {
  const me = useMe();
  const perms: string[] = me.data?.permissions || [];
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<any>(null);
  const [adding, setAdding] = useState(false);
  const [history, setHistory] = useState<string>("");
  const list = useQuery({ queryKey: ["device-signatures", q], queryFn: () => api.get(`/knowledge/device-signatures?q=${encodeURIComponent(q)}`) });
  const hist = useQuery({ queryKey: ["device-signature-history", history], enabled: !!history, queryFn: () => api.get(`/knowledge/device-signatures/${history}/history`) });
  const done = () => { setEditing(null); setAdding(false); qc.invalidateQueries({ queryKey: ["device-signatures"] }); };
  const manage = perms.includes("signature.manage");
  return (
    <div className="page col">
      <PageHeader eyebrow="지식·탐지" title="관계사·장비 공격명 관리" desc="관계사를 등록하고, 보안장비가 붙인 공격명·시그니처의 의미를 분석가가 확인한 내용으로 관리합니다." />
      <Affiliates canManage={perms.includes("org.manage")} />
      <Panel title="장비 공격명·시그니처" right={manage && <button className="btn sm" onClick={() => { setAdding(true); setEditing(null); }}>새 공격명 등록</button>}>
        <div className="small muted">조사 화면은 정확히 같은 원래 이름(또는 장비·시그니처 ID)에만 이 의미를 연결합니다. 미등록 공격명은 '의미 확인 필요'로 남고, 공격명만으로 공격 성공이나 침해를 판단하지 않습니다.</div>
        <input className="input" aria-label="공격명 검색" placeholder="이름·ID·벤더로 찾기" value={q} onChange={(e) => setQ(e.target.value)} />
        {adding && <SignatureForm onDone={done} />}
        {list.isLoading && <Loading />}
        <table className="t"><thead><tr><th>원래 공격명</th><th>벤더·제품</th><th>시그니처 ID</th><th>상태</th><th>확인한 의미</th><th>버전</th><th></th></tr></thead>
          <tbody>{(list.data?.items || []).map((x: any) => (
            <tr key={x.id}><td className="mono">{x.original_name}</td><td>{[x.vendor, x.product].filter(Boolean).join(" · ") || "-"}</td><td className="mono">{x.signature_id || "-"}</td>
              <td>{x.status === "confirmed" ? "의미 확인됨" : <span className="tag warn">확인 필요</span>}</td><td className="small">{x.meaning}</td><td>v{x.version} · {fmtTime(x.updated_at)}</td>
              <td className="row">{manage && <button className="btn ghost sm" onClick={() => { setEditing(x); setAdding(false); }}>수정</button>}<button className="btn ghost sm" onClick={() => setHistory(x.id)}>이력</button></td></tr>
          ))}</tbody></table>
        {editing && <SignatureForm key={editing.id} initial={editing} onDone={done} />}
        {history && hist.data && <div className="small">{hist.data.items.map((h: any) => <div key={h.version}>v{h.version} · {fmtTime(h.created_at)} · {h.content.status === "confirmed" ? "의미 확인됨" : "확인 필요"} — {h.content.meaning}</div>)}</div>}
        <ErrorBox error={list.error || hist.error} />
      </Panel>
    </div>
  );
}
