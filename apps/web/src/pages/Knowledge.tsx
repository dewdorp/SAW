import { ReleaseList, ReleaseWorkspace } from "./golden/ReleaseWorkspace";
import { ReleaseForm } from "./golden/ReleaseForm";
import { GoldenProfiles } from "./golden/GoldenProfiles";
import { HoldoutAttempts, HoldoutAttemptDetail, HoldoutAttemptForm } from "./golden/HoldoutAttempts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link, Route, Routes, useLocation, useParams, useSearchParams } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import { GoldenCases, GoldenReview, type GoldenChoice } from "./Golden";

const TABS: [string, string][] = [["/knowledge/golden", "정답 사례"], ["/knowledge/releases", "반출 패키지"], ["/knowledge/profiles", "반출 프로필"], ["/knowledge/holdout-attempts", "평가 사용 이력"], ["/knowledge", "SOC 경험"], ["/knowledge/review", "승인 대기"], ["/knowledge/assets", "자산 정보"],
  ["/knowledge/fp", "오탐 규칙"], ["/knowledge/playbooks", "점검 절차"], ["/knowledge/similar", "유사 사례 검색"]];

export function Knowledge() {
  const loc = useLocation();
  const principal = useMe();
  if(principal.isLoading) return <Loading />;
  if(principal.error) return <ErrorBox error={principal.error} />;
  return (
    <div className="page col">
      <PageHeader eyebrow="지식" title="SOC 지식" desc="승인된 대응 경험(SOC Experience)과 자산 정보입니다. 작성자와 다른 사람이 승인해야 반영됩니다." />
      <div className="tabs">{TABS.map(([to, l]) => <Link key={to} to={to}><button className={loc.pathname === to ? "active" : ""}>{l}</button></Link>)}</div>
      <Routes key={JSON.stringify([principal.data?.id, principal.data?.permissions])}>
        <Route path="golden" element={<GoldenCases />} />
        <Route path="releases" element={<ReleaseList />} />
        <Route path="releases/new" element={<ReleaseForm key="new" />} />
        <Route path="releases/:id" element={<ReleaseWorkspace />} />
        <Route path="releases/:id/versions/:versionId" element={<ReleaseWorkspace />} />
        <Route path="profiles" element={<GoldenProfiles />} />
        <Route path="holdout-attempts" element={<HoldoutAttempts />} />
        <Route path="holdout-attempts/new" element={<HoldoutAttemptForm />} />
        <Route path="holdout-attempts/:id" element={<HoldoutAttemptDetail />} />
        <Route index element={<ExperienceList />} />
        <Route path="review" element={<ExperienceList queue />} />
        <Route path="exp/:id" element={<ExperienceEditorKey />} />
        <Route path="assets" element={<Assets />} />
        <Route path="fp" element={<FpRules />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="similar" element={<SimilarPage />} />
      </Routes>
    </div>
  );
}

const STATUS_ICON: Record<string, string> = { draft: "✎", review: "◐", approved: "✔", deprecated: "⊘" };

function ExperienceList({ queue }: { queue?: boolean }) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [goldenOnly, setGoldenOnly] = useState(false);
  const list = useQuery({ queryKey: ["exps", queue, status, q], queryFn: () => api.get(`/experiences?${queue ? "status=review_queue" : status ? `status=${status}` : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`) });
  const qc = useQueryClient();
  const create = useMutation({ mutationFn: () => api.post("/experiences", { data: { title: "새 경험", category: "attack" } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["exps"] }) });
  return (
    <div className="col">
      {!queue && <label className="row small"><input type="checkbox" checked={goldenOnly} onChange={e => setGoldenOnly(e.target.checked)} />정답 사례 보기</label>}
      {goldenOnly ? <GoldenCases /> : <>
      <div className="row"><b>{queue ? "REVIEW QUEUE (작성자 본인 건 제외)" : "SOC EXPERIENCE"}</b>
        {!queue && <><input className="input" placeholder="검색" value={q} onChange={(e) => setQ(e.target.value)} />
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">전체</option>{["draft", "review", "approved", "deprecated"].map((s) => <option key={s}>{s}</option>)}</select></>}
        <div className="grow" />{!queue && <button className="btn sm" onClick={() => create.mutate()}>＋ 새 경험</button>}</div>
      <div className="muted small">Draft는 작성자와 Reviewer만 볼 수 있으며, 승인(작성자≠검토자)된 경험만 유사사례·컨텍스트에 사용됩니다.</div>
      {list.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>ID</th><th>Status</th><th>Title</th><th>Category</th><th>Verdict</th><th>Analyst</th><th>Reviewer</th><th>Expires</th><th>Updated</th></tr></thead>
          <tbody>{(list.data || []).map((e: any) => (
            <tr key={e.id}><td className="mono"><Link to={`/knowledge/exp/${e.id}`}>{e.display_id}</Link></td>
              <td>{STATUS_ICON[e.status]} {e.status}{e.approved && e.status !== "approved" ? " (승인본 유지)" : ""}{e.needs_review ? " ⏳만료" : ""}</td>
              <td>{e.data?.title}</td><td>{e.data?.category}</td><td>{e.data?.final_verdict}</td><td>{e.analyst}</td><td>{e.reviewer || "–"}</td>
              <td className="small">{fmtTime(e.expires_at)}</td><td className="small">{fmtTime(e.updated_at)}</td></tr>))}</tbody></table>
      )}
      </>}
    </div>
  );
}

function ListEditor({ label, items, onChange, keys }: { label: string; items: any[]; onChange: (v: any[]) => void; keys: string[] }) {
  return (
    <div className="col" style={{ gap: 2 }}>
      <div className="small muted">{label}</div>
      {items.map((it, i) => (
        <div key={i} className="row">{keys.map((k) => <input key={k} className="input grow" placeholder={k} value={typeof it[k] === "object" ? JSON.stringify(it[k]) : it[k] ?? ""}
          onChange={(e) => onChange(items.map((x, j) => (j === i ? { ...x, [k]: e.target.value } : x)))} />)}
          <button className="btn ghost sm" onClick={() => onChange(items.filter((_, j) => j !== i))}>✕</button></div>
      ))}
      <button className="btn ghost sm" style={{ alignSelf: "flex-start" }} onClick={() => onChange([...items, Object.fromEntries(keys.map((k) => [k, ""]))])}>＋</button>
    </div>
  );
}

function ExperienceEditorKey() { const { id } = useParams(); return <ExperienceEditor key={id} />; }
function ExperienceEditor() {
  const { id = "" } = useParams();
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["exp", id, me.data?.id, me.data?.permissions], queryFn: () => api.get(`/experiences/${id}`) });
  const revs = useQuery({ queryKey: ["exp-revs", id, me.data?.id, me.data?.permissions], queryFn: () => api.get(`/experiences/${id}/revisions`) });
  const [d, setD] = useState<any | null>(null);
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [goldenChoice, setGoldenChoice] = useState<GoldenChoice>({ valid: true });
  const inval = () => { qc.invalidateQueries({ queryKey: ["exp", id, me.data?.id, me.data?.permissions] }); qc.invalidateQueries({ queryKey: ["exp-revs", id, me.data?.id, me.data?.permissions] }); qc.invalidateQueries({ queryKey: ["golden", id] }); setD(null); };
  const save = useMutation({ mutationFn: () => api.patch(`/experiences/${id}`, { data: d }), onSuccess: inval });
  const act = useMutation({ mutationFn: (a: string) => api.post(`/experiences/${id}/${a}`, { comment, ack_fp_conflicts: ack, ...(a === "approve" && goldenChoice.payload ? { golden: goldenChoice.payload } : {}) }), onSuccess: inval });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const e = q.data;
  const data = d || e.data;
  const set = (k: string, v: any) => setD({ ...data, [k]: v });
  const canApprove = me.data?.permissions.includes("knowledge.approve") && me.data?.id !== e.analyst_id;
  const feats = data.behavior_features || {};
  return (
    <div className="row" style={{ alignItems: "flex-start" }}>
      <div className="col grow">
        <div className="row wrap"><b>{e.display_id}</b><span className="tag">{STATUS_ICON[e.status]} {e.status}</span><span className="muted small">rev {e.rev}{e.approved_rev ? ` · approved rev ${e.approved_rev}` : ""} · by {e.analyst}</span>
          {e.needs_review && <span className="tag warn">⏳ 만료 — 재검토 필요</span>}</div>
        <input className="input" value={data.title || ""} onChange={(x) => set("title", x.target.value)} />
        <div className="row wrap small">
          <label className="row">Category <select className="input" value={data.category || ""} onChange={(x) => set("category", x.target.value)}>{["attack", "benign_pattern", "false_positive", "operational", "tuning"].map((c) => <option key={c}>{c}</option>)}</select></label>
          <label className="row">Verdict <select className="input" value={data.final_verdict || ""} onChange={(x) => set("final_verdict", x.target.value)}>{["attack", "normal", "false_positive", "unknown"].map((c) => <option key={c}>{c}</option>)}</select></label>
          <label className="row">Attack type <input className="input" value={data.attack_type || ""} onChange={(x) => set("attack_type", x.target.value)} /></label>
          <label className="row">Confidence <select className="input" value={data.confidence || "medium"} onChange={(x) => set("confidence", x.target.value)}>{["low", "medium", "high"].map((c) => <option key={c}>{c}</option>)}</select></label>
        </div>
        <Panel title="Behavior Features (auto, 결정적)"><div className="row wrap">{Object.entries(feats).filter(([k]) => !k.startsWith("_")).map(([k, v]) => <span key={k} className="tag">{k}={Array.isArray(v) ? v.join(",") : String(v)}</span>)}</div></Panel>
        <textarea className="input" rows={2} placeholder="Initial assessment" value={data.initial_assessment || ""} onChange={(x) => set("initial_assessment", x.target.value)} />
        <ListEditor label="Analysis steps" items={data.analysis_steps || []} keys={["step", "finding"]} onChange={(v) => set("analysis_steps", v)} />
        <ListEditor label="Recommended checks" items={data.recommended_checks || []} keys={["check", "why", "how"]} onChange={(v) => set("recommended_checks", v)} />
        <textarea className="input" rows={2} placeholder="Reason (판단 근거)" value={data.reason || ""} onChange={(x) => set("reason", x.target.value)} />
        <textarea className="input" rows={2} placeholder="Response (사람이 수행한 대응)" value={data.response || ""} onChange={(x) => set("response", x.target.value)} />
        <ListEditor label="False positive conditions (SAW Query Model: field / op / value)" items={data.false_positive_conditions || []} keys={["field", "op", "value"]} onChange={(v) => set("false_positive_conditions", v)} />
        {e.fp_conflicts?.matches > 0 && <div className="tag bad">⚠ FP 조건이 확정 공격 이벤트 {e.fp_conflicts.matches}건과 일치: {e.fp_conflicts.investigations.map((i: any) => i.display_id).join(", ")}</div>}
        <ListEditor label="Detection conditions" items={data.detection_conditions || []} keys={["logic", "data_source"]} onChange={(v) => set("detection_conditions", v)} />
        <GoldenReview experience={e} onChoice={setGoldenChoice} />
        <div className="row wrap">
          {d && <button className="btn primary" onClick={() => save.mutate()}>저장 (새 revision)</button>}
          {e.status === "draft" && !d && <button className="btn" onClick={() => act.mutate("submit")}>검토 요청 (Submit)</button>}
          {e.status === "review" && canApprove && <>
            <input className="input grow" placeholder="검토 의견" value={comment} onChange={(x) => setComment(x.target.value)} />
            {e.fp_conflicts?.matches > 0 && <label className="row small"><input type="checkbox" checked={ack} onChange={(x) => setAck(x.target.checked)} />FP 충돌 확인함</label>}
            <button className="btn" onClick={() => act.mutate("reject")} disabled={!comment.trim()}>Reject</button>
            <button className="btn primary" disabled={!goldenChoice.valid || act.isPending || !!d} onClick={() => act.mutate("approve")}>경험 승인</button></>}
          {e.status === "review" && !canApprove && <span className="muted small">작성자와 다른 Senior/Manager가 승인해야 합니다 (4-eyes).</span>}
          {e.status === "approved" && me.data?.permissions.includes("knowledge.approve") && <button className="btn ghost" onClick={() => act.mutate("deprecate")}>Deprecate</button>}
        </div>
        <ErrorBox error={save.error || act.error} />
        <Panel title="Reviewer checklist"><div className="small">☐ 근거 충분성 ☐ FP 조건 범위 ☐ 개인정보 마스킹 ☐ 만료일 적절성</div></Panel>
      </div>
      <div className="col" style={{ width: 300 }}>
        <Panel title="Links">{e.source_investigation_id ? <Link to={`/inv/${e.source_investigation_id}`}>source investigation</Link> : <span className="muted small">–</span>}</Panel>
        <Panel title="Revisions">{(revs.data || []).map((r: any, i: number) => <div key={i} className="small">r{r.rev} {r.status} · {r.actor} · {fmtTime(r.at)}<div className="muted">{r.note}</div></div>)}</Panel>
      </div>
    </div>
  );
}

const SAMPLE_ASSET = { asset_id: "AST-API-0012", service: "Customer Lookup API", criticality: "high", data: { domain: ["service.example.com"], ip: ["10.10.1.21"], expected_uri: ["/api/customer"], expected_request_rate: { per_min: { min: 18, max: 32 } }, expected_access_time: { weekday: "07:00-23:00" }, expected_country: ["KR"], data_classification: "개인정보", internet_exposed: true, owner: "홍길동", department: "디지털채널개발부", batch_schedule: [{ name: "Customer Sync", cron: "0 3 * * *", src: "10.20.3.5", uri: "/internal/sync" }] } };

function Assets() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["assets"], queryFn: () => api.get("/assets") });
  const [json, setJson] = useState(JSON.stringify(SAMPLE_ASSET, null, 2));
  const [csv, setCsv] = useState("");
  const save = useMutation({ mutationFn: () => api.post("/assets", JSON.parse(json)), onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }) });
  const imp = useMutation({ mutationFn: () => api.post("/assets/import", { csv }), onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }) });
  return (
    <div className="col">
      <b>ASSET KNOWLEDGE</b><div className="muted small">“평소”를 알아야 “이상”을 말할 수 있습니다. Detector Baseline과 Context Panel의 Normal vs Current에 사용됩니다. 편집은 Senior 이상.</div>
      <table className="t"><thead><tr><th>ID</th><th>Service</th><th>Criticality</th><th>Expected rate</th><th>Access time</th><th>URIs</th><th>Owner</th><th>Source</th></tr></thead>
        <tbody>{(list.data || []).map((a: any) => <tr key={a.id}><td className="mono">{a.asset_id}</td><td>{a.service}</td><td>{a.criticality}</td>
          <td className="small">{a.expected_request_rate?.per_min ? `${a.expected_request_rate.per_min.min}–${a.expected_request_rate.per_min.max}/min` : "–"}</td>
          <td className="small">{a.expected_access_time?.weekday || "–"}</td><td className="small mono">{(a.expected_uri || []).join(", ")}</td><td>{a.owner_masked || "–"}</td><td>{a.source}</td></tr>)}</tbody></table>
      <div className="grid2">
        <Panel title="자산 등록/수정 (JSON)"><textarea className="input" rows={14} value={json} onChange={(e) => setJson(e.target.value)} /><button className="btn sm primary" onClick={() => save.mutate()}>저장</button><ErrorBox error={save.error} /></Panel>
        <Panel title="CSV Import"><textarea className="input" rows={8} value={csv} onChange={(e) => setCsv(e.target.value)} placeholder="asset_id,service,criticality,ip,expected_uri&#10;AST-2,Login API,critical,10.10.1.22,/api/auth" />
          <button className="btn sm" disabled={!csv.trim()} onClick={() => imp.mutate()}>Import</button>
          {imp.data && <div className="small">imported {imp.data.imported}{imp.data.errors.map((e: any) => <div key={e.line} className="error">line {e.line}: {e.error}</div>)}</div>}<ErrorBox error={imp.error} /></Panel>
      </div>
    </div>
  );
}

function FpRules() {
  const qc = useQueryClient();
  const me = useMe();
  const list = useQuery({ queryKey: ["fp"], queryFn: () => api.get("/fp-rules") });
  const [f, setF] = useState({ title: "", detector_id: "", field: "src_ip", op: "in", value: "10.20.3.5", reason: "", days: 180 });
  const create = useMutation({ mutationFn: () => api.post("/fp-rules", { title: f.title, detector_id: f.detector_id || null, reason: f.reason, days: f.days, conditions: [{ field: f.field, op: f.op, value: f.op === "in" || f.op === "not_in" ? f.value.split(",").map((x) => x.trim()) : f.value }] }), onSuccess: () => qc.invalidateQueries({ queryKey: ["fp"] }) });
  const approve = useMutation({ mutationFn: ({ id, ack }: { id: string; ack: boolean }) => api.post(`/fp-rules/${id}/approve`, { ack_fp_conflicts: ack }), onSuccess: () => qc.invalidateQueries({ queryKey: ["fp"] }) });
  return (
    <div className="col">
      <b>FALSE POSITIVE RULES</b><div className="muted small">FP 규칙은 Finding을 숨기지 않고 “⚑ 일치” 표시만 합니다. 확정 공격 이벤트와 충돌하면 경고합니다. 만료일 필수.</div>
      <table className="t"><thead><tr><th>ID</th><th>Title</th><th>Detector</th><th>Conditions</th><th>Status</th><th>Conflicts</th><th>Expires</th><th /></tr></thead>
        <tbody>{(list.data || []).map((r: any) => <tr key={r.id}><td className="mono">{r.display_id}</td><td>{r.title}</td><td className="small">{r.detector_id || "*"}</td><td className="small mono">{JSON.stringify(r.conditions)}</td><td>{r.status}</td>
          <td>{r.conflicts?.matches ? <span className="tag bad">⚠ {r.conflicts.matches}</span> : "0"}</td><td className="small">{fmtTime(r.expires_at)}</td>
          <td>{r.status !== "approved" && me.data?.permissions.includes("knowledge.approve") && <button className="btn sm" onClick={() => approve.mutate({ id: r.id, ack: !!r.conflicts?.matches && confirm("확정 공격과 충돌합니다. 그래도 승인합니까?") })}>Approve</button>}</td></tr>)}</tbody></table>
      <ErrorBox error={approve.error} />
      <Panel title="새 FP 규칙">
        <div className="row wrap"><input className="input" placeholder="title" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
          <input className="input" placeholder="detector_id (선택)" value={f.detector_id} onChange={(e) => setF({ ...f, detector_id: e.target.value })} />
          <input className="input" placeholder="field" value={f.field} onChange={(e) => setF({ ...f, field: e.target.value })} />
          <select className="input" value={f.op} onChange={(e) => setF({ ...f, op: e.target.value })}>{["is", "in", "prefix", "contains"].map((o) => <option key={o}>{o}</option>)}</select>
          <input className="input" placeholder="value (in: 쉼표)" value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} />
          <input className="input" placeholder="reason" value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} />
          <input className="input" type="number" style={{ width: 80 }} value={f.days} onChange={(e) => setF({ ...f, days: Number(e.target.value) })} />일
          <button className="btn primary sm" disabled={!f.title} onClick={() => create.mutate()}>생성</button></div>
        <ErrorBox error={create.error} />
      </Panel>
    </div>
  );
}

function Playbooks() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["pb"], queryFn: () => api.get("/playbooks") });
  const [t, setT] = useState("");
  const [cat, setCat] = useState("web.api_enumeration");
  const [steps, setSteps] = useState("동일 지문(JA4/UA) 다른 IP 확장 검색\n응답 크기·개인정보 포함 여부 확인\nAsset 배치 스케줄 확인");
  const save = useMutation({ mutationFn: () => api.post("/playbooks", { title: t, applies_to: [cat], steps: steps.split("\n").filter(Boolean).map((s) => ({ check: s })) }), onSuccess: () => qc.invalidateQueries({ queryKey: ["pb"] }) });
  return (
    <div className="col">
      <b>PLAYBOOKS</b>
      {(list.data || []).map((b: any) => <Panel key={b.id} title={`${b.title} · ${b.applies_to.join(", ")}`}>{b.steps.map((s: any, i: number) => <div key={i} className="small">☐ {s.check}</div>)}</Panel>)}
      <Panel title="새 Playbook (Senior 이상)"><div className="row"><input className="input grow" placeholder="title" value={t} onChange={(e) => setT(e.target.value)} /><input className="input" value={cat} onChange={(e) => setCat(e.target.value)} /></div>
        <textarea className="input" rows={4} value={steps} onChange={(e) => setSteps(e.target.value)} /><button className="btn sm primary" disabled={!t} onClick={() => save.mutate()}>저장</button><ErrorBox error={save.error} /></Panel>
    </div>
  );
}

/** Similar Case (wireframe 11): results with score decomposition + side-by-side feature compare. */
export function SimilarPage() {
  const [sp] = useSearchParams();
  const inv = sp.get("inv") || "";
  const finding = sp.get("finding") || "";
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const [sel, setSel] = useState(inv);
  const q = useQuery({ queryKey: ["similar", sel, finding], enabled: !!sel, queryFn: () => api.post("/similar/search", { investigation_id: sel, finding_id: finding || null }) });
  const [cmp, setCmp] = useState<any | null>(null);
  const fb = useMutation({ mutationFn: (x: { r: any; useful: boolean }) => api.post("/similar/feedback", { query_ref: sel, result_ref: x.r.ref_id, useful: x.useful, score: x.r.score }) });
  const qf = q.data?.query_features || {};
  return (
    <div className="col">
      <div className="row"><b>SIMILAR CASES</b><span className="small muted">기준</span>
        <select className="input" value={sel} onChange={(e) => setSel(e.target.value)}><option value="">Investigation 선택…</option>{(invs.data || []).map((i: any) => <option key={i.id} value={i.id}>{i.display_id} {i.title}</option>)}</select>
        {finding && <span className="tag">Finding 기준</span>}<span className="muted small">S = 0.45·feature + 0.35·vector + 0.20·keyword (LLM 미사용)</span></div>
      {q.isLoading && <Loading />}
      <div className="row" style={{ alignItems: "flex-start" }}>
        <div className="col grow">
          {(q.data?.results || []).map((r: any) => (
            <div key={r.ref_id} className="panel" style={{ cursor: "pointer" }} onClick={() => setCmp(r)}>
              <div className="pb col" style={{ gap: 2 }}>
                <div className="row"><b>{Math.round(r.score * 100)}%</b><span className="mono">{r.display_id}</span><span className="ellipsis">{r.title}</span><span className="tag">{r.ref_type}</span><span className="tag">{r.verdict || "–"}</span></div>
                <div className="small muted">feature {r.breakdown.feature} · vector {r.breakdown.vector} · keyword {r.breakdown.keyword} · model {r.model}</div>
                <div className="small">Same {r.same.map((x: string) => <span key={x} className="d-add">✓{x} </span>)}</div>
                <div className="small">Different {r.different.map((x: string) => <span key={x} className="d-chg">△{x} </span>)}</div>
                <div className="row small"><button className="btn sm" onClick={(e) => { e.stopPropagation(); fb.mutate({ r, useful: true }); }}>👍 유용함</button><button className="btn sm" onClick={(e) => { e.stopPropagation(); fb.mutate({ r, useful: false }); }}>👎 무관함</button>
                  {r.ref_type === "investigation" ? <Link to={`/inv/${r.ref_id}`} onClick={(e) => e.stopPropagation()}>열기</Link> : <Link to={`/knowledge/exp/${r.ref_id}`} onClick={(e) => e.stopPropagation()}>열기</Link>}</div>
              </div>
            </div>
          ))}
          {q.data && !q.data.results.length && <div className="empty">유사 사례가 없습니다. Investigation을 종료(Verdict)하거나 Experience를 승인하면 지식이 쌓입니다.</div>}
        </div>
        {cmp && (
          <Panel title={`COMPARE: 현재 vs ${cmp.display_id}`} className="grow">
            <table className="t"><thead><tr><th>Feature</th><th>현재</th><th>{cmp.display_id}</th><th /></tr></thead>
              <tbody>{Array.from(new Set([...Object.keys(qf), ...cmp.same, ...cmp.different])).filter((k) => !k.startsWith("_")).map((k) => (
                <tr key={k}><td className="mono">{k}</td><td className="mono small">{fmt(qf[k])}</td><td className="mono small">{cmp.same.includes(k) ? "≈ same" : cmp.different.includes(k) ? "≠" : "–"}</td><td>{cmp.same.includes(k) ? "✓" : cmp.different.includes(k) ? "△" : ""}</td></tr>))}</tbody></table>
          </Panel>
        )}
      </div>
    </div>
  );
}

function fmt(v: unknown): string {
  if (v === undefined || v === null) return "–";
  return Array.isArray(v) ? v.join(", ") : String(v);
}
