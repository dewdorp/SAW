import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link, Route, Routes, useLocation, useParams } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel, Sev } from "../components/common";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";
import { DetectionCatalog } from "./DetectionCatalog";

const STEPS = ["draft", "test", "approved", "deployed", "deprecated"];

export function Detections() {
  const loc = useLocation();
  return (
    <div className="page col">
      <PageHeader eyebrow="탐지 엔지니어링" title="탐지 룰" desc="기본 탐지 목록을 확인하고 Sigma 룰을 작성·시험·승인합니다. 외부 배포는 사람이 수행합니다." />
      <div className="tabs">
        <Link to="/detections"><button className={loc.pathname === "/detections" ? "active" : ""}>탐지 룰 후보</button></Link>
        <Link to="/detections/catalog"><button className={loc.pathname === "/detections/catalog" ? "active" : ""}>기본 탐지 목록</button></Link>
        <Link to="/detections/coverage"><button className={loc.pathname === "/detections/coverage" ? "active" : ""}>ATT&amp;CK 커버리지</button></Link>
      </div>
      <Routes>
        <Route index element={<DetList />} />
        <Route path="catalog" element={<DetectionCatalog />} />
        <Route path="coverage" element={<Coverage />} />
        <Route path=":id" element={<DetEditor />} />
      </Routes>
    </div>
  );
}

const BLANK = `title: New detection
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|startswith: /api/
    sc-status: 200
  condition: selection
falsepositives:
  - Unknown
level: medium
tags: []
`;

function DetList() {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["detections"], queryFn: () => api.get("/detections") });
  const create = useMutation({ mutationFn: () => api.post("/detections", { title: "New detection", logic: BLANK }), onSuccess: () => qc.invalidateQueries({ queryKey: ["detections"] }) });
  return (
    <>
      <div className="row"><b>DETECTION CANDIDATES</b><span className="muted small">SAW는 룰을 배포하지 않습니다 — 승인 후 Export, 배포는 기존 룰 관리 절차로 수행하고 기록만 합니다.</span><div className="grow" /><button className="btn sm" onClick={() => create.mutate()}>＋ 새 Sigma 룰</button></div>
      <ErrorBox error={create.error} />
      {list.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>ID</th><th>Title</th><th>Format</th><th>Status</th><th>v</th><th>Severity</th><th>ATT&CK</th><th>Created</th><th>Reviewed</th><th>Updated</th></tr></thead>
          <tbody>{(list.data || []).map((d: any) => (
            <tr key={d.id}><td className="mono"><Link to={`/detections/${d.id}`}>{d.display_id}</Link></td><td>{d.title}</td><td>{d.format}</td><td><span className="tag">{d.status}</span></td>
              <td>{d.version}</td><td><Sev level={d.severity} /></td><td className="small">{d.attack.join(" ")}</td><td>{d.created_by}</td><td>{d.reviewed_by || "–"}</td><td className="small">{fmtTime(d.updated_at)}</td></tr>))}</tbody></table>
      )}
    </>
  );
}

function DetEditor() {
  const { id = "" } = useParams();
  const me = useMe();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["detection", id], queryFn: () => api.get(`/detections/${id}`) });
  const [edit, setEdit] = useState<any | null>(null);
  const [target, setTarget] = useState("");
  const [exp, setExp] = useState<{ fmt: string; text: string } | null>(null);
  const inval = () => { qc.invalidateQueries({ queryKey: ["detection", id] }); qc.invalidateQueries({ queryKey: ["detections"] }); };
  const validate = useMutation({ mutationFn: () => api.post("/detections/validate", { format: (edit || q.data.current).format, logic: (edit || q.data.current).logic }) });
  const save = useMutation({ mutationFn: () => api.patch(`/detections/${id}`, edit), onSuccess: () => { setEdit(null); inval(); } });
  const test = useMutation({ mutationFn: () => api.post(`/detections/${id}/test`, {}), onSuccess: inval });
  const act = useMutation({ mutationFn: (a: string) => api.post(`/detections/${id}/${a}`, a === "deployed" ? { target, note: "" } : undefined), onSuccess: inval });
  const doExport = async (fmt: string) => { try { setExp({ fmt, text: await api.text(`/detections/${id}/export?fmt=${fmt}`) }); } catch (e) { setExp({ fmt, text: `⚠ ${e instanceof Error ? e.message : e}` }); } };
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  const c = edit || d.current;
  const set = (k: string, v: any) => setEdit({ ...c, [k]: v });
  const lastRun = d.test_runs[0];
  const r = lastRun?.result;
  const canApprove = me.data?.permissions.includes("detection.approve") && d.created_by !== me.data?.username;
  return (
    <>
      <div className="row wrap"><b>DETECTION {d.display_id} v{d.version}</b>
        {STEPS.map((s, i) => <span key={s} className={`tag ${d.status === s ? "ok" : ""}`}>{i > 0 ? "▸ " : ""}{s}</span>)}
        {d.source?.finding_id && <Link to={`/inv/${d.source.investigation_id}?finding=${d.source.finding_id}`}>원본 Finding →</Link>}</div>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <Panel title="META" className="">
          <div className="col" style={{ width: 280 }}>
            <input className="input" value={c.title} onChange={(e) => set("title", e.target.value)} />
            <label className="row small">Format <select className="input" value={c.format} onChange={(e) => set("format", e.target.value)}>{["sigma", "suricata", "regex", "generic_query"].map((f) => <option key={f}>{f}</option>)}</select></label>
            <label className="row small">Severity <select className="input" value={c.severity} onChange={(e) => set("severity", e.target.value)}>{["critical", "high", "medium", "low"].map((f) => <option key={f}>{f}</option>)}</select></label>
            <div className="small">Threshold (SAW): <span className="mono">{JSON.stringify(c.threshold)}</span></div>
            <textarea className="input" rows={2} placeholder='threshold JSON e.g. {"group_by":["src_ip"],"timespan_sec":600,"count_gte":30}' value={JSON.stringify(c.threshold)} onChange={(e) => { try { set("threshold", JSON.parse(e.target.value || "{}")); } catch { /* typing */ } }} />
            <textarea className="input" rows={2} placeholder="False positive notes" value={c.false_positive} onChange={(e) => set("false_positive", e.target.value)} />
            <div className="small">ATT&CK tags: {c.attack.join(", ") || "–"}</div>
            <div className="small muted">created by {c.created_by} · reviewed by {c.reviewed_by || "–"}</div>
          </div>
        </Panel>
        <Panel title={`RULE (${c.format})`} className="grow" right={validate.data ? <span className={`tag ${validate.data.valid ? "ok" : "bad"}`}>{validate.data.valid ? "✓ valid (pySigma)" : "✗ invalid"}</span> : null}>
          <textarea className="input" rows={20} spellCheck={false} value={c.logic} onChange={(e) => set("logic", e.target.value)} />
          <div className="row wrap"><button className="btn sm" onClick={() => validate.mutate()}>Validate</button>
            {edit && <button className="btn sm primary" onClick={() => save.mutate()}>저장 (새 버전 → draft)</button>}</div>
          {validate.data?.errors?.length > 0 && <div className="error small">{validate.data.errors.join("; ")}</div>}
          {validate.data?.opensearch && <div className="mono small pre muted">OpenSearch (CES): {validate.data.opensearch.join("\n")}</div>}
          <ErrorBox error={save.error || validate.error} />
        </Panel>
        <Panel title={lastRun ? `TEST RUN · v${lastRun.version} · ${lastRun.passed ? "PASS" : "FAIL"}` : "TEST RUN"}>
          <div className="col small" style={{ width: 320 }}>
            <button className="btn sm" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "테스트 중…" : "Historical Test 실행"}</button>
            <ErrorBox error={test.error} />
            {r && (<>
              <div>Hits <b>{fmtNum(r.hits)}</b> · scanned {fmtNum(r.scanned)} · {r.investigations} investigations · est {r.est_daily_alerts}/day</div>
              <div className="row"><span className="tag ok">TP {r.tp}</span><span className="tag bad">FP {r.fp}</span><span className="tag">unlabeled {r.unlabeled}</span></div>
              <div>확정 공격 탐지: {r.detects_confirmed_attacks === null ? "– (라벨 없음)" : r.detects_confirmed_attacks ? "✓" : "✗ 놓침"}</div>
              {r.fp_common.length > 0 && <div className="d-chg">⚠ FP 공통: {r.fp_common.map((x: any) => `${x.src_ip} (${x.count})`).join(", ")} → 예외 조건 검토</div>}
              <div>Unit tests: {r.unit_tests.filter((u: any) => u.ok).length}/{r.unit_tests.length}</div>
              {r.per_investigation.map((x: any) => <div key={x.id}><Link to={`/inv/${x.id}`}>{x.display_id}</Link> {x.verdict || "–"} · {x.hits}</div>)}
            </>)}
          </div>
        </Panel>
      </div>
      <Panel title="WORKFLOW / EXPORT">
        <div className="row wrap">
          {canApprove && ["test", "draft"].includes(d.status) && <button className="btn primary sm" onClick={() => act.mutate("approve")}>Approve (4-eyes, 테스트 통과 필요)</button>}
          {!canApprove && d.status === "test" && <span className="muted small">작성자와 다른 Senior/Manager가 승인해야 합니다.</span>}
          {d.status === "approved" && me.data?.permissions.includes("detection.approve") && <><input className="input" placeholder="배포 대상 (예: SIEM 룰셋, 변경번호)" value={target} onChange={(e) => setTarget(e.target.value)} /><button className="btn sm" disabled={!target} onClick={() => act.mutate("deployed")}>배포 기록 (수동 배포 후)</button></>}
          {me.data?.permissions.includes("detection.approve") && d.status !== "deprecated" && <button className="btn ghost sm" onClick={() => act.mutate("deprecate")}>Deprecate</button>}
          <span className="muted">Export:</span>
          {["native", "opensearch", "generic", "logpresso"].map((f) => <button key={f} className="btn sm" onClick={() => doExport(f)}>{f}</button>)}
        </div>
        <ErrorBox error={act.error} />
        {exp && <div className="mono small pre" style={{ background: "var(--bg)", padding: 6, marginTop: 6 }}>{exp.text}</div>}
        {d.deployments.map((x: any, i: number) => <div key={i} className="small">deployed v{x.version} → {x.target} by {x.by} {fmtTime(x.at)}</div>)}
      </Panel>
      <Panel title="VERSIONS">{d.versions.map((v: any) => <div key={v.version} className="small">v{v.version} {v.status} · {v.created_by} · {fmtTime(v.created_at)} — {v.title}</div>)}</Panel>
    </>
  );
}

const STATE: Record<string, [string, string]> = {
  detected_validated: ["▣ 탐지+검증", "rgba(60,207,145,.30)"], detected_unvalidated: ["◩ 탐지·미검증", "rgba(245,179,36,.25)"],
  gap: ["⛔ 관찰됨·탐지 없음", "rgba(255,90,95,.28)"], no_visibility: ["▨ 가시성 없음", "rgba(85,91,110,.4)"], none: ["□ 해당 없음", "transparent"],
};

function Coverage() {
  const q = useQuery({ queryKey: ["coverage"], queryFn: () => api.get("/coverage/attack") });
  const [sel, setSel] = useState<any | null>(null);
  const exportLayer = async () => {
    const layer = await api.get("/coverage/attack/navigator-layer");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" }));
    a.download = "saw_coverage_layer.json";
    a.click();
  };
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  return (
    <>
      <div className="row wrap"><b>DETECTION COVERAGE</b><span className="muted small">가시성(보유 데이터) × 탐지(승인 룰) × 검증(테스트) × 관찰 위협(확정 공격 {d.attack_investigations}건) · sources: {d.sources.join(", ")}</span>
        <div className="grow" /><button className="btn sm" onClick={exportLayer}>Export Navigator layer</button></div>
      <div className="row wrap small">{Object.entries(STATE).map(([k, [l, c]]) => <span key={k} className="tag" style={{ background: c }}>{l}</span>)}</div>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <div className="mtx grow">
          {d.tactics.map((t: any) => {
            const cells = d.cells.filter((c: any) => c.tactics[0] === t.short);
            if (!cells.length) return null;
            return (
              <div key={t.short} className="colm">
                <div className="colh">{t.name}</div>
                {cells.map((c: any) => (
                  <div key={c.technique_id} className="cell" style={{ background: STATE[c.state][1], borderColor: c.state === "gap" ? "var(--bad)" : undefined }} onClick={() => setSel(c)} title={STATE[c.state][0]}>
                    <div className="row"><b>{c.technique_id}</b><span className="grow" />{c.observed > 0 && <span className="tag">{c.observed}</span>}</div>
                    <div className="ellipsis">{c.name}</div>
                    <div className="small muted">{STATE[c.state][0]}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
        {sel && (
          <Panel title={`${sel.technique_id} ${sel.name}`} right={<button className="btn ghost sm" onClick={() => setSel(null)}>✕</button>}>
            <div className="col small" style={{ width: 300 }}>
              <div>Observed {sel.observed} (confirmed-attack investigations)</div>
              <div>Visibility {sel.visibility === null ? "–" : sel.visibility ? "✓" : "✗"}</div>
              {sel.data_needed.map((x: any) => <div key={x.component}>{x.available ? "✓" : "✗"} {x.component}</div>)}
              <div>Detections: {sel.detections.length ? sel.detections.map((x: any) => `${x.display_id} (${x.status}${x.validated ? ", tested" : ""})`).join(", ") : "없음"}</div>
              {sel.state === "gap" && <div className="d-chg">Finding 상세에서 “Create Detection Candidate”로 후보를 만들 수 있습니다.</div>}
            </div>
          </Panel>
        )}
      </div>
      <Panel title="GAP TOP 10 (관찰됨 + 탐지 없음)">
        {d.gaps.map((g: any, i: number) => <div key={g.technique_id} className="small">{i + 1} ⛔ <b>{g.technique_id}</b> {g.name} · {g.observed} findings · 가시성 {g.visibility === false ? "✗ (데이터 소스 확보 필요)" : "✓"}</div>)}
        {!d.gaps.length && <span className="muted small">공백 없음</span>}
      </Panel>
    </>
  );
}
