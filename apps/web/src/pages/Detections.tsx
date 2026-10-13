import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel, Sev } from "../components/common";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";
import { DetectionCatalog } from "./DetectionCatalog";
import { DetectionHelp, EXAMPLE_SIGMA, EXAMPLE_TESTS, EXAMPLE_THRESHOLD } from "./DetectionHelp";

const STEPS = ["draft", "test", "approved", "deployed", "deprecated"];

export function Detections() {
  const loc = useLocation();
  return (
    <div className="page col">
      <PageHeader eyebrow="탐지 엔지니어링" title="탐지 룰" desc="기본 탐지 목록을 확인하고 Sigma 룰을 작성·시험·승인합니다. 외부 배포는 사람이 수행합니다." />
      <div className="tabs">
        <Link to="/detections"><button className={loc.pathname === "/detections" ? "active" : ""}>탐지 룰 후보</button></Link>
        <Link to="/detections/catalog"><button className={loc.pathname === "/detections/catalog" ? "active" : ""}>기본 탐지 목록</button></Link>
        <Link to="/detections/help"><button className={loc.pathname === "/detections/help" ? "active" : ""}>등록·탐지 사용법</button></Link>
        <Link to="/detections/coverage"><button className={loc.pathname === "/detections/coverage" ? "active" : ""}>ATT&amp;CK 커버리지</button></Link>
      </div>
      <Routes>
        <Route index element={<DetList />} />
        <Route path="catalog" element={<DetectionCatalog />} />
        <Route path="coverage" element={<Coverage />} />
        <Route path="help" element={<DetectionHelp />} />
        <Route path=":id" element={<DetEditor />} />
      </Routes>
    </div>
  );
}

function DetList() {
  const me = useMe();
  const navigate = useNavigate();
  const exportFile = useMutation({ mutationFn: () => api.download("/detections/export?format=json", "saw-current-rules.json") });
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["detections"], queryFn: () => api.get("/detections") });
  const create = useMutation({ mutationFn: () => api.post("/detections", { title: "예시: 제한 자료 반복 조회", logic: EXAMPLE_SIGMA, threshold: EXAMPLE_THRESHOLD, test_events: EXAMPLE_TESTS }), onSuccess: (created) => { qc.invalidateQueries({ queryKey: ["detections"] }); navigate(`/detections/${created.id}`); } });
  return (
    <>
      <div className="row wrap"><b>탐지 룰 후보</b><span className="muted small">승인된 지원 Sigma는 다음 조사 분석에 적용됩니다. 외부 장비 배포는 사람이 수행합니다.</span><div className="grow" />
        <button className="btn sm" disabled={exportFile.isPending} onClick={() => exportFile.mutate()}>현재 룰 묶음 JSON 다운로드</button>
        {me.data?.permissions.includes("detection.write") && <button className="btn sm" disabled={create.isPending} onClick={() => create.mutate()}>새 Sigma 룰</button>}</div>
      <p className="small"><Link to="/detections/help">처음이라면 등록·시험·승인·재분석 순서를 확인하세요 →</Link></p>
      <ErrorBox error={exportFile.error || list.error} />
      <ErrorBox error={create.error} />
      {list.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>ID</th><th>제목</th><th>형식</th><th>상태</th><th>버전</th><th>위험도</th><th>ATT&CK</th><th>작성자</th><th>검토자</th><th>갱신 시각</th></tr></thead>
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
  const downloadFile = useMutation({ mutationFn: () => api.download(`/detections/${id}/export?fmt=native`, `saw-rule-${id}.txt`) });
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
        <Panel title="룰 정보" className="">
          <div className="col" style={{ width: 280 }}>
            <input className="input" value={c.title} onChange={(e) => set("title", e.target.value)} />
            <label className="row small">형식 <select className="input" value={c.format} onChange={(e) => set("format", e.target.value)}>{["sigma", "suricata", "regex", "generic_query"].map((f) => <option key={f}>{f}</option>)}</select></label>
            <label className="row small">위험도 <select className="input" value={c.severity} onChange={(e) => set("severity", e.target.value)}>{["critical", "high", "medium", "low"].map((f) => <option key={f}>{f}</option>)}</select></label>
            <div className="small">Threshold (SAW): <span className="mono">{JSON.stringify(c.threshold)}</span></div>
            <textarea className="input" rows={2} placeholder='threshold JSON e.g. {"group_by":["src_ip"],"timespan_sec":600,"count_gte":30}' value={JSON.stringify(c.threshold)} onChange={(e) => { try { set("threshold", JSON.parse(e.target.value || "{}")); } catch { /* typing */ } }} />
            <textarea className="input" rows={2} placeholder="False positive notes" value={c.false_positive} onChange={(e) => set("false_positive", e.target.value)} />
            <div className="small">ATT&CK tags: {c.attack.join(", ") || "–"}</div>
            <div className="small muted">created by {c.created_by} · reviewed by {c.reviewed_by || "–"}</div>
          </div>
        </Panel>
        <Panel title={`탐지 조건 (${c.format})`} className="grow" right={validate.data ? <span className={`tag ${validate.data.valid ? "ok" : "bad"}`}>{validate.data.valid ? "구문 검사 통과" : "구문 확인 필요"}</span> : null}>
          <textarea className="input" rows={20} spellCheck={false} value={c.logic} onChange={(e) => set("logic", e.target.value)} />
          <div className="row wrap"><button className="btn sm" onClick={() => validate.mutate()}>구문 검사</button>
            {edit && <button className="btn sm primary" onClick={() => save.mutate()}>저장 (새 버전 → draft)</button>}</div>
          {validate.data?.errors?.length > 0 && <div className="error small">{validate.data.errors.join("; ")}</div>}
          {validate.data?.opensearch && <div className="mono small pre muted">OpenSearch (CES): {validate.data.opensearch.join("\n")}</div>}
          <ErrorBox error={save.error || validate.error} />
        </Panel>
        <Panel title={lastRun ? `과거 자료 시험 · v${lastRun.version} · ${lastRun.passed ? "통과" : "확인 필요"}` : "과거 자료 시험"}>
          <div className="col small" style={{ width: 320 }}>
            <button className="btn sm" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? "테스트 중…" : "접근 가능한 과거 자료 시험"}</button>
            <ErrorBox error={test.error} />
            {r && (<>
              <div>일치 <b>{fmtNum(r.hits)}</b> · 검사 {fmtNum(r.scanned)} · 조사 {r.investigations}개 · 예상 {r.est_daily_alerts}/일</div>
              <div className="row"><span className="tag ok">TP {r.tp}</span><span className="tag bad">FP {r.fp}</span><span className="tag">unlabeled {r.unlabeled}</span></div>
              {(r.truncated || r.evaluation_errors > 0 || (r.execution && r.execution !== "complete")) && <div className="error">일부 범위만 검사했거나 실행 오류가 있습니다. 이 결과로 승인할 수 없습니다.</div>}
              <div>확정 공격 탐지: {r.detects_confirmed_attacks === null ? "– (라벨 없음)" : r.detects_confirmed_attacks ? "✓" : "✗ 놓침"}</div>
              {r.fp_common.length > 0 && <div className="d-chg">⚠ FP 공통: {r.fp_common.map((x: any) => `${x.src_ip} (${x.count})`).join(", ")} → 예외 조건 검토</div>}
              <div>예제 시험: {r.unit_tests.filter((u: any) => u.ok).length}/{r.unit_tests.length}</div>
              {r.per_investigation.map((x: any) => <div key={x.id}><Link to={`/inv/${x.id}`}>{x.display_id}</Link> {x.verdict || "–"} · {x.hits}</div>)}
            </>)}
          </div>
        </Panel>
      </div>
      <ExampleInputs key={`${id}:${d.version}`} values={c.test_events || []} onChange={(values) => set("test_events", values)} />
      <Panel title="승인·내보내기">
        <div className="row wrap">
          {canApprove && ["test", "draft"].includes(d.status) && <button className="btn primary sm" onClick={() => act.mutate("approve")}>현재 버전 승인 (다른 작성자·시험 통과 필요)</button>}
          {!canApprove && d.status === "test" && <span className="muted small">작성자와 다른 Senior/Manager가 승인해야 합니다.</span>}
          {d.status === "approved" && me.data?.permissions.includes("detection.approve") && <><input className="input" placeholder="배포 대상 (예: SIEM 룰셋, 변경번호)" value={target} onChange={(e) => setTarget(e.target.value)} /><button className="btn sm" disabled={!target} onClick={() => act.mutate("deployed")}>배포 기록 (수동 배포 후)</button></>}
          {me.data?.permissions.includes("detection.approve") && d.status !== "deprecated" && <button className="btn ghost sm" onClick={() => act.mutate("deprecate")}>사용 중단</button>}
          <button className="btn sm" disabled={downloadFile.isPending} onClick={() => downloadFile.mutate()}>원본 룰 파일 다운로드</button>
          <span className="muted">변환 내용 미리보기:</span>
          {["native", "opensearch", "generic", "logpresso"].map((f) => <button key={f} className="btn sm" onClick={() => doExport(f)}>{f}</button>)}
        </div>
        <p className="small muted">원본 Sigma/OpenSearch 변환에는 SAW 반복 조건·예외가 포함되지 않으며, generic 변환의 임계값은 참고 설명입니다. 전체 조건은 후보 목록의 현재 룰 묶음 JSON으로 함께 확인하세요. 외부 엔진에 원문만 넣으면 일치 결과가 달라질 수 있습니다.</p>
        <ErrorBox error={act.error || downloadFile.error} />
        {exp && <div className="mono small pre" style={{ background: "var(--bg)", padding: 6, marginTop: 6 }}>{exp.text}</div>}
        {d.deployments.map((x: any, i: number) => <div key={i} className="small">deployed v{x.version} → {x.target} by {x.by} {fmtTime(x.at)}</div>)}
      </Panel>
      <Panel title="버전 기록">{d.versions.map((v: any) => <div key={v.version} className="small">v{v.version} {v.status} · {v.created_by} · {fmtTime(v.created_at)} — {v.title}</div>)}</Panel>
    </>
  );
}

function ExampleInputs({ values, onChange }: { values: unknown[]; onChange: (values: unknown[]) => void }) {
  const [text, setText] = useState(JSON.stringify(values, null, 2));
  const [error, setError] = useState("");
  return <Panel title="일치·정상 예제">
    <p className="small">합성 기록을 JSON 배열로 입력하세요. expected는 match 또는 no_match, event에는 정규화한 로그 필드를 넣습니다. 룰 수정에 맞춰 두 종류 예제를 함께 점검하고 새 버전으로 저장하세요.</p>
    <label className="col small">예제 JSON<textarea className="input mono" rows={8} value={text} onChange={(event) => { setText(event.target.value); setError(""); }} /></label>
    <button className="btn sm" onClick={() => { try {
      const parsed = JSON.parse(text);
      if (!Array.isArray(parsed) || parsed.length > 100 || parsed.some(x => !x || !["match", "no_match"].includes(x.expected) || !x.event || typeof x.event !== "object" || Array.isArray(x.event))) throw new Error("match/no_match와 event 객체가 있는 배열을 100개 이하로 입력하세요.");
      onChange(parsed); setError("");
    } catch (problem) { setError(problem instanceof Error ? problem.message : "JSON 형식을 확인하세요."); } }}>예제 편집 반영 (이후 저장)</button>
    {error && <div className="error" role="alert">{error}</div>}
  </Panel>;
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
