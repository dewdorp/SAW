import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "../components/ui";
import { useState } from "react";
import { Link, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel, Sev } from "../components/common";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import { PolicyWorkspace } from "./detection/PolicyWorkspace";
import { RuleEditor } from "./detection/RuleEditor";
import { DetectionCatalog } from "./DetectionCatalog";
import { DetectionHelp, EXAMPLE_SIGMA, EXAMPLE_TESTS, EXAMPLE_THRESHOLD } from "./DetectionHelp";


export function Detections() {
  const loc = useLocation();
  return (
    <div className="page col">
      <PageHeader eyebrow="탐지 엔지니어링" title="탐지 룰" desc="기본 탐지 목록을 확인하고 Sigma 룰을 작성·시험·승인합니다. 외부 배포는 사람이 수행합니다." />
      <div className="tabs">
        <Link to="/detections"><button className={loc.pathname === "/detections" ? "active" : ""}>탐지 룰 후보</button></Link>
        <Link to="/detections/catalog"><button className={loc.pathname === "/detections/catalog" ? "active" : ""}>기본 탐지 목록</button></Link>
        <Link to="/detections/policies"><button className={loc.pathname.includes("/policies") ? "active" : ""}>탐지 정책·명세</button></Link>
        <Link to="/detections/help"><button className={loc.pathname === "/detections/help" ? "active" : ""}>등록·탐지 사용법</button></Link>
        <Link to="/detections/coverage"><button className={loc.pathname === "/detections/coverage" ? "active" : ""}>ATT&amp;CK 커버리지</button></Link>
      </div>
      <Routes>
        <Route index element={<DetList />} />
        <Route path="policies" element={<PolicyWorkspace />} />
        <Route path="policies/:detectorId" element={<PolicyWorkspace />} />
        <Route path="catalog" element={<DetectionCatalog />} />
        <Route path="coverage" element={<Coverage />} />
        <Route path="help" element={<DetectionHelp />} />
        <Route path=":id" element={<RuleEditor />} />
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
      <div className="row wrap"><b>탐지 룰 후보</b><span className="muted small">지원 Sigma는 독립 승인 후 SAW에 명시적으로 적용하면 다음 조사 분석에 사용됩니다. 외부 장비 배포는 사람이 수행합니다.</span><div className="grow" />
        <button className="btn sm" disabled={exportFile.isPending} onClick={() => exportFile.mutate()}>현재 룰 묶음 JSON 다운로드</button>
        {me.data?.permissions.includes("detection.write") && <button className="btn sm" disabled={create.isPending} onClick={() => create.mutate()}>새 Sigma 룰</button>}</div>
      <p className="small"><Link to="/detections/help">처음이라면 등록·시험·승인·재분석 순서를 확인하세요 →</Link></p>
      <ErrorBox error={exportFile.error || list.error} />
      <ErrorBox error={create.error} />
      {list.isLoading ? <Loading /> : (
        <table className="t"><thead><tr><th>ID</th><th>제목</th><th>형식</th><th>상태</th><th>최신 초안</th><th>승인본</th><th>활성본</th><th>최근 생성</th><th>위험도</th><th>ATT&CK</th><th>작성자</th><th>검토자</th><th>갱신 시각</th></tr></thead>
          <tbody>{(list.data || []).map((d: any) => (
            <tr key={d.id}><td className="mono"><Link to={`/detections/${d.id}`}>{d.display_id}</Link></td><td>{d.title}</td><td>{d.format}</td><td><span className="tag">{d.status}</span></td>
              <td>{d.pointers?.draft ? `v${d.pointers.draft.version}` : d.pointers ? "없음" : "미기록"}</td><td>{d.pointers?.approved ? `v${d.pointers.approved.version}` : d.pointers ? "없음" : "미기록"}</td><td>{d.pointers?.active ? `v${d.pointers.active.version}` : d.pointers ? "없음" : "미기록"}</td><td>{d.pointers?.latest ? `v${d.pointers.latest.version}` : `v${d.version} (기존 기록)`}</td><td><Sev level={d.severity} /></td><td className="small">{d.attack.join(" ")}</td><td>{d.created_by}</td><td>{d.reviewed_by || "–"}</td><td className="small">{fmtTime(d.updated_at)}</td></tr>))}</tbody></table>
      )}
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
