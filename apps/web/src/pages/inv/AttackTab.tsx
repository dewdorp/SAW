import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

/** ATT&CK lens (docs/34 V1/V3/V4): compact matrix, technique swimlane, inferred (not observed). */
export function AttackTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const nav = useNavigate();
  const [mode, setMode] = useState("compact");
  const [showInf, setShowInf] = useState(false);
  const [cell, setCell] = useState<any | null>(null);
  const m = useQuery({ queryKey: ["attack", inv, mode], queryFn: () => api.get(`/investigations/${inv}/attack/matrix?mode=${mode}`) });
  const tl = useQuery({ queryKey: ["attack-tl", inv], queryFn: () => api.get(`/investigations/${inv}/attack/timeline`) });
  const inf = useQuery({ queryKey: ["attack-inf", inv], queryFn: () => api.get(`/investigations/${inv}/attack/inferred`) });
  const exportLayer = async () => {
    const layer = await api.get(`/investigations/${inv}/attack/navigator-layer`);
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${layer.name.replace(/\s+/g, "_")}_layer.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  if (m.isLoading) return <Loading />;
  if (m.error) return <ErrorBox error={m.error} />;
  const lanes = [...new Set((tl.data || []).map((x: any) => x.tactic))] as string[];
  const ts = (tl.data || []).map((x: any) => new Date(x.ts).getTime()).filter((x: number) => !isNaN(x));
  const lo = Math.min(...ts), hi = Math.max(...ts);
  return (
    <div className="col">
      <div className="row wrap small">
        <b>ATT&CK</b><span className="muted">v{m.data.attack_version}</span>
        <label className="row"><input type="radio" checked={mode === "compact"} onChange={() => setMode("compact")} />Compact</label>
        <label className="row"><input type="radio" checked={mode === "full"} onChange={() => setMode("full")} />Full (subset)</label>
        <label className="row"><input type="checkbox" checked={showInf} onChange={(e) => setShowInf(e.target.checked)} />Show inferred</label>
        <span className="muted">◆Detector ⚙Rule 👤Analyst ✦AI · 실선=관찰 · 점선=후보/추론 — 근거 없는 매핑은 하지 않습니다</span>
        <div className="grow" />
        <button className="btn sm" onClick={exportLayer}>Export Navigator layer</button>
      </div>
      <div className="row" style={{ alignItems: "flex-start" }}>
        <div className="grow">
          <div className="mtx">
            {m.data.columns.map((c: any) => (
              <div key={c.tactic} className="colm">
                <div className="colh">{c.name}</div>
                {c.techniques.map((t: any) => (
                  <div key={t.technique_id} className={`cell ${t.observed ? `c-${t.best_confidence}` : t.findings.length ? "cand" : ""}`} onClick={() => setCell(t)} title={t.name}>
                    <div className="row"><b>{t.technique_id}</b><span className="grow" /><span>{t.sources.includes("detector_map") ? "◆" : ""}{t.sources.includes("rule_metadata") ? "⚙" : ""}{t.sources.includes("analyst") ? "👤" : ""}</span>{t.findings.length > 0 && <span className="tag">{t.findings.length}</span>}</div>
                    <div className="ellipsis">{t.name}</div>
                    {t.findings.length > 0 && <div className="small muted">{t.best_confidence}</div>}
                  </div>
                ))}
                {showInf && (inf.data?.recommendations || []).filter((r: any) => r.tactics.includes(c.tactic)).map((r: any) => (
                  <div key={r.technique_id} className="cell inferred" title="Inferred · not observed"><b>{r.technique_id}</b> <span className="tag ai">inferred {r.score}</span><div className="ellipsis">{r.name}</div></div>
                ))}
              </div>
            ))}
          </div>
          {m.data.unmapped.length > 0 && <Panel title={`Unmapped / candidate-only findings (${m.data.unmapped.length})`}>{m.data.unmapped.map((u: any) => <div key={u.id} className="small"><a onClick={() => ctx.set({ tab: "findings", findingId: u.id })}>{u.display_id} {u.title}</a> <span className="muted">{u.reason || "no mapping"}</span></div>)}</Panel>}
        </div>
        <div style={{ width: 340 }} className="col">
          {cell && (
            <Panel title={`${cell.technique_id} ${cell.name}`} right={<button className="btn ghost sm" onClick={() => setCell(null)}>✕</button>}>
              {cell.findings.map((f: any) => <div key={f.id} className="small"><a onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>{f.display_id} {f.title}</a> <span className="muted">{f.confidence}{f.condition_met === false ? " · 조건 미충족" : ""}</span></div>)}
              {!cell.findings.length && <span className="muted small">이 Investigation에서 관찰되지 않음</span>}
            </Panel>
          )}
          <Panel title="Next likely techniques" right={<span className="tag ai">Inferred · not observed</span>}>
            <div className="small muted">{inf.data?.engine} — 관찰 기법: {(inf.data?.observed || []).join(", ") || "없음"}</div>
            {(inf.data?.recommendations || []).map((r: any) => (
              <div key={r.technique_id} className="col small" style={{ borderTop: "1px solid var(--line)", padding: "4px 0", gap: 2 }}>
                <div className="row"><b>{r.technique_id}</b><span className="grow">{r.name}</span><span className="mono">{r.score}</span></div>
                <div className="muted">based on {r.based_on.join(", ")}</div>
                {r.data_needed.map((d: any) => <div key={d.component}>{d.available ? "✓" : "✗"} 필요 데이터: {d.component}{d.available ? "" : " — 현재 Evidence 없음 ⚠"}</div>)}
                <button className="btn sm" onClick={() => nav(`/hunting?inv=${inv}&tech=${r.technique_id}&name=${encodeURIComponent(r.name)}`)}>가설로 Hunting 시작</button>
              </div>
            ))}
          </Panel>
        </div>
      </div>
      <Panel title="Technique Timeline (tactic swimlanes)">
        {lanes.map((l) => (
          <div key={l} className="row small" style={{ height: 22 }}>
            <span style={{ width: 150 }} className="muted">{l}</span>
            <div className="grow" style={{ position: "relative", height: 18, borderBottom: "1px dashed var(--line)" }}>
              {(tl.data || []).filter((x: any) => x.tactic === l).map((x: any, i: number) => {
                const p = hi > lo ? ((new Date(x.ts).getTime() - lo) / (hi - lo)) * 96 : 0;
                return <span key={i} title={`${x.technique_id} ${x.name} ${fmtTime(x.ts)}`} style={{ position: "absolute", left: `${p}%`, top: 1, cursor: "pointer" }} onClick={() => ctx.set({ tab: "findings", findingId: x.finding_id })}>{x.observed ? "●" : "○"} <span className="mono">{x.technique_id}</span></span>;
              })}
            </div>
          </div>
        ))}
        {!lanes.length && <span className="muted small">매핑된 기법 없음</span>}
      </Panel>
    </div>
  );
}
