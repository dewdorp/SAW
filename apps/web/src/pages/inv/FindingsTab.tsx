import { TargetChecks } from "../../components/Checks";
import { ReviewPanel } from "../../components/Reviews";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FindingChecks } from "../../components/analysis";
import { Claim } from "../../components/ui";
import { ErrorBox, Loading, Panel, Sev } from "../../components/common";
import { EntityChip, parseEntity } from "../../components/EntityChip";
import { entityKey, useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime, pct } from "../../lib/format";
import { axisStyle, EChart, safeTooltip } from "../../viz/EChart";

function fmtMetric(m: any): string {
  const v = m.observed;
  if (typeof v === "number" && v >= 0 && v <= 1 && /ratio|share/.test(m.name)) return pct(v);
  if (typeof v === "number") return fmtNum(v, m.approx) + (m.unit ? ` ${m.unit}` : "");
  return String(v ?? "");
}

export function BaselineBar({ m }: { m: any }) {
  const b = m.baseline;
  const max = Math.max(Number(m.observed) || 0, Number(b.max) || 0) * 1.05 || 1;
  return (
    <div className="col" style={{ gap: 2 }}>
      <div className="small">{m.label} <span className="muted">({b.source})</span></div>
      <div className="row small"><span className="muted" style={{ width: 54 }}>Normal</span>
        <div className="range grow"><div className="normal" style={{ left: `${(100 * (b.min || 0)) / max}%`, width: `${Math.max(1, (100 * ((b.max || 0) - (b.min || 0))) / max)}%` }} /></div>
        <span className="mono" style={{ width: 90 }}>{fmtNum(b.min)}–{fmtNum(b.max)}</span></div>
      <div className="row small"><span className="muted" style={{ width: 54 }}>Now</span>
        <div className="range grow"><div className="obs" style={{ left: 0, width: `${(100 * Number(m.observed)) / max}%` }} /></div>
        <span className="mono" style={{ width: 90 }}>{fmtNum(m.observed)} {m.ratio ? <b>×{m.ratio}</b> : null}</span></div>
    </div>
  );
}

export function StepPlot({ values, label }: { values: number[]; label: string }) {
  return (
    <EChart ariaLabel={label} height={120} option={{
      grid: { left: 50, right: 10, top: 8, bottom: 18 }, xAxis: { type: "category", data: values.map((_, i) => i), ...axisStyle, axisLabel: { show: false } },
      yAxis: { type: "value", scale: true, ...axisStyle }, tooltip: { trigger: "axis", formatter: safeTooltip((p) => [["value", p.value]]) },
      series: [{ type: "line", step: "end", showSymbol: false, data: values }],
    } as any} />
  );
}

export function IntervalHist({ values }: { values: number[] }) {
  const lo = Math.min(...values), hi = Math.max(...values);
  const bins = 20, w = (hi - lo) / bins || 1;
  const counts = new Array(bins).fill(0);
  values.forEach((v) => { counts[Math.min(bins - 1, Math.floor((v - lo) / w))]++; });
  return (
    <EChart ariaLabel="interval histogram" height={120} option={{
      grid: { left: 40, right: 10, top: 8, bottom: 22 }, xAxis: { type: "category", data: counts.map((_, i) => `${(lo + i * w).toFixed(1)}s`), ...axisStyle },
      yAxis: { type: "value", ...axisStyle }, tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.axisValue, p.value]]) },
      series: [{ type: "bar", data: counts, itemStyle: { color: "#ff6b3d" } }],
    } as any} />
  );
}

export function SequenceCompare({ normal, observed, rarity }: { normal: string[]; observed: string[]; rarity?: number }) {
  const col = (title: string, xs: string[], hl: boolean) => (
    <div className="col" style={{ gap: 0 }}>
      <div className="small muted">{title}</div>
      {xs.map((x, i) => <div key={i} className="mono small">{i > 0 && <div className="muted">↓</div>}<span className={hl && !normal.includes(x) ? "d-chg" : ""}>{x}</span></div>)}
    </div>
  );
  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 24 }}>
      {col("Normal sequence (most common)", normal, false)}
      {col("Observed", observed, true)}
      {rarity !== undefined && <div className="small">Sequence rarity<br /><b>{(rarity * 100).toFixed(3)}%</b></div>}
    </div>
  );
}

export function RateBand({ series, band, bucket }: { series: number[]; band: number[]; bucket: number }) {
  return (
    <EChart ariaLabel="rate vs normal band" height={140} option={{
      grid: { left: 40, right: 10, top: 10, bottom: 20 }, xAxis: { type: "category", data: series.map((_, i) => `${Math.round((i * bucket) / 60)}m`), ...axisStyle },
      yAxis: { type: "value", ...axisStyle }, tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.seriesName, p.value]]) },
      series: [
        { name: "normal p05", type: "line", data: series.map(() => band[0]), lineStyle: { opacity: 0 }, stack: "band", symbol: "none" },
        { name: "normal band", type: "line", data: series.map(() => Math.max(0, band[1] - band[0])), lineStyle: { opacity: 0 }, areaStyle: { color: "rgba(60,207,145,.25)" }, stack: "band", symbol: "none" },
        { name: "observed", type: "line", data: series, showSymbol: false, itemStyle: { color: "#ff6b3d" } },
      ],
    } as any} />
  );
}

export function FindingDetail({ inv, id, onBack }: { inv: string; id: string; onBack?: () => void }) {
  const ctx = useInv(inv);
  const nav = useNavigate();
  const qc = useQueryClient();
  const [comment, setComment] = useState("");
  const f = useQuery({ queryKey: ["finding", inv, id], queryFn: () => api.get(`/investigations/${inv}/findings/${id}`) });
  const evs = useQuery({ queryKey: ["finding-events", inv, id], queryFn: () => api.post(`/investigations/${inv}/findings/${id}/events`, { limit: 50 }) });
  const fb = useMutation({ mutationFn: (verdict: string) => api.post(`/investigations/${inv}/findings/${id}/feedback`, { verdict, comment }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["finding", inv, id] }); qc.invalidateQueries({ queryKey: ["reviews", inv] }); } });
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.get("/cases") });
  const addCase = useMutation({ mutationFn: (cid: string) => api.post(`/cases/${cid}/items`, { item_type: "finding", ref_id: id }) });
  if (f.isLoading) return <Loading />;
  if (f.error) return <ErrorBox error={f.error} />;
  const d = f.data;
  const base = d.metrics.filter((m: any) => m.baseline);
  const prof = d.metrics.find((m: any) => m.name === "param_profile")?.profile;
  const intervals = d.metrics.find((m: any) => m.name === "intervals")?.series;
  const seqm = d.metrics.find((m: any) => m.name === "sequence");
  const rarity = d.metrics.find((m: any) => m.name === "sequence_rarity")?.observed;
  const rs = d.metrics.find((m: any) => m.name === "rate_series");
  const metrics = d.metrics.filter((m: any) => m.observed !== null && m.observed !== undefined);
  const [explain, advice] = String(d.explanation_md || "").split("### 확인·대응 권고 (분석가 판단 후 수행)");
  const adviceItems = (advice || "").split("\n").map((x) => x.replace(/^-\s*/, "").trim()).filter(Boolean);
  return (
    <div className="col">
      <div className="row wrap">
        {onBack && <button className="btn sm ghost" onClick={onBack}>← 탐지 목록</button>}
        <b>{d.display_id}</b><Sev level={d.risk_level} score={d.risk_score} /><Claim type={d.claim} />
        <span className="tag" title={d.risk_factors.map((x: any) => `${x.name}=${x.value}${x.factor ? ` (×${x.factor})` : ""}`).join("\n")}>신뢰도 {({ high: "높음", medium: "보통", low: "낮음" } as any)[d.confidence] || d.confidence} ⓘ</span>
        <span className="muted small">{fmtTime(d.time_start)} ~ {fmtTime(d.time_end)}</span>
        <span className="muted small">탐지기 {d.detector.id} {d.detector.version}</span>
      </div>
      <h3 style={{ margin: 0, fontSize: 18 }}>{d.title}</h3>
      {d.fp_matches?.length > 0 && d.fp_matches.map((m: any) => <span key={m.id} className="tag warn">⚑ 오탐 규칙 {m.display_id} ({m.title})와 일치 — 확인 필요 (억제하지 않음)</span>)}
      <div className="grid2">
        <Panel title={<span className="row">왜 탐지되었나 <Claim type="DERIVED" /></span>}>
          <table className="t"><tbody>{metrics.map((m: any) => <tr key={m.name}><td>{m.label}</td><td className="num">{fmtMetric(m)}</td></tr>)}</tbody></table>
          <div className="small" style={{ marginTop: 8, color: "var(--fg-1)" }}>{explain}</div>
        </Panel>
        <Panel title="기준선과 관측값 비교">
          {base.length ? base.map((m: any) => <BaselineBar key={m.name} m={m} />) : <div className="muted small">기준선 없음 — 자산 정보(Asset)를 등록하면 평소 값과 비교합니다 (현재는 조사 내부 상대 비교)</div>}
          {rs && <><div className="small" style={{ marginTop: 6 }}>Baseline band (초록) vs Current (주황)</div><RateBand series={rs.series} band={rs.band} bucket={rs.bucket_sec} /></>}
          {seqm && <div style={{ marginTop: 6 }}><SequenceCompare normal={seqm.normal_path} observed={seqm.observed_path} rarity={rarity} /></div>}
          {intervals?.length > 0 && <><div className="small" style={{ marginTop: 6 }}>Interval histogram (좁은 봉우리 = 규칙적 주기)</div><IntervalHist values={intervals} /></>}
          {prof?.step_sample?.length > 0 && <><div className="small" style={{ marginTop: 6 }}>Parameter value step plot (계단형 직선 = 순차 열거)</div><StepPlot values={prof.step_sample} label="parameter step plot" /></>}
        </Panel>
      </div>
      {adviceItems.length > 0 && (
        <Panel title="확인·대응 권고 (분석가 판단 후 수행)">
          <ul style={{ margin: 0, paddingLeft: 18 }}>{adviceItems.map((x, k) => <li key={k} style={{ marginBottom: 4 }}>{x}</li>)}</ul>
          <div className="muted small" style={{ marginTop: 6 }}>SAW는 차단·정책 변경을 하지 않습니다. 권고는 사람이 판단해 수행합니다.</div>
        </Panel>
      )}
      <Panel title={<span className="row">근거 확인 항목 <Claim type="DERIVED" /></span>}><FindingChecks checks={d.checks} /></Panel>
      <Panel title={<span className="row">분석가 확인 기록 <Claim type="VERDICT" /></span>}>
        <TargetChecks inv={inv} target={{ type: "finding", key: d.id, label: `${d.display_id} ${d.title}`, time: [d.time_start, d.time_end], evidence: (d.evidence_refs?.sample_event_ids || []).slice(0, 5) }} />
      </Panel>
      <Panel title="관련 엔티티"><div className="row wrap">{d.entities.map((e: string) => { const p = parseEntity(e); return <EntityChip key={e} inv={inv} type={p.type} value={p.value} />; })}</div></Panel>
      <Panel title={<span className="row">ATT&CK 매핑 <Claim type="INFERRED" /></span>}>
        {d.attack.map((a: any) => (
          <div key={a.technique_id} className="row small"><span className={`tag ${a.confidence === "candidate" ? "" : "ok"}`}>{a.technique_id}</span><span>{a.name}</span>
            <span className="muted">{a.confidence}{a.condition_met === false ? " · 조건 미충족" : ""} · {a.condition}</span>{a.rationale && <span className="muted">— {a.rationale}</span>}</div>
        ))}
        {d.attack_unmapped_reason && <div className="small muted">매핑하지 않음: {d.attack_unmapped_reason}</div>}
      </Panel>
      <div className="row wrap">
        <button className="btn sm" onClick={() => document.getElementById("finding-events")?.scrollIntoView()}>근거 이벤트 {fmtNum(evs.data?.total)}</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "story" })}>공격 스토리</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "timeline", time: { start: d.time_start, end: d.time_end } })}>타임라인</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "relations" })}>관계 그래프</button>
        <button className="btn sm" onClick={() => ctx.set({ tab: "http" })}>요청 비교</button>
        <button className="btn sm" onClick={() => nav(`/knowledge/similar?inv=${inv}&finding=${id}`)}>유사 사례</button>
        <button className="btn sm" onClick={() => nav(`/hunting?inv=${inv}`)}>헌팅</button>
        <select className="input" defaultValue="" onChange={(e) => e.target.value && addCase.mutate(e.target.value)} aria-label="케이스에 추가">
          <option value="">케이스에 추가…</option>{(cases.data || []).map((c: any) => <option key={c.id} value={c.id}>{c.display_id} {c.title}</option>)}
        </select>
        {addCase.isSuccess && <span className="tag ok">추가됨</span>}
        <button className="btn sm" onClick={async () => { const det = await api.post(`/detections/from-finding/${id}`); nav(`/detections/${det.id}`); }}>탐지 룰 후보 만들기</button>
      </div>
      <Panel title={<span className="row">분석가 판정 <Claim type="VERDICT" /></span>}>
        <div className="row wrap">
          {([["valid", "유효 (실제 위협)"], ["benign", "정상 활동"], ["false_positive", "오탐"], ["duplicate", "중복"]] as [string, string][]).map(([v, l]) => <button key={v} className={`btn sm ${d.status === v ? "primary" : ""}`} onClick={() => fb.mutate(v)}>{l}</button>)}
          <input className="input grow" placeholder="판단 근거 (선택)" value={comment} onChange={(e) => setComment(e.target.value)} />
        </div>
        {d.feedback.map((x: any, i: number) => <div key={i} className="small muted" style={{ marginTop: 4 }}>{fmtTime(x.at)} · {x.verdict} {x.comment}</div>)}
        {["critical", "high"].includes(d.risk_level) && ["benign", "false_positive"].includes(d.status) && (
          <div className="small d-chg" style={{ marginTop: 6 }}>높은 위험 탐지를 정상·오탐으로 낮췄습니다. 다른 사람의 검토 대상입니다(아래에서 검토자를 지정해 요청하세요).</div>
        )}
        <div style={{ marginTop: 6 }}><ReviewPanel inv={inv} subject={{ type: "finding", id: d.id, label: `${d.display_id} ${d.title}`, evidence: (d.evidence_refs?.sample_event_ids || []).slice(0, 5) }} /></div>
      </Panel>
      <Panel title={<span className="row">근거 이벤트 ({fmtNum(evs.data?.total)}) <Claim type="OBSERVED" /></span>}>
        <div id="finding-events" />
        <EventTable inv={inv} events={evs.data?.events || []} />
      </Panel>
    </div>
  );
}

export function EventTable({ inv, events, cols }: { inv: string; events: any[]; cols?: string[] }) {
  const ctx = useInv(inv);
  const c = cols || ["timestamp", "data_source", "src_ip", "method", "uri", "status_code", "bytes_out", "user_agent"];
  const sel = entityKey(ctx.selection);
  return (
    <div className="scroll" style={{ maxHeight: 420 }}>
      <table className="t"><thead><tr>{c.map((x) => <th key={x}>{x}</th>)}</tr></thead>
        <tbody>{events.map((e) => (
          <tr key={e.event_id} className={`${ctx.eventId === e.event_id ? "sel" : ""} ${sel && (sel === `ip:${e.src_ip}` || sel === `uri:${e.uri_template}`) ? "hl" : ""}`} onClick={() => ctx.set({ eventId: e.event_id })} style={{ cursor: "pointer" }}>
            {c.map((x) => <td key={x} className={`mono ellipsis ${typeof e[x] === "number" ? "num" : ""}`} style={{ maxWidth: x === "uri" || x === "user_agent" ? 320 : 160 }}>{x === "timestamp" ? fmtTime(e[x]) : String(e[x] ?? "")}</td>)}
          </tr>))}</tbody></table>
    </div>
  );
}

export function FindingsTab({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const [group, setGroup] = useState<"none" | "stage" | "category">("none");
  const q = useQuery({ queryKey: ["findings", inv], queryFn: () => api.get(`/investigations/${inv}/findings`) });
  if (ctx.findingId) return <FindingDetail inv={inv} id={ctx.findingId} onBack={() => ctx.set({ findingId: null })} />;
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const sel = entityKey(ctx.selection);
  const rows = q.data as any[];
  const groups: Record<string, any[]> = {};
  rows.forEach((f) => { const k = group === "none" ? "" : f[group]; (groups[k] ||= []).push(f); });
  return (
    <div className="col">
      <div className="row"><b>FINDINGS ({rows.length})</b><span className="muted small">정렬: risk ↓</span><div className="grow" />
        <select className="input" value={group} onChange={(e) => setGroup(e.target.value as any)}><option value="none">그룹 없음</option><option value="stage">Stage</option><option value="category">Category</option></select></div>
      {rows.length === 0 && <div className="empty">Finding이 없습니다. Evidence를 추가하거나 분석 완료를 기다리세요.</div>}
      {Object.entries(groups).map(([g, fs]) => (
        <div key={g}>
          {g && <div className="small muted" style={{ margin: "6px 0 2px" }}>{g}</div>}
          <table className="t"><thead><tr><th>Level</th><th>Title</th><th>Key metric</th><th>Entities</th><th>Time</th><th>ATT&CK</th><th>Status</th></tr></thead>
            <tbody>{fs.map((f) => {
              const km = f.metrics.find((m: any) => m.ratio) || f.metrics[0];
              const hit = sel && f.entities.some((e: string) => e === sel || e === sel.replace(/^ip:/, "ip:"));
              return (
                <tr key={f.id} className={hit ? "hl" : ""} onClick={() => ctx.set({ findingId: f.id })} style={{ cursor: "pointer" }}>
                  <td><Sev level={f.risk_level} score={f.risk_score} /></td>
                  <td>{f.display_id} <b>{f.title}</b></td>
                  <td className="mono small">{km ? `${km.label} ${fmtMetric(km)}${km.ratio ? ` ×${km.ratio}` : ""}` : ""}</td>
                  <td className="small ellipsis" style={{ maxWidth: 260 }}>{f.entities.slice(0, 3).join(", ")}</td>
                  <td className="small">{fmtTime(f.time_start)}</td>
                  <td className="small">{f.attack.map((a: any) => a.technique_id + (a.confidence === "candidate" ? "?" : "")).join(" ")}</td>
                  <td className="small">{f.status}</td>
                </tr>
              );
            })}</tbody></table>
        </div>
      ))}
    </div>
  );
}
