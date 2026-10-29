// Shared renderers for analyzer outputs. Text only — never HTML from data.
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { fmtNum, fmtTime } from "../lib/format";
import { Check, KV, Panel, Sev } from "./common";
import { EntityChip } from "./EntityChip";

export function HighlightedInput({ text, spans, active, onHover }: { text: string; spans: { span: number[]; type: string }[]; active?: number | null; onHover?: (i: number | null) => void }) {
  // non-overlapping, outermost-first; container-level detections (whole input) are not highlighted
  const sorted = spans.map((s, i) => ({ ...s, i })).filter((s) => s.span[1] > s.span[0] && !(s.span[0] === 0 && s.span[1] >= text.length - 1))
    .sort((a, b) => a.span[0] - b.span[0] || b.span[1] - a.span[1]);
  const parts: JSX.Element[] = [];
  let pos = 0;
  for (const s of sorted) {
    if (s.span[0] < pos) continue;
    if (s.span[0] > pos) parts.push(<Fragment key={`t${pos}`}>{text.slice(pos, s.span[0])}</Fragment>);
    parts.push(
      <mark key={`m${s.i}`} className={active === s.i ? "on" : ""} title={s.type} onMouseEnter={() => onHover?.(s.i)} onMouseLeave={() => onHover?.(null)}>
        {text.slice(s.span[0], s.span[1])}
      </mark>,
    );
    pos = s.span[1];
  }
  parts.push(<Fragment key="end">{text.slice(pos)}</Fragment>);
  return <div className="hlinput">{parts}</div>;
}

export function PatternCard({ p }: { p: any }) {
  return (
    <div className="panel" style={{ marginBottom: 6 }}>
      <div className="pb col" style={{ gap: 4 }}>
        <div className="row"><Sev level={p.confidence === "high" ? "high" : p.confidence === "medium" ? "medium" : "low"} /><b>{p.label}</b><span className="muted small">at {p.location}</span></div>
        <div className="small muted">Evidence</div>
        {p.evidence.map((e: any, i: number) => (
          <div key={i} className="check pass small"><span className="m">✓</span><span>{e.kind}</span><span className="mono ellipsis">{e.value}</span></div>
        ))}
        {p.not_evidence?.length > 0 && p.not_evidence.map((n: string, i: number) => (
          <div key={i} className="check fail small"><span className="m">✗</span><span>{n}</span></div>
        ))}
      </div>
    </div>
  );
}

export function DecodeChain({ input, steps, output }: { input: string; steps: any[]; output?: string }) {
  return (
    <div className="col mono" style={{ gap: 2 }}>
      <div className="pre">{input}</div>
      {steps.map((s, i) => (
        <Fragment key={i}>
          <div className="muted">&nbsp;&nbsp;│ ⓘ {i + 1}. {s.label}</div>
          <div className="pre">{s.output}</div>
        </Fragment>
      ))}
      {output !== undefined && steps.length === 0 && <div className="muted">디코딩 단계 없음</div>}
    </div>
  );
}

export function HttpResult({ r }: { r: any }) {
  const [tab, setTab] = useState("params");
  if (r.error) return <div className="error">{r.error}</div>;
  return (
    <div className="grid2">
      <div className="col">
        <Panel title={<span><b>{r.method}</b> {r.host} <span className="mono">{r.path}</span></span>} right={<span className="tag">UA: {r.user_agent?.class}</span>}>
          <div className="tabs" role="tablist">
            {["params", "headers", "body", "jwt", "response"].map((t) => <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>{t}</button>)}
          </div>
          {tab === "params" && (
            <table className="t"><thead><tr><th>loc</th><th>name</th><th>value</th><th>decoded</th><th>type</th><th>flags</th></tr></thead>
              <tbody>{r.parameters.map((p: any, i: number) => (
                <tr key={i}><td>{p.location}</td><td className="mono">{p.path || p.name}</td><td className="mono ellipsis" style={{ maxWidth: 220 }}>{p.value}</td>
                  <td className="mono ellipsis" style={{ maxWidth: 220 }} title={p.decode_chain.map((s: any) => s.label).join(" → ")}>{p.decoded ?? "—"}{p.decode_chain.length ? ` ⛓${p.decode_chain.length}` : ""}</td>
                  <td>{p.type}{p.masked ? " 🔒" : ""}</td><td>{p.flags.map((f: string) => <span key={f} className="tag warn">{f.replace("potential_", "")}</span>)}</td></tr>
              ))}</tbody></table>
          )}
          {tab === "headers" && <table className="t"><tbody>{r.headers.map((h: any, i: number) => <tr key={i}><td className="mono">{h.name}</td><td className="mono pre">{h.value}{h.masked ? " 🔒" : ""}</td></tr>)}</tbody></table>}
          {tab === "body" && <div className="mono pre">{r.body?.preview || "(empty)"}</div>}
          {tab === "jwt" && (r.jwt?.length ? r.jwt.map((j: any, i: number) => (
            <div key={i} className="col"><div className="small muted">{j.location} · {j.note}</div>
              {j.warnings.map((w: string) => <span key={w} className="tag warn">⚠ {w}</span>)}
              <div className="mono pre">{JSON.stringify({ header: j.header, payload: j.payload }, null, 2)}</div></div>)) : <div className="muted">JWT 없음</div>)}
          {tab === "response" && (r.response ? (
            <div className="col"><KV rows={[["status", r.response.status], ["size", r.response.size], ["content-type", r.response.content_type || "–"]]} />
              {r.response.error_signatures.map((e: any, i: number) => <span key={i} className="tag bad">{e.kind}: {e.match}</span>)}
              {r.response.sensitive_data_kinds.length > 0 && <span className="tag warn">민감정보 패턴: {r.response.sensitive_data_kinds.join(", ")} (마스킹됨)</span>}
              <div className="small muted">본문은 텍스트로만 표시합니다 (HTML 렌더링 안 함)</div>
              <div className="mono pre" style={{ maxHeight: 240, overflow: "auto" }}>{r.response.body_preview}</div></div>) : <div className="muted">응답 없음</div>)}
        </Panel>
        {r.hints?.length > 0 && <Panel title="Hints">{r.hints.map((h: any) => <div key={h.code} className="small">● {h.label}{h.context_required ? <span className="muted"> — {h.context_required}</span> : null}</div>)}</Panel>}
      </div>
      <div className="col">
        <Panel title={`Patterns (${r.patterns.length})`}>{r.patterns.length ? r.patterns.map((p: any, i: number) => <PatternCard key={i} p={p} />) : <div className="muted">탐지된 패턴 없음 (단정하지 않음)</div>}</Panel>
        <Panel title={`Anomalies (${r.anomalies.length})`}>{r.anomalies.map((a: any, i: number) => <div key={i} className="small">⚠ {a.detail}</div>)}{!r.anomalies.length && <span className="muted">—</span>}</Panel>
      </div>
    </div>
  );
}

export function IocCard({ r }: { r: any }) {
  if (!r.type) return <Panel title={r.input}><span className="muted">인식할 수 없는 값</span></Panel>;
  const ic = r.internal_context;
  const off = r.offline || {};
  const t = r.type.startsWith("ipv") ? "ip" : r.type;
  return (
    <Panel title={<span className="row"><EntityChip type={t} value={r.value} external={r.scope === "external"} /> <span className="muted small">{r.type}{r.scope ? ` · ${r.scope}` : ""}</span></span>}
      right={off.asn ? <span className="small">{off.cloud !== "none" ? `☁ ${off.cloud} · ` : ""}AS{off.asn} {off.as_org} · {off.country}{off.tor ? " · TOR" : ""} {off.source === "fixture" ? <span className="tag warn">fixture DB</span> : null}</span> : null}>
      <div className="col small">
        <b>INTERNAL CONTEXT</b>
        {ic ? (
          <>
            <KV rows={[["First / Last", `${fmtTime(ic.first_seen)} ~ ${fmtTime(ic.last_seen)}`], ["Events", Object.entries(ic.events_by_source).map(([k, v]) => `${k} ${fmtNum(v as number)}`).join(" · ") || "0"]]} />
            {Object.entries(ic.related || {}).map(([k, v]: any) => (
              <div key={k} className="row wrap"><span className="muted" style={{ width: 140 }}>{k}</span>{v.slice(0, 3).map((x: any) => <span key={x.value} className="mono">{x.value} ({x.count})</span>)}</div>
            ))}
            {ic.affiliate_separated && (ic.by_affiliate || []).map((g: any, i: number) => (
              <div key={g.org_unit_id || i} className="ck-item" style={{ padding: "4px 8px" }}>
                <b>관계사 {g.org_unit}</b> · 기록 {fmtNum(g.total_events)}건 · {fmtTime(g.first_seen)} ~ {fmtTime(g.last_seen)}
                {g.previous_verdicts.map((v: any) => <div key={v.investigation_id}><Link to={`/inv/${v.investigation_id}`}>{v.display_id}</Link> · {v.verdict}</div>)}
              </div>))}
            <b>PREVIOUS VERDICTS</b>
            {ic.affiliate_separated && <span className="muted">내부(사설) 주소라 관계사별로만 표시합니다. 다른 관계사의 판단을 이 주소의 이력으로 합치지 않습니다.</span>}
            {ic.previous_verdicts.length ? ic.previous_verdicts.map((v: any) => (
              <div key={v.investigation_id}><Link to={`/inv/${v.investigation_id}`}>{v.display_id}</Link> · {v.verdict} · <span className="muted">{v.verdict_reason}</span></div>
            )) : <span className="muted">없음</span>}
            {ic.related_cases.length > 0 && <div>Cases: {ic.related_cases.map((c: any) => <Link key={c.case_id} to={`/cases/${c.case_id}`}>{c.display_id} </Link>)}</div>}
            {ic.connectors?.map((c: any, i: number) => <div key={i} className="muted">SIEM {c.connector}: {c.error ? `⚠ ${c.error}` : c.note}</div>)}
            <span className="muted">{ic.scope_note}</span>
          </>
        ) : <span className="muted">—</span>}
        <b>EXTERNAL</b>
        <div className="row"><button className="btn sm" disabled title="정책상 비활성 (enrich profile)">RDAP 조회</button><button className="btn sm" disabled>TI 조회</button><span className="muted">⚠ 외부 조회는 기록되며 정책 승인 시에만 활성화됩니다</span></div>
        {r.note && <span className="muted">{r.note}</span>}
      </div>
    </Panel>
  );
}

export function PayloadResult({ r }: { r: any }) {
  return (
    <div className="col">
      <Panel title={`Transformation Chain (${r.steps.length} steps · confidence ${r.confidence})`} right={r.cyberchef_recipe ? <span className="small muted" title={r.cyberchef_recipe}>CyberChef recipe 준비됨</span> : null}>
        {r.incomplete && <div className="error small" role="alert">⚠ 입력이 중간에 끊겨 있습니다(예: 잘린 gzip). 아래 결과는 풀린 부분까지만이며 전체가 아닙니다.</div>}
        <DecodeChain input={r.input_preview} steps={r.steps} output={r.output} />
      </Panel>
      {r.patterns.length > 0 && <Panel title="Patterns in decoded output">{r.patterns.map((p: any, i: number) => <PatternCard key={i} p={p} />)}</Panel>}
      {r.iocs.length > 0 && <Panel title="IOCs in decoded output"><div className="row wrap">{r.iocs.map((o: any) => <EntityChip key={o.value} type={o.type.startsWith("ipv") ? "ip" : o.type} value={o.value} />)}</div></Panel>}
    </div>
  );
}

export function LogSummary({ r }: { r: any }) {
  return (
    <div className="col">
      <div className="row wrap small">{r.parser ? <span className="tag">parser {r.parser} ({Math.round(r.confidence * 100)}%)</span> : <span className="tag bad">알아볼 수 있는 로그 형식이 아님 — 파서 관리에서 새 파서를 만들 수 있습니다</span>}<span>{fmtNum(r.events)} events</span><span className="muted">failed {r.failed}</span>
        {r.time_range && <span className="muted">{fmtTime(r.time_range[0])} ~ {fmtTime(r.time_range[1])}</span>}</div>
      <div className="grid3">
        {(["top_src_ip", "top_uri_template", "top_status"] as const).map((k) => (
          <Panel key={k} title={k.replace("top_", "Top ")}>{r[k].map((x: any) => <div key={String(x.value)} className="row small"><span className="mono ellipsis grow">{String(x.value)}</span><span className="num">{x.count}</span></div>)}</Panel>
        ))}
      </div>
      <Panel title="Patterns">{r.patterns.map((p: any, i: number) => <div key={i} className="row small mono"><span className="grow ellipsis">{p.method} {p.uri_template}</span><span>{p.status}</span><span className="num">{p.count}</span></div>)}</Panel>
      {r.suspicious.length > 0 && <Panel title={`Potential patterns (${r.suspicious.length})`}>{r.suspicious.map((s: any) => <div key={s.line_no} className="row small"><span className="muted">L{s.line_no}</span>{s.tags.map((t: string) => <span key={t} className="tag warn">{t}</span>)}<span className="mono ellipsis">{s.uri}</span></div>)}</Panel>}
      {r.failure_samples?.length > 0 && <Panel title="Parse failures">{r.failure_samples.map((f: any) => <div key={f.line_no} className="small mono">L{f.line_no} {f.reason}: {f.raw}</div>)}</Panel>}
    </div>
  );
}

export function FindingChecks({ checks }: { checks: any[] }) {
  return <div className="col" style={{ gap: 2 }}>{checks.map((c, i) => <Check key={i} c={c} />)}</div>;
}
