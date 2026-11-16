import { useState } from "react";
import { Check, Panel } from "./common";
import { fmtNum, fmtTime } from "../lib/format";

const RISK_KO: Record<string, string> = { critical: "매우 높음", high: "높음", medium: "보통", low: "낮음", info: "참고" };
const STATUS_ORDER = ["2xx", "3xx", "4xx", "5xx", "없음"];

/** The pasted lines a result stands on, read back from the text in the box (nothing is fetched). */
function Lines({ text, nos }: { text: string; nos: number[] }) {
  const all = text.split(/\r?\n/);
  return (
    <div className="mono small" style={{ overflowX: "auto", whiteSpace: "pre", maxHeight: 220, overflowY: "auto" }} data-testid="evidence-lines">
      {nos.map((n) => <div key={n}><span className="muted">{String(n).padStart(5, " ")}  </span>{all[n - 1] ?? ""}</div>)}
    </div>
  );
}

function Finding({ f, text }: { f: any; text: string }) {
  const [open, setOpen] = useState(false);
  return (
    <section className="panel" data-testid="web-finding">
      <div className="ph">
        <span className="grow"><b>{f.title_ko}</b> <span className="muted small">· {f.category_ko}</span></span>
        <span className={`tag ${f.risk_level === "high" || f.risk_level === "critical" ? "bad" : f.risk_level === "medium" ? "warn" : ""}`}>위험 {RISK_KO[f.risk_level] || f.risk_level}</span>
      </div>
      <div className="pb col" style={{ gap: 6 }}>
        <div>{f.explanation}</div>
        {f.time_start && <div className="muted small">{fmtTime(f.time_start)} ~ {fmtTime(f.time_end)} · 관련 기록 {fmtNum(f.total_events)}건</div>}
        {f.metrics.length > 0 && (
          <div className="row wrap small">{f.metrics.map((m: any, i: number) => (
            <span key={i} className="tag">{m.label} {typeof m.value === "number" && m.value > 0 && m.value < 1 ? `${Math.round(m.value * 1000) / 10}%` : typeof m.value === "number" ? fmtNum(m.value) : String(m.value)}{m.unit === "bytes" ? " B" : ""}</span>
          ))}</div>
        )}
        <div><div className="muted small">판단 근거</div>{f.checks.map((c: any, i: number) => <Check key={i} c={c} />)}</div>
        {f.next_checks.length > 0 && (
          <div><div className="muted small">다음에 확인할 것</div><ul style={{ margin: "2px 0 0 18px" }}>{f.next_checks.map((n: string) => <li key={n}>{n}</li>)}</ul></div>
        )}
        {f.line_nos.length > 0 && (
          <div>
            <button className="btn sm" onClick={() => setOpen(!open)} aria-expanded={open}>{open ? "근거 줄 접기" : `근거 줄 보기 (${f.line_nos.length}줄${f.total_events > f.line_nos.length ? `, 전체 ${fmtNum(f.total_events)}건 중 일부` : ""})`}</button>
            {open && <Lines text={text} nos={f.line_nos} />}
          </div>
        )}
      </div>
    </section>
  );
}

export function WebLogResult({ r, text }: { r: any; text: string }) {
  const w = r.web;
  if (!w) return null;
  const found = w.findings.filter((f: any) => f.state === "found");
  const failed = w.findings.filter((f: any) => f.state === "failed");
  const total = Object.values(w.status as Record<string, number>).reduce((a, b) => a + b, 0);
  return (
    <div className="col" data-testid="web-log-result">
      <div className="row wrap small">
        {r.format_ko && <span className="tag accent">{r.format_ko}</span>}
        <span>웹 기록 {fmtNum(w.events)}건</span>
        {STATUS_ORDER.filter((k) => w.status[k]).map((k) => <span key={k} className="muted">{k === "없음" ? "응답 코드 없음" : k} {fmtNum(w.status[k])}{total ? ` (${Math.round((100 * w.status[k]) / total)}%)` : ""}</span>)}
      </div>
      <Panel title={`웹 탐지 기준으로 본 결과 (${found.length})`}>
        {found.length === 0 ? (
          <div className="muted" data-testid="no-findings">붙여넣은 범위에서 웹 탐지 기준(스캔·민감 파일·로그인 대입·주입 구문·자동화 도구·큰 응답·번호 대량 조회·요청 변조)을 넘는 활동이 없습니다. 기준을 넘지 않았다는 뜻이며 안전하다는 확인은 아닙니다. 기록이 적으면 기준에 닿지 않을 수 있습니다.</div>
        ) : (
          <div className="col">{found.map((f: any, i: number) => <Finding key={i} f={f} text={text} />)}</div>
        )}
        {failed.length > 0 && <div className="error small">계산하지 못한 기준: {failed.map((f: any) => f.detector_id).join(", ")}</div>}
      </Panel>
      {w.errors.length > 0 && (
        <Panel title={`오류 기록 묶음 (${w.errors.length})`}>
          <table className="t"><thead><tr><th>무엇</th><th className="num">건수</th><th className="num">출발지</th><th>예시 줄</th></tr></thead>
            <tbody>{w.errors.map((g: any) => <tr key={g.label}><td>{g.label}</td><td className="num">{fmtNum(g.count)}</td><td className="num">{g.sources}</td><td className="mono small">{g.lines.slice(0, 5).join(", ")}</td></tr>)}</tbody></table>
        </Panel>
      )}
      {w.sources.length > 0 && (
        <Panel title="출발지별 요약 (요청 많은 순 10개)">
          <div style={{ overflowX: "auto" }}>
            <table className="t"><thead><tr><th>출발지</th><th className="num">요청</th><th>응답</th><th className="num">경로 수</th><th>접속 도구</th><th>공격 구문 줄</th><th>시간</th></tr></thead>
              <tbody>{w.sources.map((s: any) => (
                <tr key={s.src_ip}>
                  <td className="mono">{s.src_ip}</td><td className="num">{fmtNum(s.requests)}</td>
                  <td className="small">{STATUS_ORDER.filter((k) => s.status[k]).map((k) => `${k === "없음" ? "코드 없음" : k} ${s.status[k]}`).join(" · ")}</td>
                  <td className="num">{fmtNum(s.distinct_paths)}</td>
                  <td className="small">{s.clients.map((c: any) => `${c.kind_ko} ${c.count}`).join(", ") || "기록 없음"}</td>
                  <td className="mono small">{s.attack_syntax_lines.length ? s.attack_syntax_lines.slice(0, 5).join(", ") : ""}</td>
                  <td className="small muted">{s.first ? `${fmtTime(s.first)} ~ ${fmtTime(s.last, false)}` : ""}</td>
                </tr>))}</tbody></table>
          </div>
        </Panel>
      )}
    </div>
  );
}

export function CaseCard({ c, r }: { c: any; r?: any }) {
  const found: string[] = r?.web ? r.web.findings.filter((f: any) => f.state === "found").map((f: any) => f.detector_id) : [];
  const same = r?.web && [...new Set(found)].sort().join() === [...c.expected].sort().join();
  return (
    <Panel title={<span>사례 {c.id} · {c.server} · {c.title}</span>} right={r?.web ? <span className={`tag ${same ? "ok" : "bad"}`}>{same ? "기대한 결과와 같음" : "기대한 결과와 다름"}</span> : null}>
      <div className="col" style={{ gap: 4 }} data-testid="case-card">
        <div>{c.scenario}</div>
        <div className="small"><span className="muted">살펴볼 것: </span>{c.look_for.join(" / ")}</div>
        <div className="small"><span className="muted">기대 결과: </span>{c.expected.length ? `${c.expected.length}개 판단` : "판단 없음(대조 사례)"}</div>
        <div className="small"><span className="muted">정상 가능성·한계: </span>{c.normal_possibility}</div>
        <div className="muted small">가상 자료입니다. 주소는 문서용·사설 대역, 호스트는 example.test입니다.</div>
      </div>
    </Panel>
  );
}
