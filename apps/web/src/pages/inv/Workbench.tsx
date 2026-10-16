import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, Sev } from "../../components/common";
import { UploadModal } from "../../components/UploadModal";
import { Icon } from "../../components/ui";
import { useInv, useInvTabs } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../../lib/format";
import { AttackTab } from "./AttackTab";
import { BehaviorTab } from "./BehaviorTab";
import { ChecksTab } from "./ChecksTab";
import { CloseDialog } from "./CloseDialog";
import { ConnectorImport } from "./ConnectorImport";
import { ContextPanel } from "./ContextPanel";
import { EntityTab } from "./EntityTab";
import { EventDrawer } from "./EventDrawer";
import { FindingsTab } from "./FindingsTab";
import { ForensicsTab } from "./ForensicsTab";
import { HttpTab } from "./HttpTab";
import { NetworkTab } from "./NetworkTab";
import { NotesTab } from "./NotesTab";
import { OverviewTab } from "./OverviewTab";
import { RawTab } from "./RawTab";
import { RelationsTab } from "./RelationsTab";
import { StatisticsTab } from "./StatisticsTab";
import { StoryTab } from "./StoryTab";
import { TimelineTab } from "./TimelineTab";

const TABS: [string, string][] = [
  ["overview", "개요"], ["statistics", "로그 통계"], ["behavior", "행위 분석"], ["findings", "탐지 결과"], ["story", "공격 스토리"], ["timeline", "타임라인"], ["relations", "관계 그래프"],
  ["http", "HTTP"], ["forensics", "PCAP 포렌식"], ["dns", "DNS"], ["tls", "TLS"], ["conn", "연결"], ["attack", "ATT&CK"],
  ["raw", "원본 로그"], ["checks", "확인·검토"], ["notes", "메모"],
];
const FACETS = ["data_source", "src_cloud", "status_class", "ua_class", "src_geo_country", "method"];
const FACET_KO: Record<string, string> = { data_source: "데이터 출처", src_cloud: "출발지 클라우드", status_class: "응답 코드", ua_class: "User-Agent 유형",
  src_geo_country: "출발지 국가", method: "HTTP 메서드" };
const KIND_KO: Record<string, string> = { web_log: "웹 로그", waf_log: "WAF 로그", pcap: "PCAP", ioc_list: "IOC 목록", sec_log: "보안 로그",
  fw_log: "방화벽 로그", db_audit: "DB 감사", paste: "붙여넣기", http: "HTTP", file: "파일" };
const STATUS_KO: Record<string, string> = { new: "신규", in_progress: "분석 중", closed: "종결", open: "진행 중" };

export function Workbench() {
  const { id = "" } = useParams();
  const [sp] = useSearchParams();
  const ctx = useInv(id);
  const tabs = useInvTabs();
  const qc = useQueryClient();
  const [upload, setUpload] = useState(false);
  const [closing, setClosing] = useState(false);
  const [siem, setSiem] = useState(false);
  const [left, setLeft] = useState(() => window.innerWidth >= 1100);
  const [right, setRight] = useState(() => window.innerWidth >= 1350);
  const inv = useQuery({ queryKey: ["inv", id], queryFn: () => api.get(`/investigations/${id}`), refetchInterval: 10000 });
  const fq = { filters: ctx.filters, time: ctx.time };
  const sources = useQuery({ queryKey: ["agg", id, "data_source"], queryFn: () => api.post(`/investigations/${id}/query/aggregate`, { filters: [], agg: { type: "terms", field: "data_source", size: 20 } }) });
  const facets = useQuery({
    queryKey: ["facets", id, fq],
    queryFn: async () => Object.fromEntries(await Promise.all(FACETS.map(async (f) => [f, (await api.post(`/investigations/${id}/query/aggregate`, { ...fq, agg: { type: "terms", field: f, size: 6 } }))]))),
  });
  useEffect(() => { if (inv.data) tabs.open(id, `${inv.data.display_id} ${inv.data.title}`); }, [inv.data?.display_id, inv.data?.title]); // eslint-disable-line
  useEffect(() => { const tab = sp.get("tab"); if (tab && TABS.some(([key]) => key === tab)) ctx.set({ tab }); }, [sp.get("tab")]); // eslint-disable-line
  useEffect(() => { const f = sp.get("finding"); if (f) ctx.set({ tab: "findings", findingId: f }); }, [sp.get("finding")]); // eslint-disable-line
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement)?.tagName?.match(/INPUT|TEXTAREA|SELECT/)) return;
      if (e.key === "Escape") ctx.set({ selection: null, eventId: null });
      if (e.key === ".") ctx.set({ tab: "raw" });
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  });
  if (inv.isLoading) return <Loading />;
  if (inv.error) return <div className="page"><ErrorBox error={inv.error} /></div>;
  const i = inv.data;
  const ds = new Set((sources.data?.buckets || []).map((b: any) => b.key));
  const hasNet = ["zeek_conn", "zeek_dns", "zeek_ssl", "zeek_http", "suricata"].some((x) => ds.has(x));
  const hasPcap = i.evidence.some((e: any) => e.kind === "pcap");
  const enabled = (t: string) => (["dns", "tls", "conn"].includes(t) ? hasNet : t === "forensics" ? hasPcap : true);
  const fc = i.finding_counts || {};
  const total = Object.values(fc).reduce((a: number, b: any) => a + b, 0) as number;
  return (
    <div className="wb">
      <div className="wb-head col" style={{ gap: 8 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <div className="col" style={{ gap: 2, minWidth: 0 }}>
            <div className="eyebrow" style={{ marginBottom: 0 }}>{i.display_id} · 조사 작업대</div>
            <div className="row wrap" style={{ gap: 10, maxWidth: "100%" }}>
              <h2 className="ellipsis" style={{ fontSize: 19, maxWidth: 560 }} title={i.title}>{i.title}</h2>
              <Sev level={i.risk_level} score={i.risk_score} />
              <span className="badge">{STATUS_KO[i.status] || i.status}{i.verdict ? ` · ${i.verdict}` : ""}</span>
            </div>
          </div>
          <div className="grow" />
          <button className="btn sm" onClick={() => setUpload(true)}><Icon name="upload" size={14} /> 증거 추가</button>
          <button className="btn sm" onClick={() => setSiem(true)}>SIEM에서 가져오기</button>
          <button className="btn sm" onClick={async () => { await api.post(`/investigations/${id}/reanalyze`); qc.invalidateQueries({ queryKey: ["inv", id] }); }}>재분석</button>
          <Link className="btn sm" to={`/inv/${id}/report`} title="임원 보고용으로 한 장에 정리한 화면 (인쇄·PDF 저장)"><Icon name="report" size={14} /> 보고용 요약</Link>
          <button className="btn sm ghost" aria-expanded={left} aria-controls="workbench-evidence" onClick={() => setLeft(!left)}>{left ? "증거·필터 숨기기" : "증거·필터 보기"}</button>
          <button className="btn sm ghost" aria-expanded={right} aria-controls="workbench-context" onClick={() => setRight(!right)}>{right ? "조사 안내·참고 숨기기" : "조사 안내·참고 보기"}</button>
          {i.status !== "closed" && <button className="btn sm primary" onClick={() => setClosing(true)}>조사 종결</button>}
        </div>
        <div className="row wrap small" style={{ gap: 16, color: "var(--fg-1)" }}>
          <span><span className="muted">관측 기간</span> {fmtTime(i.time_start)} ~ {fmtTime(i.time_end)}</span>
          <span><span className="muted">증거</span> {i.evidence.length}건</span>
          <span><span className="muted">탐지</span> {total}건 {["critical", "high", "medium", "low"].filter((k) => fc[k]).map((k) => <span key={k} className={`sev ${k}`} style={{ marginLeft: 6 }}>{({ critical: "심각", high: "높음", medium: "보통", low: "낮음" } as any)[k]} {fc[k]}</span>)}</span>
        </div>
        <div className="row wrap small">
          <span className="muted">필터</span>
          {ctx.filters.map((f, k) => (
            <span key={k} className={`tag ${f.op.startsWith("is_not") || f.op === "not_in" ? "bad" : ""}`} style={{ cursor: "pointer", maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis" }} onClick={() => ctx.removeFilter(k)} title="클릭하여 제거">
              {f.op === "is_not" ? "− " : ""}{f.field === "event_id" && Array.isArray(f.value) ? `선택 근거 ${f.value.length}건` : `${f.field} = ${JSON.stringify(f.value)}`} ×
            </span>
          ))}
          {ctx.time && <span className="tag" onClick={() => ctx.set({ time: null })} style={{ cursor: "pointer" }}>🕑 {fmtTime(ctx.time.start)} ~ {fmtTime(ctx.time.end)} ×</span>}
          {!ctx.filters.length && !ctx.time && <span className="muted">없음 — 차트나 값을 클릭해 추가합니다</span>}
          {ctx.selection && <span className="tag" style={{ borderColor: "var(--hl)", color: "var(--hl)" }}>선택: {ctx.selection.type} {ctx.selection.value} <a onClick={() => ctx.addFilter({ field: ({ ip: "src_ip", uri: "uri_template" } as any)[ctx.selection!.type] || ctx.selection!.type, op: "is", value: ctx.selection!.value })}>이 값으로 필터</a> <a onClick={() => ctx.set({ selection: null })}>×</a></span>}
        </div>
      </div>
      <div className={`wb-body ${right ? "" : "no-right"} ${left ? "" : "no-left"}`}>
        {left && <aside id="workbench-evidence" className="wb-left" aria-label="증거와 필터">
          <div className="section">
            <h4>증거</h4>
            {i.evidence.map((e: any) => (
              <div key={e.id} className="small row" style={{ padding: "2px 0" }} title={e.title}>
                <Icon name={e.kind === "pcap" ? "network" : "file"} size={14} />
                <span className="grow ellipsis"><b style={{ fontWeight: 600 }}>{KIND_KO[e.kind] || e.kind}</b> <span className="muted">{e.title || e.id.slice(0, 8)}</span></span>
                <span className="muted">{fmtBytes(e.size)}</span><span title={e.status}>{e.status === "processed" ? "✓" : "…"}</span>
              </div>
            ))}
            <a className="small" onClick={() => setUpload(true)}>+ 증거 추가</a>
          </div>
          <div className="section">
            <h4>데이터 출처</h4>
            {(sources.data?.buckets || []).map((b: any) => (
              <div key={b.key} className="facet-row small"><span className="grow">{b.key}</span><span className="num">{fmtNum(b.count)}</span>
                <button className="btn ghost sm" title="이 출처 제외" onClick={() => ctx.addFilter({ field: "data_source", op: "is_not", value: b.key })}>제외</button></div>
            ))}
          </div>
          <div className="section">
            <h4>값 분포 (포함 I · 제외 E)</h4>
            {facets.data && FACETS.map((f) => {
              const bs = facets.data[f]?.buckets || [];
              if (!bs.length) return null;
              const tot = facets.data[f].total || 1;
              return (
                <div key={f} style={{ marginBottom: 6 }}>
                  <div className="small muted">{FACET_KO[f] || f}</div>
                  {bs.map((b: any) => (
                    <div key={String(b.key)} className="facet-row small">
                      <span className="mono ellipsis" style={{ width: 90 }}>{String(b.key)}</span>
                      <div className="grow"><div className="bar" style={{ width: `${(100 * b.count) / tot}%` }} /></div>
                      <span className="num" style={{ width: 40 }}>{Math.round((100 * b.count) / tot)}%</span>
                      <button className="btn ghost sm" aria-label="포함" title="이 값만 보기" onClick={() => ctx.addFilter({ field: f, op: "is", value: b.key })}>I</button>
                      <button className="btn ghost sm" aria-label="제외" title="이 값 제외" onClick={() => ctx.addFilter({ field: f, op: "is_not", value: b.key })}>E</button>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </aside>}
        <section className="wb-center">
          <div className="tabs" role="tablist">
            {TABS.map(([k, l]) => <button key={k} role="tab" aria-selected={ctx.tab === k} disabled={!enabled(k)} title={!enabled(k) ? "PCAP 또는 네트워크 로그 증거가 필요합니다" : undefined} className={ctx.tab === k ? "active" : ""} onClick={() => ctx.set({ tab: k })}>{l}</button>)}
            {ctx.tab === "entity" && <button className="active">엔티티</button>}
          </div>
          <div className="tab-body">
            {ctx.tab === "overview" && <OverviewTab inv={id} />}
            {ctx.tab === "statistics" && <StatisticsTab inv={id} />}
            {ctx.tab === "behavior" && <BehaviorTab inv={id} />}
            {ctx.tab === "findings" && <FindingsTab inv={id} />}
            {ctx.tab === "story" && <StoryTab inv={id} />}
            {ctx.tab === "timeline" && <TimelineTab inv={id} />}
            {ctx.tab === "relations" && <RelationsTab inv={id} />}
            {ctx.tab === "http" && <HttpTab inv={id} />}
            {ctx.tab === "forensics" && <ForensicsTab inv={id} />}
            {(ctx.tab === "dns" || ctx.tab === "tls" || ctx.tab === "conn") && <NetworkTab inv={id} kind={ctx.tab} />}
            {ctx.tab === "attack" && <AttackTab inv={id} />}
            {ctx.tab === "raw" && <RawTab inv={id} />}
            {ctx.tab === "checks" && <ChecksTab inv={id} />}
            {ctx.tab === "notes" && <NotesTab inv={id} />}
            {ctx.tab === "entity" && <EntityTab inv={id} />}
          </div>
        </section>
        {right && <aside id="workbench-context" className="wb-right" aria-label="컨텍스트"><ContextPanel inv={id} /></aside>}
      </div>
      <EventDrawer inv={id} />
      {upload && <UploadModal invId={id} onClose={() => { setUpload(false); qc.invalidateQueries({ queryKey: ["inv", id] }); }} />}
      {siem && <ConnectorImport inv={id} onClose={() => { setSiem(false); qc.invalidateQueries(); }} />}
      {closing && <CloseDialog inv={i} onClose={() => { setClosing(false); qc.invalidateQueries({ queryKey: ["inv", id] }); }} />}
    </div>
  );
}
