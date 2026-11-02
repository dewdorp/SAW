import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ErrorBox, Loading, Sev } from "../../components/common";
import { UploadModal } from "../../components/UploadModal";
import { Icon } from "../../components/ui";
import { useInv, useInvTabs } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../../lib/format";
import { AnalysisHistoryTab } from "./AnalysisHistoryTab";
import { SourceContextTab } from "./SourceContextTab";
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
import { InternalGoldenPanel } from "./InternalGoldenPanel";
import { ScopePeriodEditor, ScopeSummary } from "./ScopeSummary";
import { RawTab } from "./RawTab";
import { RelationsTab } from "./RelationsTab";
import { StatisticsTab } from "./StatisticsTab";
import { StoryTab } from "./StoryTab";
import { TimelineTab } from "./TimelineTab";

/** Basic work areas: the whole picture, investigating, the whole log, then checks and judgement. Every earlier tab
 * is still here; specialist views fold under "전문 분석". */
type Area = { key: string; label: string; hint: string; tabs: [string, string][]; advanced?: [string, string][] };
const AREAS: Area[] = [
  { key: "picture", label: "① 전체 현황", hint: "조사 범위·전체 건수·수집과 파싱 상태·기간별 변화·주요 통신과 공격명·확인할 질문",
    tabs: [["summary", "전체 현황"], ["overview", "트래픽 개요"], ["source-context", "장비·자료 의미"], ["analysis-history", "분석 실행 이력"]] },
  { key: "investigate", label: "② 조사", hint: "조사 제안과 생성 이유, 반복 행위 묶음, 시계열",
    tabs: [["findings", "조사 제안"], ["behavior", "행위 묶음·시계열"], ["timeline", "타임라인"]],
    advanced: [["story", "공격 스토리"], ["relations", "관계 그래프"], ["http", "HTTP"], ["forensics", "PCAP 포렌식"], ["dns", "DNS"], ["tls", "TLS"], ["conn", "연결"], ["attack", "ATT&CK"]] },
  { key: "logs", label: "③ 전체 로그", hint: "조사 제안에 없는 기록까지 검색·정렬·집계·원문 확인, 전체 결과 내보내기",
    tabs: [["raw", "전체 로그·원문"], ["statistics", "로그 통계"]] },
  { key: "decide", label: "④ 확인 및 판단", hint: "확인이 필요한 사항, 확인 요청과 회신, 판단 근거, 골든셋 저장",
    tabs: [["checks", "확인 요청·검토"], ["golden", "골든셋 저장"], ["notes", "메모"]] },
];
const TABS: [string, string][] = AREAS.flatMap((a) => [...a.tabs, ...(a.advanced || [])]);
const areaOf = (tab: string) => AREAS.find((a) => [...a.tabs, ...(a.advanced || [])].some(([k]) => k === tab)) || AREAS[1];
const SEARCH_FIELDS: [string, string][] = [["src_ip", "출발지 IP"], ["dst_ip", "목적지 IP"], ["dst_port", "목적지 포트"], ["uri", "URL 경로"],
  ["hostname", "호스트명"], ["alert_name", "장비 공격명"], ["enforcement_action", "처리 결과"], ["session_id", "세션 ID"], ["user_agent", "User-Agent"],
  ["method", "HTTP 메서드"], ["status_code", "응답 코드"], ["protocol", "프로토콜"], ["data_source", "로그 종류"]];
const NUMERIC_FIELDS = new Set(["dst_port", "status_code"]);
const FACETS = ["data_source", "src_cloud", "status_class", "ua_class", "src_geo_country", "method"];
const FACET_KO: Record<string, string> = { data_source: "데이터 출처", src_cloud: "출발지 클라우드", status_class: "응답 코드", ua_class: "User-Agent 유형",
  src_geo_country: "출발지 국가", method: "HTTP 메서드" };
const KIND_KO: Record<string, string> = { web_log: "웹 로그", waf_log: "WAF 로그", pcap: "PCAP", ioc_list: "IOC 목록", sec_log: "보안 로그",
  fw_log: "방화벽 로그", db_audit: "DB 감사", paste: "붙여넣기", http: "HTTP", file: "파일" };
const STATUS_KO: Record<string, string> = { new: "신규", in_progress: "분석 중", closed: "종결", open: "진행 중" };
const VERDICT_KO: Record<string, string> = { normal: "정상 업무로 확인", attack_attempt: "공격 시도 확인", compromise_confirmed: "침해·영향 확인",
  insufficient_evidence: "증거 부족", data_quality_limited: "데이터 품질로 판단 제한", attack: "공격", false_positive: "오탐", unknown: "판단 보류" };

export function Workbench() {
  const { id = "" } = useParams();
  const [sp] = useSearchParams();
  const ctx = useInv(id);
  const tabs = useInvTabs();
  const qc = useQueryClient();
  // One refresh contract: anything that changes the period, data or analysis refreshes every view built on it.
  const refreshScope = () => ["inv", "scope-summary", "alert-names", "findings", "internal-golden", "checks"]
    .forEach((key) => qc.invalidateQueries({ queryKey: [key, id] }));
  const [upload, setUpload] = useState(false);
  const [closing, setClosing] = useState(false);
  const [siem, setSiem] = useState(false);
  const [left, setLeft] = useState(() => window.innerWidth >= 1100);
  const [right, setRight] = useState(() => window.innerWidth >= 1350);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [search, setSearch] = useState({ field: "src_ip", op: "is", value: "" });
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
  const area = areaOf(ctx.tab);
  return (
    <div className="wb">
      <div className="wb-head col" style={{ gap: 8 }}>
        <div className="row wrap" style={{ gap: 12 }}>
          <div className="col" style={{ gap: 2, minWidth: 0 }}>
            <div className="eyebrow" style={{ marginBottom: 0 }}>{i.display_id} · 조사 작업대</div>
            <div className="row wrap" style={{ gap: 10, maxWidth: "100%" }}>
              <h2 className="ellipsis" style={{ fontSize: 19, maxWidth: 560 }} title={i.title}>{i.title}</h2>
              <Sev level={i.risk_level} score={i.risk_score} />
              <span className="badge">{STATUS_KO[i.status] || i.status}{i.verdict ? ` · ${VERDICT_KO[i.verdict] || i.verdict}` : ""}</span>
            </div>
          </div>
          <div className="grow" />
          <button className="btn sm" onClick={() => setUpload(true)}><Icon name="upload" size={14} /> 증거 추가</button>
          <button className="btn sm" onClick={() => setSiem(true)}>SIEM에서 가져오기</button>
          <button className="btn sm" onClick={async () => { await api.post(`/investigations/${id}/reanalyze`); refreshScope(); }}>재분석</button>
          <Link className="btn sm" to={`/inv/${id}/report`} title="임원 보고용으로 한 장에 정리한 화면 (인쇄·PDF 저장)"><Icon name="report" size={14} /> 보고용 요약</Link>
          <button className="btn sm ghost" aria-expanded={left} aria-controls="workbench-evidence" onClick={() => setLeft(!left)}>{left ? "증거·필터 숨기기" : "증거·필터 보기"}</button>
          <button className="btn sm ghost" aria-expanded={right} aria-controls="workbench-context" onClick={() => setRight(!right)}>{right ? "조사 안내·참고 숨기기" : "조사 안내·참고 보기"}</button>
          {i.status !== "closed" && <button className="btn sm primary" onClick={() => setClosing(true)}>조사 종결</button>}
        </div>
        <div className="row wrap small" role="group" aria-label="조사 범위" style={{ gap: 16, color: "var(--fg-1)" }}>
          <span><span className="muted">관계사</span> <b>{i.org_unit || "미지정"}</b></span>
          <span><span className="muted">조사 기간</span> {i.period_start ? <b>{fmtTime(i.period_start)} ~ {fmtTime(i.period_end)}</b> : <span className="tag warn">미지정</span>}</span>
          <span><span className="muted">관측 기간</span> {fmtTime(i.time_start)} ~ {fmtTime(i.time_end)}</span>
          <span><span className="muted">증거</span> {i.evidence.length}건</span>
          <span><span className="muted">탐지</span> {total}건 {["critical", "high", "medium", "low"].filter((k) => fc[k]).map((k) => <span key={k} className={`sev ${k}`} style={{ marginLeft: 6 }}>{({ critical: "심각", high: "높음", medium: "보통", low: "낮음" } as any)[k]} {fc[k]}</span>)}</span>
        </div>
        {(!i.org_unit_id || !i.period_start) && <div role="note" className="small" style={{ color: "var(--warn)" }}>
          관계사와 조사 기간을 지정하면 모든 통계·검색·확인 요청·골든셋이 그 범위로 묶입니다. {!i.period_start && <ScopePeriodEditor inv={i} onSaved={refreshScope} />}
        </div>}
        <form className="row wrap small" role="search" aria-label="로그 직접 검색" style={{ gap: 6 }} onSubmit={(e) => {
          e.preventDefault();
          const raw = search.value.trim();
          if (!raw) return;
          const value = NUMERIC_FIELDS.has(search.field) && /^\d+$/.test(raw) ? Number(raw) : raw;
          ctx.addFilter({ field: search.field, op: search.op as any, value });
          setSearch({ ...search, value: "" });
        }}>
          <span className="muted">직접 검색</span>
          <select className="input" aria-label="검색 필드" value={search.field} onChange={(e) => setSearch({ ...search, field: e.target.value })}>{SEARCH_FIELDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <select className="input" aria-label="검색 조건" value={search.op} onChange={(e) => setSearch({ ...search, op: e.target.value })}>
            <option value="is">같음</option><option value="is_not">다름</option><option value="contains">포함</option><option value="prefix">시작</option>
          </select>
          <input className="input" aria-label="검색 값" placeholder="값 입력 후 Enter" value={search.value} onChange={(e) => setSearch({ ...search, value: e.target.value })} style={{ width: 200 }} />
          <button className="btn sm" type="submit">조건 추가</button>
          <span className="muted">조사 제안과 무관하게 전체 로그에서 찾습니다. 찾은 기록은 원문에서 확인 기록으로 이 조사에 근거로 추가할 수 있습니다.</span>
        </form>
        <div className="row wrap small">
          <span className="muted">필터</span>
          {ctx.filters.map((f, k) => (
            <span key={k} className={`tag ${f.op.startsWith("is_not") || f.op === "not_in" ? "bad" : ""}`} style={{ cursor: "pointer", maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis" }} onClick={() => ctx.removeFilter(k)} title="클릭하여 제거">
              {f.op === "is_not" ? "− " : ""}{f.field === "event_id" && Array.isArray(f.value) ? `선택 근거 ${f.value.length}건`
                : f.op === "exists" || f.op === "not_exists" ? `${(SEARCH_FIELDS.find(([k]) => k === f.field) || [f.field, f.field])[1]} ${f.op === "exists" ? "값 있음" : "값 없음"}`
                : `${(SEARCH_FIELDS.find(([k]) => k === f.field) || [f.field, f.field])[1]} ${({ contains: "포함", prefix: "시작", is_not: "≠", in: "중 하나", not_in: "제외" } as Record<string, string>)[f.op] || "="} ${JSON.stringify(f.value)}`} ×
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
          <nav className="row wrap" aria-label="작업 영역" style={{ gap: 6, marginBottom: 6 }}>
            {AREAS.map((a) => <button key={a.key} className={`btn sm ${area.key === a.key && ctx.tab !== "entity" ? "primary" : ""}`} aria-pressed={area.key === a.key && ctx.tab !== "entity"} title={a.hint}
              onClick={() => ctx.set({ tab: a.tabs[0][0] })}>{a.label}</button>)}
            <span className="small muted" style={{ alignSelf: "center" }}>{area.hint}</span>
          </nav>
          <div className="tabs" role="tablist" aria-label={area.label}>
            {[...area.tabs, ...(showAdvanced || area.advanced?.some(([k]) => k === ctx.tab) ? area.advanced || [] : [])].map(([k, l]) => <button key={k} role="tab" aria-selected={ctx.tab === k} disabled={!enabled(k)} title={!enabled(k) ? "PCAP 또는 네트워크 로그 증거가 필요합니다" : undefined} className={ctx.tab === k ? "active" : ""} onClick={() => ctx.set({ tab: k })}>{l}</button>)}
            {area.advanced && <button className="ghost" aria-expanded={showAdvanced} onClick={() => setShowAdvanced(!showAdvanced)}>{showAdvanced ? "전문 분석 접기" : `전문 분석 ${area.advanced.length}개 펼치기`}</button>}
            {ctx.tab === "entity" && <button className="active">엔티티</button>}
          </div>
          <div className="tab-body">
            {ctx.tab === "summary" && <ScopeSummary inv={id} />}
            {ctx.tab === "golden" && <InternalGoldenPanel inv={id} />}
            {ctx.tab === "overview" && <OverviewTab inv={id} />}
            {ctx.tab === "source-context" && <SourceContextTab inv={id} />}
            {ctx.tab === "analysis-history" && <AnalysisHistoryTab key={id} inv={id} />}
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
      {upload && <UploadModal invId={id} onClose={() => { setUpload(false); refreshScope(); }} />}
      {siem && <ConnectorImport inv={id} onClose={() => { setSiem(false); qc.invalidateQueries(); }} />}
      {closing && <CloseDialog inv={i} onClose={() => { setClosing(false); refreshScope(); }} />}
    </div>
  );
}
