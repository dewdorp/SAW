import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Panel, Sev } from "../components/common";
import { Badge, EmptyState, Icon, PageHeader, Stat } from "../components/ui";
import { ReviewInbox } from "../components/Reviews";
import { SupportInbox } from "../components/Support";
import { UploadModal } from "../components/UploadModal";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

// Client-side preview only (non-authoritative); the server decides on Analyze.
function previewDetect(t: string): string[] {
  const out: string[] = [];
  if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+/m.test(t)) out.push("HTTP 요청");
  if (/^HTTP\/\d/m.test(t)) out.push("HTTP 응답");
  const ips = t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  if (ips) out.push(`IPv4 ×${new Set(ips).size}`);
  if (/\b(?:https?|hxxps?):\/\//i.test(t)) out.push("URL");
  if (/eyJ[\w-]+\.eyJ[\w-]+\./.test(t)) out.push("JWT");
  if (/%[0-9a-f]{2}/i.test(t)) out.push("URL 인코딩");
  if (/\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b/i.test(t)) out.push("해시");
  if (/^\S+ \S+ \S+ \[[^\]]+\] "/m.test(t)) out.push("웹 로그");
  if (/^\s*[{[]/.test(t)) out.push("JSON");
  return out;
}

const QUICK: [kind: string, label: string, desc: string, icon: string][] = [
  ["web_log", "웹 로그", "Apache·Nginx·IIS", "file"],
  ["waf_log", "WAF 로그", "차단·탐지 이벤트", "shield"],
  ["pcap", "PCAP", "패킷 캡처·Zeek 로그", "network"],
  ["ioc_list", "IOC 목록", "IP·도메인·해시", "target"],
  ["sec_log", "보안 로그", "인증·시스템 로그", "lock"],
];
const STATUS_KO: Record<string, string> = { new: "신규", in_progress: "분석 중", closed: "종결", open: "진행 중" };
const JOB_KO: Record<string, string> = { QUEUED: "대기", PARSING: "파싱 중", INDEXING: "색인 중", ANALYZING: "분석 중", UPLOADING: "업로드 중", WAITING_INPUT: "입력 필요" };

export function Home() {
  const [text, setText] = useState("");
  const [upload, setUpload] = useState<{ kind?: string; files?: File[] } | null>(null);
  const [target, setTarget] = useState("none");
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const jobs = useQuery({ queryKey: ["jobs", "active"], queryFn: () => api.get("/jobs?active=true"), refetchInterval: 4000 });
  const findings = useQuery({ queryKey: ["findings", "recent"], queryFn: () => api.get("/findings/recent") });
  const inbox = useQuery({ queryKey: ["team-inbox"], queryFn: () => api.get("/team-checks/inbox"), refetchInterval: 60000 });
  const asks = [...(inbox.data?.recheck || []).map((c: any) => ({ ...c, why: `재확인 요청(${c.state_by}): ${c.state_note}` })),
    ...(inbox.data?.source_changed || []).map((c: any) => ({ ...c, why: c.source_state === "retracted" ? "참고한 다른 조사의 확인이 철회됨" : "참고한 다른 조사의 확인이 바뀜" }))];
  const chips = useMemo(() => (text ? previewDetect(text) : []), [text]);
  const analyze = () => nav("/analyze", { state: { input: text, investigation: target !== "none" ? target : undefined } });
  const list = (invs.data || []) as any[];
  const open = list.filter((i) => i.status !== "closed");
  const highRisk = open.filter((i) => ["critical", "high"].includes(i.risk_level));
  return (
    <div className="page">
      <PageHeader eyebrow="SOC Analysis Workbench" title="무엇을 분석할까요?"
        desc="로그·IOC·HTTP 요청·인코딩된 문자열을 붙여넣거나 파일을 올리세요. 결과는 이야기 → 근거 → 원본 순서로 보여 드립니다." />
      <div className="stats">
        <Stat label="진행 중인 조사" value={open.length} onClick={() => nav("/investigations")} />
        <Stat label="높은 위험 조사" value={highRisk.length} tone={highRisk.length ? "high" : undefined} onClick={() => nav("/investigations")} />
        <Stat label="처리 중인 작업" value={jobs.data?.length ?? 0} tone={jobs.data?.length ? "accent" : undefined} onClick={() => nav("/jobs")} />
        <Stat label="최근 탐지" value={findings.data?.length ?? 0} />
      </div>
      <ReviewInbox />
      <SupportInbox />
      {asks.length > 0 && (
        <Panel title={`내 확인 기록에 확인이 필요한 것 ${asks.length}건`}>
          {asks.map((c: any) => (
            <div key={c.id} className="row small" style={{ gap: 10 }}>
              <Badge tone="warn">{c.kind === "cited" ? "참고 근거 변경" : "재확인 요청"}</Badge>
              <Link to={`/inv/${c.investigation_id}`} className="mono">{c.target_label}</Link><span className="grow ellipsis">{c.why}</span>
            </div>))}
        </Panel>
      )}
      <div className="grid2" style={{ gridTemplateColumns: "1.6fr 1fr", alignItems: "start" }}>
        <Panel title="붙여넣기 분석">
          <div className="col">
            <textarea className="input" rows={9} placeholder={"IP / URL / HTTP 요청 / 로그 / 페이로드 / JWT / 해시 …\n예) GET /api/customer?id=123 HTTP/1.1"} value={text}
              onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && text.trim()) analyze(); }}
              onDrop={(e) => { if (e.dataTransfer.files.length) { e.preventDefault(); setUpload({ files: Array.from(e.dataTransfer.files) }); } }} />
            <div className="row wrap">
              <span className="muted small">자동 감지(미리보기)</span>
              {chips.length ? chips.map((c) => <Badge key={c} tone="accent">{c}</Badge>) : <span className="muted small">—</span>}
              <div className="grow" />
              <select className="input" value={target} onChange={(e) => setTarget(e.target.value)} aria-label="결과를 기록할 조사">
                <option value="none">기록하지 않고 분석</option>
                {list.map((i) => <option key={i.id} value={i.id}>{i.display_id}에 기록</option>)}
              </select>
              <button className="btn primary" disabled={!text.trim()} onClick={analyze}><Icon name="analyze" size={15} /> 분석 (Ctrl+Enter)</button>
            </div>
          </div>
        </Panel>
        <Panel title="파일로 새 조사 시작">
          <div className="quick">
            {QUICK.map(([k, l, dsc, ic]) => (
              <button key={k} onClick={() => setUpload({ kind: k })}><Icon name={ic} /><b>{l}</b><small>{dsc}</small></button>
            ))}
          </div>
          <div className="dropzone" style={{ marginTop: 12 }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { if (e.dataTransfer.files.length) { e.preventDefault(); setUpload({ files: Array.from(e.dataTransfer.files) }); } }}>
            <Icon name="upload" /> 파일을 여기에 끌어다 놓거나 <a onClick={() => setUpload({})}>파일 선택</a>
            <div className="muted small">.gz · .zip 압축 파일 그대로 올릴 수 있습니다</div>
          </div>
        </Panel>
      </div>
      <div className="grid2" style={{ alignItems: "start", marginTop: 4 }}>
        <Panel title="최근 조사" right={<Link to="/investigations" className="small">전체 보기 →</Link>}>
          {list.slice(0, 6).map((i) => (
            <Link key={i.id} className="inv-card" to={`/inv/${i.id}`}>
              <Sev level={i.risk_level} />
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="ellipsis"><b>{i.title}</b></div>
                <div className="muted small">{i.display_id} · {fmtTime(i.created_at)}</div>
              </div>
              <Badge tone={i.status === "closed" ? undefined : "accent"}>{STATUS_KO[i.status] || i.status}</Badge>
            </Link>
          ))}
          {list.length === 0 && <EmptyState title="아직 조사가 없습니다">파일을 올리면 새 조사가 만들어집니다.</EmptyState>}
        </Panel>
        <div className="col">
          <Panel title="최근 탐지">
            {(findings.data || []).slice(0, 8).map((f: any) => (
              <div key={f.id} className="row" style={{ padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
                <Sev level={f.risk_level} />
                <Link className="ellipsis grow" to={`/inv/${f.investigation_id}?finding=${f.id}`}>{f.title}</Link>
                <span className="muted small">{f.display_id}</span>
              </div>
            ))}
            {findings.data?.length === 0 && <span className="muted">—</span>}
          </Panel>
          <Panel title="처리 중인 작업">
            {(jobs.data || []).map((j: any) => (
              <div key={j.id} className="row small"><Link to={`/jobs/${j.id}`} className="grow ellipsis">#{j.id.slice(0, 8)} {j.kind}</Link><Badge tone="accent">{JOB_KO[j.state] || j.state}</Badge></div>
            ))}
            {jobs.data?.length === 0 && <span className="muted small">진행 중인 작업이 없습니다</span>}
          </Panel>
        </div>
      </div>
      {upload && <UploadModal kind={upload.kind} initialFiles={upload.files} onClose={() => setUpload(null)} />}
    </div>
  );
}
