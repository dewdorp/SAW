import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, Route, Routes, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";

export const TARGET_KO: Record<string, string> = {
  timestamp_raw: "시간", src_ip: "출발지 IP", src_port: "출발지 포트", dst_ip: "목적지 IP", dst_port: "목적지 포트",
  method: "HTTP 메소드", uri: "URL·경로", hostname: "호스트", status_code: "응답 코드", bytes_out: "보낸 바이트",
  bytes_in: "받은 바이트", user_agent: "User-Agent", user: "사용자", severity: "위험도", ja3: "JA3", ja4: "JA4",
  domain: "도메인", session_id: "세션 ID", protocol: "프로토콜", hash: "해시", process: "프로세스",
};
const SOURCE_KO: Record<string, string> = {
  custom: "일반 로그", web: "웹 접근 로그", waf: "웹방화벽", zeek_conn: "네트워크 연결", zeek_dns: "DNS", linux: "리눅스", windows: "윈도우",
};
const FORMAT_KO: Record<string, string> = { delimited: "구분자 (CSV·탭·|)", regex: "정규식", kv: "키=값", json: "JSON" };
const DELIMS: [string, string][] = [[",", "쉼표 ,"], ["\t", "탭"], ["|", "세로줄 |"], [";", "세미콜론 ;"]];

type Expand = { column: string; pair_sep: string; kv_sep: string; prefix?: string };
export type Spec = {
  format: "delimited" | "regex" | "kv" | "json"; delimiter?: string; has_header?: boolean; columns?: string[]; pattern?: string;
  pair_sep?: string; kv_sep?: string; expand?: Expand[]; mapping: Record<string, string>; auto_map?: boolean;
  drop?: string[]; mask?: string[]; time_format?: string; timezone?: string; data_source?: string; event_type?: string;
  detect?: { header_contains?: string[]; line_regex?: string };
};
const EMPTY: Spec = { format: "delimited", delimiter: ",", has_header: true, mapping: {}, data_source: "custom", detect: {} };

export function Parsers() {
  const loc = useLocation();
  return (
    <div className="page col">
      <PageHeader eyebrow="지식·탐지" title="파서 관리"
        desc="장비마다 다른 TXT·CSV 형식을 직접 정의합니다. 코드는 실행하지 않고 설정으로만 해석하며, 저장할 때마다 새 버전이 남습니다." />
      <div className="tabs">
        <Link to="/parsers"><button className={loc.pathname === "/parsers" ? "active" : ""}>파서 목록</button></Link>
        <Link to="/parsers/new"><button className={loc.pathname.startsWith("/parsers/new") ? "active" : ""}>＋ 새 파서</button></Link>
      </div>
      <Routes>
        <Route index element={<ParserList />} />
        <Route path="new" element={<ParserWizard />} />
      </Routes>
    </div>
  );
}

const STATUS_TAG: Record<string, [string, string]> = {
  draft: ["내 초안", "warn"], pending: ["승인 대기", "warn"], active: ["공용 · 사용 중", "ok"], disabled: ["꺼짐", ""], superseded: ["이전 버전", ""],
};

function ParserList() {
  const qc = useQueryClient();
  const nav = useNavigate();
  const me = useMe();
  const canManage = !!me.data?.permissions.includes("parser.manage");
  const canApprove = !!me.data?.permissions.includes("parser.approve");
  const q = useQuery({ queryKey: ["parser-library"], queryFn: () => api.get("/parser-library") });
  const done = () => { qc.invalidateQueries({ queryKey: ["parser-library"] }); qc.invalidateQueries({ queryKey: ["parsers"] }); };
  const toggle = useMutation({ mutationFn: ({ slug, on }: { slug: string; on: boolean }) => api.post(`/parser-library/${slug}/${on ? "enable" : "disable"}`), onSuccess: done });
  const share = useMutation({ mutationFn: (p: any) => api.post(`/parser-library/${p.slug}/versions/${p.version}/share`), onSuccess: done });
  const review = useMutation({
    mutationFn: ({ p, approve, note }: { p: any; approve: boolean; note: string }) => api.post(`/parser-library/${p.slug}/versions/${p.version}/review`, { approve, note }),
    onSuccess: done,
  });
  const imp = useMutation({ mutationFn: (doc: unknown) => api.post("/parser-library/import", doc), onSuccess: done });
  const file = useRef<HTMLInputElement>(null);
  const [impErr, setImpErr] = useState<string>("");
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows: any[] = q.data.parsers;
  const pending = rows.filter((p) => p.can_review);
  return (
    <div className="col">
      <div className="notice small">저장한 파서는 <b>내 초안</b>입니다 — 내 파일에는 바로 쓸 수 있습니다. <b>공용 요청</b> 후 다른 분석가(선임·매니저)가 승인하면 모두가 쓰는 공용 파서가 되어 자동 감지에 쓰입니다. 작성자는 자기 파서를 승인할 수 없습니다.</div>
      {pending.length > 0 && <div className="notice small high">승인을 기다리는 파서 {pending.length}건이 있습니다. 미리보기로 확인한 뒤 승인·반려하세요.</div>}
      <Panel title={`파서 ${rows.length}개`} right={canManage && <>
        <input ref={file} type="file" accept=".json,application/json" hidden onChange={async (e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (!f) return;
          try { setImpErr(""); imp.mutate(JSON.parse(await f.text())); } catch { setImpErr("파서 정의 파일(JSON)이 아닙니다."); }
        }} />
        <button className="btn sm" onClick={() => file.current?.click()}>가져오기 (내 초안으로)</button></>}>
        {impErr && <div className="error">{impErr}</div>}
        <ErrorBox error={imp.error || toggle.error || share.error || review.error} />
        {!rows.length ? <div className="muted">아직 만든 파서가 없습니다. <Link to="/parsers/new">새 파서 만들기</Link></div> : (
          <table className="t"><thead><tr><th>이름</th><th>파서 ID</th><th>버전</th><th>상태</th><th>형식</th><th>데이터 종류</th><th>자동 감지</th><th>작성 · 검토</th><th /></tr></thead>
            <tbody>{rows.map((p) => {
              const [label, tone] = STATUS_TAG[p.status] || [p.status, ""];
              return (
                <tr key={p.pinned_id}><td><b>{p.name}</b>{p.note && <div className="muted small ellipsis" style={{ maxWidth: 260 }}>{p.note}</div>}
                  {p.review_note && <div className="small" style={{ color: "var(--med)" }}>검토 의견: {p.review_note}</div>}</td>
                  <td className="mono small">{p.status === "active" ? p.id : p.pinned_id}</td><td className="num">v{p.version}</td>
                  <td><span className={`tag ${tone}`}>{label}</span></td>
                  <td>{FORMAT_KO[p.spec.format]}</td><td>{SOURCE_KO[p.spec.data_source] || p.spec.data_source}</td>
                  <td className="small">{p.status !== "active" ? <span className="muted">승인 후</span> : p.spec.detect?.header_contains?.length || p.spec.detect?.line_regex ? "예" : <span className="muted">직접 선택</span>}</td>
                  <td className="small">{p.created_by} · {fmtTime(p.created_at)}{p.reviewed_by && <div className="muted">검토 {p.reviewed_by} · {fmtTime(p.reviewed_at)}</div>}</td>
                  <td className="row wrap">
                    {canManage && <button className="btn sm" onClick={() => nav(`/parsers/new?edit=${p.slug}`)}>수정</button>}
                    {p.mine && p.status === "draft" && <button className="btn sm primary" onClick={() => share.mutate(p)}>공용 요청</button>}
                    {p.can_review && <>
                      <button className="btn sm primary" onClick={() => review.mutate({ p, approve: true, note: "" })}>승인</button>
                      <button className="btn sm" onClick={() => { const note = window.prompt("반려 사유 (작성자에게 표시)") || ""; if (note) review.mutate({ p, approve: false, note }); }}>반려</button></>}
                    <button className="btn sm" onClick={() => api.download(`/parser-library/${p.slug}/export`, `saw-parser-${p.slug}.json`)}>내보내기</button>
                    {canApprove && p.status === "active" && <button className="btn sm ghost" onClick={() => toggle.mutate({ slug: p.slug, on: false })}>끄기</button>}
                    {canApprove && p.status === "disabled" && <button className="btn sm" onClick={() => toggle.mutate({ slug: p.slug, on: true })}>켜기</button>}
                  </td></tr>);
            })}</tbody></table>
        )}
      </Panel>
    </div>
  );
}

async function readFileHead(f: File): Promise<string> {
  const buf = await f.slice(0, 256 * 1024).arrayBuffer();
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(buf); } catch { text = new TextDecoder("euc-kr").decode(buf); }
  return text.split(/\r?\n/).slice(0, 200).join("\n");
}

const list = (v: string) => v.split(",").map((x) => x.trim()).filter(Boolean);

export function ParserWizard() {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const meta = useQuery({ queryKey: ["parser-library"], queryFn: () => api.get("/parser-library") });
  const ev = params.get("ev"), fid = params.get("file"), job = params.get("job"), edit = params.get("edit");
  const [sample, setSample] = useState("");
  const [spec, setSpec] = useState<Spec>(EMPTY);
  const [columns, setColumns] = useState<string[]>([]);
  const [notes, setNotes] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [note, setNote] = useState("");
  const [newCol, setNewCol] = useState("");

  const fromFile = useQuery({ queryKey: ["file-sample", ev, fid], enabled: !!ev && !!fid, queryFn: () => api.get(`/evidence/${ev}/files/${fid}/sample?lines=100`) });
  useEffect(() => { if (fromFile.data && !sample) { setSample(fromFile.data.lines.join("\n")); if (!name) setName(fromFile.data.file.replace(/\.[^.]+$/, "")); } }, [fromFile.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const editing = useQuery({ queryKey: ["parser-history", edit], enabled: !!edit, queryFn: () => api.get(`/parser-library/${edit}`) });
  useEffect(() => {
    const d = editing.data?.[0];
    if (d) { setSpec(d.spec); setName(d.name); setSlug(d.slug); setColumns(Object.keys(d.spec.mapping || {})); }
  }, [editing.data]);

  const sug = useMutation({
    mutationFn: () => api.post("/parser-library/suggest", { sample }),
    onSuccess: (r) => { setSpec({ ...EMPTY, ...r.spec, detect: r.spec.detect || {} }); setColumns(r.columns); setNotes(r.notes); },
  });
  const pv = useMutation({ mutationFn: () => api.post("/parser-library/preview", { spec, sample }) });
  const save = useMutation({
    mutationFn: async () => {
      const saved = await api.post("/parser-library", { name, slug: slug || undefined, spec, note });
      if (ev && fid) {
        const processing = await api.post(`/evidence/${ev}/files/${fid}/parser`, { parser_id: saved.pinned_id });
        return { ...saved, processingJobId: processing.job_id };
      }
      return saved;
    },
    onSuccess: (saved) => { qc.invalidateQueries({ queryKey: ["parser-library"] }); qc.invalidateQueries({ queryKey: ["parsers"] }); if (saved.processingJobId) { nav("/jobs/" + encodeURIComponent(saved.processingJobId)); return; } nav(job ? `/jobs/${job}` : "/parsers"); },
  });

  const set = <K extends keyof Spec>(k: K, v: Spec[K]) => setSpec((s) => ({ ...s, [k]: v }));
  const cols = useMemo(() => Array.from(new Set([...columns, ...Object.keys(spec.mapping || {}), ...(spec.drop || []), ...(spec.mask || [])])), [columns, spec]);
  const targets: string[] = meta.data?.targets || Object.keys(TARGET_KO);
  const sources: string[] = meta.data?.data_sources || Object.keys(SOURCE_KO);
  const toggleIn = (k: "drop" | "mask", c: string) => set(k, (spec[k] || []).includes(c) ? (spec[k] || []).filter((x) => x !== c) : [...(spec[k] || []), c]);
  const fields: string[] = useMemo(() => {
    const keys = new Set<string>();
    (pv.data?.rows || []).forEach((r: any) => Object.keys(r.fields).forEach((k) => { if (!["ext", "timestamp_quality", "tags", "params", "param_names", "raw_redacted"].includes(k)) keys.add(k); }));
    return ["timestamp", ...[...keys].filter((k) => k !== "timestamp")].slice(0, 12);
  }, [pv.data]);

  return (
    <div className="col">
      {job && <div className="notice small">작업 화면에서 왔습니다. 저장하면 이 파서로 해당 파일을 바로 다시 처리합니다.</div>}
      <Panel title="1. 샘플 로그" right={<label className="btn sm">파일에서 불러오기<input type="file" hidden onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setSample(await readFileHead(f)); if (!name) setName(f.name.replace(/\.[^.]+$/, "")); } }} /></label>}>
        <textarea className="input" rows={8} spellCheck={false} placeholder="로그 몇 줄을 붙여넣거나 파일에서 불러오세요 (첫 줄이 머리글이면 함께)." value={sample} onChange={(e) => setSample(e.target.value)} />
        <div className="row"><button className="btn primary sm" disabled={!sample.trim() || sug.isPending} onClick={() => sug.mutate()}>자동 제안</button>
          <span className="muted small">형식·구분자·열 이름·필드 연결·펼칠 칸·민감 열을 추천합니다. 추천 후 아래에서 고치세요.</span></div>
        <ErrorBox error={sug.error || fromFile.error} />
        {notes.map((n) => <div key={n} className="small muted">• {n}</div>)}
      </Panel>

      <Panel title="2. 형식">
        <div className="row wrap">
          <label className="row small">형식 <select className="input" value={spec.format} onChange={(e) => set("format", e.target.value as Spec["format"])}>{Object.entries(FORMAT_KO).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          {spec.format === "delimited" && <>
            <label className="row small">구분자 <select className="input" value={spec.delimiter} onChange={(e) => set("delimiter", e.target.value)}>{DELIMS.map(([k, v]) => <option key={v} value={k}>{v}</option>)}</select></label>
            <label className="row small"><input type="checkbox" checked={spec.has_header !== false} onChange={(e) => set("has_header", e.target.checked)} /> 첫 줄이 머리글</label>
            {spec.has_header === false && <input className="input" style={{ minWidth: 360 }} placeholder="열 이름 (쉼표로 구분)" value={(spec.columns || []).join(", ")} onChange={(e) => { set("columns", list(e.target.value)); setColumns(list(e.target.value)); }} />}
          </>}
          {spec.format === "kv" && <>
            <label className="row small">쌍 구분 <input className="input" style={{ width: 60 }} value={spec.pair_sep ?? " "} onChange={(e) => set("pair_sep", e.target.value || " ")} /></label>
            <label className="row small">키·값 구분 <input className="input" style={{ width: 60 }} value={spec.kv_sep ?? "="} onChange={(e) => set("kv_sep", e.target.value || "=")} /></label>
            <span className="muted small">쌍 구분이 공백이면 따옴표로 묶인 값도 처리합니다.</span>
          </>}
          <label className="row small">데이터 종류 <select className="input" value={spec.data_source} onChange={(e) => set("data_source", e.target.value)}>{sources.map((k) => <option key={k} value={k}>{SOURCE_KO[k] || k}</option>)}</select></label>
        </div>
        {spec.format === "regex" && <input className="input mono" placeholder="(?P<time>\S+ \S+) (?P<src_ip>\S+) -> (?P<dst_ip>\S+)" value={spec.pattern || ""} onChange={(e) => set("pattern", e.target.value)} />}
        {spec.format === "regex" && <div className="muted small">이름 붙은 그룹 (?P&lt;이름&gt;…)이 필드가 됩니다. 그룹 이름을 src_ip·dst_ip·uri처럼 쓰면 자동으로 연결됩니다. 줄마다 0.05초가 넘으면 실패로 처리합니다.</div>}
        <div className="small"><b>칸 안의 키=값 펼치기</b> <span className="muted">(예: NDR의 meta data 칸)</span></div>
        {(spec.expand || []).map((x, i) => (
          <div key={i} className="row small">
            <input className="input" placeholder="칸 이름" value={x.column} onChange={(e) => set("expand", (spec.expand || []).map((y, j) => (j === i ? { ...y, column: e.target.value } : y)))} />
            쌍 구분 <input className="input" style={{ width: 50 }} value={x.pair_sep} onChange={(e) => set("expand", (spec.expand || []).map((y, j) => (j === i ? { ...y, pair_sep: e.target.value } : y)))} />
            키·값 <input className="input" style={{ width: 50 }} value={x.kv_sep} onChange={(e) => set("expand", (spec.expand || []).map((y, j) => (j === i ? { ...y, kv_sep: e.target.value } : y)))} />
            <button className="btn sm ghost" onClick={() => set("expand", (spec.expand || []).filter((_, j) => j !== i))}>삭제</button>
          </div>))}
        <div><button className="btn sm" onClick={() => set("expand", [...(spec.expand || []), { column: "", pair_sep: ";", kv_sep: "=" }])}>＋ 펼칠 칸 추가</button></div>
      </Panel>

      <Panel title="3. 필드 연결과 민감정보">
        <div className="muted small">연결하지 않은 열도 영문·한글 열 이름으로 자동 인식합니다(예: "출발지 IP" → 출발지 IP). 인식되지 않은 열은 부가 정보로 남습니다.</div>
        <table className="t"><thead><tr><th>원본 열·키</th><th>표준 필드</th><th>저장 안 함</th><th>가림</th></tr></thead>
          <tbody>{cols.map((c) => (
            <tr key={c}><td className="mono small">{c}</td>
              <td><select className="input" value={spec.mapping[c] || ""} onChange={(e) => {
                const m = { ...spec.mapping };
                if (e.target.value) m[c] = e.target.value; else delete m[c];
                set("mapping", m);
              }}><option value="">자동</option><option value="ignore">무시</option>{targets.map((t) => <option key={t} value={t}>{TARGET_KO[t] || t}</option>)}</select></td>
              <td><input type="checkbox" checked={(spec.drop || []).includes(c)} onChange={() => toggleIn("drop", c)} /></td>
              <td><input type="checkbox" checked={(spec.mask || []).includes(c)} onChange={() => toggleIn("mask", c)} /></td></tr>))}</tbody></table>
        <div className="row small"><input className="input" placeholder="열·키 이름 추가 (예: 펼친 칸의 키)" value={newCol} onChange={(e) => setNewCol(e.target.value)} />
          <button className="btn sm" disabled={!newCol.trim()} onClick={() => { setColumns([...columns, newCol.trim()]); setNewCol(""); }}>추가</button></div>
        <div className="row wrap small">
          <label className="row">시간 형식 <input className="input" placeholder="자동 (예: %Y%m%d%H%M%S)" value={spec.time_format || ""} onChange={(e) => set("time_format", e.target.value)} /></label>
          <label className="row">시간대 <input className="input" placeholder="조사 기본값 (예: Asia/Seoul, UTC)" value={spec.timezone || ""} onChange={(e) => set("timezone", e.target.value)} /></label>
        </div>
      </Panel>

      <Panel title="4. 자동 감지 조건">
        <div className="row wrap small">
          <label className="row">첫 줄에 모두 포함 <input className="input" style={{ minWidth: 300 }} placeholder="머리글 단어 (쉼표로 구분)" value={(spec.detect?.header_contains || []).join(", ")} onChange={(e) => set("detect", { ...spec.detect, header_contains: list(e.target.value) })} /></label>
          <label className="row">또는 줄 정규식 <input className="input mono" style={{ minWidth: 260 }} value={spec.detect?.line_regex || ""} onChange={(e) => set("detect", { ...spec.detect, line_regex: e.target.value })} /></label>
        </div>
        <div className="muted small">조건을 비워 두면 자동 감지에 쓰이지 않고, 작업 화면에서 직접 고를 때만 사용됩니다.</div>
      </Panel>

      <Panel title="5. 미리보기" right={<button className="btn primary sm" disabled={!sample.trim() || pv.isPending} onClick={() => pv.mutate()}>{pv.isPending ? "해석 중…" : "미리보기"}</button>}>
        <ErrorBox error={pv.error} />
        {pv.data && <>
          <div className="row wrap small">
            {pv.data.auto_detect ? <span className="tag ok">이 샘플에서 자동 감지됨</span> : <span className="tag">자동 감지 안 됨 (직접 선택용)</span>}
            <span>해석한 줄 {fmtNum(pv.data.coverage.lines)}</span><span>이벤트 {fmtNum(pv.data.coverage.events)}</span>
            <span>머리글 {fmtNum(pv.data.coverage.skipped_lines)}</span>
            <span>{pv.data.coverage.failed_lines ? <b style={{ color: "var(--bad)" }}>실패 {fmtNum(pv.data.coverage.failed_lines)}</b> : "실패 0"}</span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="t"><thead><tr><th>줄</th>{fields.map((f) => <th key={f}>{TARGET_KO[f] || f}</th>)}<th>부가 정보</th></tr></thead>
              <tbody>{pv.data.rows.map((r: any) => (
                <tr key={r.line_no}><td className="num">{r.line_no}</td>{fields.map((f) => <td key={f} className="small ellipsis" style={{ maxWidth: 220 }}>{String(r.fields[f] ?? "")}</td>)}
                  <td className="small ellipsis mono" style={{ maxWidth: 280 }}>{JSON.stringify(Object.values(r.fields.ext || {})[0] || {})}</td></tr>))}</tbody></table>
          </div>
          {pv.data.failures.map((x: any) => <div key={x.line_no} className="mono small">{x.line_no}: {x.reason} — {x.raw}</div>)}
        </>}
      </Panel>

      <Panel title="6. 저장">
        <div className="row wrap">
          <input className="input" placeholder="파서 이름 (예: 웹방화벽 A 이벤트)" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input mono" placeholder="ID (영문 소문자·숫자·-, 비우면 자동)" value={slug} disabled={!!edit} onChange={(e) => setSlug(e.target.value.toLowerCase())} />
          <input className="input" style={{ minWidth: 280 }} placeholder="변경 메모 (선택)" value={note} onChange={(e) => setNote(e.target.value)} />
          <button className="btn primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>{job ? "초안으로 저장하고 이 파일 다시 처리" : edit ? "새 버전(초안)으로 저장" : "초안으로 저장"}</button>
        </div>
        <div className="muted small">저장하면 <b>내 초안</b>(새 버전)이 됩니다. 내 파일에는 바로 쓸 수 있고, 목록에서 <b>공용 요청</b> → 다른 분석가 승인 후 모두의 자동 감지에 쓰입니다.</div>
        <ErrorBox error={save.error} />
      </Panel>
    </div>
  );
}
