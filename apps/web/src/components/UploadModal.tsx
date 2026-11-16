import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import "./uploadEntry.css";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { uploadFiles, UploadProgress } from "../lib/upload";
import { Bar, ErrorBox } from "./common";

export const KINDS: [string, string][] = [
  ["web_log", "웹 로그"], ["waf_log", "WAF 로그"], ["pcap", "PCAP"], ["ioc_list", "IOC 목록"], ["sec_log", "보안 로그"],
  ["fw_log", "방화벽 로그"], ["db_audit", "DB 감사"], ["auto", "자동 감지"],
];

export function UploadModal({ kind: k0, invId, initialFiles, onClose, hunt }: { kind?: string; invId?: string; initialFiles?: File[]; onClose: () => void;
  /** Opened as "새 헌팅": the title is generated and the analyst lands on the hunt's activities. */ hunt?: boolean }) {
  const [kind, setKind] = useState(k0 || "auto");
  const [files, setFiles] = useState<File[]>(initialFiles || []);
  const [target, setTarget] = useState<string>(invId || "new");
  const [title, setTitle] = useState("");
  const [org, setOrg] = useState("");
  const [device, setDevice] = useState("");
  const [profile, setProfile] = useState("");
  const [subjectOrg, setSubjectOrg] = useState("");
  const [subjectStatus, setSubjectStatus] = useState("unknown");
  const [basis, setBasis] = useState("");
  const [scope, setScope] = useState("unknown");
  const [collectionFilter, setCollectionFilter] = useState("");
  const [loss, setLoss] = useState("unknown");
  const [prog, setProg] = useState<UploadProgress[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [over, setOver] = useState(false);
  const [contextOpen, setContextOpen] = useState(false);
  const contextId = useId(), fileInput = useRef<HTMLInputElement>(null);
  const dialog = useRef<HTMLDivElement>(null), destination = useRef<HTMLSelectElement>(null);
  useEffect(() => {
    const previous = document.activeElement;
    destination.current?.focus();
    return () => { if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, []);
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const devices = useQuery({ queryKey: ["source-devices", target], queryFn: () => api.get(`/source-context/investigations/${target}/devices`), enabled: contextOpen && target !== "new" });
  const profiles = useQuery({ queryKey: ["source-profiles", device], queryFn: () => api.get(`/source-context/devices/${device}/profiles`), enabled: contextOpen && !!device && target !== "new" });
  const list = invs.data || [];
  const currentInv = list.find((i: any) => i.id === target);
  const currentOrg = currentInv?.org_unit || (orgs.data || []).find((o: any) => o.id === currentInv?.org_unit_id)?.display_name;
  const subjectName = (orgs.data || []).find((o: any) => o.id === subjectOrg)?.display_name;
  const hasBasis = !!subjectOrg && !!basis.trim();
  const subjectLabel = subjectStatus === "verified" ? (hasBasis ? `${subjectName || subjectOrg} · 근거로 확인` : "확인 근거 입력 필요")
    : subjectStatus === "conflicting" ? "귀속 충돌" : "미확인";
  const total = files.reduce((a, f) => a + f.size, 0);
  const go = async () => {
    setBusy(true); setErr(null);
    try {
      if (target !== "new" && subjectStatus === "verified" && !hasBasis) {
        setContextOpen(true);
        throw new Error("관측 대상 관계사와 귀속 확인 근거를 입력하세요.");
      }
      let id = target;
      if (target === "new") {
        if (!org) throw new Error("새 조사는 관계사를 선택해야 합니다. 조사 기간은 조사 화면 위쪽에서 지정할 수 있습니다.");
        const investigation = await api.post("/investigations", { title: title || (hunt ? `${(orgs.data || []).find((o: any) => o.id === org)?.display_name || ""} 헌팅 · ${new Date().toLocaleDateString("ko-KR")}`.trim()
          : `${files.length}개 파일 · ${new Date().toLocaleString("ko-KR")}`), ...(org ? { org_unit_id: org } : {}) });
        id = investigation.id;
      }
      const hasContext = target !== "new" && (profile || subjectOrg || subjectStatus !== "unknown" || basis || scope !== "unknown" || collectionFilter || loss !== "unknown");
      const context = hasContext ? { device_profile_version_id: profile || null, subject: { org_unit_id: subjectOrg || null, status: subjectStatus, basis: basis.trim() }, collection: { scope, filter: collectionFilter, loss } } : undefined;
      const result = await uploadFiles(id, kind, files, setProg, undefined, context);
      onClose(); nav(hunt ? `/inv/${id}?tab=activities` : `/jobs/${result.jobId}`);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return <>
    <div className="overlay" onClick={() => !busy && onClose()} />
    <div ref={dialog} className="modal panel upload-entry" role="dialog" aria-modal="true" aria-label="증거 업로드" tabIndex={-1}
      onKeyDown={e => {
        if (e.key === "Escape" && !busy) { e.preventDefault(); onClose(); }
        if (e.key !== "Tab") return;
        const controls = [...(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), select:not(:disabled), input:not(:disabled):not([hidden]), summary') || [])]
          .filter(el => el.getClientRects().length > 0 && !el.matches(":disabled"));
        if (!controls.length) { e.preventDefault(); return; }
        const first = controls[0], last = controls[controls.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }}>
      <div className="ph"><span className="grow">증거 업로드</span><button className="btn ghost sm" aria-label="닫기" onClick={onClose} disabled={busy}>✕</button></div>
      <div className="pb col">
        <fieldset disabled={busy} className="col" style={{ border: 0, padding: 0, margin: 0 }}>
          <div className="upload-target">
            <label>대상 조사 <select ref={destination} className="input" value={target} onChange={e => { setTarget(e.target.value); setContextOpen(false); setErr(null); setDevice(""); setProfile(""); setSubjectOrg(""); setSubjectStatus("unknown"); setBasis(""); setScope("unknown"); setCollectionFilter(""); setLoss("unknown"); }}>
              <option value="new">＋ 새 조사</option>{target !== "new" && !currentInv && <option value={target}>현재 조사</option>}
              {list.map((i: any) => <option key={i.id} value={i.id}>{i.display_id} {i.title}</option>)}
            </select></label>
            {target === "new"
              ? <label>새 조사 관계사 <select className="input" value={org} onChange={e => { setOrg(e.target.value); setErr(null); }}><option value="">관계사 선택</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
              : <div><span className="small muted">조사 관계사</span><b>{currentOrg || (invs.isLoading ? "조회 중…" : "정보 없음")}</b></div>}
          </div>
          <div className={`dropzone upload-drop ${over ? "over" : ""}`} onDragOver={e => { e.preventDefault(); if (!busy) setOver(true); }} onDragLeave={() => setOver(false)} onDrop={e => { e.preventDefault(); setOver(false); if (!busy) setFiles(old => [...old, ...Array.from(e.dataTransfer.files)]); }}>
            <span>조사할 파일을 여기에 놓거나 선택하세요.</span>
            <button type="button" className="btn" onClick={() => fileInput.current?.click()}>원본 파일 선택</button>
            <input ref={fileInput} aria-label="추가할 원본 파일" type="file" multiple hidden onChange={e => { const added = Array.from(e.currentTarget.files || []); setFiles(old => [...old, ...added]); e.currentTarget.value = ""; }} />
          </div>
          {files.length > 0 && <div className="upload-files">
            <b>{files.length}개 파일 · {fmtBytes(total)}</b>
            {files.map((f,i) => <div key={i} className="row"><span className="grow ellipsis" title={f.name}>{f.name}</span><span>{fmtBytes(f.size)}</span>
              {prog[i] && <Bar value={prog[i].sent} max={prog[i].total} />}
              {prog[i]?.error ? "⚠" : prog[i]?.done ? "✓" : null}
              {!busy && <button type="button" className="btn ghost sm" aria-label={`${f.name} 선택 해제`} onClick={() => { setFiles(old => old.filter((_, n) => n !== i)); setProg([]); }}>제거</button>}
            </div>)}
          </div>}
          <div className="upload-target">
            <label>자료 종류 <select className="input" value={kind} onChange={e => setKind(e.target.value)}>{KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            {target === "new" && <label>조사 제목 (선택)<input className="input" placeholder="새 조사 제목 (선택)" value={title} onChange={e => setTitle(e.target.value)} /></label>}
          </div>
          {target === "new"
            ? <p className="small muted">관계사는 조사를 구분합니다. 이 업로드의 관측 대상과 장비 기준은 미확인으로 남습니다. 장비 설정을 고정하려면 기존 조사를 선택하세요.</p>
            : <div className="upload-settings">
              <button type="button" className="btn ghost" aria-controls={contextId} aria-expanded={contextOpen} onClick={() => setContextOpen(v => !v)}>{contextOpen ? "▾ " : "▸ "}장비·귀속·수집 설정 (선택)</button>
              <p className="small">관측 대상: {subjectLabel} · 장비 프로필: {profile ? "선택됨" : "미확인"}. 이 설정은 업로드 후 바꿀 수 없습니다.</p>
              {contextOpen && <fieldset id={contextId}><legend>증거에 고정할 원천 설정</legend><div className="col" style={{ gap: 8 }}>
            <div className="row wrap"><label>관측 장비 <select className="input" value={device} onChange={e => { setDevice(e.target.value); setProfile(""); }}><option value="">미지정</option>{(devices.data || []).map((d: any) => <option key={d.id} value={d.id}>{d.display_name}</option>)}</select></label>
              <label>프로필 버전 <select className="input" disabled={!device} value={profile} onChange={e => setProfile(e.target.value)}><option value="">미확인</option>{(profiles.data || []).map((p: any) => <option key={p.id} value={p.id}>v{p.version} · {p.profile?.vendor || "제조사 미기록"}</option>)}</select></label></div>
            <div className="row wrap"><label>관측 대상 관계사 <select className="input" value={subjectOrg} onChange={e => setSubjectOrg(e.target.value)}><option value="">미확인</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
              <label>대상 귀속 상태 <select className="input" value={subjectStatus} onChange={e => setSubjectStatus(e.target.value)}><option value="unknown">미확인</option><option value="verified">근거로 확인</option><option value="conflicting">귀속 충돌</option></select></label></div>
            <label>귀속 확인 근거 <input className="input" maxLength={1000} value={basis} onChange={e => setBasis(e.target.value)} /></label>
            <label>수집 범위 <select className="input" value={scope} onChange={e => setScope(e.target.value)}>{[["unknown", "미확인"], ["full", "전체"], ["alerts_only", "경보만"], ["blocked_only", "차단만"], ["sampled", "표본"], ["filtered", "필터 적용"]].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            <label>수집 필터·조건 <input className="input" maxLength={1000} value={collectionFilter} onChange={e => setCollectionFilter(e.target.value)} /></label>
            <label>수집 손실 상태 <select className="input" value={loss} onChange={e => setLoss(e.target.value)}><option value="unknown">미확인</option><option value="known">손실 확인됨</option></select></label>
            {!profile && <p className="small muted">프로필을 선택하지 않으면 계측 의미는 미확인입니다. 장비·자료 의미 탭에서 새 버전을 설정할 수 있습니다.</p>}
          </div></fieldset>}</div>}
          <details className="upload-help"><summary>지원하는 CSV 형식과 수집 시 주의점</summary>
          <div className="small muted col" style={{ gap: 6 }} aria-label="반복 CSV 업로드 안내">
            <p>같은 형식의 CSV를 계속 추가할 수 있습니다. 자동 감지는 FW 16개·NDR 19개 필수 헤더 조합을 인식하며 UTF-8·CP949를 처리합니다. 영문 헤더 NDR HTTP(event_time·dest_ip·path·query·sc_bytes·cs_bytes 등, "| # fields" 접두 포함)와 FW(_time·action·sent_bytes·rcvd_bytes 등) 내보내기도 자동으로 인식합니다. 필수 헤더 이름을 유지하면 열 순서 변경과 추가 열도 최대 199열까지 허용합니다. 필수·추가 열 모두 빈 이름·공백뿐인 이름·점(.)이 포함된 이름은 지원하지 않습니다.</p>
            <p>예: FW는 탐지시간·장비IP·TCP플래그·세션시간, NDR은 탐지시간·장비IP·요청헤더·응답값·공격명 등이 있는 형식입니다. HTTP 요청행과 메서드·경로 요약을 구분하며, 요약 표기는 실제 패킷·HTTP 버전의 증명이 아닙니다. 장비IP·그룹명만으로 내부 장비나 동일 자산을 확인할 수 없습니다. 여러 장비가 섞인 내보내기는 장비별로 나눈 뒤 장비·자료 의미에서 프로필의 방향 카운터·누적/차분·시간 단위와 수집 범위를 확인하세요.</p>
            <p>업로드 작업 완료 후 분석 실행 이력에서 CSV 자료 준비도와 시나리오별 실행 결과를 확인하세요. 반복 업로드가 중복 기록을 자동 제거한다고 가정하지 마세요. 기존 증거는 재처리 기능과 처리 세대를 확인하고, 과거 실행은 저장된 당시 결과로 확인하세요. 공격명·허용·탐지·HTTP 200은 정오탐 정답이나 침해 성공을 확정하지 않습니다.</p>
          </div>
          </details>
        </fieldset>
        {prog.some(p => p.error) && <div className="error small">{prog.filter(p => p.error).map(p => `${p.file}: ${p.error}`).join("; ")}</div>}
        <ErrorBox error={err || invs.error || orgs.error || devices.error || profiles.error} />
        <div className="row"><div className="grow" /><button className="btn primary" disabled={busy || !files.length} onClick={go}>{busy ? "업로드 중…" : "업로드 및 분석 시작"}</button></div>
      </div>
    </div>
  </>;
}
