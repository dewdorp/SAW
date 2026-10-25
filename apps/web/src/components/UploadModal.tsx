import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { uploadFiles, UploadProgress } from "../lib/upload";
import { Bar, ErrorBox } from "./common";

export const KINDS: [string, string][] = [
  ["web_log", "웹 로그"], ["waf_log", "WAF 로그"], ["pcap", "PCAP"], ["ioc_list", "IOC 목록"], ["sec_log", "보안 로그"],
  ["fw_log", "방화벽 로그"], ["db_audit", "DB 감사"], ["auto", "자동 감지"],
];

export function UploadModal({ kind: k0, invId, initialFiles, onClose }: { kind?: string; invId?: string; initialFiles?: File[]; onClose: () => void }) {
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
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const devices = useQuery({ queryKey: ["source-devices", target], queryFn: () => api.get(`/source-context/investigations/${target}/devices`), enabled: target !== "new" });
  const profiles = useQuery({ queryKey: ["source-profiles", device], queryFn: () => api.get(`/source-context/devices/${device}/profiles`), enabled: !!device && target !== "new" });
  const total = files.reduce((a, f) => a + f.size, 0);
  const go = async () => {
    setBusy(true); setErr(null);
    try {
      if (target !== "new" && subjectStatus === "verified" && (!subjectOrg || !basis.trim())) throw new Error("관측 대상 관계사와 귀속 확인 근거를 입력하세요.");
      let id = target;
      if (target === "new") {
        const investigation = await api.post("/investigations", { title: title || `${files.length}개 파일 · ${new Date().toLocaleString("ko-KR")}`, ...(org ? { org_unit_id: org } : {}) });
        id = investigation.id;
      }
      const hasContext = target !== "new" && (profile || subjectOrg || subjectStatus !== "unknown" || basis || scope !== "unknown" || collectionFilter || loss !== "unknown");
      const context = hasContext ? { device_profile_version_id: profile || null, subject: { org_unit_id: subjectOrg || null, status: subjectStatus, basis: basis.trim() }, collection: { scope, filter: collectionFilter, loss } } : undefined;
      const result = await uploadFiles(id, kind, files, setProg, undefined, context);
      onClose(); nav(`/jobs/${result.jobId}`);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return <>
    <div className="overlay" onClick={() => !busy && onClose()} />
    <div className="modal panel" role="dialog" aria-label="증거 업로드" style={{ maxHeight: "90vh", overflowY: "auto" }}>
      <div className="ph"><span className="grow">증거 업로드</span><button className="btn ghost sm" aria-label="닫기" onClick={onClose} disabled={busy}>✕</button></div>
      <div className="pb col">
        <fieldset disabled={busy} className="col" style={{ border: 0, padding: 0, margin: 0 }}>
          <div className="row wrap">
            <label className="row">종류 <select className="input" value={kind} onChange={e => setKind(e.target.value)}>{KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            <label className="row grow">대상 조사 <select className="input grow" value={target} onChange={e => { setTarget(e.target.value); setDevice(""); setProfile(""); setSubjectOrg(""); setSubjectStatus("unknown"); setBasis(""); setScope("unknown"); setCollectionFilter(""); setLoss("unknown"); }}><option value="new">＋ 새 조사</option>{(invs.data || []).map((i: any) => <option key={i.id} value={i.id}>{i.display_id} {i.title}</option>)}</select></label>
          </div>
          {target === "new" ? <>
            <input className="input" placeholder="새 조사 제목 (선택)" value={title} onChange={e => setTitle(e.target.value)} />
            <label>새 조사 관계사 <select className="input" value={org} onChange={e => setOrg(e.target.value)}><option value="">미지정</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
            <p className="small muted">장비·프로필을 먼저 설정하려면 조사 목록에서 새 조사를 만든 뒤 작업대의 장비·자료 의미 탭을 여세요. 지금 업로드하면 관측 귀속과 계측 의미는 미확인으로 처리합니다.</p>
          </> : <fieldset><legend>증거에 고정할 원천 맥락 (선택)</legend><div className="col" style={{ gap: 8 }}>
            <p className="small muted">조사 관계사 선택만으로 관측 대상 관계사를 확정하지 않습니다. 업로드 후 맥락은 바꿀 수 없습니다.</p>
            <div className="row wrap"><label>관측 장비 <select className="input" value={device} onChange={e => { setDevice(e.target.value); setProfile(""); }}><option value="">미지정</option>{(devices.data || []).map((d: any) => <option key={d.id} value={d.id}>{d.display_name}</option>)}</select></label>
              <label>프로필 버전 <select className="input" disabled={!device} value={profile} onChange={e => setProfile(e.target.value)}><option value="">미확인</option>{(profiles.data || []).map((p: any) => <option key={p.id} value={p.id}>v{p.version} · {p.profile?.vendor || "제조사 미기록"}</option>)}</select></label></div>
            <div className="row wrap"><label>관측 대상 관계사 <select className="input" value={subjectOrg} onChange={e => setSubjectOrg(e.target.value)}><option value="">미확인</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>
              <label>대상 귀속 상태 <select className="input" value={subjectStatus} onChange={e => setSubjectStatus(e.target.value)}><option value="unknown">미확인</option><option value="verified">근거로 확인</option><option value="conflicting">귀속 충돌</option></select></label></div>
            <label>귀속 확인 근거 <input className="input" maxLength={1000} value={basis} onChange={e => setBasis(e.target.value)} /></label>
            <label>수집 범위 <select className="input" value={scope} onChange={e => setScope(e.target.value)}>{[["unknown", "미확인"], ["full", "전체"], ["alerts_only", "경보만"], ["blocked_only", "차단만"], ["sampled", "표본"], ["filtered", "필터 적용"]].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            <label>수집 필터·조건 <input className="input" maxLength={1000} value={collectionFilter} onChange={e => setCollectionFilter(e.target.value)} /></label>
            <label>수집 손실 상태 <select className="input" value={loss} onChange={e => setLoss(e.target.value)}><option value="unknown">미확인</option><option value="known">손실 확인됨</option></select></label>
            {!profile && <p className="small muted">프로필을 선택하지 않으면 계측 의미는 미확인입니다. 장비·자료 의미 탭에서 새 버전을 설정할 수 있습니다.</p>}
          </div></fieldset>}
          <div className="small muted col" style={{ gap: 6 }} aria-label="반복 CSV 업로드 안내">
            <p>같은 형식의 CSV를 계속 추가할 수 있습니다. 자동 감지는 FW 16개·NDR 19개 필수 헤더 조합을 인식하며 UTF-8·CP949를 처리합니다. 필수 헤더 이름을 유지하면 열 순서 변경과 추가 열도 최대 199열까지 허용합니다. 필수·추가 열 모두 빈 이름·공백뿐인 이름·점(.)이 포함된 이름은 지원하지 않습니다.</p>
            <p>예: FW는 탐지시간·장비IP·TCP플래그·세션시간, NDR은 탐지시간·장비IP·요청헤더·응답값·공격명 등이 있는 형식입니다. HTTP 요청행과 메서드·경로 요약을 구분하며, 요약 표기는 실제 패킷·HTTP 버전의 증명이 아닙니다. 장비IP·그룹명만으로 내부 장비나 동일 자산을 확인할 수 없습니다. 여러 장비가 섞인 내보내기는 장비별로 나눈 뒤 장비·자료 의미에서 프로필의 방향 카운터·누적/차분·시간 단위와 수집 범위를 확인하세요.</p>
            <p>업로드 작업 완료 후 분석 실행 이력에서 CSV 자료 준비도와 시나리오별 실행 결과를 확인하세요. 반복 업로드가 중복 기록을 자동 제거한다고 가정하지 마세요. 기존 증거는 재처리 기능과 처리 세대를 확인하고, 과거 실행은 저장된 당시 결과로 확인하세요. 공격명·허용·탐지·HTTP 200은 정오탐 정답이나 침해 성공을 확정하지 않습니다.</p>
          </div>
          <div className={`dropzone ${over ? "over" : ""}`} onDragOver={e => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={e => { e.preventDefault(); setOver(false); if (!busy) setFiles([...files, ...Array.from(e.dataTransfer.files)]); }}>
            파일을 끌어다 놓거나 <label className="btn sm">선택<input type="file" multiple hidden onChange={e => setFiles([...files, ...Array.from(e.target.files || [])])} /></label><div className="small muted">access.log, *.gz, *.zip, JSON Lines, CSV, Syslog, PCAP … (압축은 서버에서 안전하게 해제)</div>
          </div>
        </fieldset>
        {files.length > 0 && <div className="small">{files.length}개 파일 · {fmtBytes(total)}</div>}
        <div className="col small" style={{ maxHeight: 220, overflow: "auto" }}>{files.map((f, i) => <div key={i} className="row"><span className="mono ellipsis grow">{f.name}</span><span className="muted">{fmtBytes(f.size)}</span><div style={{ width: 160 }}>{prog[i] ? <Bar value={prog[i].sent} max={prog[i].total} /> : null}</div><span style={{ width: 20 }}>{prog[i]?.error ? "⚠" : prog[i]?.done ? "✓" : ""}</span></div>)}</div>
        {prog.some(p => p.error) && <div className="error small">{prog.filter(p => p.error).map(p => `${p.file}: ${p.error}`).join("; ")}</div>}
        <ErrorBox error={err || invs.error || orgs.error || devices.error || profiles.error} />
        <div className="row"><div className="grow" /><button className="btn primary" disabled={busy || !files.length} onClick={go}>{busy ? "업로드 중…" : "업로드 및 분석 시작"}</button></div>
      </div>
    </div>
  </>;
}
