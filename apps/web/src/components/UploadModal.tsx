import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { fmtBytes } from "../lib/format";
import { uploadFiles, UploadProgress } from "../lib/upload";
import { Bar, ErrorBox } from "./common";

export const KINDS: [string, string][] = [
  ["web_log", "Web Logs"], ["waf_log", "WAF Logs"], ["pcap", "PCAP"], ["ioc_list", "IOC List"], ["sec_log", "Security Logs"],
  ["fw_log", "Firewall Logs"], ["db_audit", "DB Audit"], ["auto", "자동 감지"],
];

export function UploadModal({ kind: k0, invId, initialFiles, onClose }: { kind?: string; invId?: string; initialFiles?: File[]; onClose: () => void }) {
  const [kind, setKind] = useState(k0 || "auto");
  const [files, setFiles] = useState<File[]>(initialFiles || []);
  const [target, setTarget] = useState<string>(invId || "new");
  const [title, setTitle] = useState("");
  const [prog, setProg] = useState<UploadProgress[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [over, setOver] = useState(false);
  const nav = useNavigate();
  const invs = useQuery({ queryKey: ["investigations"], queryFn: () => api.get("/investigations") });
  const total = files.reduce((a, f) => a + f.size, 0);
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      let id = target;
      if (target === "new") {
        const inv = await api.post("/investigations", { title: title || `${files.length} files · ${new Date().toLocaleString("ko-KR")}` });
        id = inv.id;
      }
      const r = await uploadFiles(id, kind, files, setProg);
      onClose();
      nav(`/jobs/${r.jobId}`);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };
  return (
    <>
      <div className="overlay" onClick={() => !busy && onClose()} />
      <div className="modal panel" role="dialog" aria-label="증거 업로드">
        <div className="ph"><span className="grow">증거 업로드</span><button className="btn ghost sm" onClick={onClose} disabled={busy}>✕</button></div>
        <div className="pb col">
          <div className="row wrap">
            <label className="row">종류 <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>{KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            <label className="row grow">대상 조사
              <select className="input grow" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="new">＋ 새 조사</option>
                {(invs.data || []).map((i: any) => <option key={i.id} value={i.id}>{i.display_id} {i.title}</option>)}
              </select>
            </label>
          </div>
          {target === "new" && <input className="input" placeholder="새 조사 제목 (선택)" value={title} onChange={(e) => setTitle(e.target.value)} />}
          <div className={`dropzone ${over ? "over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
            onDrop={(e) => { e.preventDefault(); setOver(false); setFiles([...files, ...Array.from(e.dataTransfer.files)]); }}>
            파일을 끌어다 놓거나 <label className="btn sm">선택<input type="file" multiple hidden onChange={(e) => setFiles([...files, ...Array.from(e.target.files || [])])} /></label>
            <div className="small muted">access.log, *.gz, *.zip, JSON Lines, CSV, Syslog, PCAP … (압축은 서버에서 안전하게 해제)</div>
          </div>
          {files.length > 0 && <div className="small">{files.length} files · {fmtBytes(total)}</div>}
          <div className="col small" style={{ maxHeight: 220, overflow: "auto" }}>
            {files.map((f, i) => {
              const p = prog[i];
              return (
                <div key={i} className="row">
                  <span className="mono ellipsis grow">{f.name}</span>
                  <span className="muted">{fmtBytes(f.size)}</span>
                  <div style={{ width: 160 }}>{p ? <Bar value={p.sent} max={p.total} /> : null}</div>
                  <span style={{ width: 20 }}>{p?.error ? "⚠" : p?.done ? "✓" : ""}</span>
                </div>
              );
            })}
          </div>
          {prog.some((p) => p.error) && <div className="error small">{prog.filter((p) => p.error).map((p) => `${p.file}: ${p.error}`).join("; ")}</div>}
          <ErrorBox error={err} />
          <div className="row"><div className="grow" /><button className="btn primary" disabled={busy || !files.length} onClick={go}>{busy ? "업로드 중…" : "업로드 및 분석 시작"}</button></div>
        </div>
      </div>
    </>
  );
}
