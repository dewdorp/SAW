import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";

type Props = { sourceKind: "casebook" | "investigation"; sourceId: string };

/** One click puts the case in the golden-set candidate inbox; a note is optional and can be added afterwards. */
export function GoldenCandidateButton({ sourceKind, sourceId }: Props) {
  const [item, setItem] = useState<any>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setItem(null); setMessage(""); setError(""); setNote(null);
    api.get(`/knowledge/golden-candidates?source_kind=${sourceKind}&source_id=${encodeURIComponent(sourceId)}`)
      .then(r => { if (live) setItem((previous: any) => previous ?? r.items?.[0] ?? null); }).catch(() => undefined);
    return () => { live = false; };
  }, [sourceKind, sourceId]);
  const add = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const r = await api.post("/knowledge/golden-candidates", { source_kind: sourceKind, source_id: sourceId });
      setItem(r.item);
      setMessage(r.created ? "골든 후보에 담았습니다." : "이미 담긴 후보입니다. 한 건으로 유지합니다.");
    } catch (e: any) { setError(e?.message || "후보로 담지 못했습니다."); } finally { setBusy(false); }
  };
  const saveNote = async () => {
    try { setItem(await api.patch(`/knowledge/golden-candidates/${item.id}`, { note: note ?? "" })); setNote(null); setMessage("메모를 저장했습니다."); }
    catch (e: any) { setError(e?.message || "메모를 저장하지 못했습니다."); }
  };
  return <span className="row wrap golden-candidate" role="group" aria-label="골든셋 후보" style={{ gap: 6, alignItems: "center" }}>
    <button type="button" className="btn sm" disabled={busy} onClick={add}>골든 후보로 담기</button>
    {item && <span className="tag">{item.status === "saved" ? "골든셋 저장됨" : "후보함에 있음"}</span>}
    {item && (note === null
      ? <button type="button" className="btn sm ghost" onClick={() => setNote(item.note || "")}>{item.note ? "메모 고치기" : "메모 남기기(선택)"}</button>
      : <><input className="input" aria-label="후보 메모" maxLength={2000} value={note} onChange={e => setNote(e.target.value)} />
        <button type="button" className="btn sm" onClick={saveNote}>메모 저장</button></>)}
    {item && <Link className="btn sm ghost" to="/golden-candidates">후보함 열기</Link>}
    {message && <span className="small muted" role="status">{message}</span>}
    {error && <span className="small" role="alert">{error}</span>}
  </span>;
}
