import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

const SPLITS: Record<string, string> = { unassigned: "미지정", train: "학습", validation: "검증", test: "평가" };

/** Cases set aside for the golden set: find them, go back to the source, save chosen ones, remove, export. */
export function GoldenCandidates() {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const params = new URLSearchParams({ q, ...(kind ? { source_kind: kind } : {}), ...(status ? { status } : {}) }).toString();
  const list = useQuery({ queryKey: ["golden-candidates", params], queryFn: () => api.get(`/knowledge/golden-candidates?${params}`) });
  const items: any[] = list.data?.items || [];
  const chosen = items.filter(i => picked.includes(i.id));
  const refresh = () => qc.invalidateQueries({ queryKey: ["golden-candidates"] });
  const save = useMutation({
    mutationFn: () => api.post("/knowledge/golden-candidates/save", { ids: chosen.map(i => i.id) }),
    onSuccess: r => { setMessage(`${r.items.length}건을 골든셋으로 저장했습니다. 원본 조사와 판단은 바뀌지 않습니다.`); refresh(); },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/knowledge/golden-candidates/${id}`),
    onSuccess: (_r, id) => { setPicked(p => p.filter(x => x !== id)); setMessage("후보함에서 뺐습니다. 원본 조사·로그와 저장한 골든 버전은 그대로입니다."); refresh(); },
  });
  const split = useMutation({ mutationFn: ({ id, value }: { id: string; value: string }) => api.patch(`/knowledge/golden-candidates/${id}`, { split: value }), onSuccess: refresh });
  const exporting = useMutation({
    mutationFn: async () => {
      const ids = chosen.map(i => i.id);
      await api.downloadPost("/knowledge/golden-candidates/export?audience=agent", { ids }, "agent-input.jsonl");
      await api.downloadPost("/knowledge/golden-candidates/export?audience=evaluator", { ids }, "evaluator-answer.jsonl");
    },
    onSuccess: () => setMessage(`선택한 저장본 ${chosen.length}건을 agent-input.jsonl과 evaluator-answer.jsonl로 내보냈습니다.`),
  });
  const unsaved = chosen.filter(i => i.status !== "saved");
  const toggle = (id: string, on: boolean) => setPicked(p => on ? [...new Set([...p, id])] : p.filter(x => x !== id));
  return <div className="page">
    <PageHeader eyebrow="골든셋" title="골든셋 후보함"
      desc="사례집과 실제 조사에서 나중에 골든셋으로 쓸 사례를 모읍니다. 담기만으로는 골든셋에 저장되지 않으며, 원본 조사의 판단과 운영 통계도 바뀌지 않습니다." />
    <Panel title={`후보 ${items.length}건`}>
      <div className="row wrap" style={{ gap: 12, marginBottom: 10 }}>
        <label className="row wrap">찾기<input className="input" type="search" value={q} onChange={e => setQ(e.target.value)} placeholder="제목·사례 번호·관계사·메모" /></label>
        <label className="row wrap">출처<select className="input" value={kind} onChange={e => setKind(e.target.value)}>
          <option value="">전체</option><option value="casebook">합성 예제</option><option value="investigation">실제 조사</option></select></label>
        <label className="row wrap">상태<select className="input" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">전체</option><option value="candidate">후보</option><option value="saved">골든셋 저장됨</option></select></label>
      </div>
      <div className="row wrap" style={{ gap: 8, marginBottom: 10 }}>
        <span className="small muted">선택 {chosen.length}건</span>
        <button className="btn sm primary" disabled={!chosen.length || save.isPending} onClick={() => save.mutate()}>선택한 후보를 골든셋으로 저장</button>
        <button className="btn sm" disabled={!chosen.length || !!unsaved.length || exporting.isPending} onClick={() => exporting.mutate()}
          title={unsaved.length ? "골든셋으로 저장한 후보만 내보낼 수 있습니다" : undefined}>선택한 저장본 내보내기</button>
        {!!unsaved.length && <span className="small muted">저장하지 않은 후보 {unsaved.length}건은 내보낼 수 없습니다.</span>}
      </div>
      {message && <p role="status" className="small">{message}</p>}
      <ErrorBox error={list.error || save.error || remove.error || split.error || exporting.error} />
      {list.isLoading ? <Loading /> : !items.length ? <p>담긴 후보가 없습니다. 사례집이나 조사 ④ 확인 및 판단에서 "골든 후보로 담기"를 누르세요.</p> :
        <div style={{ overflowX: "auto" }}><table className="t">
          <thead><tr><th>선택</th><th>제목</th><th>출처</th><th>관계사</th><th>담은 날짜</th><th>상태</th><th>분할</th><th>메모</th><th>동작</th></tr></thead>
          <tbody>{items.map(i => <tr key={i.id}>
            <td><input type="checkbox" aria-label={`선택: ${i.title}`} checked={picked.includes(i.id)} onChange={e => toggle(i.id, e.target.checked)} /></td>
            <td><b>{i.title}</b><div className="small muted mono">{i.source_id} · 버전 {String(i.source_version).slice(0, 12)}</div></td>
            <td>{i.origin_label}</td>
            <td>{i.org_label || "미지정"}</td>
            <td>{fmtTime(i.created_at)}</td>
            <td><span className={`tag ${i.status === "saved" ? "ok" : ""}`}>{i.status_label}</span>{i.golden_version && <div className="small muted">골든 v{i.golden_version}</div>}</td>
            <td><select className="input" aria-label={`분할: ${i.title}`} value={i.split} onChange={e => split.mutate({ id: i.id, value: e.target.value })}>
              {Object.entries(SPLITS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></td>
            <td className="small">{i.note || "—"}</td>
            <td className="row wrap" style={{ gap: 4 }}><Link className="btn sm" to={i.link}>{i.source_kind === "casebook" ? "사례로 돌아가기" : "조사로 돌아가기"}</Link>
              <button className="btn sm ghost" disabled={remove.isPending} onClick={() => { if (window.confirm(`"${i.title}"을(를) 후보함에서 뺄까요? 원본과 저장한 골든 버전은 남습니다.`)) remove.mutate(i.id); }}>후보함에서 빼기</button></td>
          </tr>)}</tbody>
        </table></div>}
    </Panel>
  </div>;
}
