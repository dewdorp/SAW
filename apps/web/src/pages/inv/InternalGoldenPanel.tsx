import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

export const JUDGEMENTS: [string, string][] = [["", "미정"], ["normal", "정상 업무로 확인"], ["attack_attempt", "공격 시도 확인(성공 미확인)"],
  ["compromise_confirmed", "침해·실제 영향 확인"], ["insufficient_evidence", "증거 부족 · 추가 확인 필요"], ["data_quality_limited", "데이터 품질로 판단 제한"]];
const lines = (v: string) => v.split("\n").map((x) => x.trim()).filter(Boolean);
const LIST_FIELDS = ["initial_logs", "initial_evidence_refs", "observed_facts", "questions", "followups", "later_logs",
  "later_evidence_refs", "later_facts", "unresolved"];
// Versions saved before a field existed still open: missing lists are shown empty, never as an error.
const normalized = (c: any) => ({ ...c, ...Object.fromEntries(LIST_FIELDS.map((k) => [k, c?.[k] ?? []])), provenance: c?.provenance ?? {} });

function Judgement({ label, value, onChange }: { label: string; value: any; onChange: (v: any) => void }) {
  return (
    <fieldset className="col" style={{ gap: 4 }}>
      <legend className="small"><b>{label}</b></legend>
      <select className="input" aria-label={`${label} 상태`} value={value.status} onChange={(e) => onChange({ ...value, status: e.target.value })}>
        {JUDGEMENTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </select>
      <textarea className="input" aria-label={`${label} 근거`} rows={2} placeholder="근거" value={value.rationale} onChange={(e) => onChange({ ...value, rationale: e.target.value })} />
      <input className="input" aria-label={`${label} 범위`} placeholder="판단 범위(관계사·기간·대상) — 이 범위 밖으로 확대하지 않습니다" value={value.scope} onChange={(e) => onChange({ ...value, scope: e.target.value })} />
    </fieldset>
  );
}

export function InternalGoldenPanel({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["internal-golden", inv], queryFn: () => api.get(`/investigations/${inv}/internal-golden`) });
  const [content, setContent] = useState<any>(null);
  const [note, setNote] = useState("");
  const [viewing, setViewing] = useState<any>(null);
  // The version this screen started editing from: a later save by someone else is a conflict, not an overwrite.
  const [baseVersion, setBaseVersion] = useState<number | null>(null);
  useEffect(() => {
    const rec = current.data?.record;
    setContent(rec?.content ? normalized(structuredClone(rec.content)) : null);
    setBaseVersion(rec?.version ?? null);
  }, [current.data]);
  const draft = useMutation({ mutationFn: () => api.get(`/investigations/${inv}/internal-golden/draft`), onSuccess: (r: any) => setContent(normalized(r.content)) });
  const save = useMutation({
    mutationFn: () => api.post(`/investigations/${inv}/internal-golden`, { content, change_note: note, expected_version: baseVersion }),
    onSuccess: () => { setNote(""); qc.invalidateQueries({ queryKey: ["internal-golden", inv] }); },
  });
  const openVersion = useMutation({ mutationFn: (v: number) => api.get(`/knowledge/internal-golden/${current.data.record.id}?version=${v}`), onSuccess: setViewing });
  if (current.isLoading) return <Loading />;
  const record = current.data?.record;
  const set = (key: string, value: any) => setContent({ ...content, [key]: value });
  return (
    <div className="col" style={{ gap: 12 }}>
      <Panel title="골든셋 저장 — 이 조사의 분석 과정을 내부 골든셋으로 남깁니다">
        <div className="small muted">
          내부용이므로 가명처리·별도 승인·직접 해시 확인 없이 바로 저장·수정합니다. 이 조사를 볼 수 있는 사람만 볼 수 있고, 관계사와 조사 기간은 조사에서 그대로 가져옵니다.
          저장할 때마다 새 버전이 남아 무엇이 바뀌었는지 볼 수 있습니다. 처음 알던 내용(초기 로그·관찰 사실·최초 판단·질문)과 나중에 받은 회신·근거, 최종 판단을 구분해 적으세요.
        </div>
        {!content && <div className="row" style={{ marginTop: 8 }}><button className="btn primary" onClick={() => draft.mutate()} disabled={draft.isPending}>조사 내용으로 초안 만들기</button></div>}
        <ErrorBox error={draft.error || current.error} />
      </Panel>
      {record?.restricted && <div className="small" role="alert">{record.restricted_reason} 이 버전의 내용은 볼 수 없습니다.</div>}
      {content && (
        <>
          <Panel title="① 조사 범위와 초기 로그 (처음 받은 자료)">
            <input className="input" aria-label="제목" value={content.title} onChange={(e) => set("title", e.target.value)} />
            <div className="small">관계사 <b>{content.scope.org_unit || "미지정"}</b> · 조사 기간 {content.scope.period_start ? `${fmtTime(content.scope.period_start)} ~ ${fmtTime(content.scope.period_end)}` : "미지정"}</div>
            <div className="small muted">초기 로그 파일 {content.initial_logs.length}개 · 근거 기록 {content.initial_evidence_refs.length}건 (조사의 확인 기록에서 가져옴)</div>
            <ul className="small">{content.initial_logs.slice(0, 10).map((f: any, i: number) => <li key={i}>{f.file} · {f.parser || "파서 없음"} · 기록 {f.events ?? "-"}{f.failed ? ` · 실패 ${f.failed}` : ""}</li>)}</ul>
          </Panel>
          <Panel title="② 당시 관찰된 사실과 최초 판단·질문">
            <textarea className="input" aria-label="관찰된 사실" rows={5} value={content.observed_facts.join("\n")} onChange={(e) => set("observed_facts", lines(e.target.value))} />
            {content.provenance?.cutoff
              ? <div className="small"><b>최초 판단</b> {JUDGEMENTS.find(([k]) => k === content.initial_judgement.status)?.[1] || "기록 없음"} — {content.initial_judgement.rationale || "근거 없음"}
                  <div className="muted">첫 확인 요청({fmtTime(content.provenance.cutoff)}) 시점의 확인 기록으로 고정됩니다. 그 뒤에 바뀐 판단은 ③ 후속 내용과 ④ 최종 판단에 남습니다.</div></div>
              : <Judgement label="최초 판단" value={content.initial_judgement} onChange={(v) => set("initial_judgement", v)} />}
            <textarea className="input" aria-label="추가 질문" rows={3} placeholder="추가로 확인해야 했던 질문(한 줄에 하나)" value={content.questions.join("\n")} onChange={(e) => set("questions", lines(e.target.value))} />
          </Panel>
          <Panel title="③ 후속 증거와 회신 (나중에 받은 자료 — 최초 분석의 입력이 아닙니다)">
            {!content.followups.length && <div className="small muted">확인 요청이 없습니다.</div>}
            {content.followups.map((f: any, i: number) => (
              <div key={i} className="small" style={{ borderBottom: "1px solid var(--line)", padding: "4px 0" }}>
                <b>{f.question}</b>{f.target && <> · 대상 {f.target}</>}{f.period && <> · 기간 {f.period}</>}
                <div>회신: {f.reply || "없음"}{f.reply_scope_result && <> · 범위 비교: {f.reply_scope_result}</>}</div>
                <div>결과: {f.outcome || "-"}{f.remaining?.length ? <> · 남은 의문: {f.remaining.join("; ")}</> : null}</div>
              </div>
            ))}
            {(content.later_facts.length > 0 || content.later_logs.length > 0 || content.later_evidence_refs.length > 0) && (
              <div className="small" style={{ marginTop: 6 }}>
                <b>첫 확인 요청 이후에 바뀌거나 추가된 내용</b>
                <ul>{content.later_facts.map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
                {content.later_logs.length > 0 && <div>추가 로그 파일 {content.later_logs.length}개: {content.later_logs.map((f: any) => f.file).join(", ")}</div>}
                {content.later_evidence_refs.length > 0 && <div>후속 근거 기록 {content.later_evidence_refs.length}건</div>}
              </div>
            )}
            {content.provenance?.hidden_followups > 0 && <div className="small muted">열람 권한이 없는 조사를 근거로 쓴 확인 요청 {content.provenance.hidden_followups}건은 포함하지 않았습니다.</div>}
            <button className="btn sm" onClick={() => draft.mutate()} title="확인 요청·회신·판단을 조사에서 다시 읽어 초안을 새로 채웁니다(저장 전까지 반영되지 않음)">조사 내용으로 다시 채우기</button>
          </Panel>
          <Panel title="④ 최종 판단과 끝내 확인하지 못한 사항">
            <Judgement label="최종 판단" value={content.final_judgement} onChange={(v) => set("final_judgement", v)} />
            <textarea className="input" aria-label="확인하지 못한 사항" rows={3} placeholder="끝내 확인하지 못한 사항(한 줄에 하나)" value={content.unresolved.join("\n")} onChange={(e) => set("unresolved", lines(e.target.value))} />
            <textarea className="input" aria-label="메모" rows={2} placeholder="메모" value={content.notes} onChange={(e) => set("notes", e.target.value)} />
            <div className="row wrap small" style={{ gap: 10 }}>
              <label className="row"><input type="checkbox" checked={content.lineage.synthetic} onChange={(e) => set("lineage", { ...content.lineage, synthetic: e.target.checked })} /> 합성(가상) 자료 사례</label>
              <label className="row">계보 그룹 <input className="input" aria-label="계보 그룹" value={content.lineage.variant_group_id} onChange={(e) => set("lineage", { ...content.lineage, variant_group_id: e.target.value })} /></label>
              <label className="row">학습·평가 분할 <select className="input" aria-label="분할" value={content.lineage.split} onChange={(e) => set("lineage", { ...content.lineage, split: e.target.value })}>
                {[["unassigned", "미지정"], ["train", "학습"], ["validation", "검증"], ["test", "평가"]].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
            </div>
            <div className="small muted">같은 원본 사례의 기간·수량 변형은 같은 계보 그룹·같은 분할에 두어 평가 점수가 부풀려지지 않게 합니다.</div>
          </Panel>
          <div className="row wrap" style={{ gap: 8 }}>
            <input className="input" aria-label="변경 메모" placeholder="무엇을 바꿨는지(선택)" value={note} onChange={(e) => setNote(e.target.value)} style={{ minWidth: 280 }} />
            <button className="btn primary" disabled={save.isPending || !content.title} onClick={() => save.mutate()}>{record ? `저장 (v${record.version + 1})` : "골든셋으로 저장"}</button>
            {save.isSuccess && <span className="small">저장했습니다.</span>}
          </div>
          <ErrorBox error={save.error} />
        </>
      )}
      {record && (
        <Panel title={`변경 이력 (현재 v${record.version})`}>
          {record.versions.map((v: any) => (
            <div key={v.version} className="row small" style={{ gap: 8 }}>
              <span>v{v.version}</span><span className="muted">{fmtTime(v.created_at)}</span><span className="grow">{v.restricted ? "열람 권한 없는 근거 포함" : v.change_note || "메모 없음"}</span>
              <button className="btn ghost sm" disabled={v.restricted} onClick={() => openVersion.mutate(v.version)}>보기</button>
            </div>
          ))}
          {viewing && <pre className="small" style={{ whiteSpace: "pre-wrap", maxHeight: 300, overflow: "auto" }}>v{viewing.shown_version} 최종 판단: {viewing.content.final_judgement.status || "미정"} — {viewing.content.final_judgement.rationale}</pre>}
        </Panel>
      )}
    </div>
  );
}
