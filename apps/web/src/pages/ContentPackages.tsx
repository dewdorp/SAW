import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

const LIMIT = 1024 * 1024;
const STATUS: Record<string, string> = { staged: "반입 초안", applied: "적용됨", rolled_back: "되돌림" };
const KIND: Record<string, string> = { sigma: "Sigma 룰", parser: "선언형 파서" };

function downloadDocument(document: any) {
  const href = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2) + "\n"], { type: "application/json" }));
  const anchor = window.document.createElement("a");
  anchor.href = href;
  anchor.download = `saw-content-${document.package_id}-r${document.revision}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
}

function JsonView({ value }: { value: unknown }) {
  return <pre className="small mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 300, overflow: "auto" }}>{JSON.stringify(value, null, 2)}</pre>;
}

export function ContentPackages() {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const [verifiedText, setVerifiedText] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [localError, setLocalError] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const history = useQuery({ queryKey: ["content-packages"], queryFn: () => api.get("/content-packages") });
  const detail = useQuery({ queryKey: ["content-package", selectedId], enabled: !!selectedId,
    queryFn: () => api.get(`/content-packages/${selectedId}`) });
  const update = (value: string) => { setText(value); setVerifiedText(""); setLocalError(""); };
  const fresh = (data: any) => {
    qc.setQueryData(["content-package", data.id], data);
    setSelectedId(data.id);
    qc.invalidateQueries({ queryKey: ["content-packages"] });
    qc.invalidateQueries({ queryKey: ["detections"] });
    qc.invalidateQueries({ queryKey: ["parser-library"] });
    qc.invalidateQueries({ queryKey: ["parsers"] });
  };
  const example = useMutation({ mutationFn: () => api.get("/content-packages/example"),
    onSuccess: data => update(JSON.stringify(data, null, 2)) });
  const build = useMutation({ mutationFn: () => api.post("/content-packages/build", { text }),
    onSuccess: data => { update(JSON.stringify(data, null, 2)); downloadDocument(data); } });
  const verify = useMutation({ mutationFn: (input: string) => api.post("/content-packages/verify", { text: input }),
    onSuccess: (_data, input) => setVerifiedText(input) });
  const stage = useMutation({ mutationFn: () => api.post("/content-packages/stage", { text }), onSuccess: fresh });
  const action = useMutation({ mutationFn: ({ name, id, digest }: { name: string; id: string; digest: string }) =>
    api.post(`/content-packages/${id}/${name}`, { digest, ...(name === "test" ? {} : { reason }) }),
    onSuccess: data => { fresh(data); rollbackPreview.reset(); } });
  const rollbackPreview = useMutation({ mutationFn: (id: string) => api.get(`/content-packages/${id}/rollback-preview`) });
  const exporting = useMutation({ mutationFn: (id: string) => api.download(`/content-packages/${id}/export`, "saw-content.json") });
  const current = detail.data;
  const fileValid = !!text.trim() && new TextEncoder().encode(text).length <= LIMIT;
  const verified = !!verify.data && verifiedText === text && fileValid;
  const busy = verify.isPending || stage.isPending || build.isPending || action.isPending;
  const select = (id: string) => { setSelectedId(id); setReason(""); rollbackPreview.reset(); action.reset(); };

  return <div className="col" style={{ minWidth: 0 }}>
    <PageHeader title="오프라인 룰·파서" desc="외부에서 만든 JSON을 반입하고 다른 검토자가 시험 결과를 확인한 뒤 적용합니다." />
    <div className="notice small">지원 범위: Sigma·선언형 파서, 최대 1MiB·20항목. 양성·정상 합성 예제를 함께 넣으세요. 프로그램·내장 엔진·설치 파일 업데이트는 별도 설치 매체 절차입니다.</div>
    <Panel title="1. 파일 만들기 또는 불러오기">
      <div className="row wrap">
        <input ref={file} type="file" accept=".json,application/json" aria-label="콘텐츠 파일 선택" hidden onChange={async event => {
          const chosen = event.target.files?.[0]; event.target.value = "";
          if (!chosen) return;
          if (chosen.size > LIMIT) { setLocalError("콘텐츠 파일은 최대 1MiB입니다."); return; }
          try { update(await chosen.text()); } catch { setLocalError("파일을 읽지 못했습니다."); }
        }} />
        <button className="btn sm" onClick={() => file.current?.click()}>JSON 파일 불러오기</button>
        <button className="btn sm" disabled={example.isPending} onClick={() => example.mutate()}>합성 예제 불러오기</button>
      </div>
      <label className="small" htmlFor="content-package-json">콘텐츠 JSON</label>
      <textarea id="content-package-json" className="input mono small" value={text} rows={10} style={{ width: "100%", minWidth: 0 }}
        placeholder="외부에서 준비한 JSON을 불러오거나 합성 예제를 수정하세요." onChange={event => update(event.target.value)} />
      <p className="small muted">직접 수정했다면 package_id·revision과 source_version을 확인하고 파일을 다시 만드세요. 원본 로그·계정·비밀값을 넣지 마세요.</p>
      <div className="row wrap">
        <button className="btn sm" disabled={!fileValid || busy} onClick={() => build.mutate()}>내용 검증·파일 만들기</button>
        <button className="btn sm primary" disabled={!fileValid || busy} onClick={() => verify.mutate(text)}>파일 검증·변경 미리보기</button>
        <button className="btn sm" disabled={!verified || busy} onClick={() => stage.mutate()}>반입 초안 저장</button>
      </div>
      {localError && <div className="error">{localError}</div>}
      <ErrorBox error={example.error || build.error || verify.error || stage.error} />
      {verified && <div className="col">
        <p className="notice small">SHA-256 무결성을 확인했습니다. 발행자 신원은 인증되지 않았습니다. 반입 초안은 현재 룰·파서를 변경하지 않습니다.</p>
        <div className="mono small" style={{ overflowWrap: "anywhere" }}>{verify.data.digest}</div>
        {verify.data.changes.map((change: any) => <details key={change.kind + change.source_id}>
          <summary>{KIND[change.kind]} · {change.source_id} · {change.action === "add" ? "추가" : "변경"} · 원본 v{change.source_version}</summary>
          <div className="small">변경 전</div><JsonView value={change.before} />
          <div className="small">변경 후</div><JsonView value={change.after} />
        </details>)}
      </div>}
    </Panel>

    <Panel title="2. 반입·적용 이력">
      <ErrorBox error={history.error} />
      {history.isLoading ? <Loading /> : <div className="row wrap">{(history.data?.packages || []).map((p: any) =>
        <button key={p.id} className={`btn sm ${p.id === selectedId ? "primary" : ""}`} onClick={() => select(p.id)}>
          {p.package_id} r{p.revision}</button>)}</div>}
      {history.data?.packages?.length === 0 && <p className="small muted">아직 반입한 묶음이 없습니다.</p>}
    </Panel>

    {selectedId && <Panel title="3. 시험·승인·적용">
      {detail.isLoading && <Loading />}
      <ErrorBox error={detail.error || action.error || rollbackPreview.error || exporting.error} />
      {current && <div className="col">
        <div className="row wrap"><b>{current.package_id} r{current.revision}</b><span className="tag">{STATUS[current.status] || current.status}</span>
          <button className="btn sm" disabled={exporting.isPending} onClick={() => exporting.mutate(current.id)}>이 묶음 JSON 내보내기</button></div>
        <div className="small">반입한 사람: {current.imported_by}</div>
        <div className="small muted">{fmtTime(current.created_at)}</div>
        <div className="mono small" style={{ overflowWrap: "anywhere" }}>{current.digest}</div>
        <p className="notice small">합성 예제 시험은 과거 조사 재생 시험과 다릅니다. 반입한 사람과 다른 선임·매니저가 승인·적용합니다. 적용은 이후 처리와 명시적으로 실행한 재분석에 반영됩니다.</p>
        {(current.document?.entries || []).map((entry: any) => <details key={entry.kind + entry.source_id}>
          <summary>{KIND[entry.kind]} · {entry.source_id} · 원본 v{entry.source_version}</summary>
          <JsonView value={entry.content} /><div className="small">합성 예제</div><JsonView value={entry.fixtures} />
        </details>)}
        {current.status === "staged" && <button className="btn sm" disabled={busy} onClick={() => action.mutate({ name: "test", id: current.id, digest: current.digest })}>양성·정상 합성 예제 시험</button>}
        {typeof current.test_result?.passed === "boolean" && <div>
          <b>{current.test_result.passed ? "합성 예제 시험 통과" : "합성 예제 시험 실패"}</b>
          <div className="small">{current.test_result.tested_by} · {fmtTime(current.test_result.tested_at)}</div>
          <table className="t"><thead><tr><th>원본 ID</th><th>예제</th><th>기대</th><th>결과</th></tr></thead>
            <tbody>{(current.test_result.results || []).map((r: any, i: number) => <tr key={i}>
              <td>{r.source_id}</td><td>{r.name}</td><td>{r.expected}</td><td>{r.passed ? "통과" : r.error || "실패"}</td></tr>)}</tbody></table>
        </div>}
        {current.status !== "rolled_back" && <>
          <label htmlFor="content-review-reason" className="small">검토·되돌리기 사유</label>
          <input id="content-review-reason" className="input" maxLength={1000} value={reason} onChange={event => setReason(event.target.value)} />
        </>}
        {current.status === "staged" && <button className="btn primary" disabled={busy || !current.can_apply || !reason.trim()}
          onClick={() => action.mutate({ name: "apply", id: current.id, digest: current.digest })}>승인·적용</button>}
        {current.status === "applied" && <>
          <p className="small muted">이전 Sigma 룰을 복구할 때는 적용한 사람·직전 버전 작성자·최초 룰 작성자를 제외한 검토자가 필요합니다. 두 담당자만으로는 복구할 수 없는 경우가 있습니다.</p>
          <button className="btn sm" disabled={rollbackPreview.isPending} onClick={() => rollbackPreview.mutate(current.id)}>되돌리기 영향 확인</button>
          {(rollbackPreview.data?.rollback_blocked_reasons ?? current.rollback_blocked_reasons ?? []).map((blocked: string) =>
            <p key={blocked} className="notice small">{blocked}</p>)}
          {rollbackPreview.data && <div className="col">
            {rollbackPreview.data.changes.map((change: any) => <div key={change.source_id} className="small">
              {change.source_id}: {change.action === "restore" ? "직전 승인본 복원" : "새로 추가한 콘텐츠 끄기"} · {change.drift ? "이후 변경 있음 — 되돌리기 차단" : "적용 후 상태 일치"}</div>)}
            <button className="btn" disabled={busy || !current.can_rollback || !rollbackPreview.data.can_rollback || !reason.trim()}
              onClick={() => action.mutate({ name: "rollback", id: current.id, digest: current.digest })}>확인한 이전 승인본으로 되돌리기</button>
          </div>}
        </>}
        {current.receipt?.applied_by && <p className="small">적용: {current.receipt.applied_by} · {fmtTime(current.receipt.applied_at)} · {current.receipt.reason}</p>}
        {current.receipt?.rollback && <p className="small">되돌림: {current.receipt.rollback.by} · {fmtTime(current.receipt.rollback.at)} · {current.receipt.rollback.reason}</p>}
      </div>}
    </Panel>}
  </div>;
}
