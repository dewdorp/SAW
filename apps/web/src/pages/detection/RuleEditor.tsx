import { RuleHistory } from "./RuleHistory";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMe } from "../../App";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";
import { GovernanceActions } from "./GovernanceActions";
import { SelectedTruthPanel } from "./SelectedTruthPanel";

export type VersionRef = { id: string; version: number; payload_sha256: string };
export type Pointers = { draft: VersionRef | null; approved: VersionRef | null; active: VersionRef | null; latest: VersionRef; activation_revision: number; active_approval_id?: string | null; approved_approval_id?: string | null };
export function VersionCards({ pointers, label="룰 버전 상태" }: { pointers?: Pointers; label?:string }) {
  return <section role="region" aria-label={label} className="panel pb col"><div className="row wrap" style={{ gap: 16 }}>
    <b>{pointers?.draft ? `최신 초안 v${pointers.draft.version}` : pointers ? "초안 없음" : "초안 상태 미기록"}</b>
    <b>{pointers?.approved ? `승인본 v${pointers.approved.version}` : pointers ? "승인본 없음" : "승인 상태 미기록"}</b>
    <b>{pointers?.latest ? `최근 생성 v${pointers.latest.version}` : "최대 버전 미기록"}</b>
    <b>{pointers?.active ? `활성본 v${pointers.active.version}` : pointers ? "활성본 없음" : "활성 상태 미기록"}</b>
  </div><span className="small muted">초안 저장·시험·승인은 활성본을 바꾸지 않습니다. 별도 적용이 필요합니다.</span>{pointers && <details><summary>정확한 버전·해시</summary><pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(pointers, null, 2)}</pre></details>}</section>;
}
const semanticKeys = ["title", "description", "data_source", "format", "logic", "threshold", "exceptions", "false_positive", "severity", "confidence", "test_events", "attack"];
const thresholdKeys = ["count_gte", "timespan_sec", "group_by", "distinct_field"];
function parseObject(text: string, label: string) {
  let value: any; try { value = JSON.parse(text); } catch { throw new Error(`${label} JSON 형식을 확인하세요. 초안은 유지됩니다.`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} JSON은 객체여야 합니다.`);
  return value;
}
function thresholdValue(value: any) {
  if (!Object.keys(value).length) return {};
  if (Object.keys(value).some(key => !thresholdKeys.includes(key))) throw new Error("지원하지 않는 임계값 키가 있습니다. 엔진 조건을 확인하세요.");
  if (!Number.isInteger(value.count_gte) || value.count_gte < 1 || value.count_gte > 500000 || !Number.isInteger(value.timespan_sec ?? 600) || (value.timespan_sec ?? 600) < 1 || (value.timespan_sec ?? 600) > 604800) throw new Error("일치 수는 1~500000, 기간은 1~604800초의 정수여야 합니다.");
  const groups = value.group_by || [];
  if (!Array.isArray(groups) || groups.length > 4 || groups.some((field: any) => typeof field !== "string" || !field) || new Set(groups).size !== groups.length) throw new Error("그룹 필드는 중복 없이 4개 이하로 입력하세요.");
  if (value.distinct_field !== undefined && typeof value.distinct_field !== "string") throw new Error("고유값 필드는 문자열이어야 합니다.");
  return value;
}
export function RuleEditor() {
  const { id = "" } = useParams();
  const me = useMe(); const editing=useRef(false); const snapshot=useRef<any>(null);
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["detection", id], queryFn: () => api.get(`/detections/${id}`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["detection", id] }); qc.invalidateQueries({ queryKey: ["detections"] }); };
  if(query.data && !editing.current) snapshot.current=query.data;
  if (query.isLoading && !snapshot.current) return <Loading />;
  if (!snapshot.current) return <ErrorBox error={query.error} />;
  return <RuleEditorContent key={`${id}:${snapshot.current.current?.id || snapshot.current.pointers?.draft?.id || snapshot.current.pointers?.approved?.id || snapshot.current.pointers?.latest?.id || snapshot.current.version}`} id={id} data={snapshot.current} permissions={me.data?.permissions || []} refresh={refresh} onEditing={value=>{editing.current=value;}} />;
}
function RuleEditorContent({ id, data: d, permissions, refresh, onEditing }: { id: string; data: any; permissions: string[]; refresh: () => void; onEditing:(value:boolean)=>void }) {
  const [draft, setDraft] = useState<any>(() => Object.fromEntries(semanticKeys.filter(key => key in d.current).map(key => [key, d.current[key]])));
  const initialThreshold = d.current.threshold || {};
  const [enabled, setEnabled] = useState(!!Object.keys(initialThreshold).length);
  const [mode, setMode] = useState(Object.keys(initialThreshold).some(key => !thresholdKeys.includes(key)) ? "json" : "form");
  const [thresholdText, setThresholdText] = useState(JSON.stringify(initialThreshold, null, 2));
  const [count, setCount] = useState(String(initialThreshold.count_gte ?? 5));
  const [seconds, setSeconds] = useState(String(initialThreshold.timespan_sec ?? 600));
  const [groups, setGroups] = useState<string>((initialThreshold.group_by || []).join(", "));
  const [distinct, setDistinct] = useState(initialThreshold.distinct_field || "");
  const [exceptionsText, setExceptionsText] = useState(JSON.stringify(d.current.exceptions || [], null, 2));
  const [dirty, markDirty] = useState(false); const setDirty=(value:boolean)=>{markDirty(value);onEditing(value);}; const [baseVersion,setBaseVersion]=useState(d.pointers?.draft?.id||d.pointers?.latest?.id);
  const [selectedLegacy, setSelectedLegacy] = useState("");
  const [target, setTarget] = useState("");
  const [deploymentVersion, setDeploymentVersion] = useState(""); const [deploymentNote,setDeploymentNote] = useState(""); const [modeError,setModeError] = useState<unknown>(null);
  const editorVersion = d.current.id ? {id:d.current.id,version:d.current.version,payload_sha256:d.current.payload_sha256} : d.pointers?.draft || d.pointers?.approved || d.pointers?.latest;
  const [exportVersion,setExportVersion]=useState(editorVersion?.id||""); const exportQuery=(format:string)=>`/detections/${id}/export?fmt=${format}${exportVersion?`&version_id=${encodeURIComponent(exportVersion)}`:""}`;
  const [exported, setExported] = useState("");
  const [selectedTest, setSelectedTest] = useState<any>(null);
  const write = permissions.includes("detection.write");
  const set = (key: string, value: any) => { setDraft((old: any) => ({ ...old, [key]: value })); setDirty(true); };
  const formThreshold = () => !enabled ? {} : thresholdValue({ count_gte: Number(count), timespan_sec: Number(seconds), group_by: groups.split(",").map(value => value.trim()).filter(Boolean), ...(distinct.trim() ? { distinct_field: distinct.trim() } : {}) });
  const switchMode = (next: string) => { try { if (next === "json") setThresholdText(JSON.stringify(formThreshold(),null,2)); else { const value = thresholdValue(parseObject(thresholdText,"임계값")); setEnabled(!!Object.keys(value).length); setCount(String(value.count_gte ?? 5)); setSeconds(String(value.timespan_sec ?? 600)); setGroups((value.group_by || []).join(", ")); setDistinct(value.distinct_field || ""); } setMode(next); setModeError(null); } catch(error) { setModeError(error); } };
  const build = () => {
    const threshold = mode === "json" ? thresholdValue(parseObject(thresholdText, "임계값")) : !enabled ? {} : thresholdValue({ count_gte: Number(count), timespan_sec: Number(seconds), group_by: groups.split(",").map(value => value.trim()).filter(Boolean), ...(distinct.trim() ? { distinct_field: distinct.trim() } : {}) });
    let exclusions; try { exclusions = JSON.parse(exceptionsText); } catch { throw new Error("예외 JSON 형식을 확인하세요. 초안은 유지됩니다."); }
    if (!Array.isArray(exclusions) || exclusions.some(value => !value || typeof value !== "object" || Array.isArray(value))) throw new Error("예외는 필터 객체 배열이어야 합니다.");
    return { ...draft, threshold, exceptions: exclusions };
  };
  const validate = useMutation({ mutationFn: () => { const payload = build(); return api.post("/detections/validate", { format: payload.format, logic: payload.logic, threshold: payload.threshold, exceptions: payload.exceptions }); } });
  const save = useMutation({ mutationFn: () => api.patch(`/detections/${id}`, { ...build(), ...(d.pointers ? { expected_draft_version_id: d.pointers.draft?.id || null, base_version_id: baseVersion } : {}) }), onSuccess: () => { setDirty(false); refresh(); } });
  const legacy = useMutation({ mutationFn: () => api.post(`/detections/${id}/test`, { method: "legacy_investigation_verdict" }), onSuccess: row => { setSelectedLegacy(row.id); refresh(); } });
  const recordDeployment=useMutation({mutationFn:()=>api.post(`/detections/${id}/deployed`,{version_id:deploymentVersion,target:target.trim(),note:deploymentNote.trim()}),onSuccess:refresh});
  const download = useMutation({ mutationFn: () => api.download(exportQuery("native"), `saw-rule-${id}.txt`) });
  const preview = useMutation({ mutationFn: (format: string) => api.text(exportQuery(format)), onSuccess: text => setExported(text) });
  const copyVersion=(value:any)=>{setDraft(Object.fromEntries(semanticKeys.filter(key=>key in value).map(key=>[key,value[key]])));const threshold=value.threshold||{};setThresholdText(JSON.stringify(threshold,null,2));setEnabled(!!Object.keys(threshold).length);setCount(String(threshold.count_gte??5));setSeconds(String(threshold.timespan_sec??600));setGroups((threshold.group_by||[]).join(", "));setDistinct(threshold.distinct_field||"");setExceptionsText(JSON.stringify(value.exceptions||[],null,2));setBaseVersion(value.id);setSelectedTest(null);setDirty(true);};
  const runs = (d.test_runs || []).filter((row: any) => ["legacy_investigation_verdict", "legacy_historical_replay"].includes(row.scope?.method || row.result?.method || row.method || "legacy_investigation_verdict"));
  const result = runs.find((row: any) => row.id === selectedLegacy)?.result;
  return <div className="col" style={{ gap: 16 }}>
    <div className="row wrap"><h3>{d.display_id} · {draft.title}</h3>{d.source?.finding_id && <Link to={`/inv/${d.source.investigation_id}?finding=${d.source.finding_id}`}>원본 탐지 근거</Link>}</div>
    <VersionCards pointers={d.pointers} />
    {draft.format==="sigma"&&<Link to={`/detections/policies/${encodeURIComponent(`sigma.approved:${id}`)}`}>이 등록 룰의 범위별 사용 정책</Link>}
    <Panel title="새 초안 편집"><fieldset disabled={!write || save.isPending} className="col" style={{ border: 0, margin: 0, padding: 0 }}>
      <div className="row wrap"><label>규칙 제목 <input className="input" value={draft.title || ""} onChange={event => set("title", event.target.value)} /></label><label>형식 <select className="input" value={draft.format} onChange={event => set("format", event.target.value)}>{["sigma", "suricata", "regex", "generic_query"].map(format => <option key={format}>{format}</option>)}</select></label><label>위험도 <select className="input" value={draft.severity} onChange={event => set("severity", event.target.value)}>{["critical", "high", "medium", "low"].map(value => <option key={value}>{value}</option>)}</select></label></div>
      <label>탐지 조건 <textarea className="input mono" rows={12} value={draft.logic || ""} onChange={event => set("logic", event.target.value)} /></label>
      <label>임계값 편집 방식 <select className="input" value={mode} onChange={event => switchMode(event.target.value)}><option value="form">숫자·그룹 폼</option><option value="json">고급 JSON 초안</option></select></label>
      {mode === "form" ? <><label><input type="checkbox" checked={enabled} onChange={event => { setEnabled(event.target.checked); setDirty(true); }} />집계 조건 사용</label><div className="row wrap">
        <label>최소 일치 수 <input className="input" type="number" min={1} max={500000} disabled={!enabled} value={count} onChange={event => { setCount(event.target.value); setDirty(true); }} /></label>
        <label>집계 기간 (초) <input className="input" type="number" min={1} max={604800} disabled={!enabled} value={seconds} onChange={event => { setSeconds(event.target.value); setDirty(true); }} /></label>
        <label>그룹 필드 <input className="input" disabled={!enabled} placeholder="src_ip, dst_ip" value={groups} onChange={event => { setGroups(event.target.value); setDirty(true); }} /></label>
        <label>고유값 필드 <input className="input" disabled={!enabled} value={distinct} onChange={event => { setDistinct(event.target.value); setDirty(true); }} /></label>
      </div><p className="small muted">Sigma 슬라이딩 시간창은 경계 시각을 포함합니다. 다른 엔진의 시간 경계를 같은 방식으로 바꾸지 않습니다.</p></> : <label>임계값 JSON <textarea className="input mono" rows={6} value={thresholdText} onChange={event => { setThresholdText(event.target.value); setDirty(true); }} /></label>}
      <label>예외 필터 JSON <textarea className="input mono" rows={4} value={exceptionsText} onChange={event => { setExceptionsText(event.target.value); setDirty(true); }} /></label>
      <label>오탐·승인 활동 참고 <textarea className="input" rows={2} value={draft.false_positive || ""} onChange={event => set("false_positive", event.target.value)} /></label>
      <div className="row wrap"><button className="btn" disabled={validate.isPending} onClick={() => validate.mutate()}>조건 검증</button><button className="btn primary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>새 초안 버전 저장</button></div>
      <ErrorBox error={save.error || validate.error} />{validate.data && <div role="status">{validate.data.valid ? "구문·조건 검사 통과" : "조건 확인 필요"}{validate.data.errors?.length ? ` · ${validate.data.errors.join("; ")}` : ""}</div>}
    </fieldset></Panel>
    <ErrorBox error={modeError}/>
    <ExampleInputs key={`${id}:${d.version}:${baseVersion}`} values={draft.test_events || []} onChange={value => set("test_events", value)} disabled={!write} />
    {d.pointers && <><SelectedTruthPanel testPath={`/detections/${id}/test`} version={editorVersion} versions={(d.versions || []).filter((row: any) => row.id)} activeVersionId={d.pointers.active?.id} supportedUnits={["event", "window", "entity"]} existingRuns={d.test_runs || []} disabled={dirty || !write} onResult={setSelectedTest} />
      <GovernanceActions path={`/detections/${id}`} data={d} version={editorVersion} selectedTest={selectedTest} permissions={permissions} disabled={dirty} onChange={refresh} /></>}
    {!d.eligibility && <div className="small muted">작성자와 다른 Senior/Manager가 승인해야 합니다.</div>}    <details className="panel pb"><summary>기존 조사 판단 기반 시험 (legacy)</summary><p className="small muted">전체 조사 판단을 사용한 과거 방식입니다. 선택 단위 정답의 정확도나 새 승인 근거로 승격하지 않습니다.</p><button className="btn sm" disabled={!write || legacy.isPending} onClick={() => legacy.mutate()}>기존 방식으로 과거 자료 시험</button><ErrorBox error={legacy.error} />
      <label>기존 시험 선택 <select className="input" value={selectedLegacy} onChange={event => setSelectedLegacy(event.target.value)}><option value="">시험을 선택하세요</option>{runs.map((row: any) => <option key={row.id} value={row.id}>{row.id} · v{row.version} · {row.passed ? "통과" : "확인 필요"}</option>)}</select></label>
      {result && <><div>일치 {fmtNum(result.hits)} · 검사 {fmtNum(result.scanned)} · 조사 {result.investigations}개</div><div>기존 판단 기반 TP {result.tp ?? "미기록"} · FP {result.fp ?? "미기록"} · unlabeled {result.unlabeled ?? "미기록"}</div><details><summary>기존 시험 전체 결과</summary><pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(result, null, 2)}</pre></details></>}
    </details>
    <Panel title="룰 내보내기·외부 수동 배포 기록"><p className="small muted">내보내기는 선택한 저장 버전을 사용하며 저장하지 않은 편집은 포함하지 않습니다. 외부 장비 배포 기록과 SAW 활성화는 별개입니다. 원본 변환에 SAW 반복 조건·예외가 모두 포함되지는 않습니다.</p><label>내보낼 저장 버전 <select className="input" value={exportVersion} onChange={event=>{setExportVersion(event.target.value);setExported("");}}>{!(d.versions||[]).length&&<option value="">기존 현재 버전 (정확한 ID 미기록)</option>}{(d.versions||[]).filter((row:any)=>row.id).map((row:any)=><option key={row.id} value={row.id}>v{row.version} · {row.id}</option>)}</select></label><div className="row wrap"><button className="btn" disabled={download.isPending} onClick={() => download.mutate()}>원본 룰 파일 다운로드</button>{["native", "opensearch", "generic", "logpresso"].map(format => <button className="btn sm" key={format} onClick={() => preview.mutate(format)}>{format}</button>)}</div><ErrorBox error={download.error || preview.error} />{exported && <pre style={{ whiteSpace: "pre-wrap" }}>{exported}</pre>}<label>외부 수동 배포 대상 <input className="input" value={target} onChange={event => setTarget(event.target.value)} /></label><label>외부 배포 승인 버전 <select className="input" value={deploymentVersion} onChange={event=>setDeploymentVersion(event.target.value)}><option value="">정확한 승인 버전 선택</option>{d.pointers?.approved&&<option value={d.pointers.approved.id}>v{d.pointers.approved.version} · {d.pointers.approved.id}</option>}</select></label><label>외부 배포 기록 메모 <textarea className="input" value={deploymentNote} onChange={event=>setDeploymentNote(event.target.value)}/></label><button className="btn" disabled={!permissions.includes("detection.approve") || !deploymentVersion || !target.trim() || recordDeployment.isPending} onClick={()=>recordDeployment.mutate()}>외부 수동 배포 사실 기록</button><ErrorBox error={recordDeployment.error}/>{recordDeployment.isSuccess&&<div role="status">외부 수동 배포 기록을 저장했습니다. SAW 활성본은 별도입니다.</div>}{(d.deployments || []).map((row: any, index: number) => <div key={index}>v{row.version} · {row.target} · {fmtTime(row.at)}</div>)}</Panel>
    <RuleHistory id={id} versions={d.versions||[]} current={draft} write={write} onCopy={copyVersion}/>
  </div>;
}
function ExampleInputs({ values, onChange, disabled }: { values: unknown[]; onChange: (value: unknown[]) => void; disabled: boolean }) {
  const [text, setText] = useState(JSON.stringify(values, null, 2));
  const [error, setError] = useState("");
  return <Panel title="합성 일치·비일치 예제"><label>예제 JSON<textarea className="input mono" rows={5} value={text} disabled={disabled} onChange={event => setText(event.target.value)} /></label><button className="btn sm" disabled={disabled} onClick={() => { try { const parsed = JSON.parse(text); if (!Array.isArray(parsed) || parsed.length > 100 || parsed.some(row => !row || !["match", "no_match"].includes(row.expected) || !row.event || typeof row.event !== "object" || Array.isArray(row.event))) throw new Error("match/no_match와 event 객체를 가진 배열을 100개 이하로 입력하세요."); onChange(parsed); setError(""); } catch (problem) { setError(problem instanceof Error ? problem.message : "JSON 형식을 확인하세요."); } }}>예제 편집 반영 (이후 저장)</button>{error && <div className="error" role="alert">{error}</div>}</Panel>;
}
