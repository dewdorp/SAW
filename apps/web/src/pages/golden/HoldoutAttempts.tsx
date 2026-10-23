import { useMe } from "../../App";
import { useEffect,useRef,useState } from "react";
import { useMutation,useQuery } from "@tanstack/react-query";
import { Link,useLocation,useNavigate,useParams } from "react-router-dom";
import { ErrorBox,Loading,Panel } from "../../components/common";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import { Reasons } from "./labels";
import { HASH,principalKey,ROOT } from "./types";
import { usePages } from "./usePages";
const STATUS:Record<string,string>={reserved:"평가 시도 등록",input_accessed:"입력 내려받음",result_recorded:"사용자 결과 등록",answers_accessed:"내부 평가자 정답 열람"};
export function HoldoutAttempts() {
 const q=usePages<any>(ROOT+"/holdout-attempts",["golden-attempts"]);
 return <Panel title="비공개 평가 사용 이력"><div className="col"><Link to="/knowledge/holdout-attempts/new">평가 시도 등록</Link><div className="small">입력 파일 → 외부에서 직접 실행 → 사용자 결과 등록 → 내부 평가자 정답 열람 순서입니다.</div>
 {(q.data?.items||[]).map(a=><div className="row" key={a.id}><Link to={`/knowledge/holdout-attempts/${a.id}`}>{a.target.name} · {a.target.version}</Link><span>{STATUS[a.status]} · {fmtTime(a.created_at)}</span></div>)}
 {q.data?.next_cursor&&<button className="btn" onClick={q.next}>다음 평가 이력</button>}{q.cursor&&<button className="btn" onClick={q.first}>첫 목록</button>}<ErrorBox error={q.error}/></div></Panel>;
}
export function HoldoutAttemptForm() {
 const loc=useLocation();const nav=useNavigate();const me=useMe();
 const initial=(loc.state as any)?.principal===principalKey(me.data)?(loc.state as any)?.release:undefined;
 const [selection,setSelection]=useState<any>(initial||null);
 const [accessError,setAccessError]=useState<unknown>(null);const [denied,setDenied]=useState<string[]>([]);
 const q=usePages<any>(ROOT+"/releases",["golden-releases","holdout-picker"]);
 const exact=useQuery({queryKey:["golden-release",selection?.id,selection?.version_id,me.data?.id,me.data?.permissions],enabled:!!selection,queryFn:()=>api.get(`${ROOT}/releases/${selection.id}/versions/${selection.version_id}`)});
 const selected=!q.error&&!exact.error&&exact.data?.id===selection?.id&&exact.data?.version?.id===selection?.version_id&&exact.data?.version?.artifact?.sha256===selection?.artifact_sha256&&exact.data?.state==="approved"&&exact.data?.version?.split==="holdout"?exact.data:undefined;
 useEffect(()=>{if(q.error||exact.error){setAccessError(q.error||exact.error);if(selection)setDenied(old=>[...old,selection.version_id]);setSelection(null);}},[q.error,exact.error]);
 const options=q.error?[]:[...(selected?[selected]:[]),...(q.data?.items||[]).filter(r=>r.version?.id!==selected?.version?.id)].filter(r=>r.version?.split==="holdout"&&r.state==="approved"&&!denied.includes(r.version.id));
 const [kind,setKind]=useState("model");const [name,setName]=useState("");const [version,setVersion]=useState("");const [hash,setHash]=useState("");const [purpose,setPurpose]=useState("");
 const identity=useRef({json:"",key:""});
 const create=useMutation({mutationFn:()=>{
  if(!selected?.version||selected.version.split!=="holdout")throw new Error("승인된 비공개 평가용 정확한 반출 버전을 선택하세요.");
  if(!name.trim()||!version.trim()||!HASH.test(hash)||!purpose.trim())throw new Error("대상 이름·버전·파일 SHA256과 평가 목적을 입력하세요.");
  const body={release_version_id:selected.version.id,expected_artifact_sha256:selected.version.artifact.sha256,target:{kind,name:name.trim(),version:version.trim(),artifact_sha256:hash},purpose_text:purpose.trim()};
  const json=JSON.stringify(body);if(identity.current.json!==json)identity.current={json,key:crypto.randomUUID()};
  return api.post(ROOT+"/holdout-attempts",{...body,idempotency_key:identity.current.key});
 },onSuccess:a=>nav(`/knowledge/holdout-attempts/${a.id}`)});
 return <Panel title="평가 시도 등록"><div className="col">
 <label className="col">승인된 비공개 평가 입력<select className="input" value={selected?.version?.id||""} onChange={e=>{const r=options.find(r=>r.version?.id===e.target.value);setSelection(r?{id:r.id,version_id:r.version.id,artifact_sha256:r.version.artifact.sha256}:null);setAccessError(null);}}><option value="">정확한 반출 버전 선택</option>{options.map(r=><option key={r.version.id} value={r.version.id}>{r.id} · v{r.version.revision} · {r.version.id}</option>)}</select></label>
 {q.data?.next_cursor&&<button className="btn" onClick={q.next}>다음 반출 목록</button>}
 {selected&&<div className="small mono">고정 파일 SHA256 {selected.version?.artifact?.sha256}</div>}
 <label className="row">대상 종류<select className="input" value={kind} onChange={e=>setKind(e.target.value)}><option value="model">모델</option><option value="detector">탐지기</option><option value="application">응용 프로그램</option></select></label>
 <label className="col">대상 이름<input className="input" maxLength={200} value={name} onChange={e=>setName(e.target.value)}/></label>
 <label className="col">대상 버전<input className="input" maxLength={200} value={version} onChange={e=>setVersion(e.target.value)}/></label>
 <label className="col">대상 파일 SHA256<input className="input mono" maxLength={64} value={hash} onChange={e=>setHash(e.target.value)}/></label>
 <label className="col">평가 목적<textarea className="input" maxLength={1000} value={purpose} onChange={e=>setPurpose(e.target.value)}/></label>
 <div className="small muted">대상 해시는 사용자 기재값 · 파일 직접 검증 전입니다. 대상 이름이나 반출 ID 변경은 같은 사건군·대상 파일의 반복 평가를 허용하지 않습니다.</div>
 <button className="btn primary" disabled={create.isPending||!selected} onClick={()=>create.mutate()}>평가 시도 등록 요청</button><ErrorBox error={accessError||q.error||exact.error||create.error}/></div></Panel>;
}
export function HoldoutAttemptDetail() {
 const me=useMe();
 const {id=""}=useParams();
 const q=useQuery({queryKey:["golden-attempt",id,me.data?.id,me.data?.permissions],queryFn:()=>api.get(`${ROOT}/holdout-attempts/${id}`)});
 if(q.isLoading)return <Loading/>;if(q.error)return <ErrorBox error={q.error}/>;
 return <Attempt key={JSON.stringify([id,me.data?.id,me.data?.permissions])} value={q.data} refresh={()=>q.refetch()}/>;
}
function Attempt({value:a,refresh}:{value:any;refresh:()=>Promise<any>}) {
 const [hash,setHash]=useState("");const [summary,setSummary]=useState("");const [answers,setAnswers]=useState<string|null>(null);
 const download=useMutation({mutationFn:()=>api.download(`${ROOT}/releases/${a.release_id}/versions/${a.release_version_id}/download?attempt_id=${encodeURIComponent(a.id)}`,"holdout-input.zip"),onSuccess:()=>refresh()});
 const result=useMutation({mutationFn:()=>{if(!HASH.test(hash)||!summary.trim())throw new Error("실제 결과 파일 SHA256과 직접 실행한 결과를 입력하세요.");return api.post(`${ROOT}/holdout-attempts/${a.id}/result`,{expected_result_sha256:null,artifact_sha256:hash,summary:summary.trim()});},onSuccess:()=>{setAnswers(null);refresh();},onError:()=>setAnswers(null)});
 const read=useMutation({mutationFn:()=>api.text(`${ROOT}/holdout-attempts/${a.id}/answers`),onSuccess:text=>{setAnswers(text);refresh();},onError:()=>setAnswers(null)});
 return <Panel title="비공개 평가 시도"><div className="col"><Link to="/knowledge/holdout-attempts">평가 이력 목록</Link>
 <b>{a.target.name}</b><div className="small">{a.target.version} · {STATUS[a.status]} · 정확 반출 버전 {a.release_version_id}</div>
 <div className="small mono">대상 SHA256 {a.target.artifact_sha256}</div><div className="small muted">사용자 기재값 · 파일 직접 검증 전</div>
 <div>{a.purpose_text}</div><Reasons value={a.limits}/>
 <div className="small">입력 열람 {a.input_access?.count||0}회 · 정답 열람 {a.answers_access?.count||0}회</div>
 <button className="btn" disabled={!a.release_id||!a.eligibility?.download_input?.enabled||download.isPending} onClick={()=>download.mutate()}>이 평가 시도의 입력 내려받기</button><Reasons value={a.eligibility?.download_input}/>
 {a.result?.status==="operator_reported"?<><b>사용자가 보고한 결과</b><div>{a.result.summary}</div><div className="mono small">{a.result.artifact_sha256}</div></>:<><label className="col">결과 파일 SHA256<input className="input mono" maxLength={64} value={hash} onChange={e=>setHash(e.target.value)}/></label>
 <label className="col">직접 실행한 결과 요약<textarea className="input" maxLength={4000} value={summary} onChange={e=>setSummary(e.target.value)}/></label>
 <button className="btn" disabled={!a.eligibility?.record_result?.enabled||result.isPending} onClick={()=>result.mutate()}>사용자 보고 결과 등록</button></>}
 <Reasons value={a.eligibility?.record_result}/>
 <div className="small muted">이 기록은 사용자가 별도 환경에서 수행한 결과입니다. SAW가 모델 추론·학습·품질 평가를 실행했다는 뜻이 아닙니다. 등록된 결과는 덮어쓰지 않습니다.</div>
 <button className="btn" disabled={!a.eligibility?.read_answers?.enabled||read.isPending} onClick={()=>read.mutate()}>내부 평가자 정답 열람</button><Reasons value={a.eligibility?.read_answers}/>
 {answers!==null&&a.eligibility?.read_answers?.enabled&&<pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{answers}</pre>}
 <ErrorBox error={download.error||result.error||read.error}/></div></Panel>;
}
