import { useEffect,useState } from "react";
import { useMutation,useQuery,useQueryClient } from "@tanstack/react-query";
import { Link,useLocation,useParams } from "react-router-dom";
import { useMe } from "../../App";
import { ErrorBox,Loading,Panel } from "../../components/common";
import { api,ApiError } from "../../lib/api";
import { fmtBytes,fmtTime } from "../../lib/format";
import { Applicability,Reasons,SPLITS,STATES } from "./labels";
import { principalKey,ROOT } from "./types";
import { usePages } from "./usePages";
import { ReleaseForm } from "./ReleaseForm";
import { ReleasePreview } from "./ReleasePreview";
import { GoldenExportJob } from "./GoldenExportJob";
const CONFIRM:Record<string,string>={preview_reviewed:"파일 미리보기 확인",redistribution_rights:"재제공 권리 확인",recipient_and_purpose:"수신처와 목적 확인",limits_accepted:"한계 수용 확인"};
export function ReleaseList() {
 const q=usePages<any>(ROOT+"/releases",["golden-releases"]);const me=useMe();
 return <Panel title="반출 패키지"><div className="col">{me.data?.permissions.includes("golden.release.create")&&<Link to="/knowledge/releases/new">새 반출 패키지 작성</Link>}
 {q.isLoading?<Loading/>:(q.data?.items||[]).map(r=><div className="row wrap" key={r.id}><Link to={`/knowledge/releases/${r.id}`}>반출 {r.id}</Link><span>{STATES[r.state]||r.state}</span><span>{SPLITS[r.version?.split]||""}</span><span>{r.version?.recipient?.organization}</span></div>)}
 <div className="row">{q.cursor&&<button className="btn" onClick={q.first}>첫 목록</button>}{q.data?.next_cursor&&<button className="btn" onClick={q.next}>다음 목록</button>}</div><ErrorBox error={q.error}/></div></Panel>;
}
export function ReleaseWorkspace() {
 const me=useMe(); const qc=useQueryClient();
 const {id="",versionId}=useParams(); const loc=useLocation();
 const path=`${ROOT}/releases/${id}${versionId?"/versions/"+versionId:""}`;
 const queryKey=["golden-release",id,versionId||"current",me.data?.id,me.data?.permissions];
 const q=useQuery({queryKey,queryFn:()=>api.get(path)});
 if(q.isLoading)return <Loading/>;if(q.error)return <ErrorBox error={q.error}/>;
 const r=q.data;const jobId=r.pending_job?.id||(loc.state as any)?.job_id;
 return <div className="col"><Link to="/knowledge/releases">반출 목록</Link>
 {jobId&&<GoldenExportJob key={jobId} id={jobId}/>}
 {!r.version?<div>파일 생성 중입니다. 완료 후 현재 버전을 다시 불러오세요.<button className="btn" onClick={()=>q.refetch()}>상태 새로고침</button></div>
 :<ReleaseDetail key={r.id+":"+r.version.id} release={r} refresh={()=>q.refetch()} refreshExact={async()=>{const value=await api.get(`${ROOT}/releases/${r.id}/versions/${r.version.id}`);qc.setQueryData(queryKey,value);return value;}}/>}</div>;
}
function ReleaseDetail({release:r,refresh,refreshExact}:{release:any;refresh:()=>Promise<any>;refreshExact:()=>Promise<any>}) {
 const me=useMe();
 const v=r.version;const base=`${ROOT}/releases/${r.id}/versions/${v.id}`;
 const [reason,setReason]=useState("");const [confirmed,setConfirmed]=useState<Record<string,boolean>>({});
 const [receipt,setReceipt]=useState<any>(null);const [newVersion,setNewVersion]=useState(false);
 const reset=()=>{setReceipt(null);setConfirmed({});};
 useEffect(reset,[v.id,v.payload_sha256,v.artifact?.sha256,r.current_version_id,r.approval?.id]);
 const stale=(error:unknown)=>{if(error instanceof ApiError&&[403,409].includes(error.status))reset();};
 const preview=useMutation({mutationFn:async()=>{const value=await api.get(base+"/preview");const current=await refreshExact();if(current.version?.id!==v.id||current.version?.payload_sha256!==v.payload_sha256||current.version?.artifact?.sha256!==v.artifact?.sha256||current.current_version_id!==r.current_version_id||current.approval?.id!==r.approval?.id){reset();throw new Error("반출 상태가 변경되었습니다. 정확한 버전을 다시 미리 보세요.");}return value;},onSuccess:value=>{setReceipt(value);setConfirmed({});},onError:stale});
 const validReceipt=receipt?.version_id===v.id&&receipt?.payload_sha256===v.payload_sha256&&receipt?.artifact_sha256===v.artifact?.sha256;
 const decide=useMutation({mutationFn:(decision:string)=>api.post(base+"/approve",{expected_current_version_id:r.current_version_id,expected_payload_sha256:v.payload_sha256,expected_artifact_sha256:v.artifact.sha256,expected_decision_id:r.approval?.id||null,decision,reason:reason.trim(),confirmations:decision==="approve"?confirmed:{}}),onSuccess:()=>{reset();refresh();},onError:stale});
 const revoke=useMutation({mutationFn:()=>api.post(base+"/revoke",{expected_decision_id:r.approval?.id,reason:reason.trim()}),onSuccess:()=>{reset();refresh();},onError:stale});
 const download=useMutation({mutationFn:()=>api.download(base+"/download","golden-release.zip"),onError:stale});
 return <Panel title={`반출 버전 ${v.revision}`}><div className="col">
 <div className="row wrap"><span className="tag">{STATES[r.state]||r.state}</span><span>{SPLITS[v.split]} · {v.projection}</span></div>
 {r.current_version_id!==v.id&&<div className="small warn">과거의 정확한 버전입니다. 현재 버전 {r.current_version_id}와 구분합니다.</div>}
 {r.pending_job&&<div className="small">새 버전 생성 중이며 이 버전의 승인 상태는 별도로 유지됩니다.</div>}
 <div>{v.purpose_text}</div><div className="small">수신자 {v.recipient?.name} · {v.recipient?.organization} · 만료 {fmtTime(v.expires_at)}</div>
 {(v.usage_conditions||[]).map((c:string,i:number)=><div key={i} className="small">{c}</div>)}
 <Applicability value={v.applicability}/>
 <div className="small mono">정확 버전 {v.id} · 내용 SHA256 {v.payload_sha256}</div>
 <div className="small mono">파일 {fmtBytes(v.artifact?.size_bytes)} · SHA256 {v.artifact?.sha256}</div>
 <details><summary>고정 프로필·파일 구성</summary><div className="small">가명처리 {v.profiles?.pseudonymization?.id} · {v.profiles?.pseudonymization?.sha256}</div><div className="small">변환 {v.profiles?.model_conversion?.id} · {v.profiles?.model_conversion?.sha256}</div>
 <table className="t"><thead><tr><th>파일</th><th>크기</th><th>SHA256</th></tr></thead><tbody>{(v.manifest?.files||[]).map((f:any)=><tr key={f.path}><td>{f.path}</td><td>{f.size_bytes}</td><td className="mono small">{f.sha256}</td></tr>)}</tbody></table></details>
 <button className="btn" disabled={!r.eligibility?.preview?.enabled||preview.isPending} onClick={()=>preview.mutate()}>실제 파일 미리보기</button><Reasons value={r.eligibility?.preview}/>
 {validReceipt&&<ReleasePreview value={receipt}/>}
 <label className="col">검토 사유<textarea className="input" maxLength={2000} value={reason} onChange={e=>{setReason(e.target.value);setConfirmed({});}}/></label>
 {Object.entries(CONFIRM).map(([k,label])=><label className="row small" key={k}><input type="checkbox" checked={!!confirmed[k]} disabled={!validReceipt||!r.eligibility?.approve?.enabled} onChange={e=>setConfirmed({...confirmed,[k]:e.target.checked})}/>{label}</label>)}
 <div className="row wrap"><button className="btn primary" disabled={!r.eligibility?.approve?.enabled||r.current_version_id!==v.id||!validReceipt||!reason.trim()||!Object.keys(CONFIRM).every(k=>confirmed[k])||decide.isPending} onClick={()=>decide.mutate("approve")}>반출 승인</button>
 <button className="btn" disabled={!r.eligibility?.decline?.enabled||r.current_version_id!==v.id||!reason.trim()||decide.isPending} onClick={()=>decide.mutate("decline")}>반출 반려</button></div><Reasons value={r.eligibility?.approve}/><Reasons value={r.eligibility?.decline}/>
 {r.approval&&<div className="small">최근 결정 {STATES[r.approval.decision]||r.approval.decision} · {r.approval.reason} · {fmtTime(r.approval.created_at)}</div>}
 {v.split==="holdout"?<Link to="/knowledge/holdout-attempts/new" state={{principal:principalKey(me.data),release:{id:r.id,version_id:v.id,artifact_sha256:v.artifact?.sha256}}}>이 정확한 입력 파일로 평가 시도 등록</Link>
 :<button className="btn" disabled={!r.eligibility?.download?.enabled||download.isPending} onClick={()=>download.mutate()}>승인된 정확한 파일 내려받기</button>}<Reasons value={r.eligibility?.download}/>
 <button className="btn" disabled={!r.eligibility?.revoke?.enabled||!reason.trim()||revoke.isPending} onClick={()=>revoke.mutate()}>반출 승인 철회</button><Reasons value={r.eligibility?.revoke}/>
 <div className="small muted">철회는 앞으로의 다운로드를 차단하며 이미 받은 파일을 회수하지 못합니다.</div>
 <button className="btn" onClick={()=>{reset();refresh();}}>최신 상태 다시 보기</button>
 <button className="btn" disabled={!r.eligibility?.new_version?.enabled} onClick={()=>setNewVersion(!newVersion)}>새 반출 버전 작성</button><Reasons value={r.eligibility?.new_version}/>
 {newVersion&&<ReleaseForm key={r.id+":"+r.current_version_id} existing={r}/>}
 <details><summary>버전 이력</summary>{(r.versions||[]).map((h:any)=><div key={h.id}><Link to={`/knowledge/releases/${r.id}/versions/${h.id}`}>v{h.revision} · {STATES[h.state]||h.state}</Link></div>)}<ReleaseHistory id={r.id}/></details>
 <ErrorBox error={preview.error||decide.error||revoke.error||download.error}/></div></Panel>;
}
function ReleaseHistory({id}:{id:string}) {
 const [open,setOpen]=useState(false);
 return open?<HistoryPage id={id}/>:<button className="btn sm" onClick={()=>setOpen(true)}>전체 버전 목록 열기</button>;
}
function HistoryPage({id}:{id:string}) {
 const q=usePages<any>(`${ROOT}/releases/${id}/versions`,["golden-release-history",id]);
 return <div className="col">{(q.data?.items||[]).map((v:any)=><Link key={v.id} to={`/knowledge/releases/${id}/versions/${v.id}`}>버전 {v.revision} · {v.id}</Link>)}{q.data?.next_cursor&&<button className="btn" onClick={q.next}>다음 버전</button>}<ErrorBox error={q.error}/></div>;
}
