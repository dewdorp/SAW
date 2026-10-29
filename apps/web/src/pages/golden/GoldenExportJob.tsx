import { useMe } from "../../App";
import { useEffect,useState } from "react";
import { useMutation,useQuery,useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api,ApiError } from "../../lib/api";
import { ErrorBox,Loading,Panel } from "../../components/common";
import { principalKey,TERMINAL } from "./types";
const LABEL:Record<string,string>={QUEUED:"대기",PARSING:"파일 생성 중",ANALYZING:"파일 검증 중",INDEXING:"파일 저장 중",COMPLETED:"파일 생성 완료 · 반출 승인 별도",FAILED:"실패",CANCELLED:"취소됨",WAITING_INPUT:"확인 필요"};
const enabled=(v:any)=>v===true||v?.enabled===true;
type JobProps={id:string;initial?:any;initialPrincipal?:string;onRetry?:(job:any)=>void};
export function GoldenExportJob(props:JobProps) {
 const me=useMe();if(me.isLoading)return <Loading/>;if(me.error)return <ErrorBox error={me.error}/>;
 const principal=principalKey(me.data);
 return <GoldenExportJobContent key={principal+":"+props.id} {...props} principal={principal}/>;
}
function GoldenExportJobContent({id,initial,initialPrincipal,onRetry,principal}:JobProps&{principal:string}) {
 const qc=useQueryClient();
 const [jobId,setJobId]=useState(id);useEffect(()=>setJobId(id),[id]);
 const q=useQuery({queryKey:["job",jobId,principal],queryFn:()=>api.get(`/jobs/${jobId}`),initialData:initialPrincipal===principal&&initial?.id===jobId?initial:undefined,refetchInterval:qq=>TERMINAL.includes((qq.state.data as any)?.state)?false:2000});
 useEffect(()=>{if(q.error instanceof ApiError&&[403,404].includes(q.error.status))qc.removeQueries({queryKey:["job",jobId,principal],exact:true});},[q.error,jobId,principal,qc]);
 const retry=useMutation({mutationFn:()=>api.post(`/jobs/${jobId}/retry`),onSuccess:j=>{setJobId(j.id);onRetry?.(j);}});
 const cancel=useMutation({mutationFn:()=>api.post(`/jobs/${jobId}/cancel`),onSuccess:()=>q.refetch()});
 if(q.isLoading)return <Loading/>;if(q.error)return <ErrorBox error={q.error}/>;
 const j=q.data;const g=j?.stages?.golden_export;
 return <Panel title="정답 사례 반출 파일 생성"><div className="col"><ErrorBox error={q.error||cancel.error||retry.error}/>{j&&<>
 <div role="status">{LABEL[j.state]||"작업 상태 확인 필요"} · 작업 {jobId}</div>
 {typeof g?.summary==="string"&&<span className="small">{g.summary}</span>}
 {typeof g?.progress==="number"&&<progress max={100} value={g.progress}/>}
 {g?.release_id&&<Link to={`/knowledge/releases/${g.release_id}${g.version_id?"/versions/"+g.version_id:""}`}>반출 버전·승인 보기</Link>}
 <div className="row"><button className="btn" disabled={cancel.isPending||!enabled(g?.actions?.cancel??j.can_cancel)} onClick={()=>cancel.mutate()}>파일 생성 취소</button>
 <button className="btn" disabled={retry.isPending||!enabled(g?.actions?.retry??j.can_retry)} onClick={()=>retry.mutate()}>같은 고정 입력으로 다시 시도</button></div>
 <div className="small muted">생성 완료는 반출 승인이 아닙니다. 승인·다운로드는 정확한 반출 버전에서 확인합니다. 실패·취소는 기존 승인본을 바꾸지 않습니다.</div></>}</div></Panel>;
}
