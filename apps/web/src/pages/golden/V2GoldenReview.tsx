import { useMe } from "../../App";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ErrorBox, Loading, Panel } from "../../components/common";
import { api, ApiError } from "../../lib/api";
import { GoldenVersionView } from "./GoldenVersionView";
import { hiddenHoldout, lines, ROOT, type Capture } from "./types";
import type { GoldenChoice } from "../Golden";
const CONFIRM:Record<string,string>={required_facts_actions:"필수 사실과 조사 항목 확인",judgement_evidence:"판단과 근거 확인",followups:"후속확인 확인",forbidden_claims:"금지 주장 확인"};
export function V2GoldenReview({experience:e,onChoice,versions}:{experience:any;onChoice:(v:GoldenChoice)=>void;versions:any[]}) {
 const me=useMe(); const qc=useQueryClient(); const pins:Capture|undefined=e.data?.golden_capture;
 const [selected,setSelected]=useState(""); const g=versions.find(v=>v.id===selected)||(!selected?versions[0]:undefined);
 const [run,setRun]=useState(""); const [truth,setTruth]=useState<string[]>([]);
 const [answer,setAnswer]=useState<any>(null); const [decision,setDecision]=useState("none"); const [split,setSplit]=useState("dev"); const [confirm,setConfirm]=useState<Record<string,boolean>>({});
 useEffect(()=>{onChoice({valid:true});},[onChoice]);
 useEffect(()=>{setAnswer(null);setConfirm({});setDecision("none");},[g?.id,g?.content_sha256,g?.status,g?.answers_access?.available]);
 const [before,setBefore]=useState("");
 const cases=useQuery({queryKey:["detection-cases","golden",e.source_investigation_id,before,me.data?.id,me.data?.permissions],enabled:!!pins,queryFn:()=>api.get(`/detection-cases?limit=100&investigation_id=${encodeURIComponent(e.source_investigation_id)}${before?"&before="+encodeURIComponent(before):""}`)});
 const refresh=()=>{qc.invalidateQueries({queryKey:["golden",e.id]});qc.invalidateQueries({queryKey:["goldens"]});};
 const failure=(error:unknown)=>{if(error instanceof ApiError && [403,409].includes(error.status)) {setConfirm({});setDecision("none");}};
 const prepare=useMutation({mutationFn:()=>api.post(`${ROOT}/experience/${e.id}/prepare`,{expected_experience_rev:e.rev,schema_version:"saw.golden.v2",check_ids:pins?.check_revisions.map(c=>c.check_id)||[],...(run?{analysis_run_id:run}:{}),truth_case_version_ids:truth}),onSuccess:(v:any)=>{setSelected(v.id);refresh();},onError:failure});
 const save=useMutation({mutationFn:()=>api.patch(`${ROOT}/${g.id}`,{expected_content_sha256:g.content_sha256,answers:answer}),onSuccess:(v:any)=>{setSelected(v.id);setAnswer(null);setConfirm({});refresh();},onError:failure});
 const review=useMutation({mutationFn:()=>api.post(`${ROOT}/${g.id}/review`,{expected_content_sha256:g.content_sha256,decision,split,confirmations:confirm}),onSuccess:refresh,onError:failure});
 const available=!!g && !hiddenHoldout(g) && g.answers_access?.available!==false;
 const a=available ? answer||g.answers : null; const inv=a?.investigation_truth;
 const edit=(key:string,value:any)=>{setAnswer({...a,investigation_truth:{...inv,[key]:value}});setConfirm({});};
 return <Panel title="정답 사례 채택"><div className="col">
 <div className="small muted">경험 승인 후 정확한 v2 초안을 별도로 검토합니다. 답안 변경은 새 초안에 저장한 뒤 다른 검토자가 채택합니다.</div>
 {pins ? <details open={!g}><summary>새 v2 초안에 사용할 고정 참조</summary><div className="col">
 <div className="small">고정 확인 기록 {pins.check_revisions.length}개 · 후속확인 {pins.followup_versions.length}개</div>
 <label className="col small">고정 분석 실행<select className="input" value={run} onChange={x=>setRun(x.target.value)}><option value="">실행 선택 안 함</option>{pins.analysis_runs.map(r=><option key={r.id} value={r.id}>{r.id}</option>)}</select></label>
 {cases.isLoading?<Loading/>:(cases.data?.items||[]).map((c:any)=><label className="row small" key={c.id}><input type="checkbox" aria-label={`정답 버전 ${c.title} v${c.version}`} checked={truth.includes(c.id)} disabled={!truth.includes(c.id)&&truth.length>=20} onChange={x=>setTruth(x.target.checked?[...truth,c.id]:truth.filter(id=>id!==c.id))}/>{c.title} v{c.version} · {c.id}</label>)}
 <div className="row"><span className="small">정확 정답 버전 선택 {truth.length}/20</span>{before&&<button className="btn sm" onClick={()=>setBefore("")}>첫 정답 목록</button>}{cases.data?.next_cursor&&<button className="btn sm" onClick={()=>setBefore(cases.data.next_cursor)}>다음 정답 사례</button>}</div>
 <button className="btn" disabled={prepare.isPending} onClick={()=>prepare.mutate()}>{!g?"조사 기록에서 채택 초안 만들기":"현재 경험의 고정 참조로 새 초안 만들기"}</button><ErrorBox error={cases.error}/></div></details>
 :<div className="small warn">이 경험에는 당시의 정확한 확인·실행 참조가 없습니다. 기존 버전은 읽을 수 있지만 현재 자료를 붙여 과거 v2 입력으로 만들 수 없습니다.</div>}
 {versions.length>1 && <label className="row small">정답 사례 버전<select className="input" value={g?.id||""} onChange={x=>setSelected(x.target.value)}>{versions.map(v=><option key={v.id} value={v.id}>v{v.version} · {v.status} · {v.id}</option>)}</select></label>}
 {g && <><span className="small">버전 {g.version} · {g.status} · {g.schema_version}</span><GoldenVersionView golden={g}/>
 {available&&inv&&<><fieldset disabled={!g.can_edit} className="col" style={{border:0,padding:0}}>
 <label className="col small">관측 행위 판단<input className="input" value={inv.behavior||""} onChange={x=>edit("behavior",x.target.value)}/></label>
 <label className="col small">침해·영향 확인 내용<textarea className="input" value={inv.impact||""} onChange={x=>edit("impact",x.target.value)}/></label>
 <label className="col small">판단 근거<textarea className="input" value={inv.reason||""} onChange={x=>edit("reason",x.target.value)}/></label>
 <label className="col small">필수 사실과 조사 항목<textarea className="input" value={(inv.required_facts_actions||[]).map((v:any)=>v.text).join("\n")} onChange={x=>edit("required_facts_actions",lines(x.target.value).map((text,i)=>({text,evidence_refs:inv.required_facts_actions?.[i]?.evidence_refs||[]})))}/></label>
 {(inv.followups||[]).map((v:any,i:number)=><div className="small" key={i}>고정 후속확인: {typeof v==="string"?v:JSON.stringify(v)}</div>)}
 {!inv.followups?.length&&<label className="col small">후속확인이 불필요한 이유<input className="input" value={inv.no_followups_reason||""} onChange={x=>edit("no_followups_reason",x.target.value)}/></label>}
 <label className="col small">해서는 안 되는 단정<textarea className="input" value={(inv.forbidden_claims||[]).join("\n")} onChange={x=>edit("forbidden_claims",lines(x.target.value))}/></label>
 </fieldset>
 {answer&&g.can_edit&&<><button className="btn" disabled={save.isPending} onClick={()=>save.mutate()}>새 초안으로 저장</button><div className="small warn">답안 변경을 저장한 뒤 다른 검토자가 새 버전을 채택해야 합니다.</div></>}
 {g.status==="draft"&&g.can_review&&e.status==="approved"&&<><label className="row">정답 사례 결정<select className="input" value={decision} onChange={x=>{setDecision(x.target.value);setConfirm({});}}><option value="none">결정 선택</option><option value="adopt">정답 사례로 채택</option><option value="decline">미채택</option></select></label>
 <label className="row">사용 용도<select className="input" value={split} onChange={x=>{setSplit(x.target.value);setConfirm({});}}><option value="train">학습용</option><option value="dev">개발평가용</option><option value="holdout">비공개 평가용</option></select></label>
 {decision==="adopt"&&Object.entries(CONFIRM).map(([k,label])=><label className="row small" key={k}><input type="checkbox" checked={!!confirm[k]} onChange={x=>setConfirm({...confirm,[k]:x.target.checked})}/>{label}</label>)}
 <button className="btn primary" disabled={!!answer||decision==="none"||review.isPending||(decision==="adopt"&&!Object.keys(CONFIRM).every(k=>confirm[k]))} onClick={()=>review.mutate()}>정답 사례 결정 저장</button></>}
 {g.status==="draft"&&!g.can_review&&<span className="small muted">작성자·편집자와 다른 검토자가 채택해야 합니다.</span>}
 {e.status!=="approved"&&<span className="small muted">먼저 경험의 정확한 버전을 독립 승인해야 합니다.</span>}</>}</>}
 <ErrorBox error={prepare.error||save.error||review.error}/></div></Panel>;
}
