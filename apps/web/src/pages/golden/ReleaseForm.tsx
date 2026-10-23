import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useMe } from "../../App";
import { ErrorBox, Panel } from "../../components/common";
import { api } from "../../lib/api";
import { Applicability, Reasons, SPLITS } from "./labels";
import { exactSelection, HASH, lines, ROOT, safeCaseLabel, type Profile, principalKey } from "./types";

export function ReleaseForm({existing}:{existing?:any}) {
 const location=useLocation(); const nav=useNavigate(); const me=useMe();
 const seed=(location.state as any)?.principal===principalKey(me.data)?location.state as any:undefined;
 const [split,setSplit]=useState(existing?.version?.split || seed?.split || "dev");
 const [selection,setSelection]=useState<any[]>(seed?.selected || []);
 const [pp,setPp]=useState(""); const [mp,setMp]=useState(""); const [projection,setProjection]=useState("v2");
 const [purpose,setPurpose]=useState(existing?.version?.purpose_text||""); const [name,setName]=useState(existing?.version?.recipient?.name||""); const [org,setOrg]=useState(existing?.version?.recipient?.organization||"");
 const [conditions,setConditions]=useState((existing?.version?.usage_conditions||[]).join("\n")); const [expiry,setExpiry]=useState("");
 const [rights,setRights]=useState(false); const [basis,setBasis]=useState(""); const [mode,setMode]=useState("interpretation_only");
 const [scopes,setScopes]=useState<Record<string,{golden_version_id:string;analysis_run_id:string;scope_sha256:string}>>({});
 const identity=useRef({json:"",key:""});
 const cases=useQuery({queryKey:["goldens","release",split,me.data?.id,me.data?.permissions],queryFn:()=>api.get(`${ROOT}?status=adopted&split=${split}`)});
 const available:any[]=cases.error?[]:cases.data||[];
 const selected=selection.flatMap(ref=>available.filter(g=>g.id===ref.version_id&&JSON.stringify(exactSelection(g))===JSON.stringify(ref)));
 const setSelected=(items:any[])=>setSelection(items.map(exactSelection));
 useEffect(()=>{if(cases.error){setSelection([]);setScopes({});setRights(false);}else if(cases.isSuccess){setSelection(old=>old.filter(ref=>available.some(g=>g.id===ref.version_id&&JSON.stringify(exactSelection(g))===JSON.stringify(ref))));}},[cases.dataUpdatedAt,cases.error]);
 const ps=useQuery({queryKey:["golden-profiles","pseudonymization",me.data?.id,me.data?.permissions],queryFn:()=>api.get(`${ROOT}/profiles?kind=pseudonymization&limit=100`)});
 const ms=useQuery({queryKey:["golden-profiles","model_conversion",me.data?.id,me.data?.permissions],queryFn:()=>api.get(`${ROOT}/profiles?kind=model_conversion&limit=100`)});
 const [extraProfiles,setExtraProfiles]=useState<Profile[]>([]);
 const [profileCursors,setProfileCursors]=useState<Record<string,string|null>>({});
 const nextP=Object.hasOwn(profileCursors,"pseudonymization")?profileCursors.pseudonymization:ps.data?.next_cursor;
 const nextM=Object.hasOwn(profileCursors,"model_conversion")?profileCursors.model_conversion:ms.data?.next_cursor;
 const moreProfiles=useMutation({mutationFn:async(kind:string)=>({kind,page:await api.get(`${ROOT}/profiles?kind=${kind}&limit=100&cursor=${encodeURIComponent(kind==="pseudonymization"?nextP:nextM)}`)}),onSuccess:({kind,page})=>{setExtraProfiles(old=>[...old,...page.items].filter((p,i,all)=>all.findIndex(v=>v.id===p.id)===i));setProfileCursors(old=>({...old,[kind]:page.next_cursor}));}});
 const pseudos:Profile[]=[...(ps.data?.items||[]),...extraProfiles].filter((p:Profile)=>p.kind==="pseudonymization");
 const models:Profile[]=[...(ms.data?.items||[]),...extraProfiles].filter((p:Profile)=>p.kind==="model_conversion"&&(split!=="holdout"||p.implementation==="golden-native/1"));
 const create=useMutation({mutationFn:()=>{
  const p=pseudos.find(p=>p.id===pp),m=models.find(p=>p.id===mp);
  if(!selected.length||selected.length>100||selected.some(g=>g.split!==split||!g.export_eligibility?.external_release?.enabled)) throw new Error("같은 용도의 반출 가능한 사례를 1~100개 선택하세요.");
  if(!p||!m) throw new Error("정확한 프로필 버전을 선택하세요.");
  if(!purpose.trim()||!name.trim()||!org.trim()||!lines(conditions).length||!rights||!basis.trim()) throw new Error("목적·수신처·사용 조건·재제공 권리를 모두 입력하세요.");
  if(lines(conditions).length>20||lines(conditions).some(v=>v.length>500)) throw new Error("사용 조건은 최대 20개이며 각 500자 이내여야 합니다.");
  const date=new Date(expiry);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()||date.getTime()>Date.now()+365*86400000) throw new Error("만료는 현재 이후 365일 이내의 시각이어야 합니다.");
  if(mode==="full_recalculation"&&(projection!=="v2"||selected.some(g=>!scopes[g.id]||!HASH.test(scopes[g.id].scope_sha256)))) throw new Error("모든 사례의 고정 분석 실행과 범위 해시를 선택하세요.");
  const body={schema_version:"saw.golden.release.v2",expected_current_version_id:existing?.current_version_id||null,purpose:({train:"external_training",dev:"external_development",holdout:"external_evaluation"} as Record<string,string>)[split],purpose_text:purpose.trim(),recipient:{name:name.trim(),organization:org.trim()},usage_conditions:lines(conditions),expires_at:date.toISOString(),examples:selected.map(exactSelection),split,artifact_kind:split==="holdout"?"holdout_input":split,projection,pseudonymization_profile:{id:p.id,sha256:p.payload_sha256},model_conversion_profile:{id:m.id,sha256:m.payload_sha256},redistribution:{confirmed:true,basis:basis.trim()},applicability_request:{mode,complete_scopes:mode==="full_recalculation"?selected.map(g=>scopes[g.id]):[]}};
  const json=JSON.stringify(body);if(identity.current.json!==json)identity.current={json,key:crypto.randomUUID()};
  return api.post(existing?`${ROOT}/releases/${existing.id}/versions`:`${ROOT}/releases`,{...body,idempotency_key:identity.current.key});
 },onError:()=>setRights(false),onSuccess:(v:any)=>nav(`/knowledge/releases/${v.release_id}`,{state:{job_id:v.job_id}})});
 const chooseSplit=(value:string)=>{setSplit(value);setSelected([]);setScopes({});setMp("");setMode("interpretation_only");setRights(false);};
 return <Panel title={existing?"반출 새 버전 작성":"새 반출 패키지"}><div className="col">
 <p className="small">사례 채택과 반출 승인은 별도입니다. 파일 생성 후 실제 파일을 미리 보고 독립 승인을 받아야 내려받을 수 있습니다.</p>
 {existing&&<div className="small">기준 현재 버전: {existing.current_version_id}. 새 파일 생성 중에도 기존 승인본은 별도로 유지됩니다.</div>}
 <label className="row">반출 용도<select className="input" value={split} onChange={e=>chooseSplit(e.target.value)}>{Object.entries(SPLITS).map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>
 <div className="small">선택 {selected.length}/100</div>
 {available.map((g:any)=><div key={g.id} className="col small"><label className="row"><input type="checkbox" aria-label={`반출 선택 ${safeCaseLabel(g)}`} checked={selected.some(v=>v.id===g.id)} disabled={!g.export_eligibility?.external_release?.enabled||(!selected.some(v=>v.id===g.id)&&selected.length>=100)} onChange={e=>{setSelected(e.target.checked?[...selected,g]:selected.filter(v=>v.id!==g.id));setRights(false);}}/>{safeCaseLabel(g)}</label><Reasons value={g.export_eligibility?.external_release}/></div>)}
 {selected.length>0&&<details open><summary>고정 선택 버전</summary>{selected.map(g=><div className="small mono" key={g.id}>{safeCaseLabel(g)} · {split==="holdout"?g.input_sha256:g.content_sha256}</div>)}</details>}
 <label className="col">가명처리 프로필<select className="input" value={pp} onChange={e=>{setPp(e.target.value);setRights(false);}}><option value="">정확한 버전 선택</option>{pseudos.map(p=><option key={p.id} value={p.id}>{p.profile_key} v{p.version} · {p.implementation} · {p.id}</option>)}</select></label>
 {nextP&&<button className="btn sm" disabled={moreProfiles.isPending} onClick={()=>moreProfiles.mutate("pseudonymization")}>가명처리 프로필 더 보기</button>}
 <label className="col">변환 프로필<select className="input" value={mp} onChange={e=>{setMp(e.target.value);setRights(false);}}><option value="">정확한 버전 선택</option>{models.map(p=><option key={p.id} value={p.id}>{p.profile_key} v{p.version} · {p.implementation} · {p.id}</option>)}</select></label>
 {nextM&&<button className="btn sm" disabled={moreProfiles.isPending} onClick={()=>moreProfiles.mutate("model_conversion")}>변환 프로필 더 보기</button>}
 <div className="small muted">변환 형식은 모델 호환성·학습·품질 개선을 보증하지 않습니다. 가명 대응표는 반출하지 않습니다.</div>
 <label className="row">출력 스키마<select className="input" value={projection} onChange={e=>{setProjection(e.target.value);setMode("interpretation_only");setRights(false);}}><option value="v2">v2</option><option value="v1">v1 호환 · 새 문맥 미제공</option></select></label>
 <label className="row">자료 용도<select className="input" value={mode} onChange={e=>{setMode(e.target.value);setScopes({});setRights(false);}}><option value="interpretation_only">대표 근거 해석용</option><option value="full_recalculation" disabled={projection!=="v2"||split==="holdout"}>전체 재계산 검증 요청</option></select></label>
 <Applicability value={{mode:"interpretation_only"}}/>
 {mode==="full_recalculation"&&<><div className="small warn">완료된 단일 FW 실행과 정확한 시간 구간 정답이 필요합니다. 서버의 전체 열거·변환 재계산 검증이 실패하면 파일을 게시하지 않습니다.</div>{selected.map(g=><FullScope key={g.id} golden={g} onSelect={v=>{setScopes(old=>({...old,[g.id]:v}));setRights(false);}}/>)}</>}
 <label className="col">반출 목적 설명<textarea className="input" maxLength={1000} value={purpose} onChange={e=>{setPurpose(e.target.value);setRights(false);}}/></label>
 <label className="col">수신자<input className="input" maxLength={200} value={name} onChange={e=>{setName(e.target.value);setRights(false);}}/></label>
 <label className="col">수신 기관<input className="input" maxLength={200} value={org} onChange={e=>{setOrg(e.target.value);setRights(false);}}/></label>
 <label className="col">사용 조건<textarea className="input" placeholder="한 줄에 한 조건, 최대 20개" value={conditions} onChange={e=>{setConditions(e.target.value);setRights(false);}}/></label>
 <label className="col">만료 시각<input className="input" type="datetime-local" value={expiry} onChange={e=>{setExpiry(e.target.value);setRights(false);}}/></label>
 <span className="small muted">현재 브라우저 시간대 기준으로 입력하며 서버에는 UTC로 저장합니다.</span>
 <label className="col">재제공 권리 근거<textarea className="input" maxLength={2000} value={basis} onChange={e=>{setBasis(e.target.value);setRights(false);}}/></label>
 <label className="row"><input type="checkbox" checked={rights} onChange={e=>setRights(e.target.checked)}/>재제공 권리를 확인했습니다</label>
 <button className="btn primary" disabled={create.isPending||!me.data?.permissions.includes("golden.release.create")||(existing&&!existing.eligibility?.new_version?.enabled)} onClick={()=>create.mutate()}>반출 파일 생성 요청</button>
 <ErrorBox error={cases.error||ps.error||ms.error||moreProfiles.error||create.error}/>
 </div></Panel>;
}
function FullScope({golden:g,onSelect}:{golden:any;onSelect:(v:any)=>void}) {
 const [id,setId]=useState("");
 const pin=g.analysis_run_ref;
 const valid=!!pin?.id&&HASH.test(pin.sha256||"")&&HASH.test(pin.scope_sha256||"");
 useEffect(()=>{setId("");onSelect(undefined);},[g.id,pin?.id,pin?.sha256,pin?.scope_sha256]);
 if(!valid)return <div className="col small"><span>이 정답 버전에는 범위 해시가 고정된 분석 실행이 없어 전체 재계산을 요청할 수 없습니다.</span>{g.experience_id&&<Link to={`/knowledge/exp/${g.experience_id}`}>새 v2 캡처 만들기</Link>}</div>;
 return <label className="col small">{safeCaseLabel(g)} 고정 실행<select className="input" value={id} onChange={e=>{setId(e.target.value);onSelect(e.target.value===pin.id?{golden_version_id:g.id,analysis_run_id:pin.id,scope_sha256:pin.scope_sha256}:undefined);}}><option value="">범위 해시가 고정된 실행 선택</option><option value={pin.id}>{pin.id}</option></select></label>;
}
