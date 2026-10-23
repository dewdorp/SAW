import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useMe } from "../../App";
import { ErrorBox,Panel } from "../../components/common";
import { api } from "../../lib/api";
import { ROOT,type Profile } from "./types";
import { usePages } from "./usePages";
import { Reasons } from "./labels";
const MODES:Record<string,{name:string;mapping:string;serialization:string}>={"golden-native/1":{name:"golden-native",mapping:"native-input-and-answers/1",serialization:"native-files/1"},"input-output-jsonl/1":{name:"input-output",mapping:"input-output/1",serialization:"jsonl-utf8/1"},"messages-jsonl/1":{name:"messages",mapping:"messages/1",serialization:"jsonl-utf8/1"}};
export function GoldenProfiles() {
 const [kind,setKind]=useState("pseudonymization");
 return <div className="col"><label className="row">프로필 종류<select className="input" value={kind} onChange={e=>setKind(e.target.value)}><option value="pseudonymization">가명처리</option><option value="model_conversion">변환 형식</option></select></label><Registry key={kind} kind={kind}/></div>;
}
function Registry({kind}:{kind:string}) {
 const me=useMe();const q=usePages<Profile>(`${ROOT}/profiles?kind=${kind}`,["golden-profiles",kind]);
 const [base,setBase]=useState<Profile|null>(null);const [key,setKey]=useState("");const [impl,setImpl]=useState(kind==="pseudonymization"?"scoped-identities/1":"golden-native/1");
 const [saved,setSaved]=useState<Profile|null>(null);
 const create=useMutation({mutationFn:()=>{
 if(!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$/.test(key))throw new Error("프로필 이름은 영문·숫자·밑줄·점·하이픈으로 입력하세요.");
 const mode=MODES[impl];
 const payload=kind==="pseudonymization"?{schema:"saw.pseudonymization-profile.v1",version:1,identity_scope:"org_network",identity_mapping:"scoped_injective/1",time_transform:"none",free_text:"drop_unapproved",metadata:"allowlist_v2"}:{schema:"saw.model-conversion-profile.v1",version:1,target:{name:mode.name,version:"1"},field_mapping:mode.mapping,serialization_contract:mode.serialization,validation_suite:"saw-release-reference-leakage/1"};
 return api.post<Profile>(ROOT+"/profiles",{kind,profile_key:key,expected_latest_id:base?.id||null,implementation:impl,payload});
 },onSuccess:p=>{setSaved(p);setBase(p);q.refetch();}});
 return <Panel title="불변 프로필 버전"><div className="col">
 <p className="small">프로필을 바꾸면 새 버전이 생깁니다. 작성 중인 반출 요청은 선택해 둔 정확한 프로필을 유지합니다.</p>
 {(q.data?.items||[]).map(p=><div className="col small" key={p.id}><b>{p.profile_key} v{p.version} · {p.implementation}</b><span className="mono">{p.id} · {p.payload_sha256}</span><Reasons value={p.limits}/><details><summary>정확한 프로필 정의</summary><pre style={{whiteSpace:"pre-wrap"}}>{JSON.stringify(p.payload,null,2)}</pre></details>
 {me.data?.permissions.includes("knowledge.write")&&<button className="btn sm" onClick={()=>{setBase(p);setKey(p.profile_key);setImpl(p.implementation);setSaved(null);}}>이 버전 기준 새 버전 작성</button>}</div>)}
 {q.data?.next_cursor&&<button className="btn" onClick={q.next}>다음 프로필</button>}{q.cursor&&<button className="btn" onClick={q.first}>첫 목록</button>}
 {me.data?.permissions.includes("knowledge.write")&&<><b>프로필 새 버전</b>{base&&<div className="small">현재 기준 {base.id} · v{base.version}<button className="btn sm" onClick={()=>{setBase(null);setKey("");}}>새 이름으로 작성</button></div>}
 <label className="col">프로필 이름<input className="input" value={key} disabled={!!base} maxLength={100} onChange={e=>setKey(e.target.value)}/></label>
 <label className="col">지원 변환<select className="input" value={impl} onChange={e=>setImpl(e.target.value)}>{(kind==="pseudonymization"?["scoped-identities/1"]:Object.keys(MODES)).map(v=><option key={v} value={v}>{v}</option>)}</select></label>
 <div className="small">관계사·망별 가명 일관성을 유지하고 시간 변환은 하지 않습니다. 사용자 스크립트나 임의 필드 표현식은 사용하지 않습니다.</div>
 <button className="btn" disabled={create.isPending} onClick={()=>create.mutate()}>프로필 버전 저장</button></>}
 {saved&&<div role="status">프로필 v{saved.version} 저장됨 · {saved.id}</div>}<ErrorBox error={q.error||create.error}/></div></Panel>;
}
