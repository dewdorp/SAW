import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox } from "../../components/common";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
export function ActivationHistory({path,revision}:{path:string;revision:number}) {
 const [open,setOpen]=useState(false);const [older,setOlder]=useState<any[]>([]);const [before,setBefore]=useState<number|null|undefined>(undefined);
 const query=useQuery({queryKey:["activation-history",path,revision],queryFn:()=>api.get(`${path}/activations?limit=50`),enabled:open});
 const next=before===undefined?query.data?.next_cursor:before;
 const more=useMutation({mutationFn:()=>api.get(`${path}/activations?limit=50&before_revision=${next}`),onSuccess:page=>{setOlder(old=>[...old,...page.items]);setBefore(page.next_cursor);}});
 const rows=[...(query.data?.items||[]),...older].filter((item,index,all)=>all.findIndex(row=>row.id===item.id)===index);
 const actions:Record<string,string>={activate:"적용",rollback:"복구",disable:"해제",legacy_admission:"기존 상태 편입"};
 return <details className="panel pb" onToggle={event=>setOpen(event.currentTarget.open)}><summary>SAW 적용·복구 이력</summary><ErrorBox error={query.error||more.error}/>{query.data&&<><p className="small">적용 이력 {rows.length}건</p><div style={{overflowX:"auto"}}><table className="t"><thead><tr><th>리비전·시각</th><th>동작</th><th>이전 버전</th><th>적용 버전</th><th>승인</th><th>실행자·사유</th></tr></thead><tbody>{rows.map(item=><tr key={item.id}><td>{item.revision} · {fmtTime(item.created_at)}</td><td>{actions[item.action]||item.action}</td><td className="mono">{item.from_version_id||"없음"}</td><td className="mono">{item.to_version_id||"없음"}</td><td className="mono">{item.approval_id||"미기록"}</td><td>{item.actor_name} · {item.reason}</td></tr>)}</tbody></table></div>{next&&<button className="btn" disabled={more.isPending} onClick={()=>more.mutate()}>이전 적용 이력 더 보기</button>}</>}</details>;
}
