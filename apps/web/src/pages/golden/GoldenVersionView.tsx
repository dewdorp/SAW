import { fmtTime } from "../../lib/format";
import { Applicability } from "./labels";
import { hiddenHoldout, safeCaseLabel } from "./types";
const DET:Record<string,string>={expected_match:"일치",expected_no_match:"불일치",unlabeled:"정답 미지정"};
const INV:Record<string,string>={attack:"공격",attempt:"공격 시도",approved_activity:"승인된 활동",normal:"정상",false_positive:"오탐",undetermined:"판단 유보",insufficient_data:"자료 부족"};
export function GoldenVersionView({golden:g}:{golden:any}) {
 if(hiddenHoldout(g) || g.answers_access?.available === false) return <div className="col"><b>{safeCaseLabel(g)}</b><Applicability value={g.applicability}/><div>정답은 평가 입력과 결과를 기록한 뒤 내부 평가자 경로에서 열람합니다.</div></div>;
 const a=g.answers;
 return <div className="col"><Applicability value={g.applicability} validation={g.validation}/>
 <div className="small">입력 기준 시각 {fmtTime(g.input?.cutoff?.as_of)} · 경험 r{g.experience_rev} · 정확 버전 {g.id}</div>
 {a?.schema === "saw.golden.answers.v2" && <><b>탐지 정답과 조사 판단</b>
 {a.detection_truth?.status === "not_labeled" && <div>탐지 정답 미지정</div>}
 {(a.detection_truth?.units || []).map((u:any)=><div className="col small" key={u.case_version_id+":"+u.unit_id}>
 <span>{u.unit_kind} · {u.unit_id} · 정답 버전 {u.case_version_id}</span><span>탐지 기대: {DET[u.detection_truth] || "미지정"}</span><span>조사 판단: {INV[u.investigation_truth] || "미확인"}</span><span>{u.basis}</span>
 <details><summary>고정된 판정 범위</summary><pre style={{whiteSpace:"pre-wrap"}}>{JSON.stringify({event_ids:u.event_ids,filters:u.filters,time:u.time},null,2)}</pre></details></div>)}
 <div className="small muted">승인된 활동도 탐지 조건에 해당할 수 있습니다. 두 정답 축을 합치지 않습니다.</div>
 {(a.later_confirmed_facts || []).map((v:any,i:number)=><div className="small" key={i}>후일 확인: {v.fact} · 확인 {fmtTime(v.confirmed_at)} · 알려진 시각 {fmtTime(v.known_at)}</div>)}</>}
 </div>;
}
