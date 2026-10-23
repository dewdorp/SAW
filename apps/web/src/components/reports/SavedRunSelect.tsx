import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { ErrorBox } from "../common";
import { fmtTime } from "../../lib/format";
import { eligibleRun } from "./types";
export function SavedRunSelect({ inv, value, onChange, label = "내보낼 저장 분석 실행" }: {
    inv: string;
    value: string;
    onChange: (value: string) => void;
    label?: string;
}) { const [before, setBefore] = useState<number | null>(null); const [older, setOlder] = useState<any[]>([]); const q = useQuery({ queryKey: ["export-runs", inv, before], queryFn: () => api.get(`/investigations/${inv}/analysis-runs?limit=50${before ? `&before_version=${before}` : ""}`) }); const runs = [...older, ...(q.data?.runs || [])].filter((r, i, a) => a.findIndex(x => x.id === r.id) === i); return <div className="col"><label>{label}<select className="input" value={value} onChange={e => onChange(e.target.value)}><option value="">정확한 실행 선택</option>{runs.map(r => <option key={r.id} value={r.id} disabled={!eligibleRun(r)}>v{r.version} · {({ complete: "완료", completed: "완료", partial: "일부 처리", insufficient_data: "자료 부족", limited: "한도 도달", running: "실행 중", failed: "실패", cancelled: "취소" } as Record<string, string>)[r.status] || r.status} · {fmtTime(r.created_at)} · {r.id}</option>)}</select></label><ErrorBox error={q.error}/>{q.data?.next_before_version && <button className="btn sm" onClick={() => { setOlder(runs); setBefore(q.data.next_before_version); }}>이전 저장 실행 더 보기</button>}<span className="small muted">실행 중·실패·취소는 성공한 분석으로 내보내지 않습니다. 부분 처리·자료 부족 상태는 그대로 보존합니다.</span></div>; }
