import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";

const STATE: Record<string, string> = { linked: "분석에 연결", candidate: "연결(의미 확인 필요)", raw: "원문 보존" };

/** Each export column: what it is, how this investigation's analysis used it, and how many records had it. */
export function FieldMeanings({ inv }: { inv: string }) {
  const [open, setOpen] = useState(false);
  const q = useQuery<any>({ enabled: open, queryKey: ["field-meanings", inv], queryFn: () => api.get(`/investigations/${inv}/field-meanings`) });
  return (
    <details className="scope-fold" onToggle={e => setOpen(e.currentTarget.open)}>
      <summary>필드 의미와 분석 연결</summary>
      {open && q.isPending && <p className="scope-fold-content" role="status">입력 필드를 확인하고 있습니다…</p>}
      {open && q.error && <p className="scope-fold-content" role="alert">필드 설명을 불러올 수 없습니다. <button className="btn sm" onClick={() => q.refetch()}>다시 조회</button></p>}
      {q.data && !q.data.formats?.length && <p className="scope-fold-content">필드 설명에 연결된 NDR·FW 형식이 없습니다. 원문에서 실제 헤더를 확인하세요.</p>}
      {open && q.data?.formats?.map((f: any) => (
        <div key={f.parser} className="scope-fold-content">
          <b className="small">{f.label} · 기록 {fmtNum(f.records)}건</b>
          <table className="t small"><thead><tr><th>원래 필드</th><th>의미</th><th>분석 연결</th><th>값 있는 기록</th><th>이번 분석에서의 사용·주의</th></tr></thead>
            <tbody>{f.fields.map((x: any) => (
              <tr key={x.column}><td className="mono">{x.column}</td><td>{x.meaning}</td>
                <td><span className={`tag ${x.state === "linked" ? "" : "warn"}`}>{STATE[x.state] || x.state}</span>{x.common_field ? <span className="mono muted"> → {x.common_field}</span> : null}</td>
                <td className="num">{fmtNum(x.records_with_value)} / {fmtNum(x.records)}</td><td>{x.use}</td></tr>))}</tbody></table>
        </div>
      ))}
    </details>
  );
}
