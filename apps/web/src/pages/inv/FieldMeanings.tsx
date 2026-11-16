import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { fmtNum } from "../../lib/format";

const STATE: Record<string, string> = { linked: "분석에 연결", candidate: "연결(의미 확인 필요)", raw: "원문 보존" };

/** Each export column: what it is, how this investigation's analysis used it, and how many records had it. */
export function FieldMeanings({ inv }: { inv: string }) {
  const q = useQuery<any>({ queryKey: ["field-meanings", inv], queryFn: () => api.get(`/investigations/${inv}/field-meanings`) });
  if (!q.data?.formats?.length) return null;
  return (
    <details className="panel pb">
      <summary><b>필드 의미와 분석 연결</b> <span className="small muted">— 이 필드가 무엇인지, 이번 분석에서 어떻게 썼는지, 값이 있는 기록 수</span></summary>
      {q.data.formats.map((f: any) => (
        <div key={f.parser} style={{ overflowX: "auto", marginTop: 8 }}>
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
