import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { scopeKeyOf, useInv, type Filter, type TimeRange } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtPeriod, getTz } from "../../lib/format";
import { CLAIM_COLUMNS, PRESETS } from "./evidenceView";

type Candidate = {
  kind: "spread" | "outbound"; src: string; dst?: string; port?: number; protocol?: string;
  observed: string; baseline: string; corroboration: string; next_check: string;
  filters: Filter[]; time: TimeRange; evidence_ids: string[]; corroborating_event_ids?: string[];
};
type Comparison = {
  status: "ready" | "insufficient" | "partial";
  scope: { baseline_start: string | null; baseline_end: string | null; recent_start: string | null; recent_end: string | null };
  counts: { baseline: number; recent: number }; candidates: Candidate[]; note: string;
};

export function LongWindowComparison({ inv }: { inv: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const ctx = useInv(inv);
  const query = useQuery({ queryKey: ["long-window-comparisons", inv], enabled: false, retry: false,
    queryFn: () => api.get<Comparison>(`/investigations/${encodeURIComponent(inv)}/long-window-comparisons`) });
  const data = query.data;
  function openEvidence(candidate: Candidate, ndrIds?: string[]) {
    const { time } = candidate;
    const filters: Filter[] = ndrIds ? [{ field: "event_id", op: "in", value: ndrIds }] : candidate.filters;
    const columns = ndrIds ? { label: "NDR 요청 대조 열", cols: ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "method", "uri"] }
      : candidate.kind === "spread" ? CLAIM_COLUMNS.spread : { label: "FW 송신 근거 열", cols: [...PRESETS.network, "src_port", "data_source"] };
    ctx.set({ tab: "raw", filters, time, eventId: null, selection: null, findingId: null, judgeScope: null,
      evidenceColumns: { key: scopeKeyOf(filters, time), ...columns } });
  }
  return <section className="queue-tools" aria-label="장기 로그 비교">
    <button className="btn sm" type="button" aria-expanded={open} aria-controls={id} onClick={() => {
      if (!open) void query.refetch();
      setOpen(!open);
    }}>장기 로그 비교</button>
    <div id={id} hidden={!open}>{open && (query.isFetching ? <p role="status">최근 7일의 활동을 직전 8주의 주간 기록과 비교하고 있습니다.</p>
      : query.isError ? <p role="alert">장기 로그 비교를 불러오지 못했습니다. <button className="btn sm" type="button" onClick={() => query.refetch()}>비교 다시 시도</button></p>
      : data && <>
        {data.scope?.baseline_start && <p className="queue-scope">FW·NDR 원문 기준 · 끝 시각 제외<br />이전 기준 기간 {fmtPeriod(data.scope.baseline_start, data.scope.baseline_end)} {getTz()} · {fmtNum(data.counts.baseline)}건<br />
          최근 비교 기간 {fmtPeriod(data.scope.recent_start, data.scope.recent_end)} {getTz()} · {fmtNum(data.counts.recent)}건</p>}
        <p role="status"><strong>{data.status === "insufficient" ? "비교할 자료가 부족합니다." : data.status === "partial" ? (data.candidates.length ? "자료 일부만 비교했습니다." : "계산 한도 도달") : data.candidates.length ? `검토할 후보 ${fmtNum(data.candidates.length)}개` : "두 기간을 비교한 결과 조건에 맞는 후보가 없습니다."}</strong> {data.note}</p>
        {data.candidates.map(candidate => <article className="activity-detail" key={JSON.stringify([candidate.kind, candidate.src, candidate.dst, candidate.port, candidate.protocol])}>
          <h4>{candidate.kind === "spread" ? "새 내부 목적지 접촉" : "외부 송신 후보"} · {candidate.src}{candidate.dst && ` → ${candidate.dst}`}{candidate.port != null && ` · ${candidate.protocol ? `${candidate.protocol.toUpperCase()} ` : ""}포트 ${candidate.port}`}</h4>
          <dl><div><dt>최근 관측</dt><dd>{candidate.observed}</dd></div>
            <div><dt>이전 기준과의 차이</dt><dd>{candidate.baseline}</dd></div>
            <div><dt>{candidate.kind === "spread" ? "FW 처리 결과" : "FW·NDR 대조"}</dt><dd>{candidate.corroboration}</dd></div>
            <div><dt>다음 확인</dt><dd>{candidate.next_check}</dd></div></dl>
          {candidate.filters.length > 0 && candidate.time?.start && candidate.time.end && <button className="btn sm" type="button" onClick={() => openEvidence(candidate)}>이 후보의 원문 보기</button>}
          {!!candidate.corroborating_event_ids?.length && <button className="btn sm" type="button" onClick={() => openEvidence(candidate, candidate.corroborating_event_ids)}>대조한 NDR 원문 예시 {candidate.corroborating_event_ids.length}건 보기</button>}
        </article>)}
      </>)}</div>
  </section>;
}
