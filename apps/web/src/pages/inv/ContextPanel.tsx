import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { TeamChecks } from "../../components/Checks";
import { Panel } from "../../components/common";
import { Assistant } from "./Assistant";
import { GuidancePanel } from "./GuidancePanel";
import { entityKey, useInv } from "../../context/invContext";
import { api, ApiError } from "../../lib/api";

/** Scoped investigation guidance followed by existing reference knowledge and optional assistance. */
export function ContextPanel({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const key = ctx.findingId || (ctx.selection ? `${ctx.selection.type}:${ctx.selection.value}` : "inv");
  const q = useQuery({
    queryKey: ["context", inv, key],
    queryFn: () => api.post(`/investigations/${inv}/context`, { finding_id: ctx.findingId, entity: ctx.selection }),
    retry: false,
  });
  const notAvail = q.error instanceof ApiError && q.error.status === 404;
  const d = q.data || {};
  return (
    <div className="col" style={{ padding: 6 }}>
      <div className="small muted">기준: {ctx.findingId ? "선택한 Finding" : ctx.selection ? `${ctx.selection.type} ${ctx.selection.value}` : "Investigation 전체"}</div>
      <GuidancePanel inv={inv} />
      <div className="small muted">아래 지식은 참고 자료입니다. 위 조사 안내의 시간·필터 범위에 대한 확인 결과와 구분하세요.</div>
      {ctx.selection && <TeamChecks inv={inv} keys={[entityKey(ctx.selection)]} />}
      <Panel title="자산 정보">
        {d.assets?.length ? d.assets.map((a: any) => (
          <div key={a.asset_id} className="col small" style={{ gap: 2 }}>
            <div className="row"><b>{a.service}</b><span className="tag">{a.criticality}</span><span className="muted">{a.data_classification}</span></div>
            {a.comparisons?.map((c: any) => <div key={c.label} className="row"><span className="muted" style={{ width: 90 }}>{c.label}</span><span className="grow">Normal {c.normal}</span><span className={c.deviates ? "sev high" : ""}>Now {c.current}{c.deviates ? " ⚠" : ""}</span></div>)}
            {a.batch_schedule?.map((b: any) => <div key={b.name} className="muted">Known batch: {b.name} {b.cron} {b.matches ? "✓ 일치" : "— 현재 활동은 대상 아님"}</div>)}
          </div>
        )) : <span className="muted small">{notAvail ? "Asset Knowledge는 Phase 8에서 활성화" : "매칭되는 자산 없음 (Knowledge › Asset 등록)"}</span>}
      </Panel>
      <Panel title="유사 사례">
        {d.similar?.length ? d.similar.map((s: any) => (
          <div key={s.ref_id} className="col small" style={{ gap: 1, borderBottom: "1px solid var(--line)", paddingBottom: 3 }}>
            <div className="row"><b>{Math.round(s.score * 100)}%</b><Link className="ellipsis" to={s.ref_type === "investigation" ? `/inv/${s.ref_id}` : `/knowledge/exp/${s.ref_id}`}>{s.display_id} {s.title}</Link><span className="tag">{s.verdict || "–"}</span></div>
            <div className="muted">feature {s.breakdown.feature} · vector {s.breakdown.vector} · keyword {s.breakdown.keyword}</div>
            <div>공통 {s.same.map((x: string) => <span key={x} className="d-add">✓{x} </span>)}</div>
            <div>차이 {s.different.map((x: string) => <span key={x} className="d-chg">△{x} </span>)}</div>
          </div>
        )) : <span className="muted small">{notAvail ? "Similar Case는 Phase 9에서 활성화" : "유사 사례 없음"}</span>}
      </Panel>
      <Panel title="우리 SOC 경험 (승인됨)">
        {d.experiences?.length ? d.experiences.map((x: any) => (
          <div key={x.id} className="col small" style={{ gap: 1, borderBottom: "1px solid var(--line)", paddingBottom: 3 }}>
            <div className="row"><span className="muted">{x.date}</span><Link className="ellipsis" to={`/knowledge/exp/${x.id}`}><b>{x.title}</b></Link><span className="tag">{x.verdict}</span></div>
            <div>공통 {x.same.slice(0, 4).map((k: string) => <span key={k} className="d-add">✓{k} </span>)} 차이 {x.different.slice(0, 3).map((k: string) => <span key={k} className="d-chg">△{k} </span>)}</div>
            {x.fp_conditions?.length > 0 && <div className="d-chg">⚑ FP 조건: {x.fp_conditions.join("; ")}</div>}
            {x.recommended_checks?.slice(0, 3).map((c: string) => <div key={c}>☐ {c}</div>)}
          </div>
        )) : <span className="muted small">{notAvail ? "SOC Experience는 Phase 8에서 활성화" : "승인된 경험 없음"}</span>}
      </Panel>
      {d.playbooks?.length > 0 && <Panel title="점검 절차">{d.playbooks.map((b: any) => <div key={b.id} className="small"><b>{b.title}</b>{b.steps.map((s: any, i: number) => <div key={i}>☐ {s.check}</div>)}</div>)}</Panel>}
      <Assistant inv={inv} />
    </div>
  );
}
