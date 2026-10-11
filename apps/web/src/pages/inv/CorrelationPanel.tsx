import { useQuery } from "@tanstack/react-query";
import { Panel } from "../../components/common";
import { EntityChip, parseEntity } from "../../components/EntityChip";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtNum, fmtTime } from "../../lib/format";

/** Cross-source correlation chains (docs/32 §2): strong = shared entity within window, weak = time/asset only. */
export function CorrelationPanel({ inv }: { inv: string }) {
  const ctx = useInv(inv);
  const q = useQuery({ queryKey: ["correlations", inv], queryFn: () => api.get(`/investigations/${inv}/correlations`) });
  const rows = (q.data || []) as any[];
  if (!rows.length) return null;
  return (
    <Panel title={`Cross-source Correlation (${rows.length})`} right={<span className="small muted">실선=강한 연결(공통 Entity) · 점선=약한 연결</span>}>
      <div className="col" style={{ gap: 6, maxHeight: 260, overflow: "auto" }}>
        {rows.slice(0, 20).map((c) => (
          <div key={c.id} className="row wrap small" style={{ borderLeft: `2px ${c.strength === "strong" ? "solid" : "dashed"} var(--accent)`, paddingLeft: 6 }}>
            {c.entity_keys.slice(0, 2).map((e: string) => { const p = parseEntity(e); return <EntityChip key={e} inv={inv} type={p.type} value={p.value} />; })}
            {c.steps.map((st: any, i: number) => (
              <span key={i} className="row">
                {i > 0 && <span className="muted">→</span>}
                {st.finding_id
                  ? <a onClick={() => ctx.set({ tab: "findings", findingId: st.finding_id })}>{st.display_id} {st.title}</a>
                  : <span className="tag" title={`${st.sources.join(", ")} · ${st.role.join("/")}`}>{st.family} {fmtNum(st.count)} · {fmtTime(st.first, false)}</span>}
              </span>
            ))}
            <span className="tag">{c.strength}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}
