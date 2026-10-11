import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMe } from "../App";
import { ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader, Stat } from "../components/ui";
import { api } from "../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../lib/format";

const short = (h?: string) => (h ? h.slice(0, 12) : "–");

/** Processing records: who processed which input with which parser/settings, and what came out (fingerprints). */
export function Provenance() {
  const me = useMe();
  const canAll = !!me.data?.permissions.includes("audit.read");
  const [picked, setTab] = useState<"mine" | "all" | null>(null);
  // auditors without investigation access only have the consolidated view
  const tab = picked ?? (canAll && !me.data?.permissions.includes("investigation.read") ? "all" : "mine");
  return (
    <div className="page col">
      <PageHeader eyebrow="분석" title="처리 기록"
        desc="증거를 처리할 때마다 처리한 사람, 입력 파일 지문, 파서·설정 지문, 결과 지문이 자동으로 남습니다. 로그 내용은 담지 않으며 감사 로그(해시 체인)에도 같이 기록됩니다." />
      <div className="tabs">
        <button className={tab === "mine" ? "active" : ""} onClick={() => setTab("mine")}>내 조사의 처리 기록</button>
        {canAll && <button className={tab === "all" ? "active" : ""} onClick={() => setTab("all")}>통합 보기</button>}
      </div>
      {tab === "all" && canAll ? <Consolidated /> : <RunTable scope="mine" />}
    </div>
  );
}

function RunTable({ scope, title }: { scope: "mine" | "all"; title?: string }) {
  const q = useQuery({ queryKey: ["runs", scope], queryFn: () => api.get(`/processing-runs?scope=${scope}`) });
  const verify = useMutation({ mutationFn: (id: string) => api.get(`/processing-runs/${id}/verify`) });
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows: any[] = q.data;
  return (
    <Panel title={title || `처리 ${rows.length}건 (최근 90일)`}>
      {!rows.length ? <span className="muted">처리 기록이 없습니다.</span> : (
        <div style={{ overflowX: "auto" }}>
          <table className="t"><thead><tr><th>처리 시각</th><th>처리자</th><th>조사</th><th>파일</th><th>파서</th><th className="num">이벤트</th><th className="num">실패</th>
            <th>입력 지문</th><th>설정 지문</th><th>결과 지문</th><th>검증</th></tr></thead>
            <tbody>{rows.map((r) => (
              <tr key={r.id}>
                <td className="small">{fmtTime(r.finished_at)}</td><td className="small">{r.actor}</td>
                <td className="small">{r.investigation_id ? <Link to={`/inv/${r.investigation_id}`}>{r.investigation}</Link> : r.investigation}
                  {r.investigation_title && <div className="muted ellipsis" style={{ maxWidth: 180 }}>{r.investigation_title}</div>}</td>
                <td className="small ellipsis" style={{ maxWidth: 200 }} title={r.file_name}>{r.file_name}<div className="muted">{fmtBytes(r.input_size)}</div></td>
                <td className="mono small">{r.parser_id} <span className="muted">v{r.parser_version}</span>{r.draft_parser && <span className="tag warn">초안</span>}</td>
                <td className="num">{fmtNum(r.events)}</td><td className="num">{r.failed ? <b style={{ color: "var(--bad)" }}>{fmtNum(r.failed)}</b> : 0}</td>
                <td className="mono small" title={r.input_sha256}>{short(r.input_sha256)}</td>
                <td className="mono small" title={r.settings_digest}>{short(r.settings_digest)}</td>
                <td className="mono small" title={r.run_digest}>{short(r.run_digest)}</td>
                <td>{r.id in checked ? (checked[r.id] ? <span className="tag ok">일치</span> : <span className="tag bad">불일치</span>)
                  : <button className="btn sm" disabled={verify.isPending} onClick={() => verify.mutateAsync(r.id).then((v) => setChecked((c) => ({ ...c, [r.id]: v.ok })))}>검증</button>}</td>
              </tr>))}</tbody></table>
        </div>)}
      <ErrorBox error={verify.error} />
      <div className="muted small">검증: 저장된 기록에서 지문을 다시 계산하고, 감사 로그(해시 체인)에 남은 사본과 비교합니다. 불일치면 기록이 바뀐 것입니다.</div>
    </Panel>
  );
}

function Consolidated() {
  const q = useQuery({ queryKey: ["runs-summary"], queryFn: () => api.get("/processing-runs/summary") });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  const w = d.warnings;
  return (
    <div className="col">
      <div className="stats">
        <Stat label="처리 건수 (90일)" value={fmtNum(d.runs)} />
        <Stat label="서로 다른 입력 파일" value={fmtNum(d.inputs)} />
        <Stat label="같은 입력·다른 설정" value={fmtNum(w.same_input_different_settings.length)} tone={w.same_input_different_settings.length ? "high" : undefined} />
        <Stat label="초안 파서로 처리" value={fmtNum(w.draft_parser_runs.length)} tone={w.draft_parser_runs.length ? "medium" : undefined} />
      </div>
      {w.same_input_different_settings.length > 0 && (
        <Panel title="⚠ 같은 입력 파일을 서로 다른 설정으로 처리">
          <div className="muted small">같은 파일(입력 지문 동일)이 다른 파서·설정으로 처리되어 결과가 다를 수 있습니다. 어느 결과를 근거로 쓸지 확인하세요.</div>
          {w.same_input_different_settings.map((g: any) => (
            <div key={g.input_sha256} className="col" style={{ gap: 2 }}>
              <div className="small"><span className="mono">{short(g.input_sha256)}</span> · 설정 {g.settings_variants}종</div>
              {g.runs.map((r: any) => <div key={r.id} className="small mono">  {fmtTime(r.finished_at)} {r.actor} — {r.parser_id} v{r.parser_version} 설정 {short(r.settings_digest)} → 이벤트 {fmtNum(r.events)}</div>)}
            </div>))}
        </Panel>)}
      {w.parser_definition_changed.length > 0 && (
        <Panel title="파서 정의(코드·설정)가 기간 중 바뀜">
          {w.parser_definition_changed.map((x: any) => <div key={x.parser_id} className="small mono">{x.parser_id}: {x.variants}가지 정의로 처리됨</div>)}
        </Panel>)}
      <div className="grid2">
        <Panel title="분석가별">
          <table className="t"><thead><tr><th>처리자</th><th className="num">처리</th><th className="num">파일</th><th className="num">이벤트</th><th className="num">초안 파서</th></tr></thead>
            <tbody>{d.by_user.map((u: any) => <tr key={u.actor_id}><td>{u.actor}</td><td className="num">{fmtNum(u.runs)}</td><td className="num">{fmtNum(u.files)}</td><td className="num">{fmtNum(u.events)}</td><td className="num">{u.draft_runs || 0}</td></tr>)}</tbody></table>
        </Panel>
        <Panel title="파서별">
          <table className="t"><thead><tr><th>파서</th><th>버전</th><th className="num">처리</th><th className="num">설정 종류</th><th>처리한 사람</th></tr></thead>
            <tbody>{d.by_parser.map((p: any) => <tr key={p.parser_id + p.parser_version}><td className="mono small">{p.parser_id}</td><td>{p.parser_version}</td><td className="num">{fmtNum(p.runs)}</td>
              <td className="num">{p.settings_variants > 1 ? <b style={{ color: "var(--med)" }}>{p.settings_variants}</b> : p.settings_variants}</td><td className="small">{p.analysts.join(", ")}</td></tr>)}</tbody></table>
        </Panel>
      </div>
      <RunTable scope="all" title="전체 처리 기록 (최근 90일)" />
    </div>
  );
}
