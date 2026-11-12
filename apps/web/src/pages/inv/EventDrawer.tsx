import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { TargetChecks, useMarks } from "../../components/Checks";
import { ErrorBox, Loading, Sev } from "../../components/common";
import { EntityChip } from "../../components/EntityChip";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import { columnLabel, displayField, PRESETS, profileOf } from "./evidenceView";
import "./evidenceView.css";
import { RememberDialog } from "./flows/RememberDialog";

const CHECK_TYPES = ["ip", "domain", "uri", "user", "session", "ja4"];
const ENT_FIELDS: [string, string][] = [["src_ip", "ip"], ["dst_ip", "ip"], ["uri_template", "uri"], ["user_agent", "user_agent"], ["ja4", "ja4"], ["user", "user"], ["domain", "domain"], ["session_id", "session"]];

/** Bottom drawer: Normalized / Raw / Entities / Findings / Context lines (docs/15 §1.5). */
export function EventDrawer({ inv }: { inv: string }) {
  const { eventId } = useInv(inv);
  if (!eventId) return <div className="drawer closed"><div className="tabs"><button disabled>기록을 선택하면 상세와 원문을 볼 수 있습니다</button></div></div>;
  // Remount the detail per event: an audited raw line, reason and stream must not follow a new selection.
  return <EventRecord key={`${inv}:${eventId}`} inv={inv} eventId={eventId}/>;
}

function EventRecord({ inv, eventId }: { inv: string; eventId: string }) {
  const ctx = useInv(inv);
  const [tab, setTab] = useState("normalized");
  const [reason, setReason] = useState("");
  const [streamOpen, setStreamOpen] = useState(false);
  const [remember, setRemember] = useState(false);
  const ev = useQuery({ queryKey: ["event", inv, ctx.eventId], queryFn: () => api.get(`/investigations/${inv}/events/${ctx.eventId}`), enabled: !!ctx.eventId });
  const lines = useQuery({ queryKey: ["ctxlines", inv, ctx.eventId], queryFn: () => api.get(`/investigations/${inv}/events/${ctx.eventId}/context?lines=20`), enabled: !!ctx.eventId && tab === "context" });
  const unmask = useMutation({ mutationFn: () => api.post(`/investigations/${inv}/events/${ctx.eventId}/unmask`, { reason }) });
  const marks = useMarks(inv);
  const linked = useQuery({ queryKey: ["linked", inv, ctx.eventId], queryFn: () => api.get(`/investigations/${inv}/network/linked/${ctx.eventId}`), enabled: !!ctx.eventId });
  const pcap = useMutation({ mutationFn: () => api.download(`/investigations/${inv}/network/sessions/${ctx.eventId}/pcap`, "session.pcap").then((r) => r.headers.get("x-saw-packets")) });
  const e = ev.data?.event;
  const profile = profileOf(e?.data_source);
  const keyFields = [...new Set(["data_source", ...PRESETS[profile], "src_port", "source_file"])].filter(k => e?.[k] != null && e?.[k] !== "");
  // Additional, device-reported context. Never derive units or the policy outcome from a TCP flag.
  const device = e?.ext?.security_csv?.source_columns ?? e?.ext?.security_csv;
  const deviceFields = [["_device_name","원천 장비"],["action","장비의 원래 조치값"],["tcp_flag","TCP 플래그"],["duration","지속 시간 (장비 원값·단위 확인)"]]
    .filter(([key]) => typeof device?.[key] === "string" || typeof device?.[key] === "number")
    .filter(([key]) => device[key] !== "" && device[key] !== "-");
  const nLinked = (linked.data?.groups || []).reduce((a: number, g: any) => a + g.count, 0);
  const nChecks = (marks.data?.events?.[eventId] || []).length;
  // packets are reachable for PCAP-derived events and for NDR/log events whose session was also captured
  const hasPackets = !!e && e.src_port != null && (String(e.data_source || "").startsWith("zeek_") || !!linked.data?.pcap_session);
  return (
    <div className="drawer">
      <div className="tabs">
        <button disabled title={eventId}>기록 상세</button>
        {([["normalized", "핵심 필드"], ["raw", "원문"], ["entities", "주소·계정"], ["findings", "관련 탐지"], ["context", "전후 로그"], ["linked", `연결된 기록${nLinked ? ` ${nLinked}` : ""}`], ["checks", `확인${nChecks ? ` ${nChecks}` : ""}`]] as [string, string][]).map(([t, l]) => <button key={t} className={tab === t ? "active" : ""} aria-pressed={tab === t} onClick={() => setTab(t)}>{l}</button>)}
        <div className="grow" />
        {e && e.uri && e.hostname && <button className="btn sm" onClick={() => setRemember(true)} title="이 요청의 업무 의미를 저장해 다음 자료부터 자동으로 적용합니다">메모하고 기억하기</button>}
        {e && e.alert_name && <a className="btn ghost sm" href="/registry" title="이 장비 공격명의 해석을 등록합니다">공격명 해석 저장</a>}
        {hasPackets && (
          <button className="btn ghost sm" onClick={() => setStreamOpen(true)} title="재조립한 세션 내용 보기 (Follow TCP Stream, 감사 기록)">⇄ 스트림 보기</button>
        )}
        {hasPackets && (
          <button className="btn ghost sm" disabled={pcap.isPending} onClick={() => pcap.mutate()} title="이 세션의 원본 패킷을 PCAP 파일로 받아 Wireshark 등에서 열 수 있습니다 (감사 기록)">
            {pcap.isPending ? "추출 중…" : pcap.data != null ? `⬇ 세션 PCAP (${pcap.data} pkts)` : "⬇ 세션 PCAP"}
          </button>
        )}
        {pcap.error && <span className="small bad" style={{ alignSelf: "center" }}>{(pcap.error as Error).message}</span>}
        {e && <span className="small muted" style={{ alignSelf: "center" }} title={`${e.parser || ""} ${e.parser_version || ""}`}>{e.source_file || "원본 파일 미기록"}{e.raw_ref?.line_no != null && ` · ${e.raw_ref.line_no}행`}</span>}
        <button className="btn ghost sm" aria-label="기록 상세 닫기" onClick={() => ctx.set({ eventId: null })}>✕</button>
      </div>
      {streamOpen && ctx.eventId && <StreamModal inv={inv} eventId={ctx.eventId} onClose={() => setStreamOpen(false)} />}
      {remember && e && <RememberDialog inv={inv} seed={{ host: String(e.hostname).toLowerCase(), method: e.method || "", path: String(e.uri).split("?")[0], eventIds: [e.event_id], source: "event" }}
        onClose={() => setRemember(false)} onSaved={() => { setRemember(false); ctx.set({ tab: "flows" }); }} />}
      <div className="scroll" style={{ padding: 8 }}>
        {e && (e.ext?.zeek?.capture_gap || e.ext?.zeek?.missed_bytes > 0) && (
          <div className="error small" role="alert" style={{ marginBottom: 6 }}>⚠ 패킷 빠짐 — 이 세션은 캡처에서 일부 패킷이 빠져 있습니다{e.ext.zeek.missed_bytes > 0 ? ` (${Number(e.ext.zeek.missed_bytes).toLocaleString()} B)` : ""}. 요청·응답 짝, 응답 코드, 추출 파일·해시가 실제와 다를 수 있으니 판단 근거로 쓰기 전에 스트림 보기로 직접 확인하세요.</div>
        )}
        {ev.isLoading && <Loading />}
        <ErrorBox error={ev.error} />
        {e && tab === "normalized" && (
          <div className="col">
            <dl className="evidence-key">{keyFields.map(k => <div key={k}><dt title={k}>{columnLabel(k,profile)}</dt><dd className="mono">{displayField(k,e[k])}</dd></div>)}
              {deviceFields.map(([key,name]) => <div key={key}><dt title={key}>{name}</dt><dd className="mono">{String(device[key])}</dd></div>)}</dl>
            {profile === "http" && e.status_code != null && <p className="small muted">HTTP 코드는 해당 요청의 응답입니다. 인증 성공이나 반환된 내용은 이 값만으로 확인할 수 없습니다.</p>}
            {profile === "network" && e.enforcement_action && <p className="small muted">처리 결과는 장비가 기록한 조치입니다. 허용만으로 실제 접속 성공을 확인할 수 없습니다.</p>}
            <details><summary>전체 필드와 원천 속성 보기</summary>
            <table className="t"><tbody>{Object.entries(e).filter(([k]) => !["raw_event", "raw_visual", "ext", "raw_ref"].includes(k)).map(([k, v]) => (
            <tr key={k}><td className="muted" style={{ width: 180 }}>{k}</td><td className="mono pre">{typeof v === "object" ? JSON.stringify(v) : String(v)}</td></tr>
          ))}{e.ext && <tr><td className="muted">원천 속성 (ext)</td><td className="mono pre">{JSON.stringify(e.ext, null, 1)}</td></tr>}</tbody></table></details></div>
        )}
        {e && tab === "raw" && (
          <div className="col">
            <div className="row small">{ev.data.masked_kinds.length > 0 && <span className="tag warn">민감값 가림: {ev.data.masked_kinds.join(", ")}</span>}{e.raw_has_bidi && <span className="tag bad">⚠ Bidi/제어문자 포함</span>}<span className="muted">{fmtTime(e.timestamp)} · 시각 품질 {e.timestamp_quality || "미기록"}</span></div>
            <div className="mono pre" style={{ background: "var(--bg)", padding: 8, borderRadius: 4 }}>{e.raw_visual}</div>
            {ev.data.can_unmask && !unmask.data && (
              <div className="row small"><input className="input grow" aria-label="민감값 열람 사유" placeholder="열람 사유 (감사 기록)" value={reason} onChange={(x) => setReason(x.target.value)} /><button className="btn sm" disabled={reason.trim().length < 5 || unmask.isPending} onClick={() => unmask.mutate()}>민감값 열람</button></div>
            )}
            {ev.data.can_unmask && unmask.data && <div className="col"><span className="tag warn">민감값 열람 중 · 감사 기록됨</span><div className="mono pre">{unmask.data.event.raw_event}</div><button className="btn sm" onClick={() => {unmask.reset();setReason("");}}>다시 가리기</button></div>}
            <ErrorBox error={unmask.error} />
          </div>
        )}
        {e && tab === "entities" && (
          <div className="row wrap">{ENT_FIELDS.filter(([f]) => e[f]).map(([f, t]) => <span key={f} className="row"><span className="muted small">{f}</span><EntityChip inv={inv} type={t} value={String(e[f])} external={f === "src_ip" && e.src_ip_scope === "external"} /></span>)}</div>
        )}
        {e && tab === "findings" && (ev.data.related_findings.length ? ev.data.related_findings.map((f: any) => (
          <div key={f.id} className="row"><Sev level={f.risk_level} /><a onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>{f.display_id} {f.title}</a></div>
        )) : <span className="muted">이 이벤트를 샘플 근거로 쓰는 Finding 없음</span>)}
        {e && tab === "checks" && (
          <div className="col" style={{ gap: 14 }}>
            <div className="muted small">열어 본 것만으로는 확인으로 남지 않습니다. 무엇을 확인했는지(요청 성격·성공 여부·피해 여부·정상 업무 여부)를 고르고, 판단은 할 수 있을 때만 남기세요.</div>
            <TargetChecks inv={inv} target={{ type: "event", key: e.event_id, label: `이 기록 · ${[e.method, e.uri || e.domain, e.status_code].filter((v: unknown) => v != null).join(" ") || e.event_type || e.data_source}`, time: [e.timestamp, e.timestamp], evidence: [e.event_id] }} />
            {ENT_FIELDS.filter(([f, t]) => e[f] && CHECK_TYPES.includes(t)).map(([f, t]) => (
              <TargetChecks key={f} inv={inv} compact target={{ type: "entity", key: `${t}:${t === "domain" ? String(e[f]).toLowerCase() : e[f]}`, label: `${f} ${e[f]}`, evidence: [e.event_id] }} />))}
          </div>
        )}
        {tab === "linked" && (linked.isLoading ? <Loading /> : linked.data ? (
          <div className="col">
            <div className="muted small">다른 원천에서 주소·포트 쌍이 ±5분 또는 출발지·요청 경로가 ±5초 안에 겹친 기록입니다. 동일한 세션·요청인지는 시각과 원문을 대조하세요.
              {linked.data.pcap_session ? <b> 연결 가능한 PCAP이 있습니다. 스트림·패킷을 열어 대조하세요.</b> : " 이 범위에 연결된 PCAP이 없습니다."}</div>
            {!linked.data.groups.length && <span className="muted">연결된 기록 없음</span>}
            {linked.data.groups.map((g: any) => (
              <div key={g.relation + g.data_source} className="col" style={{ gap: 4 }}>
                <div className="row small"><span className="tag">{g.relation === "same_session" ? "주소·포트 일치" : "출발지·경로 일치"}</span><b>{displayField("data_source",g.data_source)}</b><span className="muted">{g.count}건</span></div>
                <table className="t"><tbody>{g.events.map((x: any) => (
                  <tr key={x.event_id} style={{ cursor: "pointer" }} onClick={() => ctx.set({ eventId: x.event_id })}>
                    <td className="small" style={{ width: 170 }}>{fmtTime(x.timestamp)}</td>
                    <td className="mono small">{x.src_ip}{x.src_port != null ? `:${x.src_port}` : ""} → {x.dst_ip}{x.dst_port != null ? `:${x.dst_port}` : ""}</td>
                    <td className="mono small ellipsis" style={{ maxWidth: 420 }}>{[x.method, x.uri || x.domain, x.status_code].filter((v) => v != null).join(" ")}</td>
                    <td className="small muted">{x.source_file}</td></tr>))}</tbody></table>
              </div>))}
          </div>) : <ErrorBox error={linked.error} />)}
        {tab === "context" && (lines.isLoading ? <Loading /> : lines.data ? (
          <div className="mono small">{lines.data.lines.map((l: string, k: number) => (
            <div key={k} className="pre" style={k === lines.data.target_index ? { background: "var(--hl-bg)" } : undefined}><span className="muted">{lines.data.first_line_no + k} </span>{l}</div>
          ))}</div>) : <ErrorBox error={lines.error} />)}
      </div>
    </div>
  );
}


/** Follow-stream view: reassembled client/server payload (masked text, or hex for binary). Never rendered as HTML. */
function StreamModal({ inv, eventId, onClose }: { inv: string; eventId: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ["stream", inv, eventId], queryFn: () => api.get(`/investigations/${inv}/forensics/sessions/${eventId}/stream`) });
  const d = q.data;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="modal xl panel" role="dialog" aria-label="세션 스트림">
        <div className="ph"><span className="grow">세션 스트림 {d ? `${d.client} → ${d.server}` : ""}</span><button className="btn ghost sm" onClick={onClose}>닫기</button></div>
        <div className="pb col">
          {q.isLoading && <Loading />}
          <ErrorBox error={q.error} />
          {d && (
            <>
              <div className="row wrap small muted">
                <span>패킷 {d.packets}</span><span>클라이언트 {d.client_bytes.toLocaleString()} B</span><span>서버 {d.server_bytes.toLocaleString()} B</span>
                {d.missed_bytes > 0 && <span className="tag warn">누락 {d.missed_bytes.toLocaleString()} B</span>}
                {d.truncated && <span className="tag warn">표시 한도에서 잘림</span>}
                {[...d.client_view.masked, ...d.server_view.masked].length > 0 && <span className="tag">마스킹: {[...new Set([...d.client_view.masked, ...d.server_view.masked])].join(", ")}</span>}
              </div>
              <div className="grid2">
                <div><div className="small" style={{ color: "var(--low)", fontWeight: 700 }}>클라이언트 → 서버 ({d.client_view.mode === "hex" ? "HEX" : "텍스트"})</div>
                  <pre className="mono pre" style={{ background: "var(--bg)", padding: 10, borderRadius: 6, maxHeight: "56vh", overflow: "auto", borderLeft: "3px solid var(--low)" }}>{d.client_view.text || "(데이터 없음)"}</pre></div>
                <div><div className="small" style={{ color: "var(--high)", fontWeight: 700 }}>서버 → 클라이언트 ({d.server_view.mode === "hex" ? "HEX" : "텍스트"})</div>
                  <pre className="mono pre" style={{ background: "var(--bg)", padding: 10, borderRadius: 6, maxHeight: "56vh", overflow: "auto", borderLeft: "3px solid var(--high)" }}>{d.server_view.text || "(데이터 없음)"}</pre></div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
