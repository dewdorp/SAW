import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, Panel, Sev } from "../../components/common";
import { Badge, EmptyState, Icon, Stat } from "../../components/ui";
import { useInv } from "../../context/invContext";
import { api } from "../../lib/api";
import { fmtBytes, fmtNum, fmtTime } from "../../lib/format";
import { EChart, axisStyle, safeTooltip } from "../../viz/EChart";

const CAT_KO: Record<string, string> = {
  executable: "실행 파일", script: "스크립트", exploit_content: "익스플로잇 콘텐츠", archive: "압축 파일", document: "문서",
  image: "이미지", web: "웹 문서", text: "텍스트", unknown: "알 수 없음",
};
const OUT_KO: Record<string, string> = { success: "성공", failure: "실패", unknown: "확인 불가" };
type Sub = "overview" | "files" | "creds" | "certs" | "captures";

/** PCAP 포렌식 작업 공간: 요약 판단 → 탐지 → 추출 파일 → 평문 인증 → 캡처 정보 (Story → Evidence → Raw). */
export function ForensicsTab({ inv }: { inv: string }) {
  const [sub, setSub] = useState<Sub>("overview");
  const q = useQuery({ queryKey: ["forensics", inv], queryFn: () => api.get(`/investigations/${inv}/forensics/summary`) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d.captures.length) {
    return <EmptyState icon="network" title="PCAP 증거가 없습니다">PCAP/PCAPNG 파일을 증거로 추가하면 연결·DNS·HTTP·TLS, 전송 파일, 평문 인증을 자동 분석합니다.</EmptyState>;
  }
  const base = `/investigations/${inv}/forensics`;
  return (
    <div className="col" style={{ gap: 14 }}>
      <div className={`notice ${d.verdict.level}`}>
        <div className="row wrap">
          <Icon name={d.verdict.level === "low" ? "shield" : "alert"} />
          <b>{d.verdict.text}</b>
          <div className="grow" />
          <button className="btn sm" onClick={() => api.download(`${base}/report.html`, "saw-pcap-report.html")}><Icon name="report" size={15} /> 보고서 (HTML)</button>
          <button className="btn sm" onClick={() => api.download(`${base}/export/findings.csv`, "saw-findings.csv")}><Icon name="download" size={15} /> 탐지 CSV</button>
        </div>
      </div>
      <div className="stats">
        <Stat label="심각" value={d.severity.critical} tone="critical" />
        <Stat label="높음" value={d.severity.high} tone="high" />
        <Stat label="보통" value={d.severity.medium} tone="medium" />
        <Stat label="연결" value={fmtNum(d.counts.connections)} sub={`HTTP ${fmtNum(d.counts.http)} · DNS ${fmtNum(d.counts.dns)} · TLS ${fmtNum(d.counts.tls)}`} />
        <Stat label="추출 파일" value={fmtNum(d.counts.files)} sub={d.counts.masquerade ? `위장 의심 ${d.counts.masquerade}` : "위장 의심 없음"} tone={d.counts.masquerade ? "high" : undefined} onClick={() => setSub("files")} />
        <Stat label="평문 인증" value={fmtNum(d.counts.auth)} sub="비밀번호는 저장하지 않음" tone={d.counts.auth ? "medium" : undefined} onClick={() => setSub("creds")} />
      </div>
      <div className="tabs" role="tablist" style={{ borderRadius: 8 }}>
        {([["overview", "요약"], ["files", "추출 파일"], ["creds", "평문 인증"], ["certs", "TLS 인증서"], ["captures", "캡처 정보"]] as [Sub, string][]).map(([k, l]) => (
          <button key={k} role="tab" aria-selected={sub === k} className={sub === k ? "active" : ""} onClick={() => setSub(k)}>{l}</button>
        ))}
      </div>
      {sub === "overview" && <Overview d={d} inv={inv} />}
      {sub === "files" && <Files inv={inv} />}
      {sub === "creds" && <Creds inv={inv} />}
      {sub === "certs" && <Certs inv={inv} />}
      {sub === "captures" && <Captures d={d} />}
    </div>
  );
}

function Overview({ d, inv }: { d: any; inv: string }) {
  const ctx = useInv(inv);
  const buckets = d.traffic?.buckets || [];
  return (
    <div className="grid2" style={{ alignItems: "start" }}>
      <Panel title="네트워크 탐지 (위험도 순)">
        {d.findings.length ? d.findings.slice(0, 14).map((f: any) => (
          <div key={f.id} className="row" style={{ padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
            <Sev level={f.risk_level} />
            <a className="grow ellipsis" onClick={() => ctx.set({ tab: "findings", findingId: f.id })}>{f.title}</a>
            <span className="muted small">{fmtTime(f.time_start)}</span>
          </div>
        )) : <span className="muted">탐지 없음</span>}
      </Panel>
      <div className="col">
        <Panel title="시간대별 연결">
          {buckets.length ? (
            <EChart ariaLabel="시간대별 연결 수" height={170} option={{
              grid: { left: 40, right: 10, top: 10, bottom: 24 },
              xAxis: { type: "category", data: buckets.map((b: any) => fmtTime(b.key, false)), ...axisStyle },
              yAxis: { type: "value", ...axisStyle },
              tooltip: { trigger: "axis", formatter: safeTooltip((p) => [[p.name, p.value]]) },
              series: [{ type: "bar", data: buckets.map((b: any) => b.count), itemStyle: { color: "#69bfb5" } }],
            }} />
          ) : <span className="muted">데이터 없음</span>}
        </Panel>
        <Panel title="파일 유형">
          <div className="row wrap">
            {(d.file_categories || []).map((b: any) => <Badge key={b.key} tone={["executable", "script", "exploit_content"].includes(b.key) ? "bad" : undefined}>{CAT_KO[b.key] || b.key} {b.count}</Badge>)}
            {!d.file_categories?.length && <span className="muted">추출 파일 없음</span>}
          </div>
        </Panel>
        <Panel title="상위 통신 IP (바이트)">
          {(d.captures[0]?.summary?.top_talkers || []).slice(0, 8).map((t: any) => (
            <div key={t.ip} className="row small"><span className="mono grow">{t.ip}</span><span className="num">{fmtBytes(t.bytes)}</span></div>
          ))}
        </Panel>
      </div>
    </div>
  );
}

function Files({ inv }: { inv: string }) {
  const [only, setOnly] = useState(true);
  const q = useQuery({ queryKey: ["forensics-files", inv], queryFn: () => api.get(`/investigations/${inv}/forensics/files`) });
  const dl = useMutation({ mutationFn: (f: any) => api.download(`/investigations/${inv}/forensics/files/${f.sha256}/download`, f.sha256) });
  if (q.isLoading) return <Loading />;
  const rows = (q.data || []).filter((f: any) => !only || f.risky);
  return (
    <Panel title={`추출 파일 ${rows.length}건`} right={
      <div className="row">
        <label className="row small"><input type="checkbox" checked={only} onChange={(e) => setOnly(e.target.checked)} /> 위험 유형만</label>
        <button className="btn sm" onClick={() => api.download(`/investigations/${inv}/forensics/export/files.csv`, "saw-files.csv")}><Icon name="download" size={14} /> CSV</button>
      </div>}>
      <div className="notice small" style={{ marginBottom: 10 }}>
        파일은 실행하거나 화면에 표시하지 않습니다. 다운로드 시 위험 유형에는 <span className="mono">.infected</span> 확장자가 붙고 감사 로그에 기록됩니다. 해시로 내부 위협 정보를 조회하세요.
      </div>
      <ErrorBox error={dl.error} />
      <div className="scroll">
        <table className="t">
          <thead><tr><th>시각</th><th>파일명</th><th>실제 형식</th><th>선언 형식</th><th>크기</th><th>엔트로피</th><th>SHA-256</th><th>송신 → 수신</th><th /></tr></thead>
          <tbody>{rows.map((f: any) => (
            <tr key={f.event_id}>
              <td className="small">{fmtTime(f.timestamp)}</td>
              <td className="ellipsis" style={{ maxWidth: 200 }} title={f.http_uri || ""}>{f.filename || <span className="muted">(이름 없음)</span>} <span className="muted small">{f.source === "FTP_DATA" ? "FTP" : f.direction === "upload" ? "업로드" : ""}</span></td>
              <td>{f.masquerade ? <Badge tone="bad">위장 · {f.kind}</Badge> : <Badge tone={["executable", "script", "exploit_content"].includes(f.category) ? "warn" : undefined}>{CAT_KO[f.category] || f.category} · {f.kind}</Badge>}</td>
              <td className="small muted">{f.declared_type || "—"}</td>
              <td className="num">{fmtBytes(f.size)}</td>
              <td className="num" style={{ color: f.entropy >= 7.5 ? "var(--med)" : undefined }}>{f.entropy?.toFixed(2)}</td>
              <td className="mono small ellipsis" style={{ maxWidth: 140 }} title={`MD5 ${f.md5}\nSHA1 ${f.sha1}\nSHA256 ${f.sha256}`}>{f.sha256}</td>
              <td className="mono small">{f.tx} → {f.rx}</td>
              <td>{f.extracted && <button className="btn ghost sm" title="파일 다운로드 (감사 기록)" onClick={() => dl.mutate(f)}><Icon name="download" size={14} /></button>}</td>
            </tr>
          ))}</tbody>
        </table>
        {!rows.length && <EmptyState icon="file" title="해당 파일 없음" />}
      </div>
    </Panel>
  );
}

function Creds({ inv }: { inv: string }) {
  const q = useQuery({ queryKey: ["forensics-creds", inv], queryFn: () => api.get(`/investigations/${inv}/forensics/credentials`) });
  if (q.isLoading) return <Loading />;
  const rows = q.data || [];
  return (
    <Panel title={`평문 인증 ${rows.length}건`} right={<button className="btn sm" onClick={() => api.download(`/investigations/${inv}/forensics/export/credentials.csv`, "saw-credentials.csv")}><Icon name="download" size={14} /> CSV</button>}>
      <div className="notice small" style={{ marginBottom: 10 }}><Icon name="lock" size={14} /> SAW는 비밀번호를 저장하지 않습니다. 길이와 취약 여부(기본·흔한 비밀번호, 계정명과 동일)만 기록합니다.</div>
      <table className="t">
        <thead><tr><th>시각</th><th>프로토콜</th><th>계정</th><th>결과</th><th>출발지</th><th>목적지</th><th>비밀번호</th></tr></thead>
        <tbody>{rows.map((c: any) => (
          <tr key={c.event_id}>
            <td className="small">{fmtTime(c.timestamp)}</td><td><Badge>{c.protocol}</Badge></td><td className="mono">{c.user || "—"}</td>
            <td><Badge tone={c.outcome === "success" ? "bad" : c.outcome === "failure" ? undefined : "warn"}>{OUT_KO[c.outcome] || c.outcome}</Badge></td>
            <td className="mono small">{c.src_ip}</td><td className="mono small">{c.dst_ip}:{c.dst_port}</td>
            <td className="small">{c.password_weak ? <Badge tone="bad">취약</Badge> : <span className="muted">{c.password_length}자</span>}{c.password_equals_user ? <span className="muted"> · 계정명과 동일</span> : null}</td>
          </tr>
        ))}</tbody>
      </table>
      {!rows.length && <EmptyState icon="lock" title="평문 인증이 관측되지 않았습니다" />}
    </Panel>
  );
}

function Captures({ d }: { d: any }) {
  return (
    <div className="col">
      {d.captures.map((c: any) => {
        const s = c.summary || {};
        return (
          <Panel key={c.file_id} title={c.name} right={<Badge tone="accent">{c.engine}</Badge>}>
            <div className="stats" style={{ marginBottom: 8 }}>
              <Stat label="패킷" value={fmtNum(s.packets)} sub={`해석 ${fmtNum(s.decoded)} · 해석 불가 ${fmtNum(s.undecoded)}`} />
              <Stat label="중복 프레임 제외" value={fmtNum(s.duplicates)} sub="SPAN 이중 수집" />
              <Stat label="IP 바이트" value={fmtBytes(s.ip_bytes)} />
              <Stat label="추출 파일" value={fmtNum(s.files_extracted)} sub={fmtBytes(s.extracted_bytes)} />
            </div>
            <div className="small muted">기간 {s.first_ts ? fmtTime(s.first_ts) : "—"} ~ {s.last_ts ? fmtTime(s.last_ts) : "—"} · SHA-256 <span className="mono">{c.sha256}</span></div>
            <div className="row wrap small" style={{ marginTop: 8 }}>{Object.entries(s.services || {}).map(([k, v]) => <Badge key={k}>{k} {String(v)}</Badge>)}</div>
            {c.note && <div className="small muted" style={{ marginTop: 6 }}>{c.note}</div>}
          </Panel>
        );
      })}
    </div>
  );
}

/** Server certificates (TLS <= 1.2 sends them in clear): external first, anomalies highlighted. */
function Certs({ inv }: { inv: string }) {
  const q = useQuery({ queryKey: ["forensics-certs", inv], queryFn: () => api.get(`/investigations/${inv}/forensics/certificates`) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows: any[] = q.data.certificates;
  return (
    <Panel title={`TLS 인증서 ${rows.length}종`} right={<span className="muted small">TLS 세션 {fmtNum(q.data.tls_sessions)} · 인증서 확인 {fmtNum(q.data.with_certificate)} (TLS 1.3은 인증서가 암호화되어 보이지 않음)</span>}>
      {!rows.length ? <EmptyState icon="lock" title="평문으로 오간 서버 인증서가 없습니다">TLS 1.2 이하 세션의 인증서만 볼 수 있습니다.</EmptyState> : (
        <div style={{ overflowX: "auto" }}>
          <table className="t"><thead><tr><th>목적지</th><th>요청한 서버 이름</th><th>인증서 이름(CN)</th><th>발급자</th><th>유효 기간</th><th>이상 징후</th><th className="num">세션</th><th>SHA-1 지문</th></tr></thead>
            <tbody>{rows.map((r) => {
              const flags = [r.self_signed && "자체 서명", r.name_mismatch && "이름 불일치", r.expired_at_use && "만료 후 사용", r.key.startsWith("rsa-") && Number(r.key.split("-")[1]) < 2048 && "약한 키"].filter(Boolean) as string[];
              return (
                <tr key={r.dst_ip + r.sha1}>
                  <td className="mono small">{r.dst_ip}:{r.dst_port}{!r.external && <span className="muted"> (내부)</span>}</td>
                  <td className="small">{r.server_names.join(", ") || <span className="muted">없음</span>}</td>
                  <td className="small">{r.subject_cn}</td><td className="small">{r.issuer_cn}</td>
                  <td className="small">{String(r.not_before).slice(0, 10)} ~ {String(r.not_after).slice(0, 10)}</td>
                  <td>{flags.length ? flags.map((f) => <Badge key={f} tone={r.external ? "bad" : "warn"}>{f}</Badge>) : <span className="muted small">없음</span>}</td>
                  <td className="num">{fmtNum(r.sessions)}</td><td className="mono small" title={r.sha256}>{r.sha1}</td>
                </tr>);
            })}</tbody></table>
        </div>)}
    </Panel>
  );
}
