import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ErrorBox, Loading } from "../../components/common";
import { PageHeader } from "../../components/ui";
import { UploadModal } from "../../components/UploadModal";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";
import "./hunt.css";

const BUCKETS: [string, string, string][] = [["running", "진행 중", "자료 처리·분석이 실행 중인 헌팅"], ["review", "확인 필요", "미검토 활동이나 추가 확인이 남았거나 아직 분석하지 않은 헌팅"],
  ["review_done", "검토 끝", "모든 활동을 검토했지만 아직 종결하지 않은 헌팅"], ["done", "완료", "종결한 헌팅"]];
const SOURCE_KO: Record<string, string> = { web: "NDR HTTP", connection: "FW·연결", firewall: "방화벽", waf: "WAF", ips: "IPS", ddos: "DDoS", app: "애플리케이션" };

/** Where an analyst starts: every hunt in one list, and a new hunt needs only an affiliate and the data. */
export function Hunts() {
  const q = useQuery({ queryKey: ["hunts"], queryFn: () => api.get("/hunts"), refetchInterval: 15000 });
  const [bucket, setBucket] = useState("all");
  const [text, setText] = useState("");
  const [creating, setCreating] = useState(false);
  const items: any[] = (q.data?.items || []).filter((i: any) => (bucket === "all" || i.bucket === bucket)
    && `${i.display_id} ${i.title} ${i.org_unit}`.toLowerCase().includes(text.trim().toLowerCase()));
  return <div className="page col">
    <PageHeader eyebrow="헌팅" title="헌팅" desc="관계사와 자료를 고르면 먼저 확인할 활동을 찾아 줍니다. 의심 IP·가설·시나리오를 미리 정하지 않아도 됩니다."
      actions={<><Link className="btn" to="/criteria">분석 기준</Link><button className="btn primary" onClick={() => setCreating(true)}>새 헌팅</button></>} />
    <div className="row wrap hunts-filters" role="group" aria-label="상태로 걸러 보기">
      <button className={`btn sm ${bucket === "all" ? "primary" : ""}`} aria-pressed={bucket === "all"} onClick={() => setBucket("all")}>전체 {q.data?.items?.length ?? 0}</button>
      {BUCKETS.map(([k, l, hint]) => <button key={k} title={hint} className={`btn sm ${bucket === k ? "primary" : ""}`} aria-pressed={bucket === k} onClick={() => setBucket(k)}>{l} {q.data?.buckets?.[k] ?? 0}</button>)}
      <input className="input" type="search" aria-label="헌팅 찾기" placeholder="제목·관계사·번호" value={text} onChange={e => setText(e.target.value)} />
    </div>
    {q.isLoading && <Loading />}<ErrorBox error={q.error} />
    {!q.isLoading && !items.length && <p>{q.data?.items?.length ? "이 조건의 헌팅이 없습니다." : "아직 헌팅이 없습니다. \"새 헌팅\"에서 관계사와 로그 파일을 고르세요."}</p>}
    {items.length > 0 && <div className="fk-table"><table className="t hunts-table"><thead><tr><th>헌팅</th><th>관계사</th><th>진행</th><th>자료</th><th>확인할 활동</th><th>분석가 검토</th><th>만든 날</th></tr></thead>
      <tbody>{items.map(i => <tr key={i.id}>
        <td><Link to={`/inv/${i.id}?tab=activities`}><b>{i.title}</b></Link><div className="small muted">{i.display_id}</div></td>
        <td>{i.org_unit || <span className="tag warn">미지정</span>}</td>
        <td><span className={`tag ${i.progress.state === "failed" ? "bad" : i.progress.state === "running" ? "warn" : ""}`}>{i.status === "closed" ? "종결" : i.progress.label}</span></td>
        <td className="small">{i.run ? <>{(i.run.records ?? 0).toLocaleString()}건<div className="muted">{Object.entries(i.run.by_source || {}).map(([k, v]) => `${SOURCE_KO[k] || k} ${(v as number).toLocaleString()}`).join(" · ")}</div></> : <span className="muted">분석 전</span>}</td>
        <td className="small">{i.run ? <>{i.activities}개{i.run.status !== "complete" && <span className="tag warn">{i.run.status === "partial" ? "일부 처리" : "실행 실패"}</span>}</> : "—"}</td>
        <td className="small">{i.run ? <>미검토 <b>{i.unreviewed}</b> · 추가 확인 {i.needs_check}{i.threat_confirmed > 0 && <span className="tag bad">위협 확인 {i.threat_confirmed}</span>}</> : "—"}</td>
        <td className="small nowrap">{fmtTime(i.created_at)}</td></tr>)}</tbody></table></div>}
    {creating && <UploadModal kind="auto" hunt onClose={() => { setCreating(false); q.refetch(); }} />}
  </div>;
}

/** Tools and administration that an analyst does not need on every hunt, in one place. Nothing was removed. */
export function Settings({ permissions }: { permissions: string[] }) {
  const admin = permissions.includes("admin.users") || permissions.includes("audit.read");
  const groups: [string, string, [string, string][]][] = [
    ["분석 도구", "헌팅 작업대에서 펼쳐 쓰는 보조 도구입니다.", [["/criteria", "분석 기준(헌팅이 찾는 것과 기준 값)"], ["/analyze", "붙여넣기 분석(HTTP·페이로드·IOC·비교)"], ["/hunting", "수동 질의(가설 기반 조회)"], ["/cases", "사건 묶음(여러 헌팅에 걸친 사건)"], ["/jobs", "작업 상태"], ["/provenance", "처리 기록"]]],
    ["지식·사전", "분석에 쓰이는 사전과 과거 경험입니다.", [["/knowledge/flows", "업무 의미·흐름 이력"], ["/registry", "관계사·장비 공격명 사전"], ["/knowledge", "SOC 경험·유사 사례·오탐 규칙"], ["/casebook", "분석 사례집(C·W·F 사례)"]]],
    ["평가 자료(전문가)", "골든셋과 반출은 평가 담당이 씁니다.", [["/golden-candidates", "골든셋 후보함"], ["/knowledge/golden", "정답 사례·반출 패키지"], ["/detections", "탐지 룰"]]],
    ["관리자", "설치·운영 설정입니다.", [["/parsers", "파서 관리"], ["/content-packages", "오프라인 룰·파서 반입"], ...(permissions.includes("ai.models.manage") ? [["/admin/local-models", "로컬 모델"] as [string, string]] : []), ...(admin ? [["/admin", "사용자·권한·감사"] as [string, string], ["/admin/data", "자료 삭제"] as [string, string]] : [])]],
    ["이전 화면", "새 메뉴로 통합되기 전의 화면입니다. 자료는 그대로이며 주소도 계속 열립니다.", [["/home", "이전 홈"], ["/investigations", "조사 목록"], ["/board", "현황판"]]],
  ];
  return <div className="page col"><PageHeader eyebrow="설정" title="도구·설정" desc="주 메뉴는 헌팅 / 시나리오 / 자산·업무입니다. 그 밖의 도구와 관리 기능은 여기에 모았습니다." />
    <div className="settings-grid">{groups.map(([title, hint, links]) => <section key={title} className="panel"><div className="ph">{title}</div><div className="pb">
      <p className="small muted">{hint}</p>{links.map(([to, label]) => <Link key={to} to={to}>{label}</Link>)}</div></section>)}</div></div>;
}
