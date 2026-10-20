import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Empty, ErrorBox, Loading, Panel } from "../components/common";
import { api } from "../lib/api";
import { fmtNum, fmtTime } from "../lib/format";

type Signature = {
  id: string; title: string; group: string; group_title: string; stage: string; severity: number;
  confidence: string; attack: string[]; cve: string; where: string; success: string;
  explain: string; checks: string[]; examples: (string | Record<string, unknown>)[];
  enabled: boolean; note: string; updated_by: string; updated_at: string | null;
};
type Detector = { id: string; title: string; stage: string; data_sources: string[] };
type Scenario = {
  id: string; title: string; severity: number; attack: string[]; explain: string; checks: string[];
  steps: { name: string; stages: string[]; categories: string[]; success: boolean }[];
  max_span_seconds?: number; entity_role?: "any" | "source"; strict_order?: boolean;
};
type NetworkRule = {
  id: string; kind: string; enabled: boolean; title: string; stage: string; severity: number; attack: string[];
  window_seconds: number; min_connections: number; min_bytes?: number; explain: string; checks: string[];
  site: { internal_cidrs: string[]; home_countries: string[]; allowed_ports: number[]; baseline_note: string;
    admin_ports: number[]; timezone: string; work_start_hour: number; work_end_hour: number; work_days: number[] };
  limits: { max_events: number; max_groups: number; max_findings: number; max_samples: number };
};
type Catalog = { signatures: Signature[]; detectors: Detector[]; scenarios: Scenario[]; can_switch: boolean; network_rules?: NetworkRule[] };
type Kind = "signatures" | "detectors" | "scenarios" | "network";



const FIELDS: Record<string, string> = {
  ua: "사용자 에이전트", path: "요청 경로", query: "쿼리 문자열", uri: "요청 주소",
  referer: "참조 주소", upload: "업로드 파일 이름", any: "요청 주소·사용자 에이전트·참조 주소",
};
const RESPONSES: Record<string, string> = {
  only: "HTTP 2xx 응답이 있을 때 탐지", matters: "HTTP 2xx 응답 유무를 구분", ignore: "응답 상태와 관계없이 관찰",
};
const STAGES: Record<string, string> = {
  RECONNAISSANCE: "정찰", WEAPONIZATION: "공격 준비", DELIVERY: "전달", EXPLOITATION: "취약점 악용",
  INSTALLATION: "설치", COMMAND_AND_CONTROL: "명령·제어", ACTIONS_ON_OBJECTIVES: "목표 수행",
  DISCOVERY: "탐색", LATERAL: "내부 이동", OUTBOUND: "외부 전송",
  RECON: "정찰", EXECUTION: "명령 실행", PERSISTENCE: "지속성 확보", DATA_ACCESS: "자료 접근", AUTHENTICATION: "인증",
};
const stageName = (stage: string) => STAGES[stage] || stage;
const EMPTY = "조건에 맞는 기본 탐지가 없습니다.";

function AttackTags({ values }: { values: string[] }) {
  return values.length ? <span className="row wrap">{values.map((value) => <span className="tag mono" key={value}>{value}</span>)}</span> : <span className="muted">연결된 기술 없음</span>;
}

export function DetectionCatalog() {
  const catalog = useQuery({ queryKey: ["detection-catalog"], queryFn: () => api.get<Catalog>("/detection-catalog") });
  const exportFile = useMutation({ mutationFn: (format: "json" | "yaml") => api.download(`/detection-catalog/export?format=${format}`, `saw-detection-catalog.${format}`) });
  const [kind, setKind] = useState<Kind>("signatures");
  const [search, setSearch] = useState("");
  const [group, setGroup] = useState("");
  const [state, setState] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  if (catalog.isLoading) return <Loading label="기본 탐지 목록을 불러오는 중…" />;
  if (catalog.error) return <ErrorBox error={catalog.error} />;
  if (!catalog.data) return <Empty>기본 탐지 목록이 없습니다.</Empty>;
  const data = catalog.data;
  const needle = search.trim().toLocaleLowerCase();
  const matches = (...values: (string | string[])[]) => values.flat().join(" ").toLocaleLowerCase().includes(needle);
  const signatures = data.signatures.filter((s) => (!group || s.group === group)
    && (!state || s.enabled === (state === "enabled"))
    && matches(s.id, s.title, s.group, s.group_title, s.explain, s.cve, s.attack, s.checks));
  const detectors = data.detectors.filter((d) => matches(d.id, d.title, d.stage, stageName(d.stage), d.data_sources));
  const scenarios = data.scenarios.filter((s) => matches(s.id, s.title, s.explain, s.attack, s.checks, s.steps.map((step) => step.name)));
  const network = (data.network_rules || []).filter((rule) => matches(rule.id, rule.title, rule.kind, rule.explain, rule.attack, rule.checks, rule.site.baseline_note));
  const current = signatures.find((s) => s.id === selected);
  const groups = [...new Map(data.signatures.map((s) => [s.group, s.group_title])).entries()];
  const tabs: [Kind, string, number][] = [
    ["signatures", "시그니처", data.signatures.length], ["detectors", "기본 탐지기", data.detectors.length],
    ["scenarios", "공격 흐름", data.scenarios.length], ["network", "NDR 연결 정책", data.network_rules?.length || 0],
  ];

  return (
    <div className="col">
      <Panel title="기본 탐지 목록">
        <div className="col small">
          <div>플랫폼에 포함된 탐지 조건과 확인 방법입니다. ATT&amp;CK 표시는 규칙의 관련 기술이며 실제 공격 여부는 조사 근거로 판단합니다.</div>
          <div>HTTP 2xx 응답만으로 공격 성공을 확정할 수 없습니다. 차단된 공격 시도도 차단 여부만으로 오탐으로 분류하지 않습니다.</div>
          <div className="muted">시그니처 사용 여부는 범위별 정책의 초안·선택 시험·독립 승인·SAW 적용으로 변경합니다. 기존 결과를 갱신하려면 재분석하고, 새 규칙의 태그가 없는 기존 자료는 증거를 다시 처리해야 합니다.</div>
        </div>
      </Panel>
      <Panel title="룰 내보내기">
        <div className="row wrap"><button className="btn sm" disabled={exportFile.isPending} onClick={() => exportFile.mutate("json")}>전체 기본 룰 JSON 다운로드</button>
          <button className="btn sm" disabled={exportFile.isPending} onClick={() => exportFile.mutate("yaml")}>전체 기본 룰 YAML 다운로드</button></div>
        <p className="small muted">검색 필터와 관계없이 전체 기본 목록을 받습니다. 실제 일치 조건·정상 예제·현재 설정을 포함하며 코드 탐지기는 ID·버전 설명만 포함합니다.</p>
        <ErrorBox error={exportFile.error} />
      </Panel>
      <div className="row wrap" aria-label="기본 탐지 종류">
        {tabs.map(([value, label, count]) => <button key={value} className={`btn sm ${kind === value ? "primary" : ""}`}
          aria-pressed={kind === value} onClick={() => { setKind(value); setSelected(null); }}>{label} ({count})</button>)}
      </div>
      <div className="row wrap">
        <label className="col small grow">기본 탐지 검색
          <input className="input" type="search" placeholder="이름, ID, 설명, CVE, ATT&CK" value={search}
            onChange={(event) => { setSearch(event.target.value); setSelected(null); }} />
        </label>
        {kind === "signatures" && <>
          <label className="col small">시그니처 묶음
            <select className="input" value={group} onChange={(event) => { setGroup(event.target.value); setSelected(null); }}>
              <option value="">모든 묶음</option>{groups.map(([id, title]) => <option key={id} value={id}>{title}</option>)}
            </select>
          </label>
          <label className="col small">시그니처 상태
            <select className="input" value={state} onChange={(event) => { setState(event.target.value); setSelected(null); }}>
              <option value="">모든 상태</option><option value="enabled">켜짐</option><option value="disabled">꺼짐</option>
            </select>
          </label>
        </>}
      </div>
      {kind === "signatures" && <>
        <div className="small muted" role="status">{signatures.length}개 표시 · 전체 {data.signatures.length}개</div>
        {!data.can_switch && <div className="small muted">조회만 가능합니다. 켜기·끄기는 탐지 승인 권한이 필요합니다.</div>}
        {signatures.length ? <div style={{ overflow: "auto", maxHeight: "45vh" }}>
          <table className="t"><thead><tr><th>규칙</th><th>묶음</th><th>상태</th><th>ATT&amp;CK</th></tr></thead>
            <tbody>{signatures.map((s) => <tr key={s.id}>
              <td><button className="btn ghost sm" aria-label={`규칙 보기: ${s.title}`} aria-pressed={selected === s.id}
                onClick={() => setSelected(s.id)}>{s.title}</button><div className="mono small muted">{s.id}</div></td>
              <td>{s.group_title}</td><td><span className={`tag ${s.enabled ? "ok" : ""}`}>{s.enabled ? "켜짐" : "꺼짐"}</span></td>
              <td><AttackTags values={s.attack} /></td>
            </tr>)}</tbody>
          </table>
        </div> : <Empty>{EMPTY}</Empty>}
        {current && <SignatureDetail key={current.id} signature={current} canSwitch={data.can_switch} onClose={() => setSelected(null)} />}
      </>}
      {kind === "detectors" && (detectors.length ? <div style={{ overflowX: "auto" }}>
        <table className="t"><thead><tr><th>기본 탐지기</th><th>ID</th><th>단계</th><th>자료 종류</th></tr></thead>
          <tbody>{detectors.map((d) => <tr key={d.id}><td>{d.title}</td><td className="mono">{d.id}</td>
            <td>{stageName(d.stage)}</td><td>{d.data_sources.join(", ") || "자료 종류 미등록"}</td></tr>)}</tbody>
        </table>
      </div> : <Empty>{EMPTY}</Empty>)}
      {kind === "network" && <>
        <Panel title="NDR 연결 정책 설정">
          <div className="col small">
            <div>조직마다 다른 내부망·허용 포트·업무시간 기준을 사용하는 정책입니다. 기본 제공 기준은 예시이므로 조직의 승인된 기준을 검토한 뒤 사용하세요.</div>
            <div>아래 YAML 기준은 기존 기준의 참조 정보입니다. <Link to="/detections/policies/ndr.observation">NDR 관측 정책 변경</Link>에서 지원 명세와 현재 범위별 적용값을 검토하세요.</div>
            <div className="muted">각 시간 구간은 UTC 기준으로 고정됩니다. 경계에 걸친 연결은 서로 다른 구간에 집계될 수 있습니다.</div>
          </div>
        </Panel>
        {network.length ? network.map((rule) => <NetworkPolicy key={rule.id} rule={rule} />) : <Empty>{EMPTY}</Empty>}
      </>}
      {kind === "scenarios" && (scenarios.length ? scenarios.map((s) => <Panel key={s.id} title={s.title}>
        <div className="col small">
          <div className="mono muted">{s.id}</div><div style={{ whiteSpace: "pre-wrap" }}>{s.explain}</div>
          <AttackTags values={s.attack} />
          {s.max_span_seconds !== undefined && <div>최대 연결 구간: {s.max_span_seconds}초</div>}
          <ol>{s.steps.map((step, index) => <li key={index}>
            <b>{step.name}</b>
            <div className="muted">{[...step.stages.map(stageName), ...step.categories].join(" · ")}</div>
            {step.success && <div>성공 신호 필요 · 개별 탐지 근거 확인</div>}
          </li>)}</ol>
          {s.checks.length > 0 && <div><b>확인 권고</b><ul>{s.checks.map((line, index) => <li key={index}>{line}</li>)}</ul></div>}
        </div>
      </Panel>) : <Empty>{EMPTY}</Empty>)}
    </div>
  );
}

function SignatureDetail({ signature, canSwitch, onClose }: { signature: Signature; canSwitch: boolean; onClose: () => void }) {



  const detailRef = useRef<HTMLElement>(null);
  useEffect(() => {
    detailRef.current?.focus({ preventScroll: true });
    detailRef.current?.scrollIntoView?.({ block: "start" });
  }, []);
  return (
    <section ref={detailRef} tabIndex={-1} aria-label="시그니처 상세">
      <Panel title={signature.title} right={<button className="btn ghost sm" onClick={onClose}>상세 닫기</button>}>
        <div className="col small">
          <div className="mono muted">{signature.id}</div>
          <div>{signature.group_title} · {stageName(signature.stage)} · {FIELDS[signature.where] || signature.where}</div>
          <div>{RESPONSES[signature.success] || signature.success}</div>
          {signature.cve && <div className="mono">{signature.cve}</div>}
          <AttackTags values={signature.attack} />
          <div style={{ whiteSpace: "pre-wrap" }}>{signature.explain || "등록된 설명이 없습니다."}</div>
          {signature.checks.length > 0 && <div><b>확인 권고</b><ul>{signature.checks.map((line, index) => <li key={index}>{line}</li>)}</ul></div>}
          <div><b>규칙 예시</b><div className="muted">규칙 설명을 위한 예시이며 실제 조사 자료가 아닙니다.</div>
            {signature.examples.length ? signature.examples.map((example, index) => <pre className="mono small" key={index}
              style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{typeof example === "string" ? example : JSON.stringify(example, null, 2)}</pre>)
              : <div className="muted">등록된 예시가 없습니다.</div>}
          </div>
          <div><b>현재 설정: {signature.enabled ? "켜짐" : "꺼짐"}</b>
            <div className="muted">{signature.updated_by ? `${signature.updated_by} · ${fmtTime(signature.updated_at)}` : "변경 기록 없음"}</div>
            {signature.note && <div style={{ whiteSpace: "pre-wrap" }}>{signature.note}</div>}
          </div>
          <div className="small muted">초안·선택 시험·독립 승인·SAW 적용으로 사용 여부를 변경합니다. 현재 표시값은 기존 공통 설정이며 범위별 유효 설정은 정책 화면에서 확인하세요.</div>
          <Link to={`/detections/policies/${encodeURIComponent(`signature:${signature.id}`)}`}>{canSwitch ? "설정 변경" : "정책·명세 보기"}</Link>
        </div>
      </Panel>
    </section>
  );
}

function NetworkPolicy({ rule }: { rule: NetworkRule }) {
  const days = ["월", "화", "수", "목", "금", "토", "일"];
  const list = (values: (string | number)[]) => values.join(", ") || "미설정";
  return <Panel title={rule.title} right={<span className={`tag ${rule.enabled ? "ok" : ""}`}>{rule.enabled ? "켜짐" : "꺼짐"}</span>}>
    <div className="col small">
      <div className="mono muted">{rule.id}</div>
      <div style={{ whiteSpace: "pre-wrap" }}>{rule.explain}</div>
      <AttackTags values={rule.attack} />
      <div>집계 구간: {rule.window_seconds}초 · 최소 연결 수: {fmtNum(rule.min_connections)}
        {rule.min_bytes !== undefined && ` · 최소 송신량: ${fmtNum(rule.min_bytes)}바이트`}</div>
      <dl>
        <dt>내부망 범위</dt><dd className="mono">{list(rule.site.internal_cidrs)}</dd>
        <dt>기준 국가</dt><dd>{list(rule.site.home_countries)}</dd>
        <dt>허용 포트</dt><dd>{list(rule.site.allowed_ports)}</dd>
        <dt>정상 기준 설명</dt><dd>{rule.site.baseline_note || "미설정"}</dd>
        <dt>관리 포트</dt><dd>{list(rule.site.admin_ports)}</dd>
        <dt>업무시간</dt><dd>{rule.site.timezone} · {rule.site.work_start_hour}시 이상 ~ {rule.site.work_end_hour}시 미만 · {rule.site.work_days.map((day) => days[day] ?? String(day)).join("·") || "요일 미설정"}</dd>
      </dl>
      {rule.checks.length > 0 && <div><b>확인 권고</b><ul>{rule.checks.map((line, index) => <li key={index}>{line}</li>)}</ul></div>}
      <details><summary>검사 범위 상한</summary><div className="muted">
        최대 이벤트 {fmtNum(rule.limits.max_events)}개 · 묶음 {fmtNum(rule.limits.max_groups)}개 · 탐지 결과 {fmtNum(rule.limits.max_findings)}개 · 예시 {fmtNum(rule.limits.max_samples)}개.
        상한에 도달한 결과는 검사한 범위를 함께 확인해야 합니다.
      </div></details>
    </div>
  </Panel>;
}
