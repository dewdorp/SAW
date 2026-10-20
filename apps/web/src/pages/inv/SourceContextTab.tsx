import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading } from "../../components/common";
import { api } from "../../lib/api";
import { fmtTime } from "../../lib/format";

const COUNTER_MODES = [["unknown", "미확인"], ["cumulative", "누적"], ["delta", "구간 변화량"], ["total", "완료 합계"]];
const PRECISION_LABELS: Record<string, string> = { s: "초", second: "초", seconds: "초", ms: "밀리초", millisecond: "밀리초", milliseconds: "밀리초", us: "마이크로초", microsecond: "마이크로초", microseconds: "마이크로초", ns: "나노초", nanosecond: "나노초", nanoseconds: "나노초", subseconds: "초 미만" };
const PRECISION_CHOICES = [["unknown", "미확인"], ["seconds", "초"], ["milliseconds", "밀리초"], ["microseconds", "마이크로초"], ["nanoseconds", "나노초"]];
const SOURCE_FIELDS = [["timestamp", "시각"], ["session_id", "세션 ID"], ["record_kind", "기록 종류"], ["action", "행위"], ["src_bytes", "출발지 바이트"], ["dst_bytes", "목적지 바이트"], ["duration", "지속시간"]];
const blankProfile = () => ({ owner_org_unit_id: null, operator_org_unit_id: null, vendor: "", product: "", product_version: "", functions: ["FW"], network: "", virtual_domain: "", observation_point: "", collection_path: "", source_fields: {}, record_kind_map: {}, action_map: {}, action_verified: false, action_basis: "", measurement_profile: { counter_semantics: "unknown", direction: "unknown", unit: "unknown", duration_unit: "unknown", verified: false, basis: "" }, time: { role: "unknown", timezone: null, precision: "unknown", verified: false, basis: "" } });

function FrozenContext({ evidence, orgs, devices }: { evidence: any; orgs: any[]; devices: any[] }) {
  const q = useQuery({ queryKey: ["evidence-context", evidence.id], queryFn: () => api.get(`/source-context/evidence/${evidence.id}/context`) });
  const snapshot = q.data?.snapshot || {};
  const observer = snapshot.observer || {};
  const profile = snapshot.profile || {};
  const subject = snapshot.subject || {};
  const collection = snapshot.collection || {};
  const measurement = profile.measurement_profile || snapshot.measurement_profile || {};
  const time = profile.time || {};
  const deviceId = observer.device_id || snapshot.device_id;
  const profileId = observer.device_profile_version_id || snapshot.device_profile_version_id;
  const versions = useQuery({ queryKey: ["source-profiles", deviceId], queryFn: () => api.get(`/source-context/devices/${deviceId}/profiles`), enabled: !!deviceId && !!profileId });
  const version = (versions.data || []).find((item: any) => item.id === profileId)?.version;
  const organization = (id: string) => orgs.find(item => item.id === id)?.display_name || id || "미확인";
  const deviceName = observer.device_name || observer.display_name || devices.find(item => item.id === deviceId)?.display_name || deviceId || "미확인";
  const mapped = (value: string, labels: Record<string, string>) => labels[value] || "미확인";
  const actionLabels: Record<string, string> = { allowed: "허용", blocked: "거부", reset: "연결 초기화", detected: "탐지", challenged: "추가 확인", unknown: "미확인", conflicting: "충돌" };
  const card = (title: string, rows: [string, string][]) => <section className="panel pb" aria-label={title}><h4>{title}</h4><dl style={{ margin: 0 }}>{rows.map(([label, value]) => <div key={label} style={{ marginTop: 6 }}><dt className="small muted">{label}</dt><dd style={{ margin: 0, overflowWrap: "anywhere" }}>{value}</dd></div>)}</dl></section>;
  return <section className="panel pb col" aria-label={`${evidence.title || evidence.id} 원천 맥락`} style={{ gap: 10 }}><h4>{evidence.title || evidence.id}</h4><ErrorBox error={q.error} />
    {q.isLoading ? <Loading /> : q.data ? <>
      <div className="row wrap"><span className="badge">불변 맥락 · 증거 첨부 시 고정</span><b>{version ? `프로필 v${version}` : profileId ? `프로필 ID ${profileId}` : "프로필 미지정"}</b><span className="small muted">{fmtTime(q.data.created_at)}</span></div>
      <div className="small muted">조사 분류: {organization(snapshot.investigation_org_unit_id)} · 등록명은 현재 목록 기준이며 당시 의미는 아래 고정된 값입니다.</div>
      <div className="grid3">
        {card("관측 대상 귀속", [["상태", mapped(subject.status, { verified: "근거로 확인됨", unknown: "미확인", conflicting: "귀속 충돌" })], ["관측 관계사", subject.status === "verified" ? organization(subject.org_unit_id) : "미확인"], ["귀속 근거", subject.basis || "미기록"]])}
        {card("관측 장비·망", [["장비", deviceName], ["망", observer.network || snapshot.network || "미확인"], ["가상 영역", observer.virtual_domain || snapshot.virtual_domain || "미기록"], ["제품", [profile.vendor || observer.vendor, profile.product || observer.product, profile.product_version || observer.product_version].filter(Boolean).join(" · ") || "미기록"]])}
        {card("카운터 의미", [["검증", measurement.verified === true ? "검증됨" : "계측 의미 미확인"], ["방식", mapped(measurement.counter_semantics, { cumulative: "누적", delta: "구간 변화량", total: "완료 합계" })], ["원천 방향", mapped(measurement.direction, { src_to_dst: "출발지 → 목적지", dst_to_src: "목적지 → 출발지" })], ["단위", mapped(measurement.unit, { bytes: "바이트", packets: "패킷" })]])}
        {card("행위 의미", [["검증", profile.action_verified === true ? "검증됨" : "행위 의미 미확인"], ["원천 값 매핑", Object.entries(profile.action_map || snapshot.action_map || {}).map(([key, value]) => `${key} → ${actionLabels[String(value)] || "미확인"}`).join(" · ") || "미기록"], ["검증 근거", profile.action_basis || "미기록"]])}
        {card("시각 의미", [["검증", time.verified === true ? "검증됨" : "시각 의미 미확인"], ["시각 역할", mapped(time.role, { occurred: "발생 시각", start: "시작 시각", end: "종료 시각", collected: "수집 시각" })], ["시간대", time.timezone || "미확인"], ["정밀도", mapped(time.precision, PRECISION_LABELS)]])}
        {card("수집 범위·품질", [["포함 범위", mapped(collection.scope, { full: "전체 범위 수집", alerts_only: "경보만 수집", blocked_only: "차단 기록만 수집", sampled: "표본 수집", filtered: "필터 적용 수집" })], ["수집 손실", collection.loss === "known" ? "손실 상태 확인됨(크기 미기록)" : "손실 여부 미확인"], ["필터·조건", collection.filter || "미기록"], ["수집 위치", profile.observation_point || observer.observation_point || "미기록"]])}
      </div>
      <details><summary>원천 맥락 구조·무결성 상세</summary><div className="small mono">맥락 ID {q.data.id || "미기록"} · 프로필 ID {profileId || "미기록"} · SHA256 {q.data.sha256}</div><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(snapshot, null, 2)}</pre></details>
    </> : <p className="muted">원천 맥락 미기록 — 관측 귀속과 계측 의미는 미확인입니다.</p>}
  </section>;
}
export function SourceContextTab({ inv }: { inv: string }) {
  const qc = useQueryClient();
  const orgs = useQuery({ queryKey: ["org-units"], queryFn: () => api.get("/source-context/org-units") });
  const devices = useQuery({ queryKey: ["source-devices", inv], queryFn: () => api.get(`/source-context/investigations/${inv}/devices`) });
  const investigation = useQuery({ queryKey: ["inv", inv], queryFn: () => api.get(`/investigations/${inv}`) });
  const [device, setDevice] = useState("");
  const [name, setName] = useState("");
  const [profile, setProfile] = useState<any>(blankProfile);
  const [advanced, setAdvanced] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const profiles = useQuery({ queryKey: ["source-profiles", device], queryFn: () => api.get(`/source-context/devices/${device}/profiles`), enabled: !!device });
  const addDevice = useMutation({ mutationFn: () => api.post(`/source-context/investigations/${inv}/devices`, { display_name: name.trim() }), onSuccess: row => { setDevice(row.id); setName(""); qc.setQueryData(["source-devices", inv], (old: any) => [...(old || []), row]); } });
  const save = useMutation({ mutationFn: (body: any) => api.post(`/source-context/devices/${device}/profiles`, body), onSuccess: () => { setAdvanced(""); setAck(false); qc.invalidateQueries({ queryKey: ["source-profiles", device] }); } });
  const field = (key: string, value: any) => setProfile((p: any) => ({ ...p, [key]: value }));
  const nested = (key: string, prop: string, value: any) => setProfile((p: any) => ({ ...p, [key]: { ...p[key], [prop]: value } }));
  const submit = () => {
    setError(null);
    try {
      let body = profile;
      if (advanced.trim()) {
        try { body = JSON.parse(advanced); } catch { throw new Error("고급 JSON 형식을 확인하세요. 입력한 초안은 유지됩니다."); }
        if (!body || Array.isArray(body) || typeof body !== "object") throw new Error("고급 JSON 형식은 프로필 객체여야 합니다.");
      }
      const verificationFlags = [body.measurement_profile?.verified, body.time?.verified, body.action_verified];
      if (verificationFlags.some(value => value !== undefined && typeof value !== "boolean")) throw new Error("검증 여부는 true 또는 false 값이어야 합니다.");
      const verified = [body.measurement_profile, body.time].filter(x => x?.verified === true);
      if ((verified.length || body.action_verified) && (!ack || verified.some(x => !x.basis?.trim()) || (body.action_verified && !body.action_basis?.trim()))) throw new Error("검증 근거와 확인 동의가 필요합니다.");
      save.mutate(body);
    } catch (e) { setError(e); }
  };
  const template = () => {
    setProfile({ ...blankProfile(), source_fields: { timestamp: "timestamp", session_id: "session_id", record_kind: "record_kind", action: "action", src_bytes: "src_bytes", dst_bytes: "dst_bytes", duration: "duration" }, record_kind_map: { start: "session_start", interim: "session_interim", end: "session_end" }, action_map: { allow: "allowed", deny: "blocked" } });
    setAck(false); setAdvanced("");
  };
  return <div className="col" style={{ gap: 16 }}>
    <div><h3>장비·자료 의미</h3><p className="muted">조사 관계사는 관측 대상의 귀속 근거가 아닙니다. 프로필은 새 버전으로 저장하며 이미 첨부한 증거의 맥락은 바뀌지 않습니다.</p></div>
    <ErrorBox error={devices.error || orgs.error || investigation.error || addDevice.error || profiles.error || error || save.error} />
    <div className="row wrap"><label>장비 선택 <select className="input" value={device} onChange={e => { setDevice(e.target.value); setProfile(blankProfile()); setAdvanced(""); setAck(false); }}><option value="">장비를 선택하세요</option>{(devices.data || []).map((d: any) => <option key={d.id} value={d.id}>{d.display_name}</option>)}</select></label>
      <label>새 장비 이름 <input className="input" maxLength={128} value={name} onChange={e => setName(e.target.value)} /></label><button className="btn" disabled={!name.trim() || addDevice.isPending} onClick={() => addDevice.mutate()}>장비 등록</button></div>
    {device && <>
      <section className="panel pb col"><h4>새 프로필 버전 초안</h4>
        <div className="row wrap">{[["vendor", "제조사"], ["product", "제품"], ["product_version", "제품 버전"], ["network", "망"], ["virtual_domain", "가상 영역"], ["observation_point", "관측 위치"], ["collection_path", "수집 경로"]].map(([key, label]) => <label key={key}>{label} <input className="input" value={profile[key] || ""} onChange={e => field(key, e.target.value)} /></label>)}</div>
        <div className="row wrap">{[["owner_org_unit_id", "장비 소유 관계사"], ["operator_org_unit_id", "장비 운영 관계사"]].map(([key, label]) => <label key={key}>{label} <select className="input" value={profile[key] || ""} onChange={e => field(key, e.target.value || null)}><option value="">미확인</option>{(orgs.data || []).map((o: any) => <option key={o.id} value={o.id}>{o.display_name}</option>)}</select></label>)}</div>
        <fieldset><legend>장비 기능</legend><div className="row wrap">{["FW", "WAF", "IPS", "DDoS", "NDR"].map(f => <label key={f}><input type="checkbox" checked={profile.functions.includes(f)} onChange={e => field("functions", e.target.checked ? [...profile.functions, f] : profile.functions.filter((x: string) => x !== f))} /> {f}</label>)}</div></fieldset>
        <fieldset><legend>원천 필드 이름</legend><div className="row wrap">{SOURCE_FIELDS.map(([key, label]) => <label key={key}>{label} 필드 <input className="input" value={profile.source_fields[key] || ""} onChange={e => { const fields = { ...profile.source_fields }; if (e.target.value) fields[key] = e.target.value; else delete fields[key]; field("source_fields", fields); }} /></label>)}</div></fieldset>
        <fieldset><legend>계측 의미</legend><div className="row wrap">
          <label>카운터 방식 <select className="input" value={profile.measurement_profile.counter_semantics} onChange={e => nested("measurement_profile", "counter_semantics", e.target.value)}>{COUNTER_MODES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
          <label>카운터 방향 <select className="input" value={profile.measurement_profile.direction} onChange={e => nested("measurement_profile", "direction", e.target.value)}>{[["unknown", "미확인"], ["src_to_dst", "출발지 → 목적지"], ["dst_to_src", "목적지 → 출발지"]].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
          <label>카운터 단위 <select className="input" value={profile.measurement_profile.unit} onChange={e => nested("measurement_profile", "unit", e.target.value)}>{[["unknown", "미확인"], ["bytes", "바이트"], ["packets", "패킷"]].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
          <label>지속시간 단위 <select className="input" value={profile.measurement_profile.duration_unit} onChange={e => nested("measurement_profile", "duration_unit", e.target.value)}><option value="unknown">미확인</option><option value="seconds">초</option><option value="milliseconds">밀리초</option></select></label>
          <label><input type="checkbox" checked={profile.measurement_profile.verified} onChange={e => nested("measurement_profile", "verified", e.target.checked)} />카운터 의미 검증됨</label>
          <label>카운터 검증 근거 <input className="input" value={profile.measurement_profile.basis} onChange={e => nested("measurement_profile", "basis", e.target.value)} /></label>
        </div></fieldset>
        <fieldset><legend>시각 의미</legend><div className="row wrap">
          <label>시각 역할 <select className="input" value={profile.time.role} onChange={e => nested("time", "role", e.target.value)}>{[["unknown", "미확인"], ["occurred", "발생"], ["start", "시작"], ["end", "종료"], ["collected", "수집"]].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
          <label>시간대 <input className="input" placeholder="예: Asia/Seoul" value={profile.time.timezone || ""} onChange={e => nested("time", "timezone", e.target.value || null)} /></label>
          <label>시각 정밀도 <select className="input" value={profile.time.precision} onChange={e => nested("time", "precision", e.target.value)}>{!PRECISION_CHOICES.some(([value]) => value === profile.time.precision) && <option value={profile.time.precision}>{PRECISION_LABELS[profile.time.precision] || "해석 미확인"} (원본 값: {profile.time.precision || "빈 값"})</option>}{PRECISION_CHOICES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label><input type="checkbox" checked={profile.time.verified} onChange={e => nested("time", "verified", e.target.checked)} />시각 의미 검증됨</label><label>시각 검증 근거 <input className="input" value={profile.time.basis} onChange={e => nested("time", "basis", e.target.value)} /></label>
        </div></fieldset>
        <fieldset><legend>원천 행위 값</legend><div className="row wrap">{[["allowed", "허용 값"], ["blocked", "거부 값"]].map(([target, label]) => <label key={target}>{label} <input className="input" value={Object.keys(profile.action_map).filter(k => profile.action_map[k] === target).join(", ")} onChange={e => { const map = Object.fromEntries(Object.entries(profile.action_map).filter(([, v]) => v !== target)); e.target.value.split(",").map(x => x.trim()).filter(Boolean).forEach(x => { map[x] = target; }); field("action_map", map); }} /></label>)}
          <label><input type="checkbox" checked={profile.action_verified} onChange={e => field("action_verified", e.target.checked)} />행위 매핑 검증됨</label><label>행위 검증 근거 <input className="input" value={profile.action_basis} onChange={e => field("action_basis", e.target.value)} /></label>
        </div></fieldset>
        <div><button className="btn sm" onClick={template}>합성 FW 필드 예제 채우기</button><p className="small muted">실제 제조사 매핑으로 검증되지 않은 합성 예제입니다. start/interim/end 종류 매핑은 고급 JSON에서 확인할 수 있습니다.</p></div>
        <label>고급 프로필 JSON <textarea className="input mono" rows={8} value={advanced} placeholder="비워 두면 위 폼을 저장합니다. 입력하면 전체 프로필 초안으로 사용합니다." onChange={e => setAdvanced(e.target.value)} /></label>
        <button className="btn sm" onClick={() => setAdvanced(JSON.stringify(profile, null, 2))}>폼을 JSON 초안으로 복사</button>
        <label><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />원천 필드 사전과 수집 조건을 확인했으며 입력한 검증 근거에 동의합니다</label>
        <button className="btn primary" disabled={save.isPending} onClick={submit}>새 프로필 버전 저장</button>{save.isSuccess && <p role="status">새 버전을 저장했습니다. 다음 업로드에서 선택하세요.</p>}
      </section>
      <section><h4>저장된 불변 프로필 버전</h4>{(profiles.data || []).map((p: any) => <details key={p.id}><summary>v{p.version} · {fmtTime(p.created_at)} · {p.sha256}</summary><pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(p.profile, null, 2)}</pre><button className="btn sm" onClick={() => { setProfile({ ...blankProfile(), ...p.profile, measurement_profile: { ...blankProfile().measurement_profile, ...p.profile.measurement_profile }, time: { ...blankProfile().time, ...p.profile.time } }); setAdvanced(""); setAck(false); }}>v{p.version}을 새 초안으로 복사</button></details>)}</section>
    </>}
    <section><h4>증거에 고정된 원천 맥락</h4><p className="small muted">읽기 전용입니다. 의미를 바꾸려면 새 증거로 업로드하세요. 과거 맥락을 다시 쓰지 않습니다.</p>{(investigation.data?.evidence || []).map((e: any) => <FrozenContext key={e.id} evidence={e} orgs={orgs.data || []} devices={devices.data || []} />)}</section>
  </div>;
}
