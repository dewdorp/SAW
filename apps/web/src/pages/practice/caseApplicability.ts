/** Compare *returned* question observations with specific worked-example motifs. Never read event rows here. */
type Obj = Record<string, any>;
type Period = {start?: string | null; end?: string | null; end_exclusive?: boolean};
export type CaseEvidence = {bundleId: string; itemIndex: number; observed: string; records: number; filters: Obj[]; time: Period | null};
export type CaseComparison = {caseId: string; status: 'matched'|'no_match'|'missing'|'partial'|'unsupported'|'failed'; criterion: string; detail: string; partial: boolean; evidence: CaseEvidence[]};
type Fact = string | false | null; // null = this observation cannot be evaluated
const obj = (x: unknown): x is Obj => !!x && typeof x === 'object' && !Array.isArray(x);
const num = (x: unknown): x is number => typeof x === 'number' && Number.isFinite(x) && x >= 0;
const int = (x: unknown): x is number => num(x) && Number.isSafeInteger(x);
const fmt = (n: number) => n.toLocaleString('ko-KR', {maximumFractionDigits: 3});
const eq = (i: Obj, field: string) => i.filters.find((f: Obj) => f.field === field && f.op === 'is')?.value;
type Bounds = {start: string | null; end: string | null; exclusive: boolean};
function instantKey(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const iso = /^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.(\d{1,9}))?(?:Z|[+-]\d\d:\d\d)$/.exec(value);
  const milliseconds = Date.parse(value);
  if (!iso || !Number.isFinite(milliseconds)) return null;
  // Date normalizes offsets but truncates sub-millisecond evidence timestamps.
  return new Date(milliseconds).toISOString().slice(0,19) + '.' + (iso[1] ?? '').padEnd(9,'0');
}
function bounds(time: unknown): Bounds | null {
  if (time === null) return {start:null, end:null, exclusive:false};
  if (!obj(time) || !('start' in time || 'end' in time) ||
      (time.end_exclusive !== undefined && typeof time.end_exclusive !== 'boolean')) return null;
  const start = instantKey(time.start), end = instantKey(time.end);
  if ((time.start != null && !start) || (time.end != null && !end) ||
      (start && end && (start > end || (start === end && time.end_exclusive)))) return null;
  return {start, end, exclusive:!!end && time.end_exclusive === true};
}
function bundleBounds(scope: unknown, bundle: unknown, inv: string): Bounds | null {
  if (!inv || !obj(scope) || !obj(bundle) || scope.investigation_id !== inv ||
      (scope.org_unit_id !== null && typeof scope.org_unit_id !== 'string')) return null;
  const period = bounds(scope.time);
  if (!period || bundle.scope === undefined) return period;
  const preview = bundle.scope;
  if (!obj(preview) || preview.investigation_id !== inv || preview.org_unit_id !== scope.org_unit_id) return null;
  const override = bounds(preview.time);
  return override && override.start === period.start && override.end === period.end &&
    override.exclusive === period.exclusive ? period : null;
}
function containsEvidence(period: Bounds, item: unknown): boolean {
  if (!obj(item)) return false;
  // A base item reuses the run period. Only an explicit evidence_time overrides the raw-log query.
  if (item.evidence_time == null) return true;
  const window = bounds(item.evidence_time);
  if (!window?.start || !window.end || (period.start && window.start < period.start)) return false;
  if (!period.end || window.end < period.end) return true;
  return window.end === period.end && (!period.exclusive || window.exclusive);
}
export function isCaseEvidenceInScope(scope: unknown, bundle: unknown, item: unknown, inv: string): boolean {
  const period = bundleBounds(scope,bundle,inv);
  return !!period && obj(bundle) && Array.isArray(bundle.items) && bundle.items.includes(item) &&
    containsEvidence(period,item);
}
type Rule = {bundle: string; criterion: string; limit: string; check: (i: Obj, b: Obj) => Fact};
function spread(i: Obj, horizontal: boolean): Fact {
  const {observed_targets:t, observed_ports:p, port_records:k, allowed_records:a, blocked_records:d, threshold_targets:tt, threshold_ports:tp} = i.basis;
  if (![t,p,k,a,d,tt,tp].every(int) || !eq(i,'src_ip') || k !== i.records || !t || !p ||
      t > i.records || p > i.records || a + d > i.records) return null;
  const threshold = Math.max(2, horizontal ? tt : tp);
  if (!(horizontal ? (t >= threshold && p === 1 && a > 0 && d > 0) : (t === 1 && p >= threshold && d > i.records / 2 && a > 0))) return false;
  return `${eq(i,'src_ip')} · 목적지 ${fmt(t)}개, 목적지 포트 ${fmt(p)}개 · ${horizontal?'목적지':'포트'} 기준 ${fmt(threshold)}개 이상 · 허용 ${fmt(a)}건, 차단 ${fmt(d)}건 / 전체 ${fmt(i.records)}건`;
}
function transfer(i: Obj, web: boolean): Fact {
  const ds = eq(i,'data_source'); if (!ds) return null;
  if (web ? ds !== 'web' : ds !== 'firewall' && ds !== 'connection') return false;
  const {observed_bytes_out:n, threshold_bytes:t, matched_directions:dirs, allowed_records:a} = i.basis;
  if (!num(t) || !t || !Array.isArray(dirs) || !eq(i,'src_ip') || !eq(i,'dst_ip')) return null;
  if (!num(n) || (!web && (!int(a) || a > i.records))) return null;
  if (!dirs.includes('out')) return false;
  if (n<t || (!web && (a!==i.records || i.records<2))) return false;
  const pair = web ? `서버 ${eq(i,'dst_ip')} → 클라이언트 ${eq(i,'src_ip')}` : `출발지 ${eq(i,'src_ip')} · 목적지 ${eq(i,'dst_ip')}`;
  return `${pair} · ${web?'HTTP 응답':'장비 송신'} 합계 ${fmt(n)} B (기준 ${fmt(t)} B 이상) · ${web?'기록':'허용'} ${fmt(i.records)}건`;
}
const RULES: Record<string,Rule> = {
  C007: {bundle:'transfer',criterion:'같은 HTTP 클라이언트·서버 쌍에서 응답(bytes_out) 합계가 적용된 전송 기준 이상',limit:'응답량만 비교합니다. 내·외부 소유, 개별 응답 크기, 반환 내용은 별도 확인이 필요합니다.',check:i=>transfer(i,true)},
  C008: {bundle:'transfer',criterion:'같은 방화벽·연결 주소 쌍의 기록 2건 이상이 모두 허용이고 장비 송신(bytes_out) 합계가 적용된 기준 이상',limit:'장비 기준 합계입니다. NAT 전후 주소와 자산 소유, 중복·누적, 전송 내용과 업무 승인은 별도 확인이 필요합니다.',check:i=>transfer(i,false)},
  C009: {bundle:'periodic',criterion:'같은 출발지·목적지·포트의 기록 간격 수와 변동계수가 적용된 반복 기준 충족',limit:'기록 시각의 규칙성만 비교합니다. 상태 점검·정상 예약 작업과 구분하려면 실행 프로그램·작업 일정·목적지 소유를 대조하세요.',check:i=>{
    const {mean_interval_seconds:m,observed_cv:c,intervals_checked:n,min_records:r,threshold_cv:t}=i.basis;
    if(!num(m)||m<=0||!num(c)||!num(t)||!int(n)||n>=i.records||!int(r)||r<3||!eq(i,'src_ip')||!eq(i,'dst_ip')||!eq(i,'dst_port'))return null;
    if(n<r-1||c>t)return false;
    return `${eq(i,'src_ip')} → ${eq(i,'dst_ip')}:${eq(i,'dst_port')} · 평균 ${fmt(m)}초 · 간격 ${fmt(n)}개 (기준 ${r-1}개 이상), 변동계수 ${fmt(c)} (기준 ${fmt(t)} 이하)`;
  }},
  C010: {bundle:'spread',criterion:'한 출발지 → 기준 이상(최소 2개) 목적지, 모든 행의 목적지 포트가 하나이고 허용·차단 모두 관측',limit:'같은 포트 번호를 비교합니다. 접촉 순서·실제 서비스·승인된 점검 여부는 원문과 작업 기록에서 확인하세요.',check:i=>spread(i,true)},
  C011: {bundle:'spread',criterion:'한 출발지 → 한 목적지, 기준 이상(최소 2개) 포트, 차단이 전체의 과반이고 허용도 관측',limit:'출발지 소유·접속 의도·인증 성공 여부는 별도 확인이 필요합니다.',check:i=>spread(i,false)},
};
export function matchCasebook(response: unknown, expectedInvestigationId: string, caseIds: readonly string[]): CaseComparison[] {
  const payload = obj(response) ? response : {}, scope = payload.scope;
  return caseIds.map(caseId => {
    const rule = Object.prototype.hasOwnProperty.call(RULES,caseId) ? RULES[caseId] : undefined;
    const result: CaseComparison = {caseId,status:'unsupported',criterion:rule?.criterion ?? '자동 비교 기준 없음',detail:'사례집에서 직접 비교할 수 있습니다.',partial:false,evidence:[]};
    if (!rule) return result;
    const b = Array.isArray(payload.bundles) && payload.bundles.find((v:unknown)=>obj(v) && v.id===rule.bundle);
    const period = bundleBounds(scope,b,expectedInvestigationId);
    if (!period || !obj(b)) {
      return {...result,status:'missing',detail:'현재 조사·관계사·기간에 대응하는 계산 결과가 없습니다.'};
    }
    if(b.status==='failed')return {...result,status:'failed',detail:'조사 질문 계산이 실패했습니다.'};
    if(!['found','looked_none','no_match'].includes(b.status) || !Array.isArray(b.items))return {...result,status:'missing',detail:(b.missing||[]).join?.(' · ') || '비교에 필요한 관측 자료가 없습니다.'};
    const limited = b.completeness==='partial' || b.returned_all===false || (int(b.found) && b.found>b.items.length);
    let incomplete = b.status==='found' && !b.items.length;
    b.items.forEach((item:unknown,itemIndex:number)=>{
      if(!containsEvidence(period,item)||!obj(item)||!obj(item.basis)||!int(item.records)||!item.records||!Array.isArray(item.filters)||!item.filters.every(obj)){incomplete=true;return;}
      const observed=rule.check(item,b); if(observed===null){incomplete=true;return;}
      if(observed)result.evidence.push({bundleId:b.id,itemIndex,observed,records:item.records,filters:item.filters,time:item.evidence_time??(b.scope||scope).time??null});
    });
    result.partial=limited || (incomplete && result.evidence.length>0);
    const limitation=limited?' 계산·표시 한도로 일부 후보만 비교했습니다.':'';
    if(result.evidence.length){result.status='matched';result.detail=`관측된 초기 특징이 겹칩니다. ${rule.limit}${limitation}${incomplete?' 일부 후보는 필드가 부족합니다.':''}`;}
    else if(limited){result.status='partial';result.detail=`받은 후보에서는 특징 일치를 확인하지 못했습니다.${limitation}`;}
    else if(incomplete){result.status='missing';result.detail='후보의 근거 구간이나 필수 측정값·주소·포트를 확인할 수 없습니다.';}
    else {result.status='no_match';result.detail='현재 조사 질문의 조건을 통과한 후보 중 비교 기준을 충족한 항목이 없습니다. 정상 판정은 아닙니다.';}
    return result;
  });
}
