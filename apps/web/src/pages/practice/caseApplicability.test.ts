import { it } from 'vitest';
import assert from 'node:assert/strict';
import { isCaseEvidenceInScope, matchCasebook } from './caseApplicability';
const period = {start:'2026-10-10T00:00:00Z',end:'2026-10-11T00:00:00Z',end_exclusive:true};
const scope = {investigation_id:'INV',org_unit_id:'A',time:period};
const f = (field:string,value:unknown)=>({field,op:'is',value});
const make = (id:string,items:unknown[],more={})=>({scope,bundles:[{id,items,status:'found',completeness:'complete',...more}]});
const compare = (data:unknown,...ids:string[])=>matchCasebook(data,'INV',ids);
const spread = (t:number,p:number)=>({records:24, title:'임의의 표시 제목', filters:[f('src_ip','10.0.0.1')],basis:{observed_targets:t,observed_ports:p,port_records:24,threshold_targets:5,threshold_ports:5,allowed_records:3,blocked_records:21}});
const transfer = (ds:string,dirs=['out'])=>({records:8,filters:[f('data_source',ds),f('src_ip','10.0.0.1'),f('dst_ip','192.0.2.1')],basis:{observed_bytes_out:8_000_000,threshold_bytes:5_000_000,matched_directions:dirs,allowed_records:8}});
it('separates horizontal and vertical geometry at the original inclusive raw-evidence window',()=>{
 const window={...period,end:'2026-10-10T00:01:00Z',end_exclusive:false}; const i={...spread(8,1),evidence_time:window};const [h,v]=compare(make('spread',[i]),'C010','C011');
 assert.equal(h.status,'matched');assert.equal(v.status,'no_match');assert.deepEqual(h.evidence[0],{bundleId:'spread',itemIndex:0,observed:'10.0.0.1 · 목적지 8개, 목적지 포트 1개 · 목적지 기준 5개 이상 · 허용 3건, 차단 21건 / 전체 24건',records:24,filters:i.filters,time:window});
 const [no,yes]=compare(make('spread',[spread(1,12)]),'C010','C011');assert.equal(no.status,'no_match');assert.equal(yes.status,'matched');
});
it('does not reduce mixed geometry, cutoffs, or allow-only logs to a worked example',()=>{
 for(const i of [spread(10,12),spread(1,1),spread(4,1),{...spread(1,12),basis:{...spread(1,12).basis,allowed_records:24,blocked_records:0}}])assert.ok(compare(make('spread',[i]),'C010','C011').every(x=>x.status==='no_match'));
});
it('requires complete observed ports; ignores counts embedded in text',()=>{
 for(const i of [{...spread(8,1),basis:{threshold_ports:1}},{...spread(8,1),basis:{...spread(8,1).basis,port_records:2}}])assert.equal(compare(make('spread',[i]),'C010')[0].status,'missing');
});
it('does not equate an HTTP response and firewall send; never claims inside/outside ownership',()=>{
 for(const [ds,expected] of [['web','C007'],['connection','C008'],['firewall','C008']]){const answers=compare(make('transfer',[transfer(ds)]),'C007','C008');const [hit]=answers.filter(x=>x.status==='matched');assert.equal(hit.caseId,expected);assert.equal(answers.filter(x=>x.status==='matched').length,1);assert.match(hit.evidence[0].observed,/8,000,000 B/);assert.equal(hit.evidence[0].time,period);}
 assert.ok(compare(make('transfer',[transfer('firewall',['in']),transfer('web',['in'])]),'C007','C008').every(x=>x.status==='no_match'));
 const one=transfer('connection');one.records=one.basis.allowed_records=1;assert.equal(compare(make('transfer',[one]),'C008')[0].status,'no_match');
});
it('only compares actual measured repetition; a scheduled task is still possible',()=>{
 const i={records:10,filters:[f('src_ip','10.0.0.1'),f('dst_ip','192.0.2.1'),f('dst_port',443)],basis:{mean_interval_seconds:60,observed_cv:0.02,intervals_checked:9,min_records:8,threshold_cv:0.1}};
 const hit=compare(make('periodic',[i]),'C009')[0];assert.equal(hit.status,'matched');assert.match(hit.detail,/정상 예약 작업/);
 assert.equal(compare(make('periodic',[{...i,basis:{...i.basis,observed_cv:0.3}}]),'C009')[0].status,'no_match');
 assert.equal(compare(make('periodic',[{...i,filters:i.filters.slice(0,2)}]),'C009')[0].status,'missing');
});
it('honors the investigation, organization, and period of preview and base results',()=>{
 for(const other of [{...scope,investigation_id:'OTHER'},{...scope,org_unit_id:'B'},{...scope,time:{...period,end_exclusive:false}}]){const r=compare(make('spread',[spread(10,1)],{scope:other}),'C010')[0];assert.equal(r.status,'missing');assert.equal(r.evidence.length,0);}
 assert.equal(matchCasebook(make('spread',[spread(8,1)]),'OTHER',['C010'])[0].status,'missing');
});
it('distinguishes unavailable facts, failed runs, unimplemented comparisons and bounded results',()=>{
 for(const [q,s] of [['insufficient_data','missing'],['no_match','no_match'],['looked_none','no_match'],['failed','failed']])assert.equal(compare(make('spread',[],{status:q}),'C010')[0].status,s);
 assert.equal(compare(make('spread',[]),'C001')[0].status,'unsupported');
 for(const limit of [{completeness:'partial'},{found:12,returned_all:false}]){const hit=compare(make('spread',[spread(9,1)],limit),'C010')[0];assert.equal(hit.status,'matched');assert.equal(hit.partial,true);const no=compare(make('spread',[spread(1,9)],limit),'C010')[0];assert.equal(no.status,'partial');}
});

it('describes HTTP response bytes from server to client and keeps device bytes device-relative',()=>{
 const [http]=compare(make('transfer',[transfer('web')]),'C007');
 assert.match(http.evidence[0].observed,/서버 192\.0\.2\.1 → 클라이언트 10\.0\.0\.1/);
 const [fw]=compare(make('transfer',[transfer('firewall')]),'C008');
 assert.match(fw.evidence[0].observed,/출발지 10\.0\.0\.1 · 목적지 192\.0\.2\.1/);
 const absent=transfer('web',['in']);
 assert.equal(compare(make('transfer',[{...absent,basis:{...absent.basis,observed_bytes_out:null}}]),'C007')[0].status,'missing');
});

it('rejects evidence that widens the actual investigation period, including fractional boundaries',()=>{
 const narrow={start:'2026-10-10T00:00:00.123456Z',end:'2026-10-10T00:00:00.124567Z',end_exclusive:true};
 const inside={start:'2026-10-10T09:00:00.123456+09:00',end:'2026-10-10T09:00:00.124566+09:00',end_exclusive:false};
 const result=(evidence_time:unknown)=>compare({...make('spread',[{...spread(8,1),evidence_time}]),scope:{...scope,time:narrow}},'C010')[0];
 assert.equal(result(inside).status,'matched');
 for(const window of [{...inside,start:'2026-10-10T00:00:00.123455Z'},{...narrow,end_exclusive:false},
   {...inside,end:'2026-10-10T09:00:00.123455+09:00'},{...inside,start:'invalid'},{...inside,end:null}]) {
   const answer=result(window);assert.equal(answer.status,'missing');assert.equal(answer.evidence.length,0);
 }
});

it('matches equivalent timezone representations and requires an explicit scope on the response',()=>{
 const data=make('spread',[spread(8,1)],{scope:{...scope,time:{...period,start:'2026-10-10T09:00:00+09:00'}}});
 assert.equal(compare(data,'C010')[0].status,'matched');
 for(const malformed of [{investigation_id:'INV'},{...scope,time:{start:'invalid'}},{investigation_id:'INV',time:null}])
   assert.equal(compare({...data,scope:malformed},'C010')[0].status,'missing');
 assert.equal(compare({...make('spread',[spread(8,1)]),scope:{investigation_id:'INV',org_unit_id:null,time:null}},'C010')[0].status,'matched');
});

it('never matches a case from addresses alone or from internally inconsistent observations',()=>{
 const raw=spread(8,1);
 for(const basis of [{},{...raw.basis,observed_targets:50},{...raw.basis,blocked_records:24}])
   assert.equal(compare(make('spread',[{...raw,basis}]),'C010')[0].status,'missing');
 const timing={records:2,filters:[f('src_ip','10.0.0.1'),f('dst_ip','192.0.2.1'),f('dst_port',443)],
   basis:{mean_interval_seconds:60,observed_cv:0,intervals_checked:8,min_records:8,threshold_cv:0.1}};
 assert.equal(compare(make('periodic',[timing]),'C009')[0].status,'missing');
});

it('supports analyst-selected comparisons without requiring any automatic motif',()=>{
 const item={title:'조사 질문의 관측'}, outside={...item,evidence_time:{...period,end_exclusive:false}};
 const manual={id:'web_attack',items:[item,outside]};
 assert.equal(isCaseEvidenceInScope(scope,manual,item,'INV'),true);
 assert.equal(isCaseEvidenceInScope(scope,{...manual,scope:{...scope,org_unit_id:'OTHER'}},item,'INV'),false);
 assert.equal(isCaseEvidenceInScope(scope,manual,outside,'INV'),false);
 assert.equal(isCaseEvidenceInScope(scope,manual,{...item},'INV'),false);
 assert.equal(isCaseEvidenceInScope(scope,manual,item,'OTHER'),false);
});
