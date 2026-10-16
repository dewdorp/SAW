# Scoped web behavior analysis design — 2026-10-16

## Intent and reuse
Implement the user's attached request in the existing SAW investigation. Reuse upload/parsing, scope, EventStore, Job/lease/cancel/retry, Raw/EventDrawer, RequestEvolution, Check, close/Experience and Golden approval/export. No new platform, LLM requirement, external scans, automatic policy change, or trainer. Work in existing independent copy F:/codex/SAW-Claude-main; F:/claude/saw remains read-only.

User has delegated routine design/execution choices. Continue after presenting this concrete scope; preserve independent human product approval boundaries. Architectural increment is limited to immutable computed results and connections. Live-only aggregates and report-only recomputation were rejected because they cannot guarantee UI/report/Golden numeric equality.

## Reference
Read local Theori ARTEX whitepaper chapter5 (viewer18–27), figure5(viewer24/body21), table7(viewer25/body22), appendixA.1/A.2(viewer37–38/body34–35). Reference profile thresholds: request30/10s, paths30/60s,40415/60s,repeats20/60s, UA2/600s with404>=2 in same window. These are informational reference thresholds, not validated production verdicts.
Do not copy experimental measurements, logo, or external rule packs. norma/0.4 and spa-api-recon are conditional code-derived tool-string indicators; default ARTEX runs01/02 did not observe them. artex-enrich/1.0 is code-defined/unreachable in described version. Match strings in supplied data without attributing actor/tool/AI or compromise. Host/console/egress indicators require their respective data, no active probing.

## Calculation contract
Pure module saw/behavior/calculator.py exposes calculate(events, profile=None, *, max_events=100000, max_seconds=120, check_cancel=None)->dict. Input events are normalized CES dicts. Definitions version saw-web-behavior/1.0. Return: methodology,profile,summary,quality,metrics,timeline,indicators,followups,limits,execution,evidence_events. Server removes evidence_events from observations and masks/captures separately.
- partition sliding metrics by src_ip + observed destination/service(hostname or dst_ip, dst_port); never aggregate multiple actors into one client threshold. Missing src cannot be assigned invented address.
- half-open [start,end) windows anchored at actual observation times, max over all starts; same-timestamp ties have no causal ordering. Fixed graph buckets are separate, <=400 buckets; annotate peak windows so narrow bursts remain discoverable.
- path is raw URI before ? (or url_path); no URL decode/lowercase/template collapse. Repeated-request candidate key method + raw uri + destination/service; query retained, no body equivalence claim.
- default no dedup: show multi-source duplicate risk. Optional explicit request_id dedup ONLY if non-empty request_id AND exact src/destination/method/rawURI and same timestamp match across distinct sensor/source identifiers; preserve count/refs. No timestamp/IP/URI-only collapsing.
- reference profile excludes OPTIONS and explicit static suffixes from request/path/repeat metrics only;404/UA include all. Exclusions and counts per metric. Cookie is never a generic exclusion. Editable thresholds/exclusions are SAW local profile in result, not production-rule deployment.
- value=null/data_state not_collected for absent required fields; partially available fields provide bounded measured subset plus partial state/denominator. Insufficient observed duration marked partial_window, never full-range normal conclusion.
- quality separates UA present/recorded_empty/not_collected/unknown. Parser-produced ext.saw_observation.user_agent state; '-'/empty is recorded_empty, not proof header absent. Incoming ext cannot forge trusted producer metadata. Existing missing UA unknown.
- timestamp original precision seconds/subseconds/unknown recorded; .000 normalized timestamp is not proof millisecond precision.
- source basis WAF-only: collected WAF events; mixed sensors: observed events, never full HTTP requests.
- gaps mean no observations / collection continuity unknown unless explicit collection-gap source exists. No model-call overlay without actual call records.
- metrics [{id,label,window_seconds,unit,value,data_state,result,window:{start,end_exclusive,src_ip,service},reference_threshold,applied_threshold,excluded_count,eligible_count,partial_window,evidence_ids}]. ids requests_10s,paths_60s,status404_60s,repeats_60s,ua_600s.
- timeline {interval_seconds,timezone:'UTC',buckets:[{start,end_exclusive,count,status404,blocked,allowed,ua_values}],annotations:[],coverage_label}.
- indicators [{id,label,category,state(observed|not_observed|unavailable),count,source,verification,conditions,evidence_ids,limits}].
- summary count/first/last/methods/services/status_codes/actions/unique_paths/user_agents; fields absent remain unavailable/null.
- execution scanned/processed/truncated/reason/elapsed_ms/limits. Bounded row/time/partition/output limits; no full claims on truncated results. Cancellation callback periodically.

## Persistence and API contract
One new model BehaviorResult (an_behavior_result), linked inv/job, immutable data and result_sha256; number/version increases per investigation, include created_by, created_at. Request persisted in Job.stages.behavior_request. Existing Job kind behavior and task behavior.run; register retry/startup recovery explicitly. Lease and investigation lock checked before publishing. Active ingest/reanalysis/deletion or source manifest change blocks mixed snapshots; recheck file/ProcessingRun manifests at completion.
API:
POST /investigations/{inv_id}/behavior {filters:[],time:null,ips:[],role:'src'|'dst'|'either',profile:{...}|null,idempotency_key?} -> job_out (202); max16IPs and existing bounded structured filters.
GET /investigations/{inv_id}/behavior -> {results:[summary DTO]}
GET /investigations/{inv_id}/behavior/{result_id} -> {id,version,job_id,created_at,created_by,result_sha256,result:{schema,scope,methodology,profile,source_manifest,observations,selected_evidence}}.
GET .../{result_id}/report -> printable HTML of exact saved result plus clearly separate current analyst Check interpretation; export audit and original inv ACL.
Result contains masked bounded representative events with raw/source hash and provenance. Before/after source checks. No raw whole ext/headers/cookies in snapshots.
Existing Check input gains behavior:{result_id,result_sha256,metric_ids:[],follow_up:{...},answer_status:'answered'|'follow_up'|'not_applicable'}; normal note/judgement/event_ids preserved. Server validates IDs/source scope, never client supplied calculated values. Behavior-only Check is valid without Guidance. Update preserves/revalidates attachment.
Close/Experience pins behavior result IDs/hashes from active Checks in its revision. Golden supports actual Behavior observation captures directly; immutable observation blob(s) contain calculations only, never notes/answers/Experience text. Include result author + Check contributors. Retain source ACL/hash limits,4eyes,family split,immutable adoption. Mixed Guidance+Behavior metadata preserves each version; do not label behavior as fabricated guidance.

## Workbench/report
Add one '행위 분석' investigation tab, keep existing statistics/timeline. Scope uses current filters/time and selected IP; multi-IP input and role. Compute via Job, show progress/cancel, saved versions. Display source coverage first, numeric summary, time chart with zoom/peak buttons, metrics table, indicators/limits/conditional followups, brief analyst note through existing Check. Drilldown carries exact frozen scope and [start,end) filter. Compare uses selected result evidence IDs and existing RequestEvolution; raw URI query changes preserved, masking before comparisons.
Printable HTML at existing report workflow:9 requested sections, title/tables/chart captions, A4 CSS, escaped untrusted data, same saved metrics/timeline, interpretation separate. No external scripts/assets/font downloads. Existing report screen links selected result.
Optional comparison against another selected saved result labels '비교 대상', never approved baseline without evidence. Normal explanations from existing Check/reference records, no auto whitelist.

## Validation
A automated discovery without identifier, B identifier+allowed attack no origin result, C approved assessment/batch exceeds threshold, D UA uncollected+seconds+gaps. Exact/under thresholds, boundaries,query variations,multi-sensor identity/no dedup,static/OPTIONS,Cookie,missing fields,scope/ACL/hash/4eyes/exportleak,jobcancel/retry/recovery,large bounded input. UI/HTML/Golden identical metrics, restart persistence. Real synthetic HTTP/native PG+OS where available. Actual browser/report rendering if tools work; keep blocked browser screenshot status explicit otherwise. Windows11 results are not LTSC acceptance. Existing installer unchanged until separately rebuilt/tested.
