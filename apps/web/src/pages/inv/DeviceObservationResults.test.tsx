import { cleanup, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { AnalysisHistoryTab } from "./AnalysisHistoryTab";
import { useInvStore } from "../../context/invContext";
afterEach(()=>{cleanup();vi.unstubAllGlobals();useInvStore.setState({byInv:{}});});
it("shows device counters, original rate unit/statistic and pinned candidate references without treating missing counts as zero",async()=>{
 const detail={engine_version:"ddos-observation/1",status:"complete",counts:{records:9,intervals:3,candidates:1},quality:{sampling_unknown:2},limits:{coverage_complete:true,max_records:1000,max_results:100},limitations:["이전 관측은 승인 기준선 아님"],candidates:[{kind:"rate_burst",interpretation:"candidate",event_refs:[{event_id:"pin-e1",raw_ref:"raw1"}],metrics:{value:1200,previous_observed_mean:200,unit:"pps",statistic:"peak",denominator:3},limitations:["표본 구간"]}],timeline:[{start_epoch:1792454400,end_epoch:1792454460,unit:"pps",statistic:"peak",value:1200,denominator:1,context:["org-a","DMZ"]}]};
 const run={id:"r1",version:1,status:"complete",executions:[{detector_id:"ddos.observation",status:"complete",detail,input_count:9,match_count:1}]};
 mockApi({"GET /source-context/org-units":[200,[]],"GET /source-context/investigations/i1/devices":[200,[]],"GET /investigations/i1/analysis-runs":[200,{runs:[run]}],"GET /investigations/i1/analysis-runs/r1":[200,run],"GET /investigations/i1/report-versions":[200,{reports:[]}]});renderUI(<AnalysisHistoryTab inv="i1"/>);
 const summary=await screen.findByRole("region",{name:"DDoS 관측 결과"});const section=within(summary);
 expect(section.getByRole("row",{name:/수집 구간 3/})).toBeTruthy();expect(section.getByRole("row",{name:/요청 미확인/})).toBeTruthy();expect(section.getByText("관측률 급증 후보")).toBeTruthy();expect(section.getAllByText("pps").length).toBeGreaterThan(0);expect(section.getAllByText("peak").length).toBeGreaterThan(0);expect(section.getByText("이전 관측은 승인 기준선 아님")).toBeTruthy();
 const raw=section.getByText("장비 결과 전체 구조·적용 정책").closest("details");expect(raw?.hasAttribute("open")).toBe(false);
 fireEvent.click(section.getByRole("button",{name:"DDoS 후보 1 근거 원문"}));expect(useInvStore.getState().get("i1").filters).toEqual([{field:"event_id",op:"in",value:["pin-e1"]}]);
});
