import { act,fireEvent,screen,waitFor } from "@testing-library/react";
import { Route,Routes } from "react-router-dom";
import { afterEach,expect,it,vi } from "vitest";
import { ME,mockApi,renderUI } from "../test/helpers";
import { JobDetail,Jobs } from "./Jobs";
import { GoldenExportJob } from "./golden/GoldenExportJob";
class Events { addEventListener() {} close() {} onerror=null; }
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});
const base={id:"gj1",kind:"golden_export",state:"FAILED",stages:{golden_export:{release_id:"rel1",version_id:null,state:"FAILED",progress:0,summary:"파일 생성 실패",actions:{cancel:{enabled:false,reasons:[]},retry:{enabled:true,reasons:[]}},artifact:null,private_mapping:"PRIVATE_MAPPING",frozen_input:{answer:"SECRET_ANSWER"},object_key:"PRIVATE_PATH"}}};
it("uses Golden job semantics and follows a fresh retry ID without leaking private fields",async()=>{
 vi.stubGlobal("EventSource",Events);
 const next={...base,id:"gj2",state:"QUEUED",stages:{golden_export:{...base.stages.golden_export,actions:{cancel:{enabled:true,reasons:[]},retry:{enabled:false,reasons:[]}}}}};
 const api=mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":[200,base],"GET /jobs/gj2":[200,next],"POST /jobs/gj1/retry":[200,next]});
 const ui=renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/></Routes>,{route:"/jobs/gj1"});
 await screen.findByText("정답 사례 반출 파일 생성");
 expect(ui.container.textContent).not.toMatch(/PRIVATE_MAPPING|SECRET_ANSWER|PRIVATE_PATH/);
 expect(api.find("GET","/parsers")).toHaveLength(0);
 expect((screen.getByRole("button",{name:"파일 생성 취소"}) as HTMLButtonElement).disabled).toBe(true);
 fireEvent.click(screen.getByRole("button",{name:"같은 고정 입력으로 다시 시도"}));
 await waitFor(()=>expect(api.find("GET","/jobs/gj2")).toHaveLength(1));
 expect((await screen.findByRole("button",{name:"같은 고정 입력으로 다시 시도"}) as HTMLButtonElement).disabled).toBe(true);
});
it("routes completed artifacts to exact release approval instead of direct Job downloads",async()=>{
 vi.stubGlobal("EventSource",Events);
 mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":[200,{...base,state:"COMPLETED",stages:{golden_export:{...base.stages.golden_export,version_id:"rv1",artifact:{filename:"private.zip",bytes:123,sha256:"a".repeat(64),download_url:"https://untrusted.invalid/private"},actions:{}}}}]});
 const ui=renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/></Routes>,{route:"/jobs/gj1"});
 const link=await screen.findByRole("link",{name:"반출 버전·승인 보기"});
 expect(link.getAttribute("href")).toBe("/knowledge/releases/rel1/versions/rv1");
 expect(ui.container.innerHTML).not.toContain("untrusted.invalid");
 expect(screen.queryByRole("button",{name:/내려받기|다운로드/})).toBeNull();
});

it.each([403,404])("hides cached Golden job data and actions after a %s refresh",async(status)=>{
 let denied=false;
 mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":()=>denied?[status,{detail:"job_hidden"}]:[200,base]});
 const ui=renderUI(<GoldenExportJob id="gj1"/>);
 await screen.findByText("파일 생성 실패");denied=true;
 await act(async()=>{await ui.qc.invalidateQueries({queryKey:["job","gj1"]});});
 await screen.findByText(/job_hidden/);
 await waitFor(()=>expect(screen.queryByText("파일 생성 실패")).toBeNull());
 expect(screen.queryByRole("link",{name:"반출 버전·승인 보기"})).toBeNull();
 expect(screen.queryByRole("button",{name:"같은 고정 입력으로 다시 시도"})).toBeNull();
});
it("isolates initialData and cached Golden job state after principal changes",async()=>{
 let denied=false;
 mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":()=>denied?[403,{detail:"job_hidden"}]:[200,base]});
 const ui=renderUI(<GoldenExportJob id="gj1" initial={base} initialPrincipal={JSON.stringify([ME.id,ME.permissions])}/>);
 await screen.findByText("파일 생성 실패");denied=true;
 await act(async()=>{ui.qc.setQueryData(["me"],{...ME,id:"another-user"});});
 await waitFor(()=>expect(screen.queryByText("파일 생성 실패")).toBeNull());
 await screen.findByText(/job_hidden/);
 expect(screen.queryByRole("button",{name:"같은 고정 입력으로 다시 시도"})).toBeNull();
});
it("does not leak a prior principal's Golden job through the main JobDetail cache",async()=>{
 vi.stubGlobal("EventSource",Events);let denied=false;
 mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":()=>denied?[403,{detail:"job_hidden"}]:[200,base]});
 const ui=renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/></Routes>,{route:"/jobs/gj1"});
 await screen.findByText("파일 생성 실패");denied=true;
 await act(async()=>{ui.qc.setQueryData(["me"],{...ME,id:"another-user"});});
 await waitFor(()=>expect(screen.queryByText("파일 생성 실패")).toBeNull());
 await screen.findByText(/job_hidden/);
 expect(screen.queryByRole("link",{name:"반출 버전·승인 보기"})).toBeNull();
});

it("discards the main Golden JobDetail cache after source access is revoked",async()=>{
 vi.stubGlobal("EventSource",Events);let denied=false;
 mockApi({"GET /auth/me":[200,ME],"GET /jobs/gj1":()=>denied?[403,{detail:"job_revoked"}]:[200,base]});
 const ui=renderUI(<Routes><Route path="/jobs/:id" element={<JobDetail/>}/></Routes>,{route:"/jobs/gj1"});
 await screen.findByText("파일 생성 실패");denied=true;
 await act(async()=>{await ui.qc.invalidateQueries({queryKey:["job","gj1"]});});
 await screen.findByText(/job_revoked/);
 expect(screen.queryByRole("button",{name:"같은 고정 입력으로 다시 시도"})).toBeNull();
 await waitFor(()=>expect(ui.qc.getQueryData(["job","gj1",JSON.stringify([ME.id,ME.permissions])])).toBeUndefined());
});
it("isolates the main Jobs list by principal and hides a denied refresh",async()=>{
 let denied=false;let empty=false;
 mockApi({"GET /auth/me":[200,ME],"GET /jobs":()=>denied?[403,{detail:"jobs_denied"}]:[200,empty?[]:[{...base,current_item:"이전 계정 작업 요약"}]]});
 const ui=renderUI(<Jobs/>);
 await screen.findByText("이전 계정 작업 요약");denied=true;
 await act(async()=>{await ui.qc.invalidateQueries({queryKey:["jobs"]});});
 await screen.findByText(/jobs_denied/);
 expect(screen.queryByText("이전 계정 작업 요약")).toBeNull();
 denied=false;empty=true;
 await act(async()=>{ui.qc.setQueryData(["me"],{...ME,id:"another-user"});});
 await screen.findByText("JOBS");
 expect(screen.queryByText("이전 계정 작업 요약")).toBeNull();
});
