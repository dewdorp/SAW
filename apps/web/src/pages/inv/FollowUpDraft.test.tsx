import {cleanup,fireEvent,screen,waitFor} from "@testing-library/react";
import {afterEach,beforeEach,describe,expect,it,vi} from "vitest";
import {ME,mockApi,renderUI} from "../../test/helpers";
import {useInvStore} from "../../context/invContext";
import {ChecksTab} from "./ChecksTab";
vi.mock("../../components/Reviews",()=>({ReviewPanel:()=>null}));
vi.mock("../../components/Support",()=>({SupportPanel:()=>null}));
beforeEach(()=>useInvStore.setState({byInv:{}}));
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
const check={id:"c1",state:"active",target_type:"finding",target_label:"10.0.0.5 목적지 15개 접촉",question_labels:[],author:"분석가"};
const connections=[{src_ip:"10.0.0.5",dst_ip:"10.0.1.1",dst_port:443},{src_ip:"10.0.0.5",dst_ip:"10.0.1.2",dst_port:443}];
const suggestion={check_id:"c1",question:"자동 질문",reason:"자동 이유",needed_data:["작업 기록"],target:{src_ips:["10.0.0.5"],dst_ips:["10.0.1.1","10.0.1.2"],dst_ports:[443],behavior:"확산",connections},
  target_summary:{basis:"whole_group",records:30,sources:1,destinations:2,ports:[443],port_count:1,connections:2,complete:true,start:"2026-10-13T01:00:00Z",end:"2026-10-13T01:05:00Z"},period:{start:"2026-10-13T01:00:00Z",end:"2026-10-13T01:05:00Z"}};
const routes=(extra:any={})=>({"GET /auth/me":[200,ME],"GET /investigations/i1/checks":[200,{checks:[check],summary:{direct:1,by_question:{}}}],"GET /investigations/i1/follow-ups":[200,{items:[],next_cursor:null}],
  "GET /investigations/i1/follow-ups/choices":[200,{org_units:[],users:[],department_kind:"descriptive_text"}],"GET /investigations/i1/follow-ups/draft":[200,suggestion],...extra}) as any;
/** Holds the draft suggestion until release() so a late answer can be simulated. */
function lateDraft(api:ReturnType<typeof mockApi>){let release=()=>{};const gate=new Promise<void>(r=>{release=r;});
  vi.stubGlobal("fetch",async(input:string,init?:RequestInit)=>{if(String(input).includes("/follow-ups/draft"))await gate;return api.fetchMock(input,init);});return ()=>release();}
describe("follow-up draft",()=>{
  it("a late suggestion fills only the fields the analyst has not typed",async()=>{
    const api=mockApi(routes());const release=lateDraft(api);
    renderUI(<ChecksTab inv="i1"/>);fireEvent.click(await screen.findByRole("button",{name:"이 확인에서 후속확인 만들기"}));
    expect(screen.getByLabelText("요청 상태").textContent).toBe("작성 중 · 등록 전");
    fireEvent.change(screen.getByLabelText("확인할 질문"),{target:{value:"내가 먼저 쓴 질문"}});
    release();
    await waitFor(()=>expect((screen.getByLabelText("필요한 이유") as HTMLTextAreaElement).value).toBe("자동 이유"));
    expect((screen.getByLabelText("확인할 질문") as HTMLTextAreaElement).value).toBe("내가 먼저 쓴 질문");
    expect(screen.getByLabelText("확인 대상 요약").textContent).toContain("출발지 1개 → 목적지 2개 · 포트 443");
    expect(screen.getByText(/계산한 그룹 전체: 기록 30건 · 연결 2개/)).toBeTruthy();
    expect(api.find("POST","/investigations/i1/follow-ups")).toHaveLength(0);
  });
  it("keeps the draft across leaving the tab and sends the exact connections only on registration",async()=>{
    const api=mockApi(routes({"POST /investigations/i1/follow-ups":[201,{id:"fu1"}]}));
    const first=renderUI(<ChecksTab inv="i1"/>);fireEvent.click(await screen.findByRole("button",{name:"이 확인에서 후속확인 만들기"}));
    await waitFor(()=>expect((screen.getByLabelText("확인할 질문") as HTMLTextAreaElement).value).toBe("자동 질문"));
    fireEvent.change(screen.getByLabelText("확인할 질문"),{target:{value:"고친 질문"}});
    first.unmount();
    renderUI(<ChecksTab inv="i1"/>);
    await waitFor(()=>expect((screen.getByLabelText("확인할 질문") as HTMLTextAreaElement).value).toBe("고친 질문"));
    expect(api.find("GET","/investigations/i1/follow-ups/draft")).toHaveLength(1);
    expect(api.find("POST","/investigations/i1/follow-ups")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button",{name:"후속확인 요청 등록"}));
    await waitFor(()=>expect(api.find("POST","/investigations/i1/follow-ups")).toHaveLength(1));
    expect(api.find("POST","/investigations/i1/follow-ups")[0].body).toMatchObject({question:"고친 질문",target:{connections}});
    await waitFor(()=>expect(useInvStore.getState().get("i1").followUpDraft).toBeNull());
  });
  it("drops the connection list once the analyst edits the addresses",async()=>{
    const api=mockApi(routes({"POST /investigations/i1/follow-ups":[201,{id:"fu1"}]}));
    renderUI(<ChecksTab inv="i1"/>);fireEvent.click(await screen.findByRole("button",{name:"이 확인에서 후속확인 만들기"}));
    await waitFor(()=>expect((screen.getByLabelText("목적지 IP") as HTMLInputElement).value).toBe("10.0.1.1, 10.0.1.2"));
    fireEvent.change(screen.getByLabelText("목적지 IP"),{target:{value:"10.0.1.1"}});
    fireEvent.click(screen.getByRole("button",{name:"후속확인 요청 등록"}));
    await waitFor(()=>expect(api.find("POST","/investigations/i1/follow-ups")).toHaveLength(1));
    expect(api.find("POST","/investigations/i1/follow-ups")[0].body.target).toMatchObject({dst_ips:["10.0.1.1"],connections:[]});
  });
});
