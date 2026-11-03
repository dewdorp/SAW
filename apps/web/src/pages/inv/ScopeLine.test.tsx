import {cleanup,render,screen} from "@testing-library/react";
import {afterEach,describe,expect,it} from "vitest";
import {ScopeSnapshot,dayRange} from "./ScopeSnapshot";
afterEach(cleanup);
const data={scope:{org_unit:"가상 B사",period_start:"2026-09-04T15:00:00Z",period_end:"2026-10-10T15:00:00Z",period_declared:true,observed_start:null,observed_end:null,timezone:"Asia/Seoul"},
  basis:{kind:"all",all_events:304,events:304},inputs:{files:2,by_file:[{parser_id:"en_ndr_http_csv",events:140},{parser_id:"en_fw_csv",events:164}],files_truncated:false},
  time:{daily:[],empty_days:[],without_timestamp:0},breakdown:{data_source:{buckets:[]}},analysis:{status:"complete",incomplete:[]}};
describe("data summary line",()=>{
  it("names affiliate, period, sources and the total in one line",()=>{
    render(<ScopeSnapshot data={data} error={null} openAll={()=>{}} openStats={()=>{}} openDetail={()=>{}}/>);
    expect(screen.getByLabelText("자료 요약").textContent).toBe("가상 B사2026년 9월 5일 ~ 10월 10일방화벽(FW) 164건 · NDR HTTP 140건전체 304건");
    expect(screen.getByRole("button",{name:"검토할 활동으로 이동"})).toBeTruthy();
  });
  it("an exclusive midnight end names the last included day, across years too",()=>{
    expect(dayRange("2025-12-30T15:00:00Z","2026-01-02T15:00:00Z")).toBe("2025년 12월 31일 ~ 2026년 1월 2일");
    expect(dayRange(null,null)).toBe("기간 미확인");
  });
});
