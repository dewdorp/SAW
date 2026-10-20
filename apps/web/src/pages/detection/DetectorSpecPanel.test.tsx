import { cleanup, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { renderUI } from "../../test/helpers";
import { DetectorSpecPanel } from "./DetectorSpecPanel";
afterEach(cleanup);
it("renders actual string provenance scopes and reviewed versus legacy attribution",()=>{
 const spec={id:"fw.observation",title:"합성",version:"1",engine:{version:"1"},parameters:[{key:"enabled",type:"boolean",label:"사용",unit:"boolean",default:true}],defaults:{enabled:true},grouping:[],window:{kind:"fixed_utc",boundary:"[start,end)"},prerequisites:[],examples:[],benign_examples:[],follow_up:[],limits:{}};renderUI(<DetectorSpecPanel spec={spec} effective={{values:{enabled:false},per_value_source:{enabled:{scope:"org",policy_version_id:"pv1",provenance:"reviewed_draft"}}}}/>);expect(screen.getByRole("row",{name:/사용.*켜짐.*꺼짐.*관계사.*pv1/})).toBeTruthy();
});
