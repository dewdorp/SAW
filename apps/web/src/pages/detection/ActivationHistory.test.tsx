import { cleanup, fireEvent, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { mockApi, renderUI } from "../../test/helpers";
import { ActivationHistory } from "./ActivationHistory";
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it("loads bounded immutable activation receipts on demand and preserves exact restored IDs",async()=>{
 const api=mockApi({"GET /detection-policies/b1/activations":call=>[200,{items:[{id:call.url.includes("before_revision")?"a1":"a2",revision:call.url.includes("before_revision")?1:2,action:"rollback",from_version_id:"v2",to_version_id:"original-v1",approval_id:"approval-v1",reason:"합성 복구",actor_name:"독립 검토자"}],next_cursor:call.url.includes("before_revision")?null:2}]});renderUI(<ActivationHistory path="/detection-policies/b1" revision={2}/>);
 expect(api.calls).toHaveLength(0);fireEvent.click(screen.getByText("SAW 적용·복구 이력"));await screen.findByText("original-v1");fireEvent.click(screen.getByRole("button",{name:"이전 적용 이력 더 보기"}));await screen.findByText("적용 이력 2건");expect(api.find("GET","/detection-policies/b1/activations")[1].url).toContain("before_revision=2");
});
