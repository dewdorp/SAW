import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { HttpResult } from "../../components/analysis";
import { ErrorBox, Loading } from "../../components/common";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

export function HttpPage() {
  const loc = useLocation() as { state?: { input?: string } };
  const [req, setReq] = useState(loc.state?.input || "");
  const [resp, setResp] = useState("");
  const m = useMutation({ mutationFn: () => api.post("/analyze/http", { request: req, response: resp || null }) });
  useEffect(() => { if (loc.state?.input) m.mutate(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="HTTP 요청 분석" desc="헤더와 파라미터를 분해하고 인증 정보 등 민감한 값은 마스킹합니다." />
      <AnalyzeNav />
      <div className="grid2">
        <textarea className="input" rows={8} placeholder="HTTP Request (raw / curl / HTTP/2 / HAR)" value={req} onChange={(e) => setReq(e.target.value)} />
        <textarea className="input" rows={8} placeholder="HTTP Response (선택)" value={resp} onChange={(e) => setResp(e.target.value)} />
      </div>
      <div className="row" style={{ margin: "8px 0" }}><button className="btn primary" disabled={!req.trim() || m.isPending} onClick={() => m.mutate()}>Analyze HTTP</button></div>
      {m.isPending && <Loading />}
      <ErrorBox error={m.error} />
      {m.data && <HttpResult r={m.data} />}
    </div>
  );
}
