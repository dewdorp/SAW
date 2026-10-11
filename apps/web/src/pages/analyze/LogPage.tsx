import { useMutation, useQuery } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { LogSummary } from "../../components/analysis";
import { ErrorBox, Loading } from "../../components/common";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

export function LogPage() {
  const loc = useLocation() as { state?: { input?: string } };
  const [text, setText] = useState(loc.state?.input || "");
  const [parser, setParser] = useState("");
  const parsers = useQuery({ queryKey: ["parsers"], queryFn: () => api.get("/parsers") });
  const m = useMutation({ mutationFn: () => api.post("/analyze/log", { text, parser_id: parser || null }) });
  useEffect(() => { if (loc.state?.input) m.mutate(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="로그 분석" desc="로그 형식을 자동 판별하고 상위 값과 반복 패턴을 요약합니다." />
      <AnalyzeNav />
      <textarea className="input" rows={8} value={text} onChange={(e) => setText(e.target.value)} placeholder="로그 라인 붙여넣기 (≤ 5 MB). 대용량은 Upload 사용" />
      <div className="row" style={{ margin: "8px 0" }}>
        <select className="input" value={parser} onChange={(e) => setParser(e.target.value)}><option value="">파서 자동 감지</option>{(parsers.data || []).map((p: any) => <option key={p.id} value={p.id}>{p.id}</option>)}</select>
        <button className="btn primary" disabled={!text.trim()} onClick={() => m.mutate()}>Analyze Log</button>
      </div>
      {m.isPending && <Loading />}
      <ErrorBox error={m.error} />
      {m.data && <LogSummary r={m.data} />}
    </div>
  );
}
