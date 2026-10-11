import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { PayloadResult } from "../../components/analysis";
import { ErrorBox, Loading } from "../../components/common";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

const OPS = ["url_decode", "base64", "base64url", "hex", "unicode_escape", "html_entity", "gzip", "deflate", "ps_encoded", "jwt"];

export function PayloadPage() {
  const loc = useLocation() as { state?: { input?: string } };
  const [text, setText] = useState(loc.state?.input || "");
  const [chain, setChain] = useState<string[]>([]);
  const m = useMutation({ mutationFn: (c: string[] | null) => api.post("/analyze/payload", { input: text, chain: c }) });
  useEffect(() => { if (loc.state?.input) m.mutate(null); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="페이로드 디코딩" desc="URL·Base64·Hex 등 인코딩을 단계별로 풀고 공격 패턴을 표시합니다." />
      <AnalyzeNav />
      <textarea className="input" rows={6} value={text} onChange={(e) => setText(e.target.value)} placeholder="%252e%252e%252f, Base64, JWT, PowerShell -enc …" />
      <div className="row wrap" style={{ margin: "8px 0" }}>
        <button className="btn primary" disabled={!text.trim()} onClick={() => m.mutate(null)}>자동 디코딩</button>
        <span className="muted small">수동 체인:</span>
        {OPS.map((o) => <button key={o} className="btn sm" onClick={() => setChain([...chain, o])}>+{o}</button>)}
        {chain.length > 0 && <><span className="mono small">{chain.join(" → ")}</span><button className="btn sm" onClick={() => m.mutate(chain)}>체인 적용</button><button className="btn sm ghost" onClick={() => setChain([])}>지우기</button></>}
      </div>
      {m.isPending && <Loading />}
      <ErrorBox error={m.error} />
      {m.data && <PayloadResult r={m.data} />}
    </div>
  );
}
