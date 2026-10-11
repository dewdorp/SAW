import { useMutation } from "@tanstack/react-query";
import { PageHeader } from "../../components/ui";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { IocCard } from "../../components/analysis";
import { ErrorBox, Loading } from "../../components/common";
import { api } from "../../lib/api";
import { AnalyzeNav } from "./UniversalPage";

export function IocPage() {
  const loc = useLocation() as { state?: { input?: string; observable?: string } };
  const [text, setText] = useState(loc.state?.observable || loc.state?.input || "");
  const m = useMutation({ mutationFn: (vals: string[]) => api.post("/analyze/ioc", { observables: vals }) });
  const run = () => m.mutate(text.split(/[\s,]+/).filter(Boolean).slice(0, 200));
  useEffect(() => { if (text) run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="page">
      <PageHeader eyebrow="빠른 분석" title="IOC 분석" desc="IP·도메인·URL·해시를 확인합니다. 내부 관측 이력을 먼저 보여 주며 외부 조회는 직접 실행할 때만 합니다." />
      <AnalyzeNav />
      <div className="row">
        <textarea className="input grow" rows={3} value={text} onChange={(e) => setText(e.target.value)} placeholder="IP / Domain / URL / Hash (여러 개는 줄바꿈·쉼표, 최대 200)" />
        <button className="btn primary" disabled={!text.trim()} onClick={run}>Analyze IOC</button>
      </div>
      <div className="muted small" style={{ margin: "6px 0" }}>내부 Context(우리 로그·과거 판단)를 먼저 보여줍니다. 분석 대상에 직접 접속하지 않습니다.</div>
      {m.isPending && <Loading />}
      <ErrorBox error={m.error} />
      <div className="grid-auto">{(m.data?.items || []).map((x: any, i: number) => <IocCard key={i} r={x} />)}</div>
    </div>
  );
}
