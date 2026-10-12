import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { Me } from "../App";
import { Empty, ErrorBox, Loading, Panel } from "../components/common";
import { PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { aiError } from "../lib/aiErrors";
import { fmtBytes, fmtTime } from "../lib/format";

type LocalModel = {
  pack_id: string; model_id: string; revision: string; checkpoint_kind: string;
  prompt_format: string; quantization: string; manifest_sha256: string; status: string;
  synthetic_only: boolean; validated_at: string; actual_inference: string; detail: string;
};
type Catalog = {
  active_pack_id: string | null;
  runtime: { configured: boolean; verified: boolean; version: string; detail: string };
  limits: { threads: number; context: number; max_new_tokens: number; max_seconds: number; max_memory_bytes: number };
  models: LocalModel[]; synthetic_only: boolean;
};
type Change = { action: "validate"; pack_id: string } | { action: "activate"; pack_id: string; reason: string } | { action: "deactivate"; reason: string };

export function LocalModels({ me }: { me: Me }) {
  const allowed = me.permissions.includes("ai.models.manage");
  const qc = useQueryClient();
  const [pack, setPack] = useState("");
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const catalog = useQuery<Catalog>({ queryKey: ["local-models"], queryFn: () => api.get("/admin/local-models"), enabled: allowed });
  const change = useMutation({
    mutationFn: ({ action, ...body }: Change) => api.post(`/admin/local-models/${action}`, body),
    onMutate: () => setNotice(""),
    onSuccess: async (_data, change) => {
      setNotice(change.action === "validate" ? "파일 검증 등록이 완료되었습니다. 실제 추론 여부는 아래 상태를 확인하세요."
        : change.action === "activate" ? "합성 추론 확인 후 모델을 선택했습니다. 운영 품질을 채택한 것은 아닙니다." : "모델 선택을 해제했습니다.");
      if (change.action !== "validate") setReason("");
      await Promise.all([qc.invalidateQueries({ queryKey: ["local-models"] }), qc.invalidateQueries({ queryKey: ["ai-status"] })]);
    },
  });
  if (!allowed) return <div className="page"><Empty>로컬 모델 관리 권한이 필요합니다.</Empty></div>;
  const data = catalog.data;
  const reasonValid = reason.trim().length >= 5 && reason.trim().length <= 512;
  const packValid = /^[a-z0-9][a-z0-9_-]{0,63}$/.test(pack.trim());
  return (
    <div className="page col">
      <PageHeader eyebrow="관리" title="로컬 모델 관리" desc="별도로 반입한 모델을 검증하고 CPU 합성 시험용으로 선택합니다." />
      <Panel title="사용 범위">
        <div className="col small">
          <strong>합성 데이터 전용 · 운영 품질 미채택</strong>
          <span>파일 검증, 실제 추론 실행, 분석 품질 채택은 서로 다른 단계입니다. 선택된 모델도 사람이 결과를 검토해야 합니다.</span>
          <span>모델 파일은 서버의 지정된 models inbox 폴더에 별도로 반입합니다. 이 화면에는 묶음 ID만 입력합니다.</span>
        </div>
      </Panel>
      <ErrorBox error={aiError(catalog.error)} />
      {catalog.isLoading && <Loading />}
      {data && <>
        <Panel title="실행 환경">
          <div className="col small">
            <div className="row wrap"><span className={`tag ${data.runtime.configured ? "ok" : "warn"}`}>{data.runtime.configured ? "실행 파일 설정됨" : "실행 파일 미설정"}</span>
              <span className={`tag ${data.runtime.verified ? "ok" : "warn"}`}>{data.runtime.verified ? "런타임 확인됨" : "런타임 미확인"}</span>
              <span className="mono">{data.runtime.version}</span></div>
            <span>{data.runtime.detail}</span>
            <span>CPU {data.limits.threads} 스레드 · 문맥 {data.limits.context} 토큰 · 출력 최대 {data.limits.max_new_tokens} 토큰 · 실행 최대 {data.limits.max_seconds}초 · 메모리 최대 {fmtBytes(data.limits.max_memory_bytes)}</span>
          </div>
        </Panel>
        <Panel title="반입 모델 검증">
          <form className="col" onSubmit={(e) => { e.preventDefault(); if (packValid && !change.isPending) change.mutate({ action: "validate", pack_id: pack.trim() }); }}>
            <label className="col small">반입 묶음 ID<input className="input" value={pack} maxLength={64} aria-describedby="model-pack-help" onChange={(e) => setPack(e.target.value)} /></label>
            <span id="model-pack-help" className="muted small">지정된 inbox 안의 묶음 이름: 소문자 영문·숫자로 시작하며 밑줄·하이픈을 포함할 수 있는 1~64자. 파일 경로는 입력하지 않습니다.</span>
            <div><button className="btn" disabled={!packValid || change.isPending}>검증 등록</button></div>
          </form>
        </Panel>
        <Panel title="모델 선택">
          <div className="col">
            <div className="row wrap"><span className="small">현재 선택</span><strong className="mono" style={{ minWidth: 0, overflowWrap: "anywhere" }}>{data.active_pack_id || "선택된 모델 없음"}</strong></div>
            <label className="col small">선택·해제 사유<textarea className="input" rows={2} value={reason} maxLength={512} aria-describedby="model-reason-help" onChange={(e) => setReason(e.target.value)} /></label>
            <span id="model-reason-help" className="muted small">앞뒤 공백을 제외한 5~512자를 입력하세요. 선택 전 고정 합성 입력으로 실제 추론을 확인하며, 실패하면 이전 선택을 유지합니다.</span>
            <div><button className="btn" disabled={!data.active_pack_id || !reasonValid || change.isPending} onClick={() => change.mutate({ action: "deactivate", reason: reason.trim() })}>모델 선택 해제</button></div>
            {change.isPending && <span className="small" role="status">요청 처리 중… 합성 추론 확인은 최대 {data.limits.max_seconds}초 걸릴 수 있습니다.</span>}
            {notice && <div className="small" role="status">{notice}</div>}
            <ErrorBox error={aiError(change.error)} />
          </div>
        </Panel>
        <Panel title={`검증 등록된 모델 (${data.models.length})`}>
          {!data.models.length ? <Empty>검증 등록된 모델이 없습니다. 반입 묶음 ID로 먼저 검증하세요.</Empty> : <div className="col">{data.models.map((model) => {
            const active = data.active_pack_id === model.pack_id;
            const verified = model.status === "FILES_VERIFIED";
            return <article key={model.pack_id} aria-label={`모델 ${model.pack_id}`} className="panel">
              <div className="ph"><strong className="grow mono" style={{ minWidth: 0, overflowWrap: "anywhere" }}>{model.pack_id}</strong>{active && <span className="tag ok">현재 선택됨</span>}</div>
              <div className="pb col small">
                <div className="row wrap"><span className={`tag ${verified ? "ok" : "warn"}`}>{verified ? "파일 검증 완료" : "파일 검증 확인 필요"}</span>
                  <span className={`tag ${model.actual_inference === "EXECUTED" ? "ok" : "warn"}`}>{model.actual_inference === "EXECUTED" ? "실제 추론 실행됨" : "실제 추론 미실행"}</span></div>
                <dl className="col" style={{ margin: 0, gap: 8 }}>
                  {[["모델", model.model_id], ["고정 버전", model.revision], ["학습 형식", model.checkpoint_kind === "INSTRUCT" ? "지시 학습형" : "기본 학습형"], ["프롬프트 형식", model.prompt_format], ["양자화", model.quantization], ["검증 시각", fmtTime(model.validated_at)]].map(([label, value]) =>
                    <div key={label} style={{ display: "grid", gridTemplateColumns: "minmax(72px, 0.4fr) minmax(0, 1fr)", gap: 12 }}>
                      <dt className="muted">{label}</dt><dd style={{ margin: 0, minWidth: 0, overflowWrap: "anywhere", whiteSpace: "normal" }}>{value}</dd>
                    </div>)}
                </dl>
                <div>검증 명세 SHA-256<div className="mono" style={{ overflowWrap: "anywhere" }}>{model.manifest_sha256}</div></div>
                <span>{model.detail}</span>
                <div><button className="btn" disabled={active || !verified || !model.synthetic_only || !data.synthetic_only || !data.runtime.configured || !reasonValid || change.isPending}
                  onClick={() => change.mutate({ action: "activate", pack_id: model.pack_id, reason: reason.trim() })}>합성 시험용으로 선택</button></div>
              </div>
            </article>;
          })}</div>}
        </Panel>
      </>}
    </div>
  );
}
