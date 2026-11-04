export type PracticeEvidence = {
  id: string; source: string; summary: string;
  fields?: Record<string, string | number | boolean | null>;
};
export type PracticeStage = {
  id: string; title: string; observation?: string; evidence: PracticeEvidence[]; question: string;
  options: { id: string; text: string; explanation: string }[];
  correctId: string; rationale: string; nextCheck?: string;
};
export type PracticeCase = {
  id: string; title: string; summary?: string; sources: string[];
  initial: PracticeStage; followups: PracticeStage[];
};
export type PracticePack = { version: string; cases: PracticeCase[] };

// The release contains this module. Loading it does not query or write an investigation.
export async function loadBundledPack(): Promise<PracticePack> {
  const { default: pack } = await import("./practice-cases.json");
  return pack as unknown as PracticePack;
}

export function conclusion(stage: PracticeStage, topic: string) {
  const example = stage.options.find(o => o.id === stage.correctId)?.text;
  if (!example) return stage.rationale.split(" 근거 참조:")[0];
  // Use the level of certainty supported by these specific source records.
  if (stage.evidence[0]?.source === "DNS 질의 기록") return "긴 임의 문자열 하위 도메인이 반복된다. 터널링 가설을 열어 두고 질의를 만든 프로세스와 질의 내용을 대조한다. 이 자료만으로 반출이나 감염을 확정할 수 없다.";
  if (stage.evidence[0]?.source === "DB 감사 기록" && example.includes("영향 없음")) return "해당 DB와 관측 구간에서 질의가 오류로 종료됐고 반환된 행은 없다. 다른 DB나 서비스 영향은 이 자료로 판단할 수 없다.";
  if (stage.evidence[0]?.source === "서버 파일 목록" && example.includes("파일 삭제")) return "해당 파일이 실행되지 않는 경로에 저장됐다. 파일 실행은 확인되지 않았으며, 파일 내용과 업로드 승인 여부를 별도로 확인한다.";
  if (stage.id.endsWith("-initial") && example.includes("장비 시각대 설정 차이로 보고")) return example.replace("장비 시각대 설정 차이로 보고 시각을 맞춘 뒤 대조한다.", "장비 시간대 차이가 후보 원인이다. 원본 시각과 포트를 보존한 채 장비 설정을 확인한다.");
  if (stage.id.endsWith("-initial") && topic.endsWith("외부 DNS로의 잦은 질의")) return example.replace(/(\d+)번 질의했다/, "$1건의 UDP 53 통신이 기록됐다");
  return example;
}

