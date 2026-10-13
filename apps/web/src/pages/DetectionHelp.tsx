import { Link } from "react-router-dom";
import { Panel } from "../components/common";

export const EXAMPLE_SIGMA = `title: Possible Repeated Restricted Export
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem: /saw-demo/restricted-export
    cs-method: POST
    sc-status: 200
  condition: selection
falsepositives:
  - Approved scheduled export task
level: medium
tags: []
`;
export const EXAMPLE_THRESHOLD = { group_by: ["src_ip"], timespan_sec: 600, count_gte: 5 };
export const EXAMPLE_TESTS = [
  { expected: "match", event: { data_source: "web", url_path: "/saw-demo/restricted-export", method: "POST", status_code: 200 } },
  { expected: "no_match", event: { data_source: "web", url_path: "/saw-demo/health", method: "GET", status_code: 200 } },
];

export function DetectionHelp() {
  return <div className="col">
    <Panel title="룰 등록부터 탐지까지">
      <p>기본 룰과 직접 작성하는 Sigma 룰은 등록 방법이 다릅니다. 먼저 어떤 자료의 어떤 행동을 확인할지 정하고 정상 업무와 구분할 조건을 적으세요.</p>
      <ol className="col small">
        <li><b>새 Sigma 룰 작성</b> — <Link to="/detections">탐지 룰 후보</Link>에서 새 룰을 만듭니다. 요청 경로·메서드·응답·반복 조건을 함께 사용하고 예시 경로를 실제 업무 기준으로 바꾸세요.</li>
        <li><b>구문 검사 후 저장</b> — 지원하는 Sigma 조건인지 확인합니다. 수정하면 새 버전의 초안으로 돌아가며 이전 승인을 물려받지 않습니다.</li>
        <li><b>일치 예제와 정상 예제 등록</b> — 잡아야 하는 기록과 잡히면 안 되는 평범한 기록을 함께 넣습니다. 예제는 합성 자료를 권장합니다.</li>
        <li><b>접근 가능한 과거 자료로 시험</b> — 실제 비교 자료의 일치 건수·정상 사례·누락·실행 상한을 확인합니다. 구문 검사 성공은 탐지 정확도 검증과 다릅니다.</li>
        <li><b>작성자와 다른 Senior/Manager가 현재 버전 승인</b> — 완전한 시험을 통과해야 합니다. 승인된 지원 Sigma 룰은 이후 조사 분석에 적용됩니다.</li>
        <li><b>조사에서 재분석 후 근거 확인</b> — 분석 결과의 룰 ID·버전과 일치 원문을 확인합니다. 룰이 일치해도 공격 성공이나 정탐으로 자동 확정하지 않습니다.</li>
      </ol>
      <p className="small">외부 SIEM·탐지 장비에는 자동 배포하지 않습니다. 파일을 내보내 검토한 뒤 기존 변경 절차로 사람이 배포하고, 이 화면에는 배포 사실만 기록합니다.</p>
    </Panel>
    <Panel title="기본 룰은 어디에 있나요?">
      <div style={{ overflowX: "auto" }}><table className="t"><thead><tr><th>종류</th><th>관리 위치</th><th>적용 방법</th></tr></thead><tbody>
        <tr><td>웹 시그니처</td><td><code>saw/detectors/packs/web_signatures.yaml</code></td><td>match/all/regex·examples/benign 추가 → 합성 시험 → 검토 → 재시작. 기존 자료는 다시 처리해야 새 태그가 생깁니다.</td></tr>
        <tr><td>공격 흐름</td><td><code>saw/detectors/packs/scenarios.yaml</code></td><td>같은 개체의 단계·순서·시간 범위를 정의하고 시험합니다.</td></tr>
        <tr><td>NDR 기준</td><td><code>saw/detectors/packs/ndr_policies.yaml</code></td><td>내부망·업무시간·허용 포트·전송량을 조직 기준으로 검토한 뒤 켭니다. 기본은 꺼짐입니다.</td></tr>
        <tr><td>기본 행동 탐지기</td><td>서버 Python 코드</td><td>목록 내보내기는 ID·버전·지원 자료 설명입니다. 구현 코드 전체를 담은 범용 룰 파일은 아닙니다.</td></tr>
      </tbody></table></div>
      <p className="small">기본 파일 변경은 검토된 배포 변경입니다. 내보낸 JSON/YAML을 올리는 것만으로 서버 룰이 자동 바뀌지는 않습니다.</p>
    </Panel>
    <Panel title="예시: 짧은 시간에 제한 자료를 반복 조회">
      <p className="small">아래는 가상 경로 예시입니다. 같은 출발지가 10분에 5번 이상 조건을 만족하면 검토 대상으로 삼습니다. 승인된 배치·백업과 정상 운영 요청을 먼저 비교하세요. HTTP 200만으로 유출을 확정하지 않습니다.</p>
      <pre className="mono small" style={{ whiteSpace: "pre-wrap" }}>{EXAMPLE_SIGMA}</pre>
      <p className="small">반복 조건(SAW): <code>{JSON.stringify(EXAMPLE_THRESHOLD)}</code></p>
      <p className="small">차단된 악성 시도는 차단되었다는 이유로 오탐이 되지 않습니다. 시간 상한에 걸렸거나 원문이 부족하면 판단을 보류하고 범위를 나눠 시험하세요.</p>
    </Panel>
    <Panel title="파일로 확인하기">
      <p className="small"><Link to="/detections/catalog">기본 탐지 목록</Link>에서 전체 조건·예제·정상 예제·현재 켜짐 상태를 JSON/YAML로 받을 수 있습니다. 후보 목록에서는 현재 사용자 룰 묶음 JSON을, 개별 룰에서는 원본 룰을 내려받습니다. 개별 원문에는 SAW의 반복 조건·예외가 없으므로 전체 조건은 묶음 JSON을 함께 확인하세요. 과거 시험 원문·이벤트는 묶음에 포함하지 않습니다. 내보내기는 승인 상태를 바꾸지 않습니다.</p>
    </Panel>
  </div>;
}
