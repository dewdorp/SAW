# SAW — 작업자(AI 포함) 안내

먼저 [STATE.md](STATE.md)에서 현재 작업과 최신 배포·검증 범위를 확인하고, [docs/HANDOVER.md](docs/HANDOVER.md)를 끝까지 읽으세요. HANDOVER의 날짜별 기록과 과거 실행 경로는 이력이며 현재 우선순위는 STATE를 따릅니다.

## 꼭 지킬 것 (요약 — 자세한 것은 HANDOVER 4절)

- 사용자에게는 **쉬운 한글**로 답합니다. 화면 문구는 한글, 코드·주석·커밋 메시지는 영어.
- `var/objects`의 NDR CSV와 개발 OpenSearch의 조사 `INV-20261008-001`은 **실제 은행 자료**입니다. 내용을 출력·인용·복사하지 말고 건수·필드 이름·규칙 id만 다룹니다. 시험과 표본에는 가상 자료만 씁니다.
- 비밀번호·토큰을 대화나 문서에 적지 않습니다(`var/dev-credentials.json`, `var/infra/secrets/`에서 읽어 쓰기만).
- 사용자 계정(`qa-manager` 등)으로 로그인하지 않습니다. 화면 확인은 `claude-check` 계정이나 자동 시험으로.
- 라이선스 없는 외부 코드와 외부 규칙 묶음을 그대로 가져오지 않습니다.
- 삭제·내려받기는 사용자가 요청했을 때만. 작업 단계별 커밋은 승인된 진행 방식입니다.
- 줄 끝 문자가 파일마다 다릅니다: 고치기 전에 `git ls-files --eol <파일>`로 확인하고 유지합니다(`sed -i`는 CRLF를 LF로 바꿉니다).
- 셸 heredoc은 역슬래시(`\n`, `\\`)를 망가뜨립니다. 역슬래시가 든 내용은 편집 도구나 패치 스크립트 파일로 고칩니다.
- 마이그레이션은 멱등으로(테이블이 있으면 건너뛰기), 기능마다 시험을 함께.
- 한 일과 확인한 방법을 구분해서 보고합니다: 실제로 돌려 본 것 / 자동 시험만 한 것 / 확인하지 못한 것.

## 시험

```bash
.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider      # 서버 (약 4분)
cd apps/web && pnpm vitest run && pnpm tsc --noEmit                  # 화면
```

## 지금 가장 먼저 할 일

[STATE.md](STATE.md)의 현재 작업 범위부터 확인하세요. 통합 브랜치 codex/updater-stabilization-20261019에서 코드와 개발기 실제 업데이트·복구 검증을 완료했습니다. 최종 서버1,733통과·6건너뜀, 웹177통과이며 후보7 실제 업데이트492.39초·복구497.54초와 계정·자료 보존을 확인했습니다. 현재 새 전체 ZIP 봉인·PR·비공개 사전 배포를 진행합니다. 대상 LTSC2019의 실제 관리자 서비스·재부팅 인수는 미검증입니다. 과거 후보6 권한 조회4건의 정확한 원인은 미확정으로 유지합니다.

[새 사용자 안내](docs/UPDATER-STABILIZATION-GUIDE-20261019.md), [24단계 흐름 감사](docs/verification/updater-flow-audit-20261019.md), [현장 읽기 전용 점검](docs/verification/updater-native-acceptance-20261019.md)을 함께 확인하세요. HANDOVER의 날짜별 기록은 과거 검증 범위이며 현재 완료 근거로 재사용하지 않습니다. 원본 F:/claude/saw, 운영 C:/SAW·D:/SAW-0.1.0, 운영 자료·계정은 보존합니다.
