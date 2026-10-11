# 웹 탐지 규칙의 근거와 해석 범위

확인일: 2026-10-11. 대상: `web_extended_signatures.yaml`의 직접 작성 규칙 18개와 `web_signatures.yaml`의 기존 규칙 4개.

외부 규칙 묶음·실행 코드를 가져오지 않았다. 아래 공개 문서에서 경로·메서드·제품 동작만 확인해 이 저장소 형식으로 직접 작성했다. YAML의 예시는 가상 문자열이며 실행하거나 외부 서버로 보내지 않는다.

## 공통 해석

- 제목의 가능성(Possible)은 조사 후보라는 뜻이다. 실제 제품인지, 인증됐는지, 승인된 관리 작업인지는 요청 한 줄로 알 수 없다.
- 관리 API 호출에 CVE 번호를 붙이지 않는다. 경로가 정상이더라도 민감한 기능이므로 승인 계정·출발지·변경 일정과 비교할 수 있도록 표시한다.
- 2xx는 응답 코드 관찰값이다. 응답 내용, 서버 프로세스·감사 기록 없이 공격 성공·파일 유출·설정 변경을 확정하지 않는다. 4xx·5xx·응답 누락 역시 WAF 차단의 증명이 아니다.
- 현재 엔진은 URI·메서드·User-Agent 등 제한된 필드를 비교한다. 임의 헤더·쿠키·요청 본문을 추가로 읽지 않으므로 그 안에만 있는 악용 구문은 이 규칙으로 확인하지 못한다.
- 제품이 하위 경로에 설치되거나 중계 장비가 경로를 바꾸면 누락될 수 있다. 일반 단어만으로 경로를 넓히지 않았다. 메서드가 없는 기록은 메서드 조건이 있는 새 규칙에 일치하지 않는다.
- `benign`은 해당 규칙에 일치하면 안 되는 경계 예시다. 정상 운영에서 민감 API를 정확히 호출하면 해당 규칙에 일치할 수 있으므로 운영 승인 확인이 필요하다.

## 새 규칙 18개

| 규칙 ID | 공식 근거 | 반영한 조건과 한계 |
|---|---|---|
| `webext.teamcity_rpc2` | [FBI·CISA AA23-347A 부록 A, 25쪽](https://www.ic3.gov/CSA/2023/231213.PDF) | 사용자 번호와 RPC2 토큰 경로, POST·DELETE. 문서가 관련 경로로 명시한다. 토큰 이름만 같을 가능성, 제품 버전·인증 확인 필요. |
| `webext.ivanti_epmm_users` | [CISA·NCSC-NO AA23-213A](https://www.cisa.gov/sites/default/files/2023-08/aa23-213a_joint_csa_threat_actors_exploiting_ivanti_eppm_vulnerabilities_1.pdf) | GET /mifs/aad/api/v2/authorized/users. 권고가 공격 중 계정 열람에 쓰인 경로로 명시한다. 성공·인증 우회 자체는 확정하지 않음. |
| `apiuse.teamcity_process` | [FBI·CISA AA23-347A 부록 A, 25쪽](https://www.ic3.gov/CSA/2023/231213.PDF) | POST /app/rest/debug/processes. 프로세스 실행 관련 경로이나 관리자 기능 자체에 CVE를 붙이지 않음. |
| `apiuse.docker_create` | [Docker Engine API 변경 이력](https://docs.docker.com/reference/api/engine/version-history/) | POST /containers/create, 선택적 API 버전. 정상 생성 요청도 동일하며 본문의 이미지·권한·마운트 미확인. |
| `apiuse.docker_exec` | [Docker Engine API 변경 이력, v1.35·v1.24](https://docs.docker.com/reference/api/engine/version-history/) | POST /containers/{id}/exec. 실행 인스턴스 준비이므로 별도 시작 요청·프로세스 확인 필요. |
| `apiuse.docker_archive_read` | [Docker Engine API 변경 이력, v1.20](https://docs.docker.com/reference/api/engine/version-history/) | GET archive와 계정 파일·SSH 키 디렉터리·proc 환경 경로를 결합. 문서는 파일 읽기 기능을 뒷받침하며 민감 경로 선정은 이 프로젝트의 탐지 판단. |
| `apiuse.docker_archive_write` | [Docker Engine API 변경 이력, v1.20](https://docs.docker.com/reference/api/engine/version-history/) | PUT archive. 정상 파일 복사와 구별하려면 본문 파일 목록과 변경 결과 필요. |
| `apiuse.etcd_range` | [etcd gRPC gateway: Put and get keys](https://etcd.io/docs/v3.5/dev-guide/api_grpc_gateway/) | POST /v3/kv/range. 범위는 본문에 있으므로 대량 조회라고 부르지 않음. |
| `apiuse.etcd_auth_disable` | [etcd 공식 HTTP API 명세, AuthDisable](https://github.com/etcd-io/etcd/blob/main/Documentation/dev-guide/apispec/swagger/rpc.swagger.json) | POST /v3/auth/disable. 인증 해제 API에 대한 요청이며 실제 설정 변경은 감사·설정 확인 필요. |
| `apiuse.consul_service_register` | [Consul 서비스 등록 API](https://developer.hashicorp.com/consul/api-docs/agent/service#register-service) | PUT /v1/agent/service/register. 정상 등록도 일치하며 본문에 스크립트가 있다고 추정하지 않음. |
| `apiuse.consul_acl_bootstrap` | [Consul ACL bootstrap](https://developer.hashicorp.com/consul/api-docs/acl#bootstrap-acls) | PUT /v1/acl/bootstrap. 초기 관리 토큰 발급 절차이며 정상 설치·복구 확인 필요. |
| `apiuse.nomad_exec` | [Nomad Exec Allocation](https://developer.hashicorp.com/nomad/api-docs/allocations#exec-allocation) | 전체 UUID와 exec 경로, command 배열을 결합한 GET WebSocket 요청. 101 전환만으로 실행 성공 확인 불가. |
| `apiuse.vault_raw_read` | [Vault /sys/raw](https://developer.hashicorp.com/vault/api-docs/system/raw) | GET /v1/sys/raw/{path}. 기본 비활성인 내부 저장소 API이며 정상 복구와 구분 필요. |
| `apiuse.vault_root_generate` | [Vault /sys/generate-root](https://developer.hashicorp.com/vault/api-docs/system/generate-root) | POST attempt 또는 update. 생성 시작·조각 제출과 최종 토큰 발급은 다름. |
| `apiuse.webhdfs_privileged_read` | [Apache WebHDFS Authentication·Open and Read a File](https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-hdfs/WebHDFS.html) | GET /webhdfs/v1/와 op=OPEN, user.name=hdfs 또는 root의 정확한 매개변수 경계. 보안 설정이 꺼진 경우의 사용자 식별 방식에 근거하며 사칭 여부는 확인 필요. |
| `apiuse.yarn_submit` | [Apache YARN Submit Application](https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html#Cluster_Applications_APISubmit_Application) | POST /ws/v1/cluster/apps. 202는 작업 제출 단계이며 실행·침해 확정 아님. |
| `wrapper.php_filter` | [PHP php://filter](https://www.php.net/manual/en/wrappers.php.php), [변환 필터](https://www.php.net/manual/en/filters.convert.php) | 파일·페이지 매개변수의 base64 변환+resource 구문. 검색·설명 매개변수는 제외. 사용자 입력을 파일 처리에 쓰는지 확인 필요. |
| `wrapper.php_expect` | [PHP expect://](https://www.php.net/manual/en/wrappers.expect.php) | 파일·페이지 매개변수의 expect:// 값. Expect 확장이 필요하고 기본 비활성이므로 구문만으로 실행 확정 불가. |

## 기존 4개 규칙 교정

규칙 ID는 저장된 평가·끄기 설정을 보존하기 위해 유지했다. 제목·설명은 경로 접근 가능성으로 바꾸고 CVE 필드는 제거했다. 관련 CVE는 추가 확인을 위한 설명에만 남겼다. 단계 DISCOVERY, 신뢰도 low, 위험도 0.35~0.45이며 부분 문자열 대신 경로 경계를 확인한다.

| 기존 ID | 교정 근거 |
|---|---|
| `rce.spring_cloud_function` | [Spring 권고](https://spring.io/security/cve-2022-22963/)와 [Red Hat 기술 설명](https://access.redhat.com/security/cve/cve-2022-22963)은 악성 라우팅 표현식이 필요함을 밝힌다. /functionRouter 자체는 정상 라우팅 경로다. |
| `rce.f5_icontrol` | [F5 공식 API 예시](https://clouddocs.f5.com/api/iapps/AppSvcsiApp_userguide_module5_lab1.html), [CISA AA22-138A](https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf). 관리 경로 자체로 인증 우회를 증명할 수 없으며 인증·연결 헤더와 본문·감사 기록이 필요하다. |
| `rce.fortinet_auth_bypass` | [Fortinet 정상 REST 관리자 조회 안내](https://community.fortinet.com/fortigate-3/technical-tip-how-to-show-super-admin-user-via-rest-api-admin-149554)는 같은 /api/v2/cmdb/system/admin 경로를 사용한다. 경로만으로 CVE-2022-40684를 판정하지 않는다. |
| `rce.panos_2024_3400` | [Palo Alto Networks 권고](https://security.paloaltonetworks.com/CVE-2024-3400)는 비정상 세션 값과 파일 경로·내장 명령, 장비 로그의 추가 조사를 안내한다. 정상 HIP 보고 경로만으로 명령 주입을 판정하지 않는다. |

F5·Fortinet 일부 보안 권고 페이지는 웹 조회에서 CSS 오류·403으로 본문 확인이 제한됐다. F5는 CISA 문서의 검색 색인과 공식 API 문서, Fortinet은 벤더의 정상 REST 사용 안내로 교정 근거를 보완했다. 확인하지 못한 헤더 조합이나 공격 본문을 새 조건으로 추정해 추가하지 않았다.

## 시험 범위

가상 입력만 사용한다. 규칙별 examples·benign은 기존 자동 예시 시험에 포함된다. `tests/unit/test_generic_web_signatures.py`는 새 18개 요청, 메서드·문서 경로 경계, 기존 4개의 낮은 신뢰도와 CVE 비단정, 평범한 매개변수·PHP 문서 예시 비일치를 추가 확인한다.

실제 제품 실행, 실제 공격 재현, 은행 자료 재생, 화면 수동 확인은 이 작업의 규칙 검증에 포함하지 않는다. 전체 시스템·성능 검증 결과는 상위 작업의 별도 보고를 따른다.
