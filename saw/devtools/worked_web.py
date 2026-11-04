"""Synthetic, cross-source investigation exercises for the March observation week."""
from datetime import datetime, timedelta, timezone


def _case(n, title, category, classification, day, hour, host, trigger, pivot, comparison,
          judgement, next_check, rows, evidence, lead_field, narrow, reason):
    base = datetime(2025, 3, day, hour, 0, tzinfo=timezone(timedelta(hours=9)))
    def stamp(offset):
        return (base + timedelta(seconds=offset)).isoformat()
    public = f'198.51.100.{150+n}'
    server = f'10.80.{n}.20'
    host += '.example.test'
    events = []
    for seq, (offset, method, path, status, received) in enumerate(rows, 1):
        trace = f'w{n:02}-{seq}'
        client = (f'192.0.2.{150+n}' if (n in (13, 18, 21) and seq > 1) else public)
        events.append(dict(source='ndr', time=stamp(offset), src=client, dst=server,
                           sport=42000+n*10+seq, dport=443, proto='TCP', method=method,
                           path=path, host=host, query='trace='+trace, status=status,
                           cs=310+seq*23, sc=received, ua='SyntheticCaseClient/1.0'))
    followups = [dict(id=f'W{n:02}-E{i}', source=source,
                      fields=dict(time=stamp(offset), **fields))
                 for i, (offset, source, fields) in enumerate(evidence, 1)]
    values = {'src_ip': public, 'dst_ip': server, 'hostname': host, 'url_path': rows[0][2]}
    if isinstance(narrow, str):
        narrow = ('url_path', narrow)
    return dict(id=f'W{n:02}', title=title, classification=classification,
                category=category, trigger=trigger, pivot=pivot, comparison=comparison,
                judgement=judgement, next_check=next_check, events=events, followups=followups,
                lead=dict(source='ndr', field=lead_field, value=values[lead_field], basis=trigger),
                narrow=[dict(field=narrow[0], op='is', value=narrow[1])] if narrow else [],
                narrow_reason=reason)


def cases():
    w, a = '웹·API', '인증·계정'
    return [
        _case(7,'거래명세서 번호를 바꾼 조회',w,'침해 확인',3,9,'statements','09:01 고객 B가 명세서 접근 알림을 신고했다. 알림에 표시된 명세서 조회 경로로 검색한다.',
              '같은 조회 경로에서 정상 소유자 조회와 타인 조회를 분리하려고 서비스 요청번호를 확인했다.',
              'w07-1은 요청자와 소유자가 A다. w07-2에서 게이트웨이는 같은 요청자를 A로, 명세서 서비스는 응답 문서의 소유자를 B로 기록했다.',
              '09:00:12에 계정 A로 고객 B의 명세서 ST-72 한 건을 열람했다. 다운로드 보관 여부는 확인되지 않았다.',
              '객체 소유권 검사 누락을 차단하고 계정 A의 다른 명세서 응답도 같은 방식으로 대조한다.',
              [(1,'GET','/api/statements',200,2310),(12,'GET','/api/statements',200,2640),(19,'GET','/api/statements',404,180)],
              [(1,'명세서 서비스',dict(trace='w07-1',subject='A',owner='A',object_id='ST-71')),(12,'인증 게이트웨이',dict(trace='w07-2',session_subject='A')),(12,'명세서 서비스',dict(trace='w07-2',owner='B',object_id='ST-72',result='body_delivered',delegation='none'))], 'url_path',('status_code',200),'명세서 본문이 반환된 요청에서 요청번호와 문서 소유자를 비교한다.'),
        _case(8,'새 기기에서 등록한 복구 수단',a,'침해 확인',3,11,'members','11:02 회원 U8이 본인이 등록하지 않은 복구 수단 알림을 신고했다. 알림의 서비스 호스트를 조회한다.',
              '로그인 화면과 실제 인증 완료를 구분하고 복구 수단을 변경한 세션을 추적했다.',
              'w08-2로 발급한 S8이 w08-3의 변경 감사에도 남았다. 신원 확인을 마친 U8은 해당 로그인과 변경을 모두 부인했다.',
              'U8 세션 S8의 무단 로그인 및 복구 수단 변경을 확인했다. 변경 후 계정 사용 범위는 추가 조사 중이다.',
              'S8과 파생 세션을 철회하고 기존 인증 수단으로 소유자를 재확인해 복구한다.',
              [(1,'GET','/login',200,3200),(15,'POST','/login',302,340),(33,'POST','/profile/recovery',204,0)],
              [(15,'인증 서버',dict(trace='w08-2',account='U8',issued_session='S8',device='new-08')),(33,'회원 변경 감사',dict(trace='w08-3',session='S8',account='U8',change='recovery_method_added')),(125,'고객센터 본인확인',dict(ticket='CS-08',account='U8',denied_actions=['login','recovery_method_added']))], 'hostname',None,'로그인부터 변경까지 전 경로를 시간순으로 확인한다.'),
        _case(9,'첨부 변환기에서 시작한 비인가 프로세스',w,'침해 확인',3,15,'convert','15:01 EDR가 변환 서버 10.80.9.20의 작업 프로세스에서 미승인 자식 프로세스를 탐지했다.',
              '서버로 들어온 업로드 중 실제 변환 작업과 연결된 요청을 작업 ID로 찾았다.',
              '변환 큐에서 w09-2는 JOB-92이고 EDR의 부모 작업도 JOB-92다. w09-1은 다른 작업 JOB-91로 정상 완료했다.',
              '15:00:21 변환 서버에서 JOB-92가 허용 목록 밖의 자식 프로세스를 실행했다. 해당 프로세스의 외부 송신 여부는 미확인이다.',
              '작업 실행기를 격리하고 JOB-92의 파일 접근 및 자식 프로세스 통신을 조사한다.',
              [(1,'POST','/convert',202,160),(18,'POST','/convert',202,160),(42,'GET','/jobs/92',500,210)],
              [(2,'변환 작업 큐',dict(trace='w09-1',job='JOB-91',outcome='normal')),(18,'변환 작업 큐',dict(trace='w09-2',job='JOB-92',worker='conv-9')),(21,'EDR 프로세스 감사',dict(job='JOB-92',host='conv-9',parent='converter',child='unapproved-runner',event='process_started',policy='deny_by_design'))], 'dst_ip','/convert','작업을 만든 업로드 요청만 추려 큐 기록과 연결한다.'),
        _case(10,'결제 완료 웹훅의 중복 전송',w,'차단 확인',4,8,'payhook','08:01 PG 연동 모니터가 동일 결제 알림의 재전송을 알렸다. 수신 URL을 확인한다.',
              '재전송에 대한 HTTP 응답과 실제 원장 반영을 각각 확인했다.',
              'w10-1과 w10-2는 PG 이벤트 P10이다. 중복방지 저장소가 두 번째 요청을 막았고 원장에는 P10 전표가 한 건이다. w10-3은 별도 이벤트다.',
              '결제 이벤트 P10의 두 번째 처리를 차단했다. 해당 결제에 대해 중복 전표는 발생하지 않았다.',
              'PG에서 최초 전송의 응답을 수신했는지 확인해 재전송 원인을 좁힌다.',
              [(1,'POST','/hooks/payment',200,55),(11,'POST','/hooks/payment',200,55),(40,'POST','/hooks/payment',200,55)],
              [(11,'웹훅 중복방지 저장소',dict(first='w10-1',repeat='w10-2',event_id='P10',decision='duplicate_suppressed')),(40,'PG 발송 이력',dict(trace='w10-3',event_id='P11')),(62,'결제 원장 조회',dict(event_id='P10',postings=['L10']))], 'url_path',None,'재전송도 정상 응답을 받으므로 모든 수신 요청을 검토한다.'),
        _case(11,'파트너 OAuth 동의 화면 이탈',a,'정상 확인',4,10,'consent','10:01 상담원이 고객의 파트너 앱 연결 여부를 문의했다. 고객이 본 동의 서비스 호스트에서 시작한다.',
              '동의 화면이 열린 것과 권한이 부여된 것을 구별하려고 동의 원장과 토큰 발급 기록을 요청했다.',
              'w11-2는 거래 TX11의 거절이다. 리디렉션 w11-3은 access_denied이며 발급 서버도 TX11이 코드 발급 없이 종료됐다고 기록했다.',
              '10:00의 TX11에서 고객이 동의를 거절했고 파트너 앱에는 새 권한이 부여되지 않았다.',
              '고객에게 이번 연결 결과를 안내하고 종전 연결 여부는 별도 동의 이력에서 확인한다.',
              [(1,'GET','/oauth/consent',200,3200),(13,'POST','/oauth/decision',302,220),(16,'GET','/oauth/return',200,400)],
              [(13,'동의 원장',dict(trace='w11-2',transaction='TX11',decision='user_denied')),(16,'연동 콜백 기록',dict(trace='w11-3',transaction='TX11',result='access_denied')),(17,'토큰 발급 서버',dict(transaction='TX11',terminal_state='closed_without_code'))], 'hostname',None,'화면 진입·결정·복귀 순서가 모두 필요하다.'),
        _case(12,'다운로드 중단과 부분 전송',w,'판단 보류',4,13,'delivery','13:02 DLP가 파일 배포 클라이언트 198.51.100.162의 대용량 전송을 보고했다.',
              '동일 파일의 부분 요청 범위를 조합하고 서버가 실제 보낸 구간과 클라이언트 수신 결과를 확인했다.',
              'w12-2와 w12-3의 바이트 범위는 겹친다. 서버는 두 번째 구간 전송 중 연결 종료를 기록했고 단말 수신 기록은 확보되지 않았다.',
              '파일 F12의 일부 구간이 송신됐다. 중복 구간과 연결 종료 때문에 전체 파일이 단말에 저장됐는지는 판단을 보류한다.',
              '단말 캐시의 파일 길이·해시와 배포 권한을 확보하고 전송 완료 범위를 재구성한다.',
              [(1,'HEAD','/files/F12',200,0),(10,'GET','/files/F12',206,600000),(26,'GET','/files/F12',206,220000)],
              [(10,'배포 서버',dict(trace='w12-2',file='F12',file_size=1000000,requested='0-599999',sent_body=600000)),(26,'배포 서버',dict(trace='w12-3',file='F12',requested='500000-999999',sent_body=220000,result='peer_reset')),(125,'단말 자료 접수대장',dict(asset='D12',receipt_log='unavailable'))], 'src_ip','/files/F12','DLP 경보가 가리킨 파일의 조회 및 부분 전송을 함께 비교한다.'),
    ] + _remaining(w, a)


def _remaining(w, a):
    return [
        _case(13,'상담 답변에 저장된 스크립트 실행',w,'침해 확인',4,16,'helpdesk','16:01 브라우저 보호 장비가 상담 서비스에서 허용되지 않은 스크립트 실행을 기록했다. 신고 호스트로 조회한다.',
              '게시글 생성과 열람 시각을 맞추고 브라우저가 실제로 실행한 코드의 지문을 확인했다.',
              'w13-1로 저장한 게시물 T13의 코드 지문 H13이 w13-2로 연 상담원 브라우저 실행 기록과 같다. w13-3의 다른 게시물에는 H13이 없다.',
              '게시물 T13의 저장형 스크립트가 상담원 단말 B13에서 실행됐다. 세션 정보 열람이나 유출 여부는 확인되지 않았다.',
              '원본을 보존한 뒤 T13을 비공개로 전환하고 다른 열람 단말에서 H13 실행을 찾는다.',
              [(2,'POST','/tickets/reply',201,130),(24,'GET','/tickets/T13',200,6920),(43,'GET','/tickets/T14',200,6540)],
              [(2,'상담 시스템 변경 이력',dict(trace='w13-1',ticket='T13',embedded_script_hash='H13')),(24,'브라우저 실행 감사',dict(trace='w13-2',device='B13',document='T13',script_hash='H13',authorized=False,result='executed')),(43,'상담 시스템 응답 검사',dict(trace='w13-3',document='T14',embedded_scripts=[]))], 'hostname',None,'등록과 열람 경로가 달라 전체 호스트를 유지한다.'),
        _case(14,'관리 작업 URL의 가짜 성공 응답',w,'차단 확인',5,8,'admin-edge','08:01 WAF 경보에서 관리 작업 경로에 대한 정책 위반과 HTTP 200을 함께 보고했다.',
              '200을 반환한 장비와 해당 요청이 운영 서버에 전달됐는지를 구별했다.',
              'w14-2는 WAF 격리 응답 템플릿과 일치하고 프록시는 업스트림 미전달로 기록했다. w14-1은 실제 관리 화면의 정상 조회다.',
              '08:00:16의 관리 작업 요청은 경계 장비에서 종결됐다. 관찰된 200은 격리 안내 페이지에 대한 응답이다.',
              'WAF 응답 지문을 경보 해석에 반영하고 같은 정책의 우회 요청을 별도로 확인한다.',
              [(1,'GET','/admin/job',200,2200),(16,'POST','/admin/job',200,720),(41,'GET','/assets/notice',200,120)],
              [(1,'관리 서버 접속 감사',dict(trace='w14-1',operation='view',actor='admin-14')),(16,'WAF 판정 이력',dict(trace='w14-2',rule='ADM14',decision='intercept',template='notice-720')),(16,'경계 프록시',dict(trace='w14-2',upstream='none',response_source='notice-720'))], 'url_path',('method','POST'),'관리 작업의 변경 요청만 추려 WAF 중단 여부를 확인한다.'),
        _case(15,'퇴사 후에도 살아 있던 API 키',a,'침해 확인',5,9,'partner-feed','09:02 파트너가 폐기 대상 키 K15 사용 알림을 신고했다. 알림에 기재된 파트너 API 호스트를 조회한다.',
              '응답 성공 건을 키 식별자와 대조하고 퇴직 효력 시점 및 권한 예외를 확인했다.',
              'w15-2의 키 K15는 3월 4일 권한이 종료된 U15 소유다. 고객조회 감사에 R15 응답 완료가 남았고 w15-3은 다른 서비스 키다.',
              '권한 종료 뒤 K15로 고객 R15 한 건을 조회한 사실을 확인했다. 키를 사용한 사람의 신원은 미확정이다.',
              'K15를 폐기하고 권한 종료 시점 이후 K15의 호출 내역을 전수 확인한다.',
              [(1,'GET','/v1/health',200,100),(23,'GET','/v1/customer',200,1410),(45,'GET','/v1/customer',200,1240)],
              [(0,'파트너 권한 원장',dict(key='K15',owner='U15',access_ended='2025-03-04T18:00:00+09:00',exception='none')),(23,'API 키 검증기',dict(trace='w15-2',key='K15',status='accepted')),(23,'고객조회 감사',dict(trace='w15-2',customer='R15',result='record_returned')),(45,'API 키 검증기',dict(trace='w15-3',key='service-15',status='accepted'))], 'hostname','/v1/customer','개별 고객 정보가 반환된 호출을 추린다.'),
        _case(16,'사내 점검기의 숨은 경로 탐색',w,'정상 확인',5,11,'public-check','11:02 관제에서 외부 인입 주소 198.51.100.166의 설정 파일 경로 조회를 발견했다.',
              '공유 출구 주소만으로 점검 트래픽으로 종결하지 않고 실행 로그의 개별 요청번호와 승인 범위를 맞췄다.',
              '점검 실행 R16의 요청번호 세 개와 실제 경로가 모두 같고 승인 CH16의 호스트·시간 범위 안이다.',
              '11:00의 세 요청은 CH16으로 승인된 노출 점검에 해당한다. 설정 경로 응답은 404였다.',
              '점검 수행자에게 응답 결과를 전달하고 CH16 범위 밖의 후속 요청은 별도 검토한다.',
              [(1,'GET','/robots.txt',200,311),(11,'GET','/config/archive',404,190),(31,'HEAD','/status',200,0)],
              [(0,'변경 승인대장',dict(change='CH16',hostname='public-check.example.test',window='11:00-11:15',runner='scanner-16')),(32,'점검기 실행 원장',dict(run='R16',runner='scanner-16',change='CH16',requests={'w16-1':'/robots.txt','w16-2':'/config/archive','w16-3':'/status'}))], 'src_ip',None,'승인 범위와 실행한 전체 경로를 일대일로 맞춘다.'),
        _case(17,'GraphQL 일부 필드만 반환된 요청',w,'차단 확인',5,14,'graph','14:01 권한 점검에서 고객 연봉 필드를 포함한 요청에 HTTP 200이 관찰됐다. 점검 대상 URL을 확인한다.',
              '전송 계층의 성공 응답을 필드별 권한 판정 및 실제 직렬화 결과와 대조했다.',
              'w17-2의 급여 필드는 권한 엔진이 거부했고 응답에는 salary=null 및 FORBIDDEN이 기록됐다. 공개 필드 displayName은 반환됐다.',
              '14:00:18의 응답에서 급여 값 반환은 차단됐다. 함께 조회한 공개 이름 필드는 정상 제공됐다.',
              '필드별 권한 회귀 검사에 별칭과 중첩 조회도 포함해 같은 통제가 적용되는지 확인한다.',
              [(2,'POST','/graphql',200,201),(18,'POST','/graphql',200,297),(35,'POST','/graphql',400,145)],
              [(2,'GraphQL 응답 감사',dict(trace='w17-1',fields=['displayName'])),(18,'필드 권한 엔진',dict(trace='w17-2',subject='guest17',field='salary',decision='deny')),(18,'GraphQL 응답 감사',dict(trace='w17-2',returned=['displayName'],null_fields=['salary'],errors=['FORBIDDEN']))], 'url_path',None,'같은 엔드포인트에서 HTTP 상태와 필드별 결과를 비교한다.'),
        _case(18,'공유 캐시가 돌려준 다른 고객의 화면',w,'침해 확인',5,16,'dashboard','16:02 고객 B18이 대시보드에 다른 고객 이름이 표시됐다고 신고했다. 해당 서비스 호스트에서 조회한다.',
              '캐시를 채운 요청과 캐시 적중 응답의 인증 주체 및 본문 소유자 지문을 대조했다.',
              'w18-1은 A18의 응답으로 캐시 K18을 채웠다. B18의 w18-2는 K18에 적중했고 브라우저의 본문 지문 HA18이 원본 A18 응답과 같다.',
              '16:00:14 B18에게 A18 대시보드 응답 한 건이 노출됐다. 같은 캐시 키를 받은 다른 이용자 범위는 조사 중이다.',
              '개인화 응답의 공유 캐싱을 중지하고 K18의 생성부터 제거까지 적중 기록을 확보한다.',
              [(2,'GET','/dashboard',200,3810),(14,'GET','/dashboard',200,3810),(38,'GET','/dashboard',200,3710)],
              [(2,'원본 서비스 응답 감사',dict(trace='w18-1',subject='A18',body_hash='HA18',cache_key='K18')),(14,'CDN 캐시 감사',dict(trace='w18-2',auth_subject='B18',cache_key='K18',cache='hit')),(15,'브라우저 진단 수집',dict(trace='w18-2',account='B18',body_hash='HA18')),(38,'CDN 캐시 감사',dict(trace='w18-3',cache='bypass'))], 'hostname','/dashboard','개인화 대시보드의 응답끼리 대조한다.'),
        _case(19,'MFA 푸시 거절 뒤의 세션 상태',a,'차단 확인',6,8,'secure-login','08:02 사용자 U19가 본인이 시작하지 않은 인증 푸시를 거절했다고 신고했다. 인증 호스트를 확인한다.',
              '푸시 호출의 202 신호와 세션을 확정하는 인증 거래 종료 기록을 구분했다.',
              'w19-2에 대응하는 CH19를 단말이 거절했다. 인증 서버의 같은 거래 TX19는 세션 없이 종료됐고 w19-3은 결과 조회였다.',
              '08:00에 U19에게 도달한 푸시 CH19는 거절됐으며 TX19에서는 세션이 발급되지 않았다.',
              '사용자가 시도하지 않은 1차 인증의 통과 경위를 확인하고 U19의 다른 인증 거래를 조사한다.',
              [(2,'POST','/signin',202,156),(14,'POST','/mfa/push',202,117),(32,'GET','/mfa/result',200,81)],
              [(14,'인증 서버',dict(trace='w19-2',user='U19',transaction='TX19',challenge='CH19',first_factor='passed')),(26,'MFA 제공자',dict(challenge='CH19',user='U19',decision='denied_by_user')),(32,'인증 서버',dict(trace='w19-3',transaction='TX19',terminal='denied',session_issued=False))], 'hostname',None,'인증 시작부터 최종 거래 상태까지 확인한다.'),
        _case(20,'공유 출구 뒤의 동시 로그인 경보',a,'판단 보류',6,10,'sso-roam','10:02 SSO가 U20의 단시간 기기 변경을 탐지해 접속지 198.51.100.170을 제공했다.',
              '두 세션의 단말 식별값을 찾고 같은 NAT 주소가 같은 단말을 뜻하는지 확인했다.',
              'w20-1과 w20-2는 U20의 서로 다른 세션 S20A·S20B다. NAT 변환 기록은 만료됐고 S20B의 기기 증명도 수집되지 않았다.',
              'U20의 두 세션 발급은 확인했다. 출구 주소를 여러 단말이 공유하므로 S20B의 실제 사용자는 미확정이다.',
              'U20에게 두 로그인 시각을 확인하고 관리 단말의 브라우저·기기 증명 기록을 대조한다.',
              [(1,'POST','/sso/finish',302,180),(20,'POST','/sso/finish',302,180),(32,'GET','/sso/profile',200,460)],
              [(1,'SSO 발급 원장',dict(trace='w20-1',account='U20',session='S20A',device='managed-20')),(20,'SSO 발급 원장',dict(trace='w20-2',account='U20',session='S20B',device='unavailable')),(100,'NAT 운영 회신',dict(address='198.51.100.170',use='shared_egress',translation_logs='expired'))], 'src_ip','/sso/finish','실제 세션 발급과 연결할 수 있는 완료 요청을 추린다.'),
        _case(21,'재설정 링크의 자동 미리 보기',a,'정상 확인',6,13,'reset','13:02 사용자가 메일 링크를 열기 전 이미 재설정 화면 접근 알림을 받았다. 알림의 호스트를 조회한다.',
              '링크 접근 주체와 토큰 소비·비밀번호 변경 주체를 각각 확인했다.',
              'w21-1은 메일 보안 서비스 작업 MS21의 사전 조회다. w21-2 뒤 w21-3에서만 토큰 R21이 소비됐고 본인 확인한 사용자가 이 변경을 확인했다.',
              '13:00:02의 선행 접근은 링크 검사였다. 13:00:42의 실제 비밀번호 변경은 사용자가 수행했다.',
              '문의자에게 토큰이 소비된 시각과 자동 접근 알림이 발생한 이유를 안내한다.',
              [(2,'GET','/reset/start',200,1520),(31,'GET','/reset/start',200,1520),(42,'POST','/reset/finish',204,0)],
              [(2,'메일 보안 서비스',dict(trace='w21-1',job='MS21',action='preview_url')),(42,'자격증명 변경 원장',dict(trace='w21-3',token_id='R21',consume_count=1,account='U21',outcome='password_changed')),(125,'고객센터 본인확인',dict(ticket='CS21',account='U21',confirmed_time='13:00:42',action='password_change'))], 'hostname',None,'선행 조회와 나중 변경의 경로를 모두 보존한다.'),
        _case(22,'파일 내보내기 작업의 취소 경쟁',w,'판단 보류',7,9,'report-export','09:02 보고서 관리자가 대량 내보내기를 취소했지만 다운로드 주소가 생성됐다고 문의했다.',
              '작업 취소 시각을 파일 생성 및 전달 기록과 구분해 확인했다. 신고된 서비스 호스트로 범위를 잡았다.',
              'w22-1의 JOB22는 임시 객체 O22를 생성했고 w22-2가 종료를 요청했다. w22-3은 상태 화면 조회다. 객체 저장소의 해당 구간 읽기 기록은 누락됐다.',
              'JOB22의 임시 파일 생성과 작업 취소는 확인했다. 서명 URL로 실제 파일을 읽었는지는 수집 공백으로 판단할 수 없다.',
              '서명 URL을 폐기하고 저장소 앞단 CDN의 요청 기록 및 객체 수명주기 원장을 확보한다.',
              [(1,'POST','/exports',202,150),(14,'DELETE','/exports/22',202,105),(31,'GET','/exports/22',200,170)],
              [(8,'내보내기 작업 큐',dict(trace='w22-1',job='JOB22',temporary_object='O22',signed_url_created=True)),(15,'작업 제어 감사',dict(trace='w22-2',job='JOB22',state='cancelled')),(61,'객체 저장소 수집 상태',dict(bucket='report-temp',gap='09:00-09:05',missing='object_read_events'))], 'hostname',None,'작업 생성·취소·상태 조회를 개별 파일 읽기와 구분한다.'),
        _case(23,'배송지 변경 요청의 이중 인증 우회',w,'침해 확인',7,13,'orders','13:02 주문자 U23이 주문 O23의 배송지 변경을 부인했다. 신고된 변경 URL을 조회한다.',
              '변경 요청과 실제 주소 이력, 해당 변경에 필요한 추가 인증 거래를 주문 번호로 맞췄다.',
              'w23-2는 O23 변경 이력 버전 4로 커밋됐다. 정책 엔진은 해당 수정에 추가 인증이 필요하다고 기록했고 승인 원장의 거래 C23은 만료 상태였다.',
              '13:00:17 주문 O23의 배송지가 추가 인증 승인 없이 변경됐다. 본인확인된 주문자는 변경을 부인했다. 실제 배송 여부는 미확인이다.',
              '배송 보류를 요청하고 O23 변경 전후 주소 및 동일 처리 경로의 다른 주문을 대조한다.',
              [(2,'GET','/order/address',200,540),(17,'PATCH','/order/address',204,0),(30,'GET','/order/address',200,537)],
              [(17,'주문 변경 감사',dict(trace='w23-2',order='O23',revision=4,old_hash='A23',new_hash='B23',result='committed')),(17,'추가 인증 정책',dict(trace='w23-2',order='O23',challenge='C23',step_up='required')),(17,'추가 인증 원장',dict(challenge='C23',terminal='expired',approval=False)),(125,'고객센터 본인확인',dict(order='O23',account='U23',revision=4,action='denied_change'))], 'url_path',('method','PATCH'),'같은 주소 경로의 조회를 제외하고 실제 변경 요청을 추린다.'),
        _case(24,'열쇠 교체 직후의 서명 검증 실패',a,'정상 확인',7,16,'service-login','16:02 운영자가 서비스 인증 실패를 신고했다. 실패한 인증의 호스트를 확인한다.',
              '키 식별자와 배포 버전을 확인해 위조 토큰과 교체 기간 중 구 키 재사용 가능성을 검토했다.',
              'w24-2는 승인된 배포 D24의 구버전 인스턴스 P24A가 보낸 이전 키 서명이었다. w24-3은 새 버전 P24B의 신규 키로 성공했다.',
              '16:00:14의 인증 실패는 승인 배포 중 구버전 인스턴스가 이전 키를 사용해 발생했다. 16:00:39의 새 키 인증은 성공했다.',
              '구버전 인스턴스가 모두 종료됐는지 확인하고 키 교체 절차에 인스턴스별 전환 확인을 추가한다.',
              [(1,'GET','/keys/current',200,480),(14,'POST','/token/verify',401,130),(39,'POST','/token/verify',200,130)],
              [(0,'배포 승인대장',dict(deployment='D24',approved=True,change='key_rotation',old='K24-old',new='K24-new')),(14,'서비스 메시 송신 감사',dict(trace='w24-2',instance='P24A',deployment='D24',kid='K24-old')),(14,'서명 검증기',dict(trace='w24-2',kid='K24-old',result='retired_key')),(39,'서비스 메시 송신 감사',dict(trace='w24-3',instance='P24B',deployment='D24',kid='K24-new')),(39,'서명 검증기',dict(trace='w24-3',kid='K24-new',result='valid'))], 'hostname','/token/verify','검증 실패와 전환 후 성공을 같은 경로에서 비교한다.'),
    ]
