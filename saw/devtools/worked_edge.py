"""Worked perimeter and egress cases W43–W60. All addresses and records are synthetic."""
from datetime import datetime, timedelta


def cases():
    rows = []

    def add(num, title, classification, category, start, lead, narrow, reason, narrative, logs, records):
        base = datetime.fromisoformat(f'2025-03-{start}+09:00')
        def ts(seconds):
            return (base + timedelta(seconds=seconds)).isoformat()
        events = []
        for i, (seconds, src, dst, port, details) in enumerate(logs):
            events.append(dict(source=lead[0], time=ts(seconds), src=src, dst=dst,
                               sport=49000 + num * 10 + i, dport=port, **({'proto':'TCP'} | details)))
        followups = [dict(id=f'W{num}-E{i}', source=source, fields=dict(time=ts(offset), **fields))
                     for i, (offset, source, fields) in enumerate(records, 1)]
        trigger, pivot, comparison, judgement, next_check = narrative
        rows.append(dict(id=f'W{num}', title=title, classification=classification, category=category,
                         trigger=trigger, pivot=pivot, comparison=comparison, judgement=judgement,
                         next_check=next_check, events=events, followups=followups,
                         lead=dict(source=lead[0], field=lead[1], value=lead[2], basis=trigger),
                         narrow=[dict(field=narrow[0], op='is', value=narrow[1])], narrow_reason=reason))

    def flow(action, sent, rcvd, proto=None):
        d = dict(action=action, sent=sent, rcvd=rcvd)
        if proto:
            d['proto'] = proto
        return d

    def http(host, method, path, status, cs, sc):
        return dict(host=host, method=method, path=path, status=status, cs=cs, sc=sc, ua='Client/2.1')

    edge, out = '경계·클라우드', '외부 통신·유출'
    a, b, c = '10.80.1.11', '10.80.1.12', '10.80.1.13'
    x, y, z = '192.0.2.81', '198.51.100.82', '203.0.113.83'
    add(43, '휴면 협력사 계정의 SSL VPN 접속', '침해 확인', edge, '03T06:10:00', ('fw','src_ip',x), ('dst_port',443), 'VPN 장비의 서비스 포트로 들어온 세션을 시간순으로 확인한다.', (
        'VPN 장비가 06:10에 휴면 대상 계정 vend-43의 외부 접속지 192.0.2.81을 통지했다.', 'FW에서 출발지를 조회하고 VPN 장비 10.80.1.11의 443 세션 시작 시각을 VPN 인증 감사와 맞춘다.', '같은 출발지의 80번 시도는 거부됐지만 이후 443 연결은 허용됐다. 다른 외부 IP의 정상 로그인과 구분한다.', 'VPN 감사에 세션 v43 및 터널 주소가 발급됐다. 계약 종료와 계정 소유자의 접속 부인이 일치해 무단 원격접속으로 확인했다.', 'VPN 운영자는 v43을 종료한 뒤 터널 주소 10.80.9.43의 할당 시간 동안 접근한 내부 자원을 세션 감사에서 추출한다.'),
        [(0,x,a,80,flow('deny',0,0)),(4,x,a,443,flow('allow',5600,18700)),(12,y,a,443,flow('allow',8700,9100))], [(5,'VPN 인증 감사',dict(session='v43',user='vend-43',peer=x,tunnel='10.80.9.43',result='authenticated')),(120,'협력사 계약대장·담당자 확인',dict(user='vend-43',contract_end='2025-02-28',user_statement='해당 시간 미접속'))])
    add(44, '외부 DNS로 전달된 카드대사 표본', '침해 확인', out, '03T11:20:00', ('fw','src_ip',b), ('dst_port',53), '외부 DNS와 내부 재귀 DNS 양쪽을 남겨 같은 단말의 질의를 비교한다.', (
        '단말 DLP가 11:20에 10.80.1.12에서 대사 파일의 표식이 포함된 DNS 질의를 발견했다.', 'FW에서 단말의 53번 흐름을 열고 목적지가 사내 재귀 DNS인 행과 외부 IP인 행을 나눈다.', '10.80.1.13은 기존 재귀 DNS다. 외부 198.51.100.82와의 두 흐름은 허용됐고 질의 내용은 DNS 증적에서 대조한다.', '단말 DLP와 외부 권한 DNS의 수신 기록에 동일한 질의 지문과 표식이 있다. 대사 표본의 외부 전달을 확인했다.', '대사 담당자는 표식 rec-44와 원본 행을 대조하고 DNS 관리자는 동일 지문의 수신 시각을 추출해 전송 범위를 계산한다.'),
        [(0,b,c,53,flow('allow',91,130,'UDP')),(5,b,y,53,flow('allow',232,88,'UDP')),(9,b,y,53,flow('allow',230,88,'UDP'))], [(5,'단말 DLP',dict(endpoint=b,file='recon-sample.csv',marker='rec-44',query_digest='q44a')),(5,'외부 DNS 사업자 권한 서버 질의 감사',dict(zone='collector.example',query_digest='q44a',marker='rec-44',result='received'))])
    add(45, '재해복구 저장소의 야간 대량 업로드', '승인된 활동', out, '04T01:00:00', ('ndr','src_ip',a), ('method','PUT'), '키 목록 GET과 실제 전송 PUT의 요청 방향 용량을 분리한다.', (
        'NDR이 01:00부터 10.80.1.11의 평소보다 큰 야간 송신을 알렸다.', '출발지에서 PUT을 선택하고 dr-vault.example의 요청 경로와 클라이언트 송신량을 복구 작업의 객체 목록에 맞춘다.', '목록 GET은 920바이트 요청이다. 두 PUT은 각각 8 MiB이며 백업 조각 01·02와 일치한다.', '사전 승인된 복구 훈련 범위와 저장소의 서비스 계정·두 객체 영수증이 일치해 승인 작업으로 종결한다.', '백업 담당자는 복구 리허설 결과에 dr45/01과 dr45/02의 검증 상태를 첨부한다.'),
        [(0,a,x,443,http('dr-vault.example','GET','/dr45',200,920,4200)),(4,a,x,443,http('dr-vault.example','PUT','/dr45/01',201,8388608,260)),(24,a,x,443,http('dr-vault.example','PUT','/dr45/02',201,8388608,260))], [(-3600,'변경 승인',dict(change='DR-45',source=a,prefix='dr45/',expected_objects=2,object_size=8388608)),(26,'복구 저장소 객체 감사',dict(principal='svc-dr',objects=['dr45/01','dr45/02'],result='stored',change='DR-45'))])
    add(46, '공개 링크로 내려받은 대출 심사 파일', '침해 확인', edge, '04T09:15:00', ('ndr','url_path','/share/l46'), ('status_code',200), '동일 링크의 만료 응답을 제외하고 성공 응답과 다운로드 영수증을 대응한다.', (
        '문서 담당자가 대출 심사 묶음의 외부 공유 경로 /share/l46을 신고했다.', 'NDR에서 경로를 정확히 조회한 후 200 응답의 출발지와 응답 방향 바이트를 문서 보관소 열람 이력에 연결한다.', '203.0.113.83은 14 MiB 응답을 받았고 링크 폐기 후 같은 요청에는 410이 반환됐다. 사내 미리보기는 다른 소량 응답이다.', '저장소가 비인증 외부 주체에게 파일 버전 7 전체를 전달했다. 문서 소유자가 공개 권한 설정 오류와 제한 등급을 확인했다.', '문서 관리자는 링크 l46의 생성부터 폐기까지 버전 7 다운로드 영수증을 수집해 외부 수신자 수를 확인한다.'),
        [(0,z,a,443,http('docs.example','GET','/share/l46',200,550,14680064)),(16,b,a,443,http('docs.example','GET','/preview/l46',200,520,5800)),(60,z,a,443,http('docs.example','GET','/share/l46',410,550,410))], [(1,'문서 저장소 전송 감사',dict(link='l46',peer=z,identity='anonymous',version=7,bytes_served=14680064,completed=True)),(40,'문서 소유자·권한 점검',dict(link='l46',classification='대출 심사 제한',public_link_approved=False,action='revoke'))])
    add(47,'업무망 단말의 외부 SMTP 직송 시도','차단 확인',out,'04T15:20:00',('fw','src_ip',c),('dst_port',25),'외부 직송과 사내 릴레이의 정책 결과를 목적지별로 비교한다.',(
        '메일 관제에서 10.80.1.13의 15:20 외부 SMTP 우회 시도를 통보했다.','FW 출발지에서 25번 연결을 조회해 목적지별 허용 여부와 송신 바이트를 확인한다.','외부 두 주소에는 정책 거부와 전송 0바이트가 기록됐다. 내부 릴레이 연결은 허용됐다.','외부 직송 두 건은 경계에서 차단됐다. 메일 큐의 재시도 ID m47은 내부 릴레이에서만 접수됐다.','메일 운영자는 큐 m47의 목적지 설정을 확인하고 단말 앱의 발송 경로를 내부 릴레이로 고정한다.'),
        [(0,c,x,25,flow('deny',0,0)),(9,c,y,25,flow('deny',0,0)),(25,c,b,25,flow('allow',9400,2200))],[(26,'SMTP 릴레이 큐',dict(queue='m47',client=c,relay=b,result='queued'))])
    add(48,'정산 CSV의 개인 클라우드 업로드','침해 확인',out,'05T10:20:00',('ndr','src_ip',b),('method','POST'),'외부 서비스 목록 조회와 전송 요청을 분리해 두 업로드의 계정을 대조한다.',(
        'DLP가 10:20에 정산 단말 10.80.1.12의 외부 업로드를 탐지했다.','NDR에서 POST를 열고 경로 /personal/48과 /team/48을 계정 감사의 객체 키에 맞춘다.','팀 경로에는 2 KiB 시험 파일이 올라갔다. 개인 경로의 요청 크기는 3 MiB다.','개인 공간의 저장 영수증에 찍힌 해시가 DLP의 제한 정산 파일 해시와 일치한다.','정산 담당자는 csv48의 고객 범위를 산정하고 저장소 사업자에게 객체 o48의 공유·다운로드 이력 보존을 요청한다.'),
        [(0,b,x,443,http('files.example','GET','/accounts',200,460,1600)),(4,b,x,443,http('files.example','POST','/team/48',201,2048,310)),(9,b,x,443,http('files.example','POST','/personal/48',201,3145728,310))],[(9,'단말 DLP 파일 식별',dict(endpoint=b,file='settlement.csv',fingerprint='csv48',classification='고객 정산 제한')),(10,'클라우드 저장 영수증',dict(path='/personal/48',object='o48',fingerprint='csv48',owner_scope='personal',result='stored'))])
    add(49,'외부 요청 급증과 송금 조회 장애','침해 확인',edge,'05T12:30:00',('ndr','hostname','balance.example'),('status_code',503),'503 응답을 노드별 상태 및 합성 거래 실패와 같은 시각에 놓는다.',(
        '12:30 합성 거래가 balance.example의 송금 조회 응답 지연을 알렸다.','NDR에서 호스트를 조회한 후 503 구간의 조회 URI를 엣지 집계와 비교한다.','시작 직전 조회는 200이었다. 서로 다른 외부 IP에서 조회 503이 발생했고 같은 시각 경량 상태 페이지는 200이었다.','엣지가 분산 봇의 요청 폭주를 확인했다. 합성 거래가 실패했고 유입 제한 직후 조회가 회복돼 서비스 거부 피해를 확인했다.','서비스 운영자는 엣지 사건 dd49의 제한 적용 시각과 합성 조회 성공 시각으로 고객 영향 시간을 확정한다.'),
        [(-12,x,a,443,http('balance.example','GET','/transfer/status',200,480,1200)),(0,y,a,443,http('balance.example','GET','/transfer/status',503,480,330)),(2,z,a,443,http('balance.example','GET','/transfer/status',503,480,330)),(4,x,a,443,http('balance.example','GET','/health',200,410,110))],[(2,'엣지 방어 집계',dict(incident='dd49',route='/transfer/status',bot_sources=2140,rps=38000,action='rate limit')),(32,'독립 합성 거래',dict(probe='branch-monitor',route='/transfer/status',failed_from='12:30:00',first_success='12:30:32'))])
    add(50,'메일 검사기의 피싱 링크 열람','승인된 활동',out,'05T14:40:00',('ndr','hostname','landing.example'),('method','GET'),'같은 주소로 보낸 HEAD와 본문을 받은 GET의 주체를 세션별로 확인한다.',(
        '메일 보안팀이 14:40에 landing.example을 열람한 사내 주소가 있다는 경보를 전달했다.','NDR에서 호스트를 조회하고 GET의 출발지와 시각을 메일 분석 VM의 작업 기록에 맞춘다.','같은 VM이 HEAD 뒤에 GET을 실행했다. 사무 단말의 같은 경로 GET은 프록시에서 403이었다.','본문을 받은 주소는 격리 검사 VM이며 작업 mail50에 URL이 등록됐다. 관찰된 사무 단말 요청은 차단됐다.','메일 담당자는 mail50의 최종 URL 판정과 원본 메시지 ID를 대조해 수신자 격리 대상을 확인한다.'),
        [(0,c,y,443,http('landing.example','HEAD','/visit',200,280,0)),(2,c,y,443,http('landing.example','GET','/visit',200,310,14400)),(14,b,y,443,http('landing.example','GET','/visit',403,290,490))],[(2,'메일 격리 분석기',dict(job='mail50',vm=c,url='https://landing.example/visit',message='msg50')),(14,'웹 프록시 정책 감사',dict(client=b,url='https://landing.example/visit',rule='phishing-block',decision='deny'))])
    add(51,'접근 키로 생성된 미승인 스냅숏 공유','침해 확인',edge,'06T02:10:00',('ndr','src_ip',c),('method','POST'),'읽기 API와 스냅숏 공유 설정을 변경한 API를 구분한다.',(
        '클라우드 감사가 02:10 배치 호스트 10.80.1.13의 키 k51 사용을 통보했다.','NDR의 POST 경로와 상태를 확인한 후 클라우드 감사 요청 ID를 키 k51과 같은 시각으로 조회한다.','목록 GET과 첫 공유 POST의 403 뒤에 같은 경로에서 200이 나왔다. 성공 대상 계정은 API 감사에서 식별한다.','감사에서 대출 스냅숏을 외부 계정에 공유한 성공 이벤트가 확인됐다. 키 담당자가 해당 변경을 부인했다.','클라우드 운영자는 공유 권한을 회수하고 외부 계정 ext51이 권한 부여 기간 중 스냅숏을 복사했는지 수명주기 이력을 조회한다.'),
        [(0,c,z,443,http('cloud-api.example','GET','/snapshots',200,430,1120)),(5,c,z,443,http('cloud-api.example','POST','/snapshots/share',403,720,320)),(11,c,z,443,http('cloud-api.example','POST','/snapshots/share',200,740,330))],[(11,'클라우드 제어면 감사',dict(request='req51',key='k51',snapshot='loan-51',grant_to='ext51',result='success')),(95,'키 소유부서 확인',dict(key='k51',approved_scope='nightly inventory read',request='req51',authorized=False))])
    add(52,'보안 점검 창의 외부 포트 탐색','승인된 활동',edge,'06T07:30:00',('fw','src_ip',y),('enforcement_action','blocked'),'거부된 포트를 점검 허가서의 주소·시각·포트 목록과 대조한다.',(
        '경계 FW가 07:30에 198.51.100.82에서 여러 서비스로 향한 시도를 탐지했다.','출발지의 거부 행을 고른 후 허용된 443 비교 행까지 포함해 허가서 범위와 맞춘다.','같은 대상에 대한 22·3389는 거부됐고 443은 허용됐다. 세 포트 모두 외부 점검 대상이었다.','점검 수행기관의 실행 영수증과 사전 허가서가 출발지와 대상 및 작업창에서 일치한다.','경계 담당자는 허가서 PT52 종료 후 같은 출발지의 재접속이 있는지 종료 시각 이후 구간을 조회한다.'),
        [(0,y,b,22,flow('deny',0,0)),(4,y,b,3389,flow('deny',0,0)),(8,y,b,443,flow('allow',610,1700))],[(-1800,'사전 점검 허가서',dict(ticket='PT52',scanner=y,target=b,ports=[22,3389,443],window='07:30–07:45 KST')),(9,'점검 수행기관 작업 기록',dict(job='PT52',scanner=y,target=b,result='completed'))])
    add(53,'인가되지 않은 외부 우편함 자동 전달','침해 확인',out,'06T09:20:00',('ndr','url_path','/mail/rules'),('method','POST'),'규칙 조회와 규칙 생성의 의미를 메일 감사에서 분리한다.',(
        '메일 관제가 외부 접속에서 /mail/rules 변경이 발생했다고 통보했다.','경로를 조회한 뒤 POST 시각과 외부 출발지를 메일 감사의 세션 s53에 맞춘다.','사내 GET은 규칙 목록 조회이고 다른 외부 POST는 401이다. 192.0.2.81의 POST가 201을 받았다.','미승인 규칙 r53 생성과 그 규칙으로 외부 우편함에 인계된 메시지 두 건을 메일 감사 및 전송 추적에서 확인했다.','메일 관리자는 규칙 r53의 생성·삭제 시각 사이에 처리된 메시지 ID와 외부 수신자를 대조해 노출 대상을 확정한다.'),
        [(0,b,a,443,http('mail.example','GET','/mail/rules',200,410,2900)),(4,y,a,443,http('mail.example','POST','/mail/rules',401,490,310)),(9,x,a,443,http('mail.example','POST','/mail/rules',201,560,340))],[(9,'우편함 변경 감사·소유자 확인',dict(session='s53',peer=x,rule='r53',owner_approved=False,forward='external@outside.example')),(80,'메일 전송 추적',dict(rule='r53',recipient='external@outside.example',messages=['m53a','m53b'],delivery='accepted by remote MTA'))])
    add(54,'TLS 인증서 교체 직후 결제 연계 실패','운영 장애',edge,'06T16:00:00',('fw','dst_ip',z),('dst_port',443),'연계 서버와 별도 모니터의 연결을 출발지별로 비교한다.',(
        '결제 운영자가 16:00부터 제휴 결제 주소 203.0.113.83의 연결 실패를 신고했다.','FW에서 목적지와 443을 선택하고 결제 노드와 독립 모니터의 전후 송수신량을 확인한다.','결제 노드의 세션은 허용됐지만 수신량이 650바이트로 감소했다. 모니터는 같은 목적지에서 응답 데이터를 받았다.','파트너 인증서 교체 후 결제 노드의 오래된 신뢰 저장소만 인증 체인을 거절해 거래 연계가 중단됐다.','결제 운영자는 신뢰 저장소를 갱신한 노드에서 시험 거래를 수행하고 실패 거래 p54의 재처리 여부를 원장에서 확인한다.'),
        [(-15,a,z,443,flow('allow',6200,14700)),(0,a,z,443,flow('allow',420,650)),(4,c,z,443,flow('allow',5900,12600))],[(0,'결제 클라이언트 TLS 감사',dict(node=a,transaction='p54',issuer='Partner CA2',error='unknown issuer')),(3,'제휴사 인증서 배포·독립 프로브',dict(endpoint=z,issuer='Partner CA2',probe=c,result='chain valid'))])
    add(55,'해외 접속지로 이어진 원격제어 채널','침해 확인',out,'07T03:20:00',('fw','src_ip',a),('dst_port',8443),'8443 세션의 출발지·목적지·시각을 단말 소켓 감사와 연결한다.',(
        'EDR이 03:20 문서 처리 서버 10.80.1.11에서 승인되지 않은 원격제어 모듈을 탐지했다.','FW에서 서버의 8443 흐름을 찾아 허용된 목적지와 간격을 단말 소켓 소유 프로세스에 대조한다.','같은 서버의 443 업무 흐름과 달리 8443은 203.0.113.83으로 반복됐다. 포트와 반복성만으로 도구를 식별할 수 없다.','두 허용 세션을 연 프로세스 rc55의 명령 수신·실행 기록과 무단 모듈 판독 결과가 일치해 외부 원격제어를 확인했다.','서버 담당자는 rc55가 실행한 자식 프로세스와 파일 변경 시각을 보존해 원격 명령의 영향 범위를 산정한다.'),
        [(0,a,y,443,flow('allow',8400,17000)),(4,a,z,8443,flow('allow',560,770)),(34,a,z,8443,flow('allow',640,940))],[(4,'EDR 소켓 소유 감사',dict(node=a,peer=z,port=8443,process='rc55',signature='미승인 원격제어 모듈')),(35,'호스트 프로세스 실행 감사',dict(parent='rc55',command_id='job55',event='remote job executed',account='svc-doc'))])
    add(56,'대외 정산 SFTP 전송의 범위 확인','판단 보류',out,'07T17:00:00',('fw','src_ip',b),('dst_port',22),'내부 스테이징 전송과 외부 제휴 목적지 전송을 같은 포트에서 비교한다.',(
        '대외계 운영자가 17:00 정산 서버 10.80.1.12의 예외 시간대 SFTP 전송을 신고했다.','FW에서 22번을 선택해 사내 스테이징과 외부 목적지의 송신량을 나누고 배치 작업 ID와 맞춘다.','사내 전송은 1 MiB, 외부 허용 세션은 16 MiB다. 외부 재시도 한 건은 거부됐다.','승인서에는 제휴 주소와 배치만 명시됐고 수신 목록 및 파일 해시가 없다. 외부 전송 내용과 승인 범위는 미확정이다.','대외계 담당자는 작업 b56의 송신 매니페스트와 제휴사 수신 영수증을 받아 파일명·해시·처리 일자를 승인서와 대조한다.'),
        [(0,b,c,22,flow('allow',1048576,8000)),(8,b,y,22,flow('allow',16777216,44000)),(80,b,y,22,flow('deny',0,0))],[(-400,'대외계 승인서',dict(job='b56',peer=y,purpose='제휴 정산',approved_files=None)),(8,'배치 실행 이력',dict(job='b56',peer=y,operator='batch',manifest=None,receiver_receipt=None))])
    add(57,'공개 저장소에 남은 고객 상담 녹취','침해 확인',edge,'08T08:20:00',('ndr','hostname','call-archive.example'),('status_code',206),'범위 요청의 부분 응답을 객체 저장소에서 바이트 구간별로 검증한다.',(
        '저장소 관제가 08:20 call-archive.example의 비인증 녹취 요청을 통보했다.','NDR에서 호스트를 조회한 뒤 206 응답을 객체 키와 시각으로 저장소 데이터 감사에 연결한다.','목록 GET은 403이지만 알려진 객체 경로에는 외부 두 주소가 각각 206을 받았다. 목록 거부만으로 객체 접근을 배제할 수 없다.','저장소 감사에서 두 익명 주체에게 제한 녹취 au57의 일부 구간을 전달했다. 노출 확인 범위는 두 부분 응답이다.','저장소 관리자는 au57의 익명 읽기를 회수하고 정책 적용 기간의 Range 영수증을 병합해 중복을 뺀 노출 구간을 계산한다.'),
        [(0,x,a,443,http('call-archive.example','GET','/audio/',403,440,280)),(4,x,a,443,http('call-archive.example','GET','/audio/au57',206,520,65536)),(8,z,a,443,http('call-archive.example','GET','/audio/au57',206,540,65536))],[(4,'객체 저장소 데이터 감사',dict(key='au57',principal='anonymous',ranges=['0-65535','65536-131071'],peers=[x,z],result='served',window_seconds=5)),(-500,'녹취 자산·권한 목록',dict(key='au57',classification='고객 상담 녹취',allowed_principals=['svc-qa'],public_grant='설정 오류'))])
    add(58,'인터넷에서 유입된 비인가 관리 포트 접근','차단 확인',edge,'08T19:10:00',('fw','dst_ip',c),('dst_port',3389),'외부 접근과 사내 점프 서버의 정규 연결을 같은 목적지에서 비교한다.',(
        '경계 정책 경보가 19:10 관리 대상 10.80.1.13으로 들어오는 원격접속을 알렸다.','FW에서 목적지와 3389를 선택해 외부 주소와 사내 점프 서버의 세션을 나눈다.','두 외부 주소의 세션은 모두 거부·0바이트이며 10.80.1.11의 사내 연결은 허용됐다.','두 외부 시도는 정책 ext-rdp에서 차단됐다. Windows 성공 로그인은 승인된 점프 세션 j58과 일치한다.','관리자는 동일 외부 주소가 다른 관리 대상에도 접근했는지 당일 경계 정책 ext-rdp의 목적지별 거부 횟수를 확인한다.'),
        [(0,x,c,3389,flow('deny',0,0)),(4,y,c,3389,flow('deny',0,0)),(16,a,c,3389,flow('allow',31000,44000))],[(4,'경계 장비 정책 감사',dict(rule='ext-rdp',peers=[x,y],target=c,action='drop')),(17,'점프 서버·Windows 세션 감사',dict(session='j58',source=a,dest=c,user='ops58',result='logon success'))])
    add(59,'동일 도메인에서 발생한 OCSP 응답 지연','운영 장애',out,'09T08:30:00',('ndr','hostname','trust.example'),('status_code',504),'같은 도메인의 정상 인증서 배포와 인증서 상태 조회 실패를 경로별로 분리한다.',(
        '공동인증 운영자가 08:30에 trust.example을 이용한 인증 검증 지연을 신고했다.','NDR에서 호스트를 선택하고 504 응답의 경로와 두 클라이언트 시각을 CA 상태 공지와 대조한다.','인증서 배포 /ca.cer는 200이고 서로 다른 단말의 /ocsp만 504였다.','인증기관 상태 조회 서버의 의존 DB 타임아웃과 내부 검증기 오류 시각이 일치해 인증 지연 원인을 확인했다.','인증 운영자는 사건 ca59 복구 뒤 두 검증기의 상태 조회 성공과 지연 거래의 재시도 결과를 확인한다.'),
        [(0,a,x,80,http('trust.example','GET','/ca.cer',200,390,4000)),(6,b,x,80,http('trust.example','POST','/ocsp',504,630,240)),(9,c,x,80,http('trust.example','POST','/ocsp',504,640,240))],[(6,'인증기관 장애 통지',dict(incident='ca59',service='/ocsp',failure='upstream database timeout')),(9,'인증 검증기 감사',dict(nodes=[b,c],error='OCSP responder timeout',incident='ca59'))])
    add(60,'승인 만료 후 계속된 외부 감사 자료 동기화','침해 확인',out,'09T21:15:00',('ndr','hostname','audit-share.example'),('method','PUT'),'목록 확인 GET과 서로 다른 크기의 두 PUT을 사업자 객체 이력과 대조한다.',(
        '감사 담당자가 21:15에 승인 만료된 audit-share.example 자료함의 객체 변경을 신고했다.','NDR에서 호스트의 PUT을 선택해 자료 경로와 요청량을 외부 감사 자료함 객체 버전에 맞춘다.','목록 확인과 빈 표식 파일의 생성도 있었다. 실제 보고서 /eng60/report는 4 MiB 요청이었다.','승인 만료 뒤 동기화 계정이 제한 등급 보고서를 외부 자료함에 저장했다. 외부 사업자의 객체 버전과 내부 매니페스트 지문이 일치한다.','감사 담당자는 외부 자료함 v60의 보존·열람 이력을 확보하고 승인 만료 후 동기화된 다른 버전까지 대조한다.'),
        [(0,c,z,443,http('audit-share.example','GET','/eng60',200,400,3700)),(3,c,z,443,http('audit-share.example','PUT','/eng60/marker',201,210,280)),(9,c,z,443,http('audit-share.example','PUT','/eng60/report',201,4194304,290))],[(-4500,'감사 자료 반출 승인·내부 매니페스트',dict(engagement='eng60',expires='2025-03-09T20:00:00+09:00',fingerprint='rpt60',classification='제한')),(10,'외부 사업자 객체 감사',dict(version='v60',object='/eng60/report',principal='svc-sync',fingerprint='rpt60',result='stored'))])
    return rows
