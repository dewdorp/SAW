"""Build six reproducible Korean investigation examples using only the standard library.

python -m saw.devtools.investigation_examples OUTPUT [--case W03] [--zip OUTPUT.zip]
python -m saw.devtools.investigation_examples --archives-dir DEST
For an existing directory use archive(output, target, case_id) to package one case.
"""
import argparse
import csv
import json
import random
import shutil
import tempfile
import zipfile
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__:
    from .practice_cases import FW, NDR
else:  # Direct execution from the web build also works.
    from practice_cases import FW, NDR

KST = timezone(timedelta(hours=9))
MIB = 1024 ** 2
CASES = {
    'W01': ('2025-01-06', 'web_attack', '198.51.100.41', '10.61.2.18', 'portal'),
    'W02': ('2025-03-10', 'periodic', '10.62.8.22', '203.0.113.82', 'telemetry'),
    'W03': ('2025-05-12', 'spread', '10.63.8.31', '10.63.22.48', 'inventory'),
    'W04': ('2025-07-14', 'transfer', '10.64.8.44', '10.64.20.12', 'release'),
    'W05': ('2025-09-15', 'long_window', '10.65.8.53', '10.65.31.0/24', 'branch'),
    'W06': ('2026-01-05', 'long_window', '10.66.8.64', '198.51.100.96', 'archive'),
}
PORTS = [22, 53, 80, 88, 135, 139, 389, 443, 445, 636, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017, 2049, 111]
PACKAGE_HASH = '9f' * 32


def followup(case, start):
    def when(day, hour):
        return (start + timedelta(days=day, hours=hour)).isoformat()

    if case == 'W01':
        records = [
            (
                'WEB-190',
                '웹 운영 담당',
                '오류 처리기 배포 기록',
                {
                    'host': 'portal.example',
                    'public_routes': ['/help', '/status'],
                    'unknown_route_behavior': '인증 안내 또는 오류 페이지',
                    'response_body_retained': False,
                },
            ),
        ]
        missing = '응답 본문과 해당 서버의 실행·파일 변경 감사 기록을 확보해야 한다.'
    elif case == 'W02':
        records = [
            (
                'OPS-258',
                '단말 운영 담당',
                '작업 등록 현황 회신',
                {
                    'src_ip': CASES[case][2],
                    'known_agent': '자산 동기화 에이전트',
                    'configured_endpoint': '192.0.2.12',
                    'suspect_process_attribution': None,
                },
            ),
        ]
        missing = '당시 소켓 소유 프로세스와 목적지 운영 주체가 확인되지 않았다.'
    elif case == 'W03':
        records = [
            (
                'CHG-327',
                '인프라 변경관리자',
                '사전 승인 점검표',
                {
                    'src_ip': CASES[case][2],
                    'dst_ip': CASES[case][3],
                    'protocol': 'TCP',
                    'ports': [22, 80, 443, 8443],
                    'from': when(60, 10),
                    'until': when(60, 11),
                },
            ),
        ]
        missing = '승인 포트 외 요청의 실행 주체와 대상 서비스의 인증 기록을 확인해야 한다.'
    elif case == 'W04':
        records = [
            (
                'REL-418',
                '배포 관리자',
                '사전 승인 배포 명세',
                {
                    'client': CASES[case][2],
                    'server': CASES[case][3],
                    'from': when(61, 13),
                    'until': when(61, 14),
                    'release': 'r17',
                    'parts': 12,
                    'bytes': 96 * MIB,
                    'package_sha256': PACKAGE_HASH,
                },
            ),
            (
                'INV-419',
                '단말 관리자',
                '수신 단말 설치 영수증',
                {
                    'client': CASES[case][2],
                    'installed_at': when(61, 14),
                    'parts_received': 12,
                    'installed_package_sha256': PACKAGE_HASH,
                },
            ),
        ]
        missing = '확인은 이 배포 명세의 시간·파일·대상 범위에 한정한다.'
    elif case == 'W05':
        records = [
            (
                'AST-523',
                '지점 자산 관리자',
                '단말의 기존 역할 확인',
                {
                    'src_ip': CASES[case][2],
                    'role': '문서 색인 서버',
                    'registered_file_shares': ['10.65.31.2', '10.65.31.3'],
                    'rollout_record_found': False,
                },
            ),
        ]
        missing = '신규 공유 대상의 업무 요청과 수신 서버의 인증·파일 접근 기록은 아직 확보하지 않았다.'
    else:
        records = [
            (
                'BKP-607',
                '백업 운영 담당',
                '백업 설정 스냅숏',
                {
                    'src_ip': CASES[case][2],
                    'registered_receiver': '192.0.2.26',
                    'registered_path': '/backup',
                    'content_inspection': False,
                },
            ),
        ]
        missing = '신규 수신자의 소유자와 전송 파일, 프로세스에 대한 독립 증거가 필요하다.'
    return {
        'synthetic': True,
        'case_id': case,
        'site': 'site-' + case.lower(),
        'records': [
            {'synthetic': True, 'record_id': record_id, 'provided_by': who, 'source': source, 'fields': fields}
            for record_id, who, source, fields in records
        ],
        'limitations': [{'synthetic': True, 'text': missing}],
    }


def generate_case(output: Path, case: str) -> dict[str, int]:
    date, _, src, dst, service = CASES[case]
    case_number = int(case[1:])
    net = f'10.{60 + case_number}'
    site = 'site-' + case.lower()
    start = datetime.fromisoformat(date).replace(tzinfo=KST)
    rng = random.Random(26200 + case_number)
    counts = {'fw': 0, 'ndr': 0}
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        writers = {}
        for key, header in [('fw', FW), ('ndr', NDR)]:
            file = stack.enter_context((output / f'{key}.csv').open('w', encoding='utf-8-sig', newline=''))
            writers[key] = csv.writer(file)
            writers[key].writerow(header)
        for day in range(63):
            rows = {'fw': [], 'ndr': []}
            midnight = start + timedelta(days=day)

            def fw(second, source_ip, target_ip, port, source_port, sent, received, allow=True, proto='TCP'):
                rows['fw'].append(
                    [
                        second,
                        net + '.0.253',
                        site + '-fw',
                        'allow' if allow else 'deny',
                        source_ip,
                        source_port,
                        target_ip,
                        port,
                        proto,
                        ('FA' if allow else 'S') if proto == 'TCP' else '',
                        round(sent / 1000000.0 + 0.02, 3) if allow else 0,
                        sent,
                        received,
                    ],
                )

            def http(second, source_ip, target_ip, source_port, path, response_bytes, request_bytes, status=200, method='GET', host=None, query='', agent='Mozilla/5.0'):
                uid = f"{case_number:02x}{day:02x}{len(rows['ndr']):06x}"
                rows['ndr'].append(
                    [
                        second,
                        site,
                        'HTTP',
                        'http',
                        'TCP',
                        source_ip,
                        source_port,
                        '',
                        target_ip,
                        443,
                        '',
                        net + '.0.254',
                        site + '-ndr',
                        method,
                        host or service + '.example',
                        path,
                        query,
                        agent,
                        '',
                        '',
                        uid,
                        status,
                        response_bytes,
                        request_bytes,
                    ],
                )
            # Most clients reuse a handful of services, with quieter shifts and weekend jitter.
            for i in range(1040 + case_number * 4):
                second = rng.randrange(86400) if i % 9 == 0 or day % 7 >= 5 else rng.randrange(7 * 3600, 20 * 3600)
                client = rng.randrange(16 + case_number)
                source_ip = f'{net}.40.{10 + client}'
                target_ip = f'{net}.20.{80 + client % 4}'
                source_port = rng.randrange(32768, 65536)
                sent = rng.randrange(180, 900)
                received = rng.randrange(450, 6000)
                if i < 650 + case_number * 3:
                    fw(second, source_ip, target_ip, 443, source_port, sent + 84, received + 102)
                    http(
                        second + 1,
                        source_ip,
                        target_ip,
                        source_port,
                        rng.choice(
                            ('/home', '/help', f'/api/{service}', '/assets/app.css', '/status'),
                        ),
                        received,
                        sent,
                        host=f'intra-{case_number}.example',
                    )
                elif i % 3:
                    fw(second, source_ip, net + '.2.53', 53, source_port, 84, rng.randrange(90, 380), proto='UDP')
                else:
                    allowed = i % 19 != 0
                    fw(second, source_ip, target_ip, 445, source_port, sent if allowed else 60, received if allowed else 0, allowed)
            if case == 'W01' and day == 59:
                for i in range(48):
                    path = ('/help', '/status')[i % 2] if i < 2 else f"/{('admin', 'api', 'backup', 'config')[i % 4]}/v{i:02d}"
                    status = (200, 200, 403, 404, 404, 500)[i % 6]
                    second = 8 * 3600 + 64 + i * 17
                    http(
                        second,
                        src,
                        dst,
                        47000 + i,
                        path,
                        900 + i * 13,
                        240,
                        status,
                        query='id=1%27%20OR%201%3D1' if i == 15 else '',
                        agent='HttpClient/4.5',
                    )
            elif case == 'W02' and day == 60:
                for i in range(96):
                    fw(
                        3 * 3600 + i * 300 + (i % 3 - 1) * 2,
                        src,
                        dst,
                        8443,
                        48000 + i,
                        288 + i % 5,
                        590 + i % 7,
                    )
            elif case == 'W03' and day == 60:
                for i, port in enumerate(PORTS):
                    allowed = port in [22, 80, 443, 8443, 3389]
                    fw(
                        10 * 3600 + 90 + i * 9,
                        src,
                        dst,
                        port,
                        49000 + i,
                        192 if allowed else 60,
                        320 if allowed else 0,
                        allowed,
                    )
            elif case == 'W04' and day == 61:
                for i in range(12):
                    http(
                        13 * 3600 + 90 + i * 70,
                        src,
                        dst,
                        50000 + i,
                        f'/packages/r17/part-{i + 1:02d}',
                        8 * MIB,
                        480,
                        206,
                        agent='PackageManager/3.1',
                    )
            elif case == 'W05':
                for k in range(2):
                    fw(6 * 3600 + k * 120, src, f'{net}.31.{2 + k}', 445, 51100 + k, 320, 640)
                if day >= 56:
                    for k in range(2):
                        allowed = k == 0
                        fw(
                            9 * 3600 + k * 15000 + day * 13,
                            src,
                            f'{net}.31.{40 + (day - 56) * 2 + k}',
                            445,
                            51000 + k,
                            154 if allowed else 60,
                            210 if allowed else 0,
                            allowed,
                        )
            elif case == 'W06':
                fw(4 * 3600, src, '192.0.2.26', 443, 52100, 256 * 1024, 720)
                if day in (56, 58, 59, 61, 62):
                    for k in range(6):
                        second = 22 * 3600 + 61 + k * 313
                        source_port = 52200 + (day - 56) * 8 + k
                        fw(second, src, dst, 443, source_port, 512 * 1024, 860)
                        if k % 2 == 0:
                            http(
                                second + 2,
                                src,
                                dst,
                                source_port,
                                '/v2/chunks',
                                340,
                                512 * 1024 - 250,
                                201,
                                'POST',
                                host='relay.example',
                                agent='SyncClient/2.4',
                            )
            for key, day_rows in rows.items():
                day_rows.sort(key=lambda row: row[0])
                counts[key] += len(day_rows)
                for row in day_rows:
                    row[0] = (midnight + timedelta(seconds=row[0])).isoformat()
                writers[key].writerows(day_rows)
    (output / 'followup.json').write_text(
        json.dumps(followup(case, start), ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
        newline='\n',
    )
    return counts


def generate(output, case_id=None):
    return {case: generate_case(Path(output) / case, case) for case in ([case_id] if case_id else CASES)}


def archive(output, target, case_id=None):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w') as out:
        for case in ([case_id] if case_id else CASES):
            for name in ('fw.csv', 'ndr.csv', 'followup.json'):
                info = zipfile.ZipInfo(case + '/' + name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o600 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with (Path(output) / case / name).open('rb') as source, out.open(info, 'w') as dest:
                    shutil.copyfileobj(source, dest)


def write_case_archives(destination: Path):
    """Generate independent archives; keep only one uncompressed case on disk at a time."""
    destination = Path(destination)
    for case in CASES:
        with tempfile.TemporaryDirectory() as scratch:
            generate(scratch, case)
            archive(scratch, destination / f'{case}.zip', case)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', nargs='?', type=Path)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--zip', type=Path)
    parser.add_argument('--archives-dir', type=Path)
    args = parser.parse_args()
    if args.archives_dir:
        if args.output or args.zip or args.case:
            parser.error('--archives-dir generates all six ZIPs and is used by itself')
        write_case_archives(args.archives_dir)
    else:
        if args.output is None:
            parser.error('provide output or --archives-dir')
        print(json.dumps(generate(args.output, args.case)))
        if args.zip:
            archive(args.output, args.zip, args.case)
