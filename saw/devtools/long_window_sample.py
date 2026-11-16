"""Generate fictional long-window traffic in the released practice CSV formats.

    python -m saw.devtools.long_window_sample /tmp/saw-deep-cases/bundle
    python -m saw.devtools.long_window_sample --zip /tmp/long-window-sample.zip

Only fw.csv and ndr.csv are event imports. operations.csv is an independent
synthetic change calendar. truth.json is for evaluator use after analysis.
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

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / 'apps/web/public/practice-data/v1/C010'
START = datetime(2026, 9, 1, tzinfo=timezone(timedelta(hours=9)))
MIB = 1024 ** 2
SMB, CLIENT = '10.44.12.77', '10.44.12.86'
SCANNER, CHANGED, BACKUP = '10.44.8.8', '10.44.8.18', '10.44.8.19'
TARGET, STABLE, VAULT = '198.51.100.177', '192.0.2.99', '203.0.113.11'
TRANSFER_DAYS = (56, 57, 59, 60, 62)
OPS_FIELDS = ('record_id', 'approved_at', 'valid_from', 'valid_to', 'src_ip',
              'dst_cidr', 'dst_port', 'protocol', 'purpose')


def headers(kind):
    with (SAMPLE / f'{kind}.csv').open(encoding='utf-8-sig', newline='') as file:
        return next(csv.reader(file))


def generate(output):
    output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261104)
    counts = {'fw': 0, 'ndr': 0}
    with ExitStack() as stack:
        def writer(name, fields):
            file = stack.enter_context((output / f'{name}.csv').open('w', newline='', encoding='utf-8-sig'))
            out = csv.writer(file)
            out.writerow(fields)
            return out

        writers = {kind: writer(kind, headers(kind)) for kind in counts}
        ops = writer('operations', OPS_FIELDS)
        for record, source, scope, port, start, end, purpose in (
            ('OPS-613', SCANNER, '10.44.33.0/26', 445, 0, 62, 'Nightly inventory'),
            ('OPS-629', BACKUP, VAULT + '/32', 443, 0, 62, 'Encrypted vault backup'),
            ('CHG-825', CHANGED, '10.44.34.0/26', 445, 56, 62, 'Asset inventory expansion'),
        ):
            opening = START + timedelta(days=start)
            ops.writerow([record, (opening - timedelta(days=4)).isoformat(), opening.isoformat(),
                          (START + timedelta(days=end + 1, seconds=-1)).isoformat(), source,
                          scope, port, 'TCP', purpose])

        for day in range(63):
            midnight = START + timedelta(days=day)
            daily = {'fw': [], 'ndr': []}

            def fw(second, src, sport, dst, port, sent, received, action='allow', proto='TCP'):
                stamp = (midnight + timedelta(seconds=second)).isoformat()
                flag = ('S' if action == 'deny' else 'FA') if proto == 'TCP' else ''
                daily['fw'].append([stamp, '10.44.0.253', 'fw-01', action, src, sport, dst, port,
                                    proto, flag, 0 if action == 'deny' else round(0.1 + sent / 8000000, 3),
                                    sent, received])

            def ndr(second, src, sport, dst, host, path, method, sent, received):
                stamp = (midnight + timedelta(seconds=second)).isoformat()
                uid = f'a{day:02x}{len(daily["ndr"]):06x}'
                daily['ndr'].append([stamp, 'site-a', 'HTTP', 'http', 'TCP', src, sport, '', dst, 443,
                                     '', '10.44.0.254', 'ndr-01', method, host, path, '', 'ExampleClient/2.4',
                                     '', '', uid, 200, received, sent])

            # Desktop work follows a day shift; each department uses a small, stable service pool.
            for i in range(1150):
                second = rng.randrange(86400) if i % 12 == 0 else rng.randrange(8 * 3600, 19 * 3600)
                department = rng.randrange(1, 7)
                src = f'10.44.{40 + department}.{rng.randrange(2, 62)}'
                sport = rng.randrange(32768, 65536)
                dst = f'10.44.20.{department * 10 + rng.randrange(4)}'
                sent, received = rng.randrange(400, 9000), rng.randrange(500, 90000)
                if i < 880:
                    if i % 5 == 0:
                        dst = f'192.0.2.{10 + department}'
                    method, path = ('POST', '/api/sync') if i % 7 == 0 else ('GET', '/records')
                    fw(second, src, sport, dst, 443, sent + 230, received + 170)
                    ndr(second + 1, src, sport, dst, f'service-{department}.example', path, method, sent, received)
                elif i % 3 == 0:
                    fw(second, src, sport, '10.44.2.53', 53, 94, 210, proto='UDP')
                else:
                    fw(second, src, sport, dst, 445, sent, received, 'deny' if i % 17 == 0 else 'allow')

            # Stable monitoring and heavy backups create volume and cardinality controls.
            for k in range(36):
                fw(3600 + k * 23, SCANNER, 37000 + k, f'10.44.33.{k + 2}', 445, 108, 88)
                fw(7 * 3600 + k * 97, '10.44.8.4', 37500 + k, f'10.44.35.{k + 2}', 8443, 555, 1980)
            fw(7800, BACKUP, 52000, VAULT, 443, 192 * MIB, 4200)
            fw(23 * 3600, CLIENT, 49800, STABLE, 443, 2 * MIB, 2120)
            for k in range(2):
                fw(11 * 3600 + k * 600, SMB, 53700 + k, f'10.44.30.{2 + k}', 445, 1700, 2300)
            if day >= 56:
                for k in range(3):
                    target = 20 + 3 * (day - 56) + k
                    fw((8 + 5 * k) * 3600 + 191 + day, SMB, 54000 + target, f'10.44.31.{target}',
                       445, 158, 84 if k == 0 else 0, 'allow' if k == 0 else 'deny')
                    fw((9 + 3 * k) * 3600 + 77, CHANGED, 57000 + target, f'10.44.34.{target}', 445, 142, 88)
            if day in TRANSFER_DAYS:
                for k in range(4):
                    second = 22 * 3600 + 17 * 60 + k * 851
                    sport = 56200 + (day - 56) * 4 + k
                    fw(second, CLIENT, sport, TARGET, 443, 6 * MIB, 1940)
                    if k % 2 == 0:
                        ndr(second + 1, CLIENT, sport, TARGET, 'files.example', '/api/parts',
                            'POST', 6 * MIB - 300, 780)
            for kind, rows in daily.items():
                rows.sort(key=lambda row: row[0])
                writers[kind].writerows(rows)
                counts[kind] += len(rows)

    truth = {'synthetic': True, 'site': 'site-a', 'timezone': '+09:00', 'baseline_days': 56,
             'recent_days': 7, 'start': START.isoformat(), 'recent_from': (START + timedelta(days=56)).isoformat(),
             'end_exclusive': (START + timedelta(days=63)).isoformat(), 'row_counts': counts,
             'slow_fanout': {'src_ip': SMB, 'dst_port': 445, 'historical_weekly_distinct': 2,
                             'recent_distinct': 23, 'recent_new_destinations': 21, 'new_per_day': 3,
                             'new_allowed': 7, 'new_denied': 14},
             'staged_transfer': {'src_ip': CLIENT, 'dst_ip': TARGET, 'dst_port': 443, 'historical_pair_rows': 0,
                                 'historical_src_weekly_sent_bytes': 14 * MIB, 'recent_pair_sent_bytes': 120 * MIB,
                                 'active_days': 5, 'fw_rows': 20, 'ndr_post_rows': 10,
                                 'ndr_client_request_bytes': 10 * (6 * MIB - 300)},
             'controls': {'inventory': SCANNER, 'maintenance': CHANGED, 'backup': BACKUP}}
    (output / 'truth.json').write_text(json.dumps(truth, indent=2) + '\n', encoding='utf-8', newline='\n')
    return counts


def zip_sample(source_dir: Path, target: Path) -> None:
    """Zip the four previously generated files with stable timestamps and permissions."""
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w') as archive:
        for name in ('fw.csv', 'ndr.csv', 'operations.csv', 'truth.json'):
            info = zipfile.ZipInfo(name, (2026, 11, 3, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with (source_dir / name).open('rb') as source, archive.open(info, 'w') as dest:
                shutil.copyfileobj(source, dest)


def write_sample_archive(target: Path) -> None:
    """Build a self-contained synthetic example archive for release media."""
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary)
        generate(source)
        zip_sample(source, target)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument('output', type=Path, nargs='?')
    destination.add_argument('--zip', type=Path, dest='archive')
    args = parser.parse_args()
    if args.archive:
        write_sample_archive(args.archive)
    else:
        print(generate(args.output))
