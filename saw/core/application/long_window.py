"""Read-only comparison of eight historical weeks and the latest seven days in one event view."""
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from saw.analyzers.ioc.observables import affiliate_local
from saw.config import get_settings
from saw.core.schemas.query import Filter, TimeRange

FW = ('en_fw_csv', 'ko_fw_csv')
NDR = ('en_ndr_http_csv', 'ko_ndr_csv')
MAX_ROWS = 250_000
MAX_PER_KIND = 10
MIB = 1024 ** 2
DAY = timedelta(days=1)
FIELDS = ['timestamp', 'event_id', 'parser', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
          'protocol', 'enforcement_action', 'bytes_out', 'method']


def _scope(view, inv_id, period, sources):
    if period and period.end:
        end = datetime.fromisoformat(period.end)
        if not period.end_exclusive:
            end += timedelta(microseconds=1)
    else:
        _, last = view.time_bounds(inv_id, sources)
        if not last:
            return None
        zone = ZoneInfo(get_settings().default_timezone)
        end = datetime.fromisoformat(last).astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0) + DAY
    declared_start = datetime.fromisoformat(period.start) if period and period.start else end - 63 * DAY
    return max(declared_start, end - 63 * DAY), end - 7 * DAY, end


def _item(kind, group, rows, filters, time):
    src, port, protocol = group
    exact = [Filter(field='parser', op='in', value=list(FW)), Filter(field='src_ip', value=src),
             Filter(field='dst_port', value=port), Filter(field='protocol', value=protocol), *filters]
    return {'kind': kind, 'src': src, 'port': port, 'protocol': protocol,
            'filters': [f.model_dump() for f in exact], 'time': time.model_dump(),
            'evidence_ids': [r['event_id'] for r in rows[:5]]}


def _spread(group, weeks, rows, time):
    past = set().union(*weeks.values())
    new = [r for r in rows if r['dst_ip'] not in past]
    targets = sorted({r['dst_ip'] for r in new})
    days = len({r['day'] for r in new})
    peak = max((len(value) for value in weeks.values()), default=0)
    total = len({r['dst_ip'] for r in rows})
    if len(targets) < 6 or days < 3 or total <= peak:
        return None
    actions = Counter(r.get('enforcement_action') for r in new)
    history = (f'직전 8주 같은 출발지·포트·프로토콜의 주간 내부 목적지는 최대 {peak:,}개였습니다.' if weeks else
               '직전 8주 같은 출발지·포트·프로토콜의 내부 FW 기록이 없어 이전 활동 규모를 알 수 없습니다.')
    # A large fan-out still opens an exact, bounded example query.
    show = targets[:100]
    shown = set(show)
    item = _item('spread', group, [r for r in new if r['dst_ip'] in shown],
                 [Filter(field='dst_ip', op='in', value=show)], time)
    item.update(observed=f"최근 {days}일에 걸쳐 내부 목적지 {total:,}개 중 {len(targets):,}개에 새로 접속을 시도했습니다.",
                baseline=history,
                corroboration=f"신규 목적지 FW 기록 {len(new):,}건 중 허용 {actions['allowed']:,}건, 차단 {actions['blocked']:,}건입니다."
                              + (f" 근거 조회에는 목적지 {len(show)}개를 표시합니다." if len(targets) > len(show) else ''),
                next_check='승인 점검의 기간·출발지·대상 대역·포트를 대조하고 대상 서버에서 인증·실행 기록을 확인하세요.',
                metrics={'new_targets': len(targets), 'recent_targets': total, 'baseline_weekly_peak': peak if weeks else None,
                         'observed_days': days, 'new_records': len(new), 'allowed': actions['allowed'], 'blocked': actions['blocked']})
    return item


def _outbound(group, dst, rows, baseline_bytes, posts, time):
    days = len({r['day'] for r in rows})
    sent = sum(r['bytes_out'] for r in rows)
    if days < 3 or sent < 8 * MIB or (baseline_bytes is not None and sent * 8 <= baseline_bytes * 2):
        return None
    overnight = sum(r['hour'] >= 22 or r['hour'] < 6 for r in rows)
    largest = max(r['bytes_out'] for r in rows)
    sessions = defaultdict(list)
    for row in rows:
        if row['src_port'] is not None:
            sessions[row['src_port']].append(row['epoch'])
    matched = []
    for post in posts:
        stamps = sessions.get(post['src_port'], [])
        i = bisect_left(stamps, post['epoch'] - 5)
        if i < len(stamps) and stamps[i] <= post['epoch'] + 5:
            matched.append(post['event_id'])
    history = (f'같은 출발지·포트·프로토콜에서 외부 범위로 향한 FW 허용 송신량은 주간 평균 {baseline_bytes / 8 / MIB:,.1f} MiB입니다.'
               if baseline_bytes is not None else '같은 출발지·서비스의 과거 송신 열이 부족해 주간 송신량을 비교할 수 없습니다.')
    item = _item('outbound', group, rows, [Filter(field='dst_ip', value=dst),
                 Filter(field='enforcement_action', value='allowed'), Filter(field='bytes_out', op='range', value={'gt': 0})], time)
    item.update(dst=dst, observed=f"최근 {days}일간 새 외부 주소 범위의 목적지로 향한 FW 허용 기록 {len(rows):,}건의 송신량은 {sent / MIB:,.1f} MiB입니다. 기록당 최대 {largest / MIB:,.1f} MiB이며, 비교 기간 시간대의 22시~06시 기록은 {overnight:,}건입니다.",
                baseline=f"직전 8주 같은 출발지·목적지·서비스의 FW 기록은 0건입니다. {history}",
                corroboration=(f"출발지·목적지 주소와 양쪽 포트·프로토콜이 같고 시각 차가 5초 이내인 NDR POST·PUT 요청 {len(matched):,}건입니다. 송신량은 FW 열만 합산했습니다."),
                next_check='FW 송신 열의 방향을 확인하고, 승인된 백업과 대조한 뒤 프록시·단말 자료로 전송 내용과 수신 주체를 확인하세요.',
                metrics={'observed_days': days, 'fw_rows': len(rows), 'sent_bytes': sent, 'overnight_rows': overnight, 'largest_fw_sent_bytes': largest,
                         'baseline_weekly_sent_bytes': baseline_bytes / 8 if baseline_bytes is not None else None, 'matched_ndr_requests': len(matched)},
                corroborating_event_ids=matched[:5])
    return item


def compare(view, inv_id, period):
    sources = [Filter(field='parser', op='in', value=[*FW, *NDR])]
    bounds = _scope(view, inv_id, period, sources)
    counts = {'baseline': 0, 'recent': 0}
    scope = dict.fromkeys(('baseline_start', 'baseline_end', 'recent_start', 'recent_end'))
    result = {'status': 'insufficient', 'scope': scope, 'counts': counts, 'candidates': [],
              'note': '비교할 시각이 있는 FW·NDR CSV 기록이 없습니다.'}
    if not bounds:
        return result
    start, split, end = bounds
    baseline_end = max(start, split)
    scope.update(baseline_start=start.isoformat(), baseline_end=baseline_end.isoformat(),
                 recent_start=baseline_end.isoformat(), recent_end=end.isoformat())
    time = TimeRange(start=scope['recent_start'], end=scope['recent_end'], end_exclusive=True)
    scan = TimeRange(start=scope['baseline_start'], end=scope['recent_end'], end_exclusive=True)
    coverage = set()
    weekly_targets = defaultdict(lambda: defaultdict(set))
    recent_internal = defaultdict(list)
    past_external = set()
    baseline_sent = Counter()
    missing_baseline_bytes = set()
    recent_external = defaultdict(list)
    posts = defaultdict(list)
    origin = end - 63 * DAY
    for i, row in enumerate(view.iterate(inv_id, sources, scan, fields=FIELDS)):
        if i >= MAX_ROWS:
            result.update(status='partial', note=f'계산 한도 {MAX_ROWS:,}건을 넘었습니다. 건수는 읽은 기록만 포함합니다. 전체 기준선과 후보를 계산할 수 없습니다.')
            return result
        stamp = datetime.fromisoformat(row['timestamp']).astimezone(end.tzinfo)
        day = (stamp - origin).days
        recent = day >= 56
        counts['recent' if recent else 'baseline'] += 1
        fw = row['parser'] in FW
        if fw:
            coverage.add(day)
        src, dst, port, protocol = (row.get(k) for k in ('src_ip', 'dst_ip', 'dst_port', 'protocol'))
        if not src or not dst or port is None or not protocol or not affiliate_local(src):
            continue
        group = (src, port, protocol)
        pair = (group, dst)
        if fw and affiliate_local(dst):
            if recent:
                recent_internal[group].append(dict(row, day=day))
            else:
                weekly_targets[group][day // 7].add(dst)
        elif fw:
            sent = row.get('bytes_out') or 0
            if not recent:
                past_external.add(pair)
                if row.get('enforcement_action') == 'allowed':
                    if row.get('bytes_out') is None:
                        missing_baseline_bytes.add(group)
                    else:
                        baseline_sent[group] += sent
            elif sent > 0 and row.get('enforcement_action') == 'allowed':
                recent_external[pair].append(dict(row, day=day, hour=stamp.hour, epoch=stamp.timestamp()))
        elif recent and row.get('method') in ('POST', 'PUT') and row.get('src_port') is not None:
            posts[pair].append(dict(event_id=row['event_id'], src_port=row['src_port'], epoch=stamp.timestamp()))
    baseline_days = sum(d < 56 for d in coverage)
    recent_days = len(coverage) - baseline_days
    if start > origin or baseline_days < 56 or recent_days < 7:
        result['note'] = f'FW 관측일은 기준 기간 {baseline_days}/56일, 최근 {recent_days}/7일입니다. 두 기간 모두 일별 기록이 있어야 신규 목적지를 비교합니다.'
        return result
    spread = [_spread(g, weekly_targets.get(g, {}), rows, time) for g, rows in recent_internal.items()]
    outgoing = [_outbound(g, dst, rows, None if g in missing_baseline_bytes else baseline_sent.get(g),
                          posts.get((g, dst), []), time)
                for (g, dst), rows in recent_external.items() if (g, dst) not in past_external]
    ranked = []
    for items, metric in ((spread, 'new_targets'), (outgoing, 'sent_bytes')):
        ranked.extend(sorted((c for c in items if c), key=lambda c: (-c['metrics'][metric], c['src'], c['port'], c['protocol'], c.get('dst', '')))[:MAX_PER_KIND])
    result.update(status='ready', candidates=ranked,
                  note='시각이 있는 FW·NDR CSV의 최근 7일과 직전 56일을 비교했습니다. 건수는 관측 기록이며 유형별 상위 10개 후보를 표시합니다. 내부·외부는 사설·로컬 주소 범위 구분이며 자산 소유·전송 내용은 별도 확인이 필요합니다.')
    return result
