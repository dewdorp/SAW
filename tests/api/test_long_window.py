from datetime import datetime, timedelta, timezone

from saw.core.application import long_window
from saw.core.schemas.query import Filter, TimeRange
from saw.storage.eventstore import SQLiteEventStore


START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(days=63)
PERIOD = TimeRange(start=START.isoformat(), end=END.isoformat(), end_exclusive=True)


def seed(store):
    rows = []

    def add(day, src, dst, port, *, ndr=False, sport=1255, sec=0, sent=64):
        row = dict(timestamp=(START + timedelta(days=day, seconds=sec)).isoformat(), event_id=str(len(rows)),
                   investigation_id='case', parser='en_ndr_http_csv' if ndr else 'en_fw_csv',
                   src_ip=src, dst_ip=dst, dst_port=port, src_port=sport, protocol='TCP', bytes_out=sent,
                   enforcement_action='allowed', method='POST' if ndr else None)
        rows.append(row)

    for day in range(63):
        add(day, '10.1.1.2', '10.2.1.1', 445)
        add(day, '10.1.1.3', '192.0.2.1', 443, sent=1024**2)
        for target in range(8):
            add(day, '10.1.1.4', f'10.3.1.{target+1}', 445)
        if day >= 56:
            add(day, '10.1.1.2', f'10.2.2.{day}', 445)
            add(day, '10.1.1.3', '203.0.113.5', 443, sent=4 * 1024**2)
            add(day, '10.1.1.3', '203.0.113.5', 443, ndr=True, sec=1, sent=999999)
            add(day, '10.1.1.3', '203.0.113.5', 443, ndr=True, sec=6)
            add(day, '10.1.1.3', '203.0.113.5', 443, ndr=True, sport=4567)
    store.index(rows)
    # An otherwise identical baseline event in a different investigation cannot suppress a new pair.
    store.index([{**rows[0], 'event_id': 'other', 'investigation_id': 'elsewhere', 'src_ip': '10.1.1.3',
                  'dst_ip': '203.0.113.5', 'dst_port': 443}])


def test_full_windows_and_requery(tmp_path):
    store = SQLiteEventStore(tmp_path / 'events.db')
    seed(store)
    result = long_window.compare(store, 'case', PERIOD)
    assert result['status'] == 'ready' and result['counts'] == {'baseline': 560, 'recent': 105}
    spread, transfer = result['candidates']
    assert spread['metrics']['new_targets'] == 7 and spread['metrics']['baseline_weekly_peak'] == 1
    assert transfer['metrics'] == {'observed_days': 7, 'fw_rows': 7, 'sent_bytes': 28 * 1024**2,
                                  'overnight_rows': 7, 'largest_fw_sent_bytes': 4 * 1024**2,
                                  'baseline_weekly_sent_bytes': 7 * 1024**2, 'matched_ndr_requests': 7}
    for item in (spread, transfer):
        rows = list(store.iterate('case', [Filter(**f) for f in item['filters']], TimeRange(**item['time'])))
        assert len(rows) == 7 and set(item['evidence_ids']) <= {r['event_id'] for r in rows}


def test_insufficient_or_capped_history_has_no_novelty_claims(tmp_path, monkeypatch):
    store = SQLiteEventStore(tmp_path / 'events.db')
    assert long_window.compare(store, 'case', None)['status'] == 'insufficient'
    seed(store)
    short = TimeRange(start=(START + timedelta(days=10)).isoformat(), end=END.isoformat(), end_exclusive=True)
    result = long_window.compare(store, 'case', short)
    assert result['status'] == 'insufficient' and result['candidates'] == []
    monkeypatch.setattr(long_window, 'MAX_ROWS', 30)
    result = long_window.compare(store, 'case', PERIOD)
    assert result['status'] == 'partial' and result['counts']['baseline'] == 30 and not result['candidates']


def test_investigation_read_access(analyst, app):
    from tests.conftest import Api, make_user

    inv = analyst.post('/investigations', json={'title': '장기 비교'}).json()['id']
    path = f'/investigations/{inv}/long-window-comparisons'
    assert analyst.get(path).json()['status'] == 'insufficient'
    make_user('outsider', ['analyst'])
    assert Api(app, 'outsider').get(path).status_code == 403


def test_missing_source_history_and_missing_byte_fields(tmp_path):
    store = SQLiteEventStore(tmp_path / 'events.db')
    seed(store)
    baseline = list(store.iterate('case', [Filter(field='src_ip', value='10.1.1.3')],
                                  TimeRange(end=(START + timedelta(days=56)).isoformat(), end_exclusive=True)))
    store.index([{**row, 'bytes_out': None} for row in baseline])
    novel = list(store.iterate('case', [Filter(field='src_ip', value='10.1.1.2')],
                               TimeRange(start=(START + timedelta(days=56)).isoformat())))
    store.index([{**row, 'src_ip': '10.1.1.5', 'event_id': 'new-' + row['event_id']} for row in novel])
    assert long_window.compare(store, 'case', None)['status'] == 'ready'
    result = long_window.compare(store, 'case', PERIOD)
    new = next(c for c in result['candidates'] if c['src'] == '10.1.1.5')
    assert new['metrics']['baseline_weekly_peak'] is None and '이전 활동 규모' in new['baseline']
    transfer = next(c for c in result['candidates'] if c['kind'] == 'outbound')
    assert transfer['metrics']['baseline_weekly_sent_bytes'] is None and '송신 열이 부족' in transfer['baseline']
