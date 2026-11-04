"""Build reproducible, chronologically interleaved FW/NDR inputs for alert-driven cases."""
import csv
import io
import json
import zipfile
from bisect import bisect_right
from pathlib import Path
from datetime import datetime, timedelta


def scenarios():
    if __package__:
        from .worked_web import cases as web
        from .worked_hosts import cases as hosts
        from .worked_edge import cases as edge
    else:
        from worked_web import cases as web
        from worked_hosts import cases as hosts
        from worked_edge import cases as edge
    result = [*web(), *hosts(), *edge()]
    for case in result:
        add_incident_series(case)
    return result


def add_incident_series(case):
    """Include repeated measurements where volume and timing affect the investigation."""
    counts = {'W33':24, 'W42':96, 'W49':240, 'W54':18, 'W59':40}
    count = counts.get(case['id'])
    if not count:
        return
    ref = case['events'][1]
    start = datetime.fromisoformat(ref['time'])
    series = []
    for n in range(count):
        event = {**ref, 'sport':54000+n}
        if case['id'] == 'W33':
            delay = 130 + 63*n + n%3
            event.update(sent=540+(n%8)*17, rcvd=1100+(n%7)*30)
        elif case['id'] == 'W42':
            delay = 3 + n//8
            event.update(sent=24000+120*n, rcvd=62000+217*n)
        elif case['id'] == 'W49':
            delay = 3 + n//10
            event.update(src=f'198.51.100.{10+n%48}', cs=460+n%6*7, sc=310+n%7*3)
        elif case['id'] == 'W54':
            delay = 5+6*n
            event.update(sent=410+n%4*5, rcvd=650)
        else:
            delay = 5+n//2
            event.update(src=f'10.80.1.{12+n%2}', cs=610+4*(n%11), sc=240)
        event['time'] = (start + timedelta(seconds=delay)).isoformat()
        series.append(event)
    case['events'].extend(series)


def csv_line(fields):
    buffer = io.StringIO(newline='')
    csv.writer(buffer).writerow(fields)
    return buffer.getvalue().encode('utf-8')


class Background:
    """Use the same benign input on every run, so differences arise from case evidence."""
    def __init__(self, path):
        self.headers, self.lines, self.times = {}, {}, {}
        for source in ('fw', 'ndr'):
            with (Path(path) / f'{source}.csv').open(encoding='utf-8-sig', newline='') as f:
                reader = csv.DictReader(f)
                header = reader.fieldnames
                self.headers[source] = header
                lines, times = [], []
                for row in reader:
                    if row['src_ip'].startswith('10.61.40.'):
                        lines.append(csv_line([row[key] for key in header]))
                        times.append(row.get('event_time') or row['_time'])
                self.lines[source], self.times[source] = lines, times

    def render(self, case):
        files, positions = {}, {}
        observations = [*case['events'], *contextual_activity(case)]
        for source in ('fw', 'ndr'):
            header = self.headers[source]
            rows, times = self.lines[source], self.times[source]
            parts, inserted = [b'\xef\xbb\xbf' + csv_line(header)], []
            start, offset = 0, len(parts[0])
            events = sorted((e for e in observations if e['source'] == source), key=lambda e:e['time'])
            for event in events:
                pos = bisect_right(times, event['time'], lo=start)
                span = b''.join(rows[start:pos])
                parts.append(span)
                offset += len(span)
                data = raw_fields(source, event, case['id'], len(inserted))
                record = csv_line([data.get(key, '') for key in header])
                if len(record.splitlines()) != 1:
                    raise ValueError('Sample event must fit one physical CSV line')
                inserted.append((pos + len(inserted) + 2, offset, record))
                parts.append(record)
                offset += len(record)
                start = pos
            parts.extend(rows[start:])
            files[source + '.csv'] = b''.join(parts)
            positions[source] = inserted
        followup = {'synthetic': True, 'case_id': case['id'], 'trigger': case['trigger'],
                    'records': case['followups']}
        files['followup.json'] = (json.dumps(followup, ensure_ascii=False, indent=2)+'\n').encode('utf8')
        return files, positions


def raw_fields(source, event, case_id, number):
    common = dict(src_ip=event['src'], src_port=event['sport'], protocol=event.get('proto','TCP'))
    if source == 'fw':
        action = event.get('action','allow')
        return {**common,'_time':event['time'],'_device_ip':'10.61.0.253','_device_name':'lab-fw',
                'dst_ip':event['dst'],'dst_port':event.get('dport',443),'action':action,
                'tcp_flag':('FA' if action=='allow' else 'S') if common['protocol']=='TCP' else '',
                'duration':event.get('duration',1 if action=='allow' else 0),
                'sent_bytes':event.get('sent',128),'rcvd_bytes':event.get('rcvd',0)}
    if source != 'ndr':
        raise ValueError('Unknown event source: '+source)
    return {**common,'event_time':event['time'],'_site':'case-lab','_schema':'http','app':'HTTP',
            'dest_ip':event['dst'],'dest_port':event.get('dport',443),'_device_ip':'10.61.0.254',
            '_device_name':'lab-ndr','method':event.get('method','GET'),'path':event.get('path','/'),
            'host':event.get('host','app.example'),'query':event.get('query',''),
            'user_agent':event.get('ua','ExampleClient/1.0'),'uuid':f'{case_id}-{number:05}',
            'status':event.get('status',200),'cs_bytes':event.get('cs',240),'sc_bytes':event.get('sc',800)}


def archive_files(path, case_id, files):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, content in files.items():
            info = zipfile.ZipInfo(f'{case_id}/{name}', (2026,1,1,0,0,0))
            info.create_system = 3
            info.external_attr = 0o600 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)


def contextual_activity(case):
    """Add other use of the lead address/hostname/route before the alert window."""
    case_number = int(case['id'][1:])
    lead = case['lead']
    first = min(datetime.fromisoformat(e['time']) for e in case['events'])
    source = lead['source']
    for i in range(48 + (case_number * 17) % 93):
        when = first - timedelta(minutes=25 + 39 * i + (i * 11) % 29)
        event = {'source':source, 'time':when.isoformat(), 'src':f'10.61.55.{11+i%19}',
                 'dst':f'10.61.56.{20+i%4}', 'sport':34000+(i*23)%25000,
                 'dport':443, 'proto':'TCP'}
        if source == 'ndr':
            event.update(method='HEAD' if i%7==0 else 'GET', host='service.example',
                         path=('/status','/assets/main.css','/help','/schedule')[i%4],
                         status=304 if i%8==1 else 200, cs=104+i*3, sc=240+i*19,
                         ua='Mozilla/5.0')
        else:
            event.update(dport=(443,8443,80)[i%3], sent=410+i*4, rcvd=720+i*17,
                         action='deny' if i%9==1 else 'allow')
            if event['action']=='deny':
                event.update(sent=60,rcvd=0)
        prop = {'hostname':'host','url_path':'path','src_ip':'src','dst_ip':'dst'}[lead['field']]
        event[prop] = lead['value']
        yield event
