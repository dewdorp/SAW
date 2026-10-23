"""Finite independent synthetic P3 writer safety/parity probes; no services."""
from copy import deepcopy
from html import unescape
import re
import pytest
from xml.etree import ElementTree as ET
from zipfile import ZipFile
from saw.reports.projection import project
from saw.reports.projection_html import render
from saw.reports.xlsx import write
from tests.unit.test_report_projection import frozen, workbook, section, N


def test_formula_prefixes_url_and_long_number_ids_remain_literal_and_same_html(tmp_path):
    content=frozen()
    literals=['=SUM(1,2)', '+cmd|\'/C synthetic\'!A0', '-1+2', '@SUM(A1:A2)',
              'https://synthetic.invalid/?q=<script>', '00000000001234567890123456789',
              '<img src=x onerror=synthetic()>']
    content['limits']=literals
    content['items'][0]['investigation']['id']='00000000001234567890123456789'
    path=tmp_path/'literals.xlsx'
    write(content,path)
    _, sheets, members=workbook(path)
    text=render(content)
    cells=[v for s in sheets for row in s for v in row.values()]
    for value in literals:
        assert any(actual==value and kind in {'inlineStr','s'} for actual,kind in cells), value
        assert value in unescape(text)
    assert '<img src=x onerror=' not in text and '<script>' not in text
    assert not any(b'<f>' in payload or b'<hyperlink' in payload for name,payload in members.items()
                   if name.startswith('xl/worksheets/sheet'))
    assert not any(b'TargetMode="External"' in payload for name,payload in members.items() if name.endswith('.rels'))


def test_every_chart_value_ref_resolves_to_its_exact_frozen_projection_row(tmp_path):
    content=frozen()
    original=deepcopy(content)
    model=project(content)
    path=tmp_path/'chart-refs.xlsx'
    write(content,path)
    _,sheets,members=workbook(path)
    timeline=sheets[4]
    header=next(row for row in timeline if any(value=='행 참조' for value,_ in row.values()))
    value_col=next(col for col,(label,_) in header.items() if label=='값')
    start_col=next(col for col,(label,_) in header.items() if label=='시작 UTC epoch 초')
    rows={row['row_ref']:row['cells'] for row in section(model,'timeline')['rows']}
    charts=[ET.fromstring(payload) for name,payload in members.items()
            if name.startswith('xl/charts/chart') and name.endswith('.xml')]
    assert len(charts)==len(model['charts'])>0
    for chart,series in zip(charts,model['charts']):
        formulas=[node.text for node in chart.findall('.//c:f',N)]
        assert len(formulas)==2
        for formula,column,key in zip(formulas,[start_col,value_col],['start','value']):
            refs=re.findall(r'!\$([A-Z]+)\$(\d+)',formula)
            assert len(refs)==len(series['row_refs'])
            for (col,number),ref in zip(refs,series['row_refs']):
                assert col==column
                value,kind=timeline[int(number)-1][column]
                assert kind=='n' and float(value)==float(rows[ref][key])
    assert content==original


def test_readable_intro_preserves_all_hidden_raw_values_and_meanings(tmp_path):
    content=frozen()
    task=content['items'][0]['followups'][0]['payload']
    task.update(status='verified',verification={'outcome':'insufficient_data','basis':'still unavailable'})
    model=project(content)
    assert any('일부만 완료' in line['value'] for line in model['overview']['lines'])
    assert any('자료 부족 (정상 판정 아님)' in line['value'] for line in model['overview']['lines'])
    html=render(content)
    assert html.index('자료 부족')<html.index('<details') and '<details open' not in html
    path=tmp_path/'readable.xlsx'
    manifest=write(content,path)
    names,sheets,members=workbook(path)
    assert len(names)==8
    for index,(sec,physical) in enumerate(zip(model['sections'],sheets)):
        header_index=next(i for i,row in enumerate(physical) if any(v=='행 참조' for v,_ in row.values()))
        header=physical[header_index]
        labels={v:col for col,(v,_) in header.items()}
        rows={row[labels['행 참조']][0]:row for row in physical[header_index+1:] if labels['행 참조'] in row}
        assert len(rows)==len(sec['rows'])
        assert manifest['sections'][index]['header_row']==header_index
        for row in sec['rows']:
            actual=rows[row['row_ref']]
            for col in sec['columns']:
                assert actual[labels[col['label']]][0]==str(row['cells'][col['key']])
        xml=ET.fromstring(members[f'xl/worksheets/sheet{index+1}.xml'])
        assert any(col.attrib.get('hidden')=='1' and col.attrib['min']=='1' and col.attrib['max']=='7'
                   for col in xml.findall('s:cols/s:col',N))


@pytest.mark.parametrize(('state','label'),[('partial','일부만 완료'),('insufficient_data','자료 부족'),('failed','실패')])
def test_overview_cannot_replace_execution_incomplete_status_with_complete_detail(state,label):
    content=frozen()
    execution=content['items'][0]['analysis']['executions'][0]
    execution['status']=state
    execution['detail']['status']='complete'
    model=project(content)
    brief=next(line for line in model['overview']['lines'] if line['label']=='WAF 관측')
    assert label in brief['value'], brief
