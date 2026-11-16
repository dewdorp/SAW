"""The 120 investigation example specifications (detection 60, hunt 40, scenario 20), searchable from a question.

They are editable knowledge, not installed rules: none of them runs by itself. Each item says three things
separately so "the field exists" is never read as "analysed": whether SAW has a computation for it (only
through the basic question it maps to), whether this investigation's data is ready, and that it has not run.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from saw import container
from saw.core.application import question_bundles as qb
from saw.core.schemas.query import Filter

DATA = Path(__file__).resolve().parents[3] / "data" / "question_examples" / "examples.json"
KINDS = {"detection": "탐지 조건 명세", "hunt": "헌팅 질문", "scenario": "조사 시나리오"}
READINESS = {"fields_available": "제공 필드로 시작 가능", "profile_required": "장비 설정·원천 의미 확인 필요",
             "additional_data_required": "추가 로그 필요"}
# Which data sources stand for each input named in the examples.
INPUT_SOURCES = {"NDR": ["web"], "FW": ["connection", "firewall"]}


@lru_cache(maxsize=1)
def _catalog() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def _present(inv_id: str) -> dict[str, bool]:
    es = container.get().events
    return {name: bool(es.count(inv_id, [Filter(field="data_source", op="in", value=sources)], None))
            for name, sources in INPUT_SOURCES.items()}


def search(inv_id: str, q: str = "", kind: str = "", limit: int = 120) -> dict:
    catalog = _catalog()
    connected = {x["id"]: x for x in qb.QUESTION_MAP}
    present = _present(inv_id)
    needle = q.strip().lower()
    items = []
    for t in catalog["templates"]:
        if kind and t["kind"] != kind:
            continue
        text = " ".join([t["id"], t["title"], t["question"], t["category"], " ".join(t["basic_questions"])]).lower()
        if needle and needle not in text:
            continue
        nearby = [connected[q] for q in t["basic_questions"] if q in connected and connected[q]["bundle"]]
        execution = ({"state": "nearby_question", "label": f"자체 실행기 없음 · 가까운 계산 {nearby[0]['id']} 연결됨",
                      "question": nearby[0]["id"], "bundle": nearby[0]["bundle"]} if nearby else
                     {"state": "spec_only", "label": "명세만 · 실행기 연결 안 됨", "question": (t["basic_questions"] or [None])[0],
                      "bundle": None})
        missing = [i for i in t["inputs"] if i in present and not present[i]]
        unknown = [i for i in t["inputs"] if i not in present]
        readiness = READINESS.get(t["availability"], t["availability"])
        if missing:
            readiness += f" · 이 조사에 {', '.join(missing)} 자료 없음"
        if unknown:
            readiness += f" · 추가 원천 필요: {', '.join(unknown)}"
        items.append({**t, "kind_ko": KINDS.get(t["kind"], t["kind"]), "execution": execution,
                      "data_readiness": {"state": t["availability"], "label": readiness, "missing_inputs": missing + unknown},
                      "calculation": {"state": "not_run", "label": "아직 실행 안 함"}})
    return {"items": items[:limit], "total": len(items), "catalog_total": len(catalog["templates"]),
            "note": catalog["note_ko"], "schema_version": catalog["schema_version"]}
