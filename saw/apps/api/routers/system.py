"""What is installed: application, web bundle, casebook content and knowledge, each with its own version.

An update that reached the server but not the open browser tab, or the application but not the content files,
looks like "the cases did not change". This endpoint lets the screen say which part is which.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from saw import container
from saw.version import __version__
from saw.apps.api.deps import AuthContext, auth, db

router = APIRouter(tags=["system"])


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def casebook_status(dist: Path) -> dict:
    """The casebook as it is on disk: the declared content version, and whether every listed case file is there."""
    root = dist / "reference-data" / "platform-cases"
    index = _json(root / "index.json")
    declared = _json(dist / "reference-data" / "content-version.json") or {}
    if not isinstance(index, list):
        return {"installed": False, "cases": 0, "declared": declared,
                "text": "분석 사례집 파일이 설치되어 있지 않습니다. 업데이트가 화면 파일까지 적용됐는지 확인하세요."}
    ids = [str(c.get("id")) for c in index if isinstance(c, dict)]
    missing = [i for i in ids if not (root / f"{i}.json").is_file()]
    archives = sum(1 for i in ids if (root / f"{i}.zip").is_file())
    digest = hashlib.sha256((root / "index.json").read_bytes()).hexdigest()
    expected = (declared.get("casebook") or {}).get("cases")
    ok = not missing and (expected is None or expected == len(ids))
    return {"installed": True, "cases": len(ids), "first": ids[0] if ids else None, "last": ids[-1] if ids else None,
            "archives": archives, "missing_case_files": missing[:20], "index_sha256": digest,
            "declared": declared, "consistent": ok,
            "text": (f"분석 사례 {len(ids)}개가 설치되어 있습니다." if ok else
                     f"사례 목록은 {len(ids)}개인데 선언된 수는 {expected}개이거나 사례 파일 {len(missing)}개가 없습니다. 업데이트가 일부만 적용됐을 수 있습니다.")}


@router.get("/system/versions")
def versions(ctx: AuthContext = Depends(auth), s: Session = Depends(db, scope="function")):
    from saw.flows.models import FlowKnowledge
    from saw.internal_kb.models import DeviceSignature

    dist = Path(container.get().settings.web_dist)
    bundle = _json(dist / "version.json") or {}
    try:
        schema = s.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - development databases are created without Alembic
        s.rollback()
        schema = None
    knowledge = {
        "flow_items": s.scalar(select(func.count()).select_from(FlowKnowledge).where(FlowKnowledge.status == "active")) or 0,
        "flow_items_updated_at": s.scalar(select(func.max(FlowKnowledge.updated_at))),
        "device_signatures": s.scalar(select(func.count()).select_from(DeviceSignature)) or 0,
        "device_signatures_updated_at": s.scalar(select(func.max(DeviceSignature.updated_at))),
    }
    web_version = bundle.get("version")
    notes = []
    if web_version and web_version != __version__:
        notes.append(f"서버는 {__version__}인데 화면 파일은 {web_version}입니다. 업데이트가 일부만 적용됐습니다.")
    case = casebook_status(dist)
    if case["installed"] and not case["consistent"]:
        notes.append(case["text"])
    return {"app_version": __version__, "web_bundle": {"version": web_version, "built_at": bundle.get("built_at")},
            "schema": schema, "casebook": case, "knowledge": knowledge, "notes": notes}
