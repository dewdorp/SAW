"""Parser library API: suggest → preview → save (versioned), enable/disable, export/import (FR-LOG-11)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from saw.apps.api.deps import AuthContext, db, require_perm
from saw.core.security.masking import mask_text
from saw.parsers import library as lib
from saw.parsers.base import Parsed, RawLine, Skip
from saw.parsers.custom import CES_TARGETS, DATA_SOURCES, DefinedParser, ParserSpec, suggest
from saw.parsers.registry import to_ces

router = APIRouter(tags=["parsers"])
MAX_SAMPLE = 512 * 1024


class SampleIn(BaseModel):
    sample: str = Field(max_length=MAX_SAMPLE)


class PreviewIn(SampleIn):
    spec: dict


class ReviewIn(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)


class SaveIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=47)
    spec: dict
    note: str = Field(default="", max_length=2000)


@router.get("/parser-library")
def list_parsers(ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    return {"parsers": lib.list_definitions(s, ctx.principal), "targets": CES_TARGETS, "data_sources": DATA_SOURCES}


@router.get("/parser-library/{slug}")
def parser_history(slug: str, ctx: AuthContext = Depends(require_perm("analyze.run")),
                   s: Session = Depends(db, scope="function")):
    return lib.history(s, slug, ctx.principal)


@router.post("/parser-library/suggest")
def suggest_spec(body: SampleIn, ctx: AuthContext = Depends(require_perm("analyze.run"))):
    return suggest(body.sample.splitlines()[:200])


@router.post("/parser-library/preview")
def preview(body: PreviewIn, ctx: AuthContext = Depends(require_perm("analyze.run"))):
    """Parse the sample with an unsaved spec: CES fields per line, failures and the detection score."""
    parser = DefinedParser("preview", 0, ParserSpec.model_validate(body.spec))
    lines = body.sample.splitlines()[:500]
    score = parser.detect(lines[:200])
    parser.reset()
    rows, failures, cov = [], [], {"lines": 0, "events": 0, "skipped_lines": 0, "failed_lines": 0}
    offset = 0
    raw_lines = []
    for i, text in enumerate(lines, 1):
        raw_lines.append(RawLine(text, offset, i))
        offset += len(text.encode("utf-8")) + 1
    for rl, r in parser.parse(x for x in raw_lines if x.text.strip()):
        cov["lines"] += 1
        if isinstance(r, Skip):
            cov["skipped_lines"] += 1
        elif isinstance(r, Parsed):
            cov["events"] += 1
            if len(rows) < 20:
                ev = to_ces(parser, rl, r, investigation_id="preview", evidence_id=None, file_id="preview",
                            source_file="preview", object_key=None, assumed_tz="Asia/Seoul")
                ev.pop("raw_ref", None)
                rows.append({"line_no": rl.line_no, "fields": {k: v for k, v in ev.items() if k not in (
                    "event_id", "investigation_id", "evidence_id", "parser", "parser_version", "source_file",
                    "raw_event", "ces_version", "product")}})
        else:
            cov["failed_lines"] += 1
            if len(failures) < 20:
                failures.append({"line_no": rl.line_no, "reason": r.reason, "raw": mask_text(rl.text[:300]).text})
    return {"detect_score": score, "auto_detect": score >= 0.8, "coverage": cov, "rows": rows, "failures": failures}


@router.post("/parser-library", status_code=201)
def save(body: SaveIn, ctx: AuthContext = Depends(require_perm("parser.manage")),
         s: Session = Depends(db, scope="function")):
    return lib.save(s, ctx.principal, body.name, body.spec, body.slug, body.note)


@router.post("/parser-library/{slug}/versions/{version}/share")
def request_share(slug: str, version: int, ctx: AuthContext = Depends(require_perm("parser.manage")),
                  s: Session = Depends(db, scope="function")):
    """Author asks to make a draft the shared (auto-detected) version."""
    return lib.request_share(s, ctx.principal, slug, version)


@router.post("/parser-library/{slug}/versions/{version}/review")
def review(slug: str, version: int, body: ReviewIn, ctx: AuthContext = Depends(require_perm("parser.approve")),
           s: Session = Depends(db, scope="function")):
    """Another analyst approves (shared) or returns (draft) a pending version - never the author (4-eyes)."""
    return lib.review(s, ctx.principal, slug, version, body.approve, body.note)


@router.post("/parser-library/{slug}/disable")
def disable(slug: str, ctx: AuthContext = Depends(require_perm("parser.approve")),
            s: Session = Depends(db, scope="function")):
    return lib.set_status(s, ctx.principal, slug, enabled=False)


@router.post("/parser-library/{slug}/enable")
def enable(slug: str, ctx: AuthContext = Depends(require_perm("parser.approve")),
           s: Session = Depends(db, scope="function")):
    return lib.set_status(s, ctx.principal, slug, enabled=True)


@router.get("/parser-library/{slug}/export")
def export(slug: str, ctx: AuthContext = Depends(require_perm("analyze.run")), s: Session = Depends(db, scope="function")):
    doc = lib.export(s, slug, ctx.principal)
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="saw-parser-{slug}-v{doc["version"]}.json"'})


@router.post("/parser-library/import", status_code=201)
def import_definition(body: dict, ctx: AuthContext = Depends(require_perm("parser.manage")),
                      s: Session = Depends(db, scope="function")):
    return lib.import_definition(s, ctx.principal, body)
