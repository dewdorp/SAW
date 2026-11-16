"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from saw import container
from saw.config import Settings
from saw.core.application.investigations import Forbidden, NotFound

log = logging.getLogger("saw.api")


def _problem(status: int, title: str, detail: str, instance: str) -> JSONResponse:
    return JSONResponse(
        {"type": f"https://saw.local/problems/{status}", "title": title, "status": status, "detail": detail,
         "instance": instance},
        status_code=status, media_type="application/problem+json",
    )


def create_app(settings: Settings | None = None, synchronous_jobs: bool = False) -> FastAPI:
    captured = container.build(settings, synchronous_jobs=synchronous_jobs)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            container.close(captured)

    from saw.version import __version__

    app = FastAPI(title="SAW API", version=__version__, openapi_url="/api/v1/openapi.json",
                  docs_url="/api/v1/docs", lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        with container.activate(captured, captured.session_factory):
            resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        immutable = request.url.path.startswith("/assets/") and resp.status_code == 200  # content-hashed web bundle
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable" if immutable else "no-store"
        if request.url.scheme == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        # a route that returns a self-contained document (reports) sets its own, stricter policy
        resp.headers.setdefault("Content-Security-Policy", (
            "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        ))
        return resp

    from saw.event_generations.reads import ReadContextMiddleware
    from saw.storage.generations import GenerationConflict, GenerationUnavailable, InvalidGenerationCursor

    app.add_middleware(ReadContextMiddleware, captured=captured)

    @app.exception_handler(GenerationUnavailable)
    async def generation_unavailable(request: Request, _exc):
        return _problem(503, "Unavailable", "선택한 자료를 현재 읽을 수 없습니다.", request.url.path)

    @app.exception_handler(GenerationConflict)
    async def generation_conflict(request: Request, _exc):
        return _problem(409, "Conflict", "자료 상태가 변경되어 요청을 완료할 수 없습니다.", request.url.path)

    @app.exception_handler(InvalidGenerationCursor)
    async def generation_cursor(request: Request, _exc):
        return _problem(400, "Bad request", "조회 위치가 만료되었거나 유효하지 않습니다.", request.url.path)

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(request: Request, exc: StarletteHTTPException):
        return _problem(exc.status_code, "HTTP error", str(exc.detail), request.url.path)

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        return _problem(422, "Validation error", str(exc.errors()[:5]), request.url.path)

    @app.exception_handler(Forbidden)
    async def forbidden(request: Request, exc: Forbidden):
        return _problem(403, "Forbidden", f"missing permission: {exc}", request.url.path)

    @app.exception_handler(NotFound)
    async def notfound(request: Request, exc: NotFound):
        return _problem(404, "Not found", str(exc), request.url.path)

    @app.exception_handler(ValidationError)
    async def content_invalid(request: Request, exc: ValidationError):
        # A definition the analyst typed did not fit: say which entry and why, not the library's wording.
        return _problem(400, "Bad request", _validation_words(exc), request.url.path)

    @app.exception_handler(ValueError)
    async def bad_value(request: Request, exc: ValueError):
        return _problem(400, "Bad request", str(exc), request.url.path)

    from saw.apps.api.routers import ROUTERS

    for r in ROUTERS:
        app.include_router(r, prefix="/api/v1")

    @app.get("/api/v1/health")
    def health():
        from saw.workers.runner import InProcessRunner
        c = captured
        queue = asdict(c.runner.status()) if isinstance(c.runner, InProcessRunner) else None
        healthy = queue is None or (queue["state"] == "running" and queue["fatal_code"] is None)
        return JSONResponse({"status": "ok" if healthy else "unavailable",
                             "event_store": c.settings.event_store, "object_store": c.settings.object_store,
                             "job_runner": c.settings.job_runner, "queue": queue},
                            status_code=200 if healthy else 503)

    _mount_web(app, captured.settings.web_dist)
    return app


_ENTRY_KO = {"name": "이름", "label": "단계 이름", "path": "요청 경로", "method": "메서드", "host": "서비스 이름", "value": "조건 값",
             "threshold": "기준 값", "min_count": "기준 값", "window_seconds": "시간 범위", "count_param": "파라미터 이름", "steps": "단계",
             "sources": "자료 종류", "conditions": "조건", "contains": "포함 글자", "meaning": "업무 의미", "kind": "찾는 방식"}


def _validation_words(exc) -> str:
    out = []
    for err in exc.errors()[:5]:
        loc = [x for x in err.get("loc") or ()]
        name = next((x for x in reversed(loc) if isinstance(x, str)), "")
        entry = _ENTRY_KO.get(name, name)
        index = next((x for x in loc if isinstance(x, int)), None)
        where = (f"{index + 1}번째 " if index is not None else "") + (f"'{entry}'" if entry else "입력 값")
        kind, msg = err.get("type") or "", str(err.get("msg") or "")
        if kind == "value_error":
            out.append(msg.removeprefix("Value error, "))
        elif kind in ("string_too_short", "missing", "too_short"):
            out.append(f"{where}을(를) 적어 주세요.")
        elif kind in ("string_too_long", "too_long"):
            out.append(f"{where}이(가) 너무 깁니다.")
        elif kind == "string_pattern_mismatch":
            out.append(f"{where}의 형식이 맞지 않습니다" + ("(/로 시작해야 합니다)." if name == "path" else "."))
        elif kind == "extra_forbidden":
            out.append(f"{where}은(는) 쓸 수 없는 항목입니다.")
        else:
            out.append(f"{where}의 값이 올바르지 않습니다.")
    return " ".join(dict.fromkeys(out)) or "입력 값이 올바르지 않습니다."


def _mount_web(app: FastAPI, dist) -> None:
    """Serve the built web UI (apps/web/dist) from the same origin as the API — single HTTPS port in production.

    Unknown non-API paths fall back to index.html (client-side routing). Path traversal is blocked by resolving
    inside the dist root. In development the Vite dev server serves the UI instead and dist may not exist.
    """
    from pathlib import Path

    root = Path(dist).resolve()
    index = root / "index.html"
    if not index.is_file():
        return

    @app.get("/{path:path}", include_in_schema=False)
    def web(path: str):
        if path.startswith("api/"):
            raise StarletteHTTPException(404)
        target = (root / path).resolve()
        if path and target.is_file() and target.is_relative_to(root):
            return FileResponse(target)
        return FileResponse(index, media_type="text/html")


_lazy: dict[str, FastAPI] = {}


def __getattr__(name: str):  # lazy `uvicorn saw.apps.api.main:app` (tests use create_app directly)
    if name == "app":
        if "app" not in _lazy:
            _lazy["app"] = create_app()
        return _lazy["app"]
    raise AttributeError(name)
