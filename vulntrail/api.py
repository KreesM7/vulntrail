"""Single-process, loopback-only service for configured scans and local evidence.

POST scans is unsafe to retry: an accepted request creates a new evidence run.
The dashboard uses a short-lived in-memory session, while API clients always
authenticate with a Bearer token. This service deliberately supports no proxy.
"""
from collections import deque
import hashlib
import hmac
import ipaddress
from pathlib import Path
import secrets
import threading
import time
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .reports import render_report
from .scanner import scan_target
from .store import Store
from .triage import compare_runs

MAX_BODY = 32768
SESSION_SECONDS = 3600
COOKIE = "vulntrail_session"
STATIC = Path(__file__).with_name("static")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=128)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=512)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def _local_host(host: str) -> bool:
    try:
        parsed = urlsplit("http://" + host)
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            return False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        return parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    except ValueError:
        return False


def create_app(settings: Settings, token: str) -> FastAPI:
    if not isinstance(token, str) or not 32 <= len(token) <= 512:
        raise ValueError("A token between 32 and 512 characters is required")
    token_digest = hashlib.sha256(token.encode()).digest()
    store = Store(settings.state_dir / "evidence.sqlite3")
    app = FastAPI(title="VulnTrail local API", docs_url=None, redoc_url=None, openapi_url=None)
    scan_lock = threading.Lock()
    sessions: dict[str, float] = {}
    attempts: dict[str, deque] = {}
    app.state.store = store

    def valid_token(value: str) -> bool:
        return hmac.compare_digest(hashlib.sha256(value.encode()).digest(), token_digest)

    def rate_limited(key: str, count: int, seconds: int) -> bool:
        now = time.monotonic()
        queue = attempts.setdefault(key, deque())
        while queue and queue[0] <= now - seconds:
            queue.popleft()
        if len(queue) >= count:
            return True
        queue.append(now)
        return False

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        response = None
        host_values = request.headers.getlist("host")
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        expected_origin = f"{request.url.scheme}://{host}"
        try:
            client_local = request.client is not None and ipaddress.ip_address(
                request.client.host).is_loopback
        except ValueError:
            client_local = False
        if not client_local or len(host_values) != 1 or not _local_host(host):
            response = _error(403, "FORBIDDEN", "Only direct local connections are allowed")
        elif origin is not None and origin != expected_origin:
            response = _error(403, "FORBIDDEN", "Origin is not allowed")
        elif request.url.path.startswith("/ui/") and (
            request.headers.get("x-vulntrail-client") != "dashboard"
            or (request.method not in {"GET", "HEAD"} and origin != expected_origin)
        ):
            response = _error(403, "FORBIDDEN", "A same-origin dashboard request is required")
        elif len(request.scope.get("query_string", b"")) > 4096:
            response = _error(414, "REQUEST_TOO_LARGE", "Request query is too large")
        else:
            try:
                content_length = int(request.headers.get("content-length", "0"))
                if content_length < 0 or content_length > MAX_BODY:
                    response = _error(413, "REQUEST_TOO_LARGE", "Request body is too large")
                else:
                    body = bytearray()
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > MAX_BODY:
                            response = _error(413, "REQUEST_TOO_LARGE", "Request body is too large")
                            break
                    request._body = bytes(body)
            except (ValueError, RuntimeError):
                response = _error(400, "BAD_REQUEST", "Invalid request body")
        path = request.url.path
        if response is None and path == "/ui/session" and request.method == "POST":
            if rate_limited("login", 10, 900):
                response = _error(429, "RATE_LIMITED", "Too many login attempts; try later")
        if response is None and path.startswith(("/api/v1/", "/ui/api/")):
            if rate_limited("requests", 120, 60):
                response = _error(429, "RATE_LIMITED", "Too many requests; try later")
            elif path.startswith("/api/v1/"):
                authorization = request.headers.get("authorization", "")
                if (len(authorization) > 520 or not authorization.startswith("Bearer ")
                        or not valid_token(authorization[7:])):
                    response = _error(401, "UNAUTHORIZED", "A valid Bearer token is required")
            else:
                cookie = request.cookies.get(COOKIE, "")
                digest = hashlib.sha256(cookie.encode()).hexdigest()
                if sessions.get(digest, 0) <= time.monotonic():
                    sessions.pop(digest, None)
                    response = _error(401, "UNAUTHORIZED", "Sign in to the local dashboard")
        if response is None:
            try:
                response = await call_next(request)
            except Exception:
                response = _error(500, "INTERNAL_ERROR", "The local operation could not complete")
        response.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request: Request, exception):
        return _error(422, "VALIDATION_ERROR", "Invalid request parameters")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exception):
        codes = {400: "BAD_REQUEST", 401: "UNAUTHORIZED", 403: "FORBIDDEN",
                 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 409: "CONFLICT",
                 422: "VALIDATION_ERROR"}
        message = exception.detail if isinstance(exception.detail, str) else "Request failed"
        return _error(exception.status_code, codes.get(exception.status_code, "REQUEST_ERROR"),
                      message)

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/static/{asset}", include_in_schema=False)
    def asset(asset: Literal["app.js", "style.css"]):
        return FileResponse(STATIC / asset,
                            media_type="text/javascript" if asset.endswith(".js") else "text/css")

    @app.post("/ui/session", include_in_schema=False)
    def login(body: LoginRequest, request: Request):
        if not valid_token(body.token):
            raise HTTPException(401, "The local token is invalid")
        now = time.monotonic()
        for digest in list(sessions):
            if sessions[digest] <= now:
                del sessions[digest]
        if len(sessions) >= 16:
            del sessions[min(sessions, key=sessions.get)]
        session = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(session.encode()).hexdigest()] = now + SESSION_SECONDS
        store.audit("dashboard_login", {})
        response = JSONResponse({"authenticated": True, "expires_in": SESSION_SECONDS})
        response.set_cookie(COOKIE, session, max_age=SESSION_SECONDS, httponly=True,
                            samesite="strict", secure=request.url.scheme == "https", path="/ui")
        return response

    @app.delete("/ui/session", include_in_schema=False)
    def logout(request: Request):
        digest = hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest()
        sessions.pop(digest, None)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(COOKIE, path="/ui", httponly=True, samesite="strict")
        return response

    router = APIRouter()

    def get_run(run_id: str):
        if len(run_id) > 128:
            raise HTTPException(422, "Invalid run identifier")
        try:
            return store.get_run(run_id)
        except KeyError:
            raise HTTPException(404, "Run not found") from None

    @router.get("/status")
    def status():
        return {"version": "0.1.0", "offline": settings.offline,
                "targets": sorted(settings.targets), "running": scan_lock.locked(),
                "run_count": store.count_runs()}

    @router.get("/runs")
    def runs(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000)):
        return {"items": store.list_summaries(limit, offset),
                "total": store.count_runs(), "limit": limit, "offset": offset}

    @router.get("/runs/{run_id}")
    def detail(run_id: str):
        return get_run(run_id).to_dict()

    @router.get("/runs/{run_id}/report")
    def report(run_id: str, format: Literal["json", "md", "html"] = "json"):
        run = get_run(run_id)
        media = {"json": "application/json", "md": "text/markdown", "html": "text/html"}
        return Response(render_report(run, format), media_type=media[format], headers={
            "Content-Disposition": f'attachment; filename="vulntrail-report.{format}"'})

    @router.get("/comparisons")
    def comparison(before: str = Query(min_length=1, max_length=128),
                   after: str = Query(min_length=1, max_length=128)):
        return compare_runs(get_run(before), get_run(after))

    @router.post("/scans", status_code=201,
                 description="Creates a new run; unsafe to retry automatically.")
    def scan(body: ScanRequest):
        if body.target not in settings.targets:
            raise HTTPException(422, "Choose a configured target")
        if not scan_lock.acquire(blocking=False):
            raise HTTPException(409, "A scan is already running")
        try:
            run = store.save_run(scan_target(settings, body.target))
            store.audit("scan_requested", {"target": body.target, "run_id": run.id})
            return run.to_dict()
        finally:
            scan_lock.release()

    @router.delete("/runs/{run_id}")
    def delete(run_id: str):
        get_run(run_id)
        deleted = store.delete_run(run_id)
        return {"deleted": deleted, "id": run_id}

    app.include_router(router, prefix="/api/v1")
    app.include_router(router, prefix="/ui/api", include_in_schema=False)
    return app
