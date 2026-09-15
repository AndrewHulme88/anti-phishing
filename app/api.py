import hmac
import json
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from pathlib import PurePath
from threading import Lock

from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.openapi.models import APIKey, APIKeyIn
from fast_mail_parser import ParseError

from app.config import settings
from app.email_parser import parse_email_content
from app.models import AnalysisResponse, ErrorResponse, HealthResponse

API_VERSION = "v1"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            event = json.loads(record.getMessage())
        except json.JSONDecodeError:
            event = {"event": record.getMessage()}
        return json.dumps({"level": record.levelname, **event}, separators=(",", ":"))


logger = logging.getLogger("phishing_analyzer")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


class RateLimiter:
    """A process-local fixed-window limiter. Use a shared gateway for multi-process deployments."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, client_id: str) -> tuple[bool, int, int]:
        now = time.monotonic()
        with self._lock:
            timestamps = self._requests[client_id]
            while timestamps and timestamps[0] <= now - self.window_seconds:
                timestamps.popleft()
            if len(timestamps) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - timestamps[0])) + 1)
                return False, 0, retry_after
            timestamps.append(now)
            return True, self.limit - len(timestamps), 0


app = FastAPI(
    title="Phishing Email Analyzer API",
    version=API_VERSION,
    description="Offline, deterministic analysis of uploaded RFC 5322 `.eml` messages. Uploaded message content is never returned or logged.",
)

MAX_EMAIL_SIZE = settings.max_upload_size
rate_limiter = RateLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)
api_key_scheme = APIKey.model_validate(
    {"type": "apiKey", "name": "X-API-Key", "in": APIKeyIn.header, "description": "Required when `PHISHING_ANALYZER_API_KEY` is configured."}
)


@app.middleware("http")
async def log_requests(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    started = time.perf_counter()
    # Health checks remain available to the hosting platform. All API routes can
    # be restricted to requests forwarded by RapidAPI's Runtime.
    if settings.rapidapi_proxy_secret and request.url.path != "/health":
        supplied_secret = request.headers.get("X-RapidAPI-Proxy-Secret", "")
        if not hmac.compare_digest(supplied_secret, settings.rapidapi_proxy_secret):
            response = Response(status_code=401, content='{"detail":{"code":"INVALID_PROXY_SECRET","message":"Request must be forwarded by the configured API gateway."}}', media_type="application/json")
            logger.info(json.dumps({"event": "request_complete", "method": request.method, "path": request.url.path, "status_code": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}, separators=(",", ":")))
            return response
    response = await call_next(request)
    logger.info(json.dumps({"event": "request_complete", "method": request.method, "path": request.url.path, "status_code": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}, separators=(",", ":")))
    return response

@app.get("/health", response_model=HealthResponse, tags=["Operations"], summary="Service health")
async def health_check() -> dict[str, object]:
    return {"status": "ok", "version": API_VERSION, "authentication_required": bool(settings.api_key)}


@app.post(
    "/v1/analyze",
    response_model=AnalysisResponse,
    tags=["Analysis"],
    summary="Analyze an EML message",
    description="Upload one `.eml` file. Analysis is offline and deterministic; attachments and URLs are never executed or fetched.",
    openapi_extra={"security": [{"ApiKeyAuth": []}]},
    responses={
        400: {"model": ErrorResponse, "description": "Empty or malformed email."},
        401: {"model": ErrorResponse, "description": "Missing or invalid API key."},
        413: {"model": ErrorResponse, "description": "Upload exceeds configured size limit."},
        415: {"model": ErrorResponse, "description": "Upload is not an `.eml` file."},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
    },
)
async def analyze_email(request: Request, response: Response, file: UploadFile = File(...)) -> dict[str, object]:
    if settings.api_key:
        supplied_key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied_key, settings.api_key):
            raise HTTPException(status_code=401, detail={"code": "INVALID_API_KEY", "message": "A valid X-API-Key header is required."})

    if settings.rate_limit_enabled:
        client_id = request.client.host if request.client else "unknown"
        allowed, remaining, retry_after = rate_limiter.check(client_id)
        if not allowed:
            raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "message": "Too many analysis requests; try again later."}, headers={"Retry-After": str(retry_after)})
        response.headers["X-RateLimit-Limit"] = str(rate_limiter.limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

    if not file.filename or PurePath(file.filename).suffix.lower() != ".eml":
        raise HTTPException(
            status_code=415,
            detail={"code": "UNSUPPORTED_FILE_TYPE", "message": "Only .eml email files are supported."},
        )

    content = await file.read(MAX_EMAIL_SIZE + 1)
    if not content:
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_FILE", "message": "The uploaded email file is empty."},
        )
    if len(content) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=413,
            detail={"code": "FILE_TOO_LARGE", "message": f"Email files must be {MAX_EMAIL_SIZE} bytes or smaller."},
        )

    try:
        return parse_email_content(content)
    except (ParseError, ValueError) as error:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_EMAIL", "message": "Invalid or corrupted email file structure."},
        ) from error


def custom_openapi() -> dict[str, object]:
    """Advertise the optional deployment API key in the versioned contract."""
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["ApiKeyAuth"] = api_key_scheme.model_dump(by_alias=True, exclude_none=True, mode="json")
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi
