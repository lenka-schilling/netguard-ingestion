import ipaddress
import logging
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path as FastAPIPath, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse

from src.database import get_alert_by_id, get_alerts, get_traffic_stats, init_db
from src.messages import DetectionType, Severity

DASHBOARD_PATH = Path(__file__).resolve().parent / "dashboard.html"

logger = logging.getLogger("NetGuard.API")
sec_logger = logging.getLogger("NetGuard.API.Security")

VALID_SEVERITIES = {s.value for s in Severity}
VALID_TYPES = {t.value for t in DetectionType}

class RateLimiter:
    """Prosty limiter zapytań w oknie 60 s per identyfikator klienta."""

    def __init__(self, max_requests_per_minute: int = 120):
        self.max_requests = max(1, max_requests_per_minute)
        self.window_s = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client_id: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_s
        with self._lock:
            q = self._hits[client_id]
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                retry_after = max(1, int(q[0] + self.window_s - now) + 1)
                return False, retry_after
            q.append(now)
            return True, 0

rate_limiter = RateLimiter(int(os.getenv("NETGUARD_RATE_LIMIT_PER_MIN", "120")))

app = FastAPI(
    title="NetGuard Alert API",
    description="REST API for querying and filtering stored network anomaly alerts.",
    version="1.0.0",
)

def _client_id(request: Request, x_api_key: Optional[str]) -> str:
    if x_api_key:
        return f"key:{x_api_key[:8]}"
    host = request.client.host if request.client else "unknown"
    return f"ip:{host}"

@app.middleware("http")
async def abuse_protection_middleware(request: Request, call_next):
    # Nie blokujemy samego pliku statycznego dashboardu przy odświeżaniu
    if request.url.path == "/dashboard":
        return await call_next(request)

    api_key = request.headers.get("x-api-key")
    cid = _client_id(request, api_key)
    allowed, retry_after = rate_limiter.check(cid)
    if not allowed:
        sec_logger.warning("Rate limit exceeded for client=%s path=%s", cid, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests. Please slow down."},
            headers={"Retry-After": str(retry_after)},
        )

    try:
        return await call_next(request)
    except HTTPException:
        raise
    except Exception:
        sec_logger.exception("Unhandled API error on path=%s client=%s", request.url.path, cid)
        raise

def _require_user_auth(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    user_key = os.getenv("NETGUARD_USER_KEY", "").strip()
    admin_key = os.getenv("NETGUARD_ADMIN_KEY", "").strip()
    require_auth = os.getenv("NETGUARD_REQUIRE_USER_AUTH", "false").lower() in ("1", "true", "yes")

    valid_keys = {k for k in (user_key, admin_key) if k}
    if not require_auth and not user_key:
        return "user"

    if not valid_keys:
        sec_logger.error("User auth requested, but no API keys are configured in environment.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is not configured.",
        )

    if not x_api_key or x_api_key not in valid_keys:
        host = request.client.host if request.client else "unknown"
        sec_logger.warning("Unauthorized user API access attempt from ip=%s path=%s", host, request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return "admin" if (admin_key and x_api_key == admin_key) else "user"

def _require_admin_auth(
    request: Request,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    admin_key = os.getenv("NETGUARD_ADMIN_KEY", "").strip()
    provided = x_admin_key or x_api_key
    host = request.client.host if request.client else "unknown"

    if not admin_key:
        sec_logger.warning("Admin endpoint accessed from ip=%s while NETGUARD_ADMIN_KEY is unset", host)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrative authentication is not configured.",
        )

    if not provided or provided != admin_key:
        sec_logger.warning("Forbidden admin access attempt from ip=%s path=%s", host, request.url.path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required.",
        )

    return "admin"

def _validate_ip(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid IP address in '{field_name}': '{value}'",
        )
    return cleaned

def _validate_severity(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().upper()
    if normalized not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid severity '{value}'. Allowed: {sorted(VALID_SEVERITIES)}",
        )
    return normalized

def _validate_type(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().upper()
    if normalized not in VALID_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid alert type '{value}'. Allowed: {sorted(VALID_TYPES)}",
        )
    return normalized

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("NetGuard API started.")


@app.get("/")
def root():
    return {
        "service": "NetGuard API",
        "status": "running",
        "endpoints": ["/alerts", "/alerts/{detection_id}", "/traffic/current", "/admin/status", "/dashboard", "/docs"],
    }


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    """Serves the monitoring dashboard (a single page that reads data from this API)."""
    return FileResponse(DASHBOARD_PATH)


@app.get("/alerts")
def list_alerts(
    _role: str = Depends(_require_user_auth),
    severity: Optional[str] = Query(
        default=None,
        max_length=16,
        description="Filter by severity: LOW, MEDIUM, HIGH, or CRITICAL",
    ),
    type: Optional[str] = Query(
        default=None,
        max_length=32,
        description="Filter by detection type: PORT_SCAN, DOS_LIKE, BRUTE_FORCE, or ABNORMAL_CONN_PATTERN",
    ),
    source: Optional[str] = Query(
        default=None,
        max_length=64,
        description="Filter by source IP address (e.g. 192.168.1.10)",
    ),
    destination: Optional[str] = Query(
        default=None,
        max_length=64,
        description="Filter by destination IP address",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of alerts to return",
    ),
    start: Optional[datetime] = Query(
        default=None,
        description="Only alerts created at or after this time (ISO 8601, UTC if no timezone)",
    ),
    end: Optional[datetime] = Query(
        default=None,
        description="Only alerts created at or before this time (ISO 8601, UTC if no timezone)",
    ),
):
    """Returns stored alert history, optionally filtered by query parameters."""
    if start and end and start > end:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'start' timestamp must not be greater than 'end' timestamp.",
        )

    validated_severity = _validate_severity(severity)
    validated_type = _validate_type(type)
    validated_source = _validate_ip(source, "source")
    validated_destination = _validate_ip(destination, "destination")

    results = get_alerts(
        severity=validated_severity,
        alert_type=validated_type,
        source=validated_source,
        destination=validated_destination,
        limit=limit,
        start=start,
        end=end,
    )
    return {
        "count": len(results),
        "alerts": results,
    }


@app.get("/traffic/current")
def current_traffic(_role: str = Depends(_require_user_auth)):
    """Returns current traffic statistics (last 60 s) and alert counts."""
    return get_traffic_stats()


@app.get("/alerts/{detection_id}")
def single_alert(
    detection_id: str = FastAPIPath(..., min_length=8, max_length=128, pattern=r"^[a-fA-F0-9_-]+$"),
    _role: str = Depends(_require_user_auth),
):
    """Returns a single alert by its detection_id."""
    alert = get_alert_by_id(detection_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{detection_id}' not found")
    return alert

@app.get("/admin/status")
def admin_status(request: Request, _role: str = Depends(_require_admin_auth)):
    """Administrative status endpoint (requires administrator privileges)."""
    host = request.client.host if request.client else "unknown"
    sec_logger.info("Admin status checked from ip=%s", host)
    stats = get_traffic_stats()
    return {
        "role": "admin",
        "rate_limit_per_minute": rate_limiter.max_requests,
        "stats": stats,
    }