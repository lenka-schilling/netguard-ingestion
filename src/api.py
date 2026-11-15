from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from src.database import get_alert_by_id, get_alerts, get_traffic_stats, init_db

app = FastAPI(
    title="NetGuard Alert API",
    description="REST API for querying and filtering stored network anomaly alerts.",
    version="1.0.0",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {
        "service": "NetGuard API",
        "status": "running",
        "endpoints": ["/alerts", "/alerts/{detection_id}", "/traffic/current", "/docs"],
    }


@app.get("/alerts")
def list_alerts(
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: LOW, MEDIUM, HIGH, or CRITICAL",
    ),
    type: Optional[str] = Query(
        default=None,
        description="Filter by detection type: PORT_SCAN, DOS_LIKE, BRUTE_FORCE, or ABNORMAL_CONN_PATTERN",
    ),
    source: Optional[str] = Query(
        default=None,
        description="Filter by source IP address (e.g. 192.168.1.10)",
    ),
    destination: Optional[str] = Query(
        default=None,
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
    results = get_alerts(
        severity=severity,
        alert_type=type,
        source=source,
        destination=destination,
        limit=limit,
        start=start,
        end=end,
    )
    return {
        "count": len(results),
        "alerts": results,
    }


@app.get("/traffic/current")
def current_traffic(
    window_s: int = Query(
        default=60,
        ge=1,
        le=3600,
        description="Length of the recent period in seconds",
    ),
):
    """Returns current traffic statistics and alert counts."""
    return get_traffic_stats(window_s=window_s)


@app.get("/alerts/{detection_id}")
def single_alert(detection_id: str):
    """Returns a single alert by its detection_id."""
    alert = get_alert_by_id(detection_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{detection_id}' not found")
    return alert