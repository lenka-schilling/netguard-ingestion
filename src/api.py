from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from src.database import get_alert_by_id, get_alerts, init_db

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
        "endpoints": ["/alerts", "/alerts/{detection_id}", "/docs"],
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
):
    """Returns stored alert history, optionally filtered by query parameters."""
    results = get_alerts(
        severity=severity,
        alert_type=type,
        source=source,
        destination=destination,
        limit=limit,
    )
    return {
        "count": len(results),
        "alerts": results,
    }


@app.get("/alerts/{detection_id}")
def single_alert(detection_id: str):
    """Returns a single alert by its detection_id."""
    alert = get_alert_by_id(detection_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{detection_id}' not found")
    return alert