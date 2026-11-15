import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column, Float, Integer, String, Text, create_engine, func
from sqlalchemy.orm import declarative_base, sessionmaker

from src.config import Config
from src.messages import DetectionResults

logger = logging.getLogger("NetGuard.Database")

# Connection string matching your docker-compose.yml settings:
# postgresql://<user>:<password>@<host>:<port>/<database_name>
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://netguard:netguard@localhost:5432/netguard",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AlertRecord(Base):
    """Defines the 'alerts' table structure inside PostgreSQL."""
    __tablename__ = "alerts"

    detection_id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    source = Column(String, nullable=True, index=True)
    destination = Column(String, nullable=True, index=True)
    time_window_s = Column(Integer, nullable=False)
    window_start = Column(Float, nullable=False)
    window_end = Column(Float, nullable=False)
    method = Column(String, nullable=False)
    feature_values = Column(JSON, nullable=False)
    explanation = Column(Text, nullable=False)
    latency_ms = Column(Float, nullable=True)

    def to_dict(self) -> dict:
        return {
            "detection_id": self.detection_id,
            "timestamp": self.timestamp,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "destination": self.destination,
            "time_window_s": self.time_window_s,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "method": self.method,
            "feature_values": self.feature_values,
            "explanation": self.explanation,
            "latency_ms": self.latency_ms,
        }


class FlowRecord(Base):
    """Defines the 'flows' table (normalized flows from the extractor or simulator)."""
    __tablename__ = "flows"

    flow_id = Column(String, primary_key=True, index=True)
    ingested_at = Column(String, nullable=False)
    start_timestamp = Column(Float, nullable=False, index=True)
    end_timestamp = Column(Float, nullable=False)
    duration = Column(Float, nullable=False)
    src_ip = Column(String, nullable=False)
    dst_ip = Column(String, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    packet_count = Column(Integer, nullable=False)
    byte_count = Column(Integer, nullable=False)
    tcp_flags = Column(String, nullable=True)


class ConfigRecord(Base):
    """Defines the 'configuration' table (detection configuration used for a run)."""
    __tablename__ = "configuration"

    saved_at = Column(String, primary_key=True)
    data = Column(JSON, nullable=False)


def init_db() -> None:
    """Creates the 'alerts', 'flows' and 'configuration' tables in PostgreSQL if they do not exist yet."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized (tables 'alerts', 'flows', 'configuration' ready).")


def save_flows(flows: list[dict]) -> int:
    """Saves extracted flows (dicts from Flow.to_dict()) into PostgreSQL."""
    if not flows:
        return 0

    init_db()
    columns = [c.name for c in FlowRecord.__table__.columns]
    with SessionLocal() as session:
        for flow in flows:
            # the same flow_id saved again does not create a duplicate
            session.merge(FlowRecord(**{c: flow.get(c) for c in columns}))
        session.commit()

    logger.info("Saved %d flow(s) to PostgreSQL.", len(flows))
    return len(flows)


def save_config(cfg: Config) -> None:
    """Saves the detection configuration used for this run."""
    init_db()
    with SessionLocal() as session:
        session.add(ConfigRecord(saved_at=datetime.now(timezone.utc).isoformat(), data=cfg.model_dump(mode="json")))
        session.commit()


def save_alerts(alerts: list[DetectionResults]) -> int:
    """Saves a list of DetectionResults into PostgreSQL."""
    if not alerts:
        return 0

    init_db()
    with SessionLocal() as session:
        for alert in alerts:
            record = AlertRecord(
                detection_id=alert.detection_id,
                timestamp=alert.timestamp,
                type=str(alert.type),
                severity=str(alert.severity),
                confidence=alert.confidence,
                source=alert.source,
                destination=alert.destination,
                time_window_s=alert.time_window_s,
                window_start=alert.window_start,
                window_end=alert.window_end,
                method=alert.method,
                feature_values=alert.feature_values,
                explanation=alert.explanation,
                latency_ms=alert.latency_ms,
            )
            # merge() inserts new alerts and safely updates existing ones if you re-run the same PCAP
            session.merge(record)
        session.commit()

    logger.info("Saved %d alert(s) to PostgreSQL.", len(alerts))
    return len(alerts)


def get_alerts(
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
    limit: int = 100,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[dict]:
    """Fetches saved alerts from PostgreSQL with optional filters."""
    init_db()
    with SessionLocal() as session:
        query = session.query(AlertRecord)

        # timestamps are stored as UTC ISO strings, so they can be compared as text
        if start:
            query = query.filter(AlertRecord.timestamp >= _iso_utc(start))
        if end:
            query = query.filter(AlertRecord.timestamp <= _iso_utc(end))
        if severity:
            query = query.filter(AlertRecord.severity == severity.upper())
        if alert_type:
            query = query.filter(AlertRecord.type == alert_type.upper())
        if source:
            query = query.filter(AlertRecord.source == source)
        if destination:
            query = query.filter(AlertRecord.destination == destination)

        records = query.order_by(AlertRecord.timestamp.desc()).limit(limit).all()
        return [r.to_dict() for r in records]


def _iso_utc(dt: datetime) -> str:
    # a datetime without a timezone is treated as UTC
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


TRAFFIC_WINDOW_S = 60


def get_traffic_stats() -> dict:
    """Current traffic from the last 60 s and alert counts by type and severity.
    'Now' is the newest flow in the database, so the stats also make sense for old PCAP files."""
    init_db()
    with SessionLocal() as session:
        latest = session.query(func.max(FlowRecord.start_timestamp)).scalar()
        flows = packets = bytes_ = destinations = 0
        if latest is not None:
            flows, packets, bytes_, destinations = session.query(
                func.count(FlowRecord.flow_id),
                func.coalesce(func.sum(FlowRecord.packet_count), 0),
                func.coalesce(func.sum(FlowRecord.byte_count), 0),
                func.count(func.distinct(FlowRecord.dst_ip)),
            ).filter(FlowRecord.start_timestamp > latest - TRAFFIC_WINDOW_S).one()

        by_type = dict(session.query(AlertRecord.type, func.count()).group_by(AlertRecord.type).all())
        by_severity = dict(session.query(AlertRecord.severity, func.count()).group_by(AlertRecord.severity).all())

    return {
        "flows": flows,
        "packets_per_s": round(packets / TRAFFIC_WINDOW_S, 3),
        "bytes_per_s": round(bytes_ / TRAFFIC_WINDOW_S, 3),
        "unique_destinations": destinations,
        "alerts_by_type": by_type,
        "alerts_by_severity": by_severity,
    }


def get_alert_by_id(detection_id: str) -> Optional[dict]:
    """Fetches a single alert by its detection_id."""
    init_db()
    with SessionLocal() as session:
        record = session.query(AlertRecord).filter(AlertRecord.detection_id == detection_id).first()
        return record.to_dict() if record else None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("SUCCESS: Connected to PostgreSQL and created the 'alerts' table!")