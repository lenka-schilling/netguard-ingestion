import logging
import os
from typing import Optional

from sqlalchemy import JSON, Column, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

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


def init_db() -> None:
    """Creates the 'alerts' table in PostgreSQL if it does not exist yet."""
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized (table 'alerts' ready).")


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
) -> list[dict]:
    """Fetches saved alerts from PostgreSQL with optional filters."""
    init_db()
    with SessionLocal() as session:
        query = session.query(AlertRecord)

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