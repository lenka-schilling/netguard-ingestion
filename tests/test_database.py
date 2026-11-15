from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src import api, database
from src.config import load_config
from src.messages import DetectionResults
from src.models import Flow


@pytest.fixture(autouse=True)
def sqlite_db(tmp_path, monkeypatch):
    # testy działają na tymczasowym SQLite zamiast PostgreSQL z docker-compose
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(autocommit=False, autoflush=False, bind=engine))


def mk_flow(flow_id, ts, src="10.0.0.5", packets=1, size=60):
    return Flow(flow_id=flow_id, start_timestamp=ts, end_timestamp=ts, src_ip=src, dst_ip="10.0.0.20",
                src_port=40000, dst_port=80, protocol="TCP", packet_count=packets, byte_count=size).to_dict()


def mk_alert(detection_id, timestamp, **kw):
    d = dict(detection_id=detection_id, timestamp=timestamp, type="PORT_SCAN", severity="HIGH", confidence=0.8,
             source="10.0.0.5", destination="10.0.0.20", time_window_s=10, window_start=1000.0, window_end=1010.0,
             method="rule", feature_values={"unique_dst_ports": 120.0}, explanation="test")
    d.update(kw)
    return DetectionResults(**d)


@pytest.fixture
def history():
    database.save_alerts([
        mk_alert("d1", "2026-11-10T10:00:00+00:00"),
        mk_alert("d2", "2026-11-11T10:00:00+00:00", type="DOS_LIKE", severity="CRITICAL", source=None),
        mk_alert("d3", "2026-11-12T10:00:00+00:00", severity="LOW", source="10.0.0.9"),
    ])


def ids(alerts):
    return [a["detection_id"] for a in alerts]


def test_flows_are_saved_without_duplicates():
    database.save_flows([mk_flow("f1", 1000.0), mk_flow("f2", 1001.0)])
    database.save_flows([mk_flow("f1", 1000.0)])
    with database.SessionLocal() as s:
        stored = s.query(database.FlowRecord).order_by(database.FlowRecord.flow_id).all()
    assert [f.flow_id for f in stored] == ["f1", "f2"]
    assert stored[0].src_ip == "10.0.0.5"
    assert stored[0].duration == 0.0


def test_same_config_is_saved_once():
    cfg = load_config()
    assert database.save_config(cfg) == database.save_config(cfg)
    with database.SessionLocal() as s:
        (row,) = s.query(database.ConfigRecord).all()
    assert row.data["windows"]["sizes_s"] == [1, 10, 60]


@pytest.mark.parametrize("filters, expected", [
    ({}, ["d3", "d2", "d1"]),
    ({"start": datetime(2026, 11, 11, tzinfo=timezone.utc)}, ["d3", "d2"]),
    ({"end": datetime(2026, 11, 11, 12)}, ["d2", "d1"]),   # bez strefy czasowej = UTC
    ({"start": datetime(2026, 11, 11), "severity": "low"}, ["d3"]),
    ({"alert_type": "DOS_LIKE"}, ["d2"]),
    ({"source": "10.0.0.5"}, ["d1"]),
])
def test_alert_filters(history, filters, expected):
    assert ids(database.get_alerts(**filters)) == expected


def test_traffic_stats_from_last_window():
    database.save_flows([
        mk_flow("old", 900.0, src="10.0.0.1"),
        mk_flow("a", 1000.0, packets=3, size=300),
        mk_flow("b", 1030.0, src="10.0.0.6", packets=2, size=300),
    ])
    database.save_alerts([mk_alert("d1", "2026-11-10T10:00:00+00:00"),
                          mk_alert("d2", "2026-11-11T10:00:00+00:00", type="DOS_LIKE", severity="CRITICAL")])
    stats = database.get_traffic_stats(window_s=60)
    assert stats["latest_flow_timestamp"] == 1030.0
    assert (stats["flows"], stats["packets"], stats["bytes"]) == (2, 5, 600)
    assert stats["bytes_per_s"] == 10.0
    assert stats["unique_sources"] == 2
    assert stats["alerts_by_type"] == {"PORT_SCAN": 1, "DOS_LIKE": 1}
    assert stats["alerts_by_severity"] == {"HIGH": 1, "CRITICAL": 1}


def test_traffic_stats_empty_database():
    stats = database.get_traffic_stats()
    assert stats["flows"] == 0
    assert stats["alerts_by_type"] == {}


def test_api_alerts_with_time_filter(history):
    result = api.list_alerts(severity=None, type="PORT_SCAN", source=None, destination=None, limit=100,
                             start=datetime(2026, 11, 11), end=None)
    assert result["count"] == 1
    assert ids(result["alerts"]) == ["d3"]


def test_api_single_alert_and_not_found(history):
    assert api.single_alert("d2")["type"] == "DOS_LIKE"
    with pytest.raises(HTTPException) as e:
        api.single_alert("missing")
    assert e.value.status_code == 404


def test_api_current_traffic():
    database.save_flows([mk_flow("a", 1000.0)])
    assert api.current_traffic(window_s=60)["flows"] == 1
