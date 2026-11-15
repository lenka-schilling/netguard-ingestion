from datetime import datetime, timezone

import pytest
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


def mk_flow(flow_id, ts, dst="10.0.0.20", packets=1, size=60):
    return Flow(flow_id=flow_id, start_timestamp=ts, end_timestamp=ts, src_ip="10.0.0.5", dst_ip=dst,
                src_port=40000, dst_port=80, protocol="TCP", packet_count=packets, byte_count=size).to_dict()


def mk_alert(detection_id, timestamp, **kw):
    d = dict(detection_id=detection_id, timestamp=timestamp, type="PORT_SCAN", severity="HIGH", confidence=0.8,
             source="10.0.0.5", destination="10.0.0.20", time_window_s=10, window_start=1000.0, window_end=1010.0,
             method="rule", feature_values={"unique_dst_ports": 120.0}, explanation="test")
    d.update(kw)
    return DetectionResults(**d)


def test_flows_are_saved_without_duplicates():
    database.save_flows([mk_flow("f1", 1000.0), mk_flow("f2", 1001.0)])
    database.save_flows([mk_flow("f1", 1000.0)])
    with database.SessionLocal() as s:
        assert s.query(database.FlowRecord).count() == 2


def test_config_is_saved():
    database.save_config(load_config())
    with database.SessionLocal() as s:
        (row,) = s.query(database.ConfigRecord).all()
    assert row.data["windows"]["sizes_s"] == [1, 10, 60]


@pytest.mark.parametrize("filters, expected", [
    ({"start": datetime(2026, 11, 11, tzinfo=timezone.utc)}, ["d3", "d2"]),
    ({"end": datetime(2026, 11, 11, 12)}, ["d2", "d1"]),   # bez strefy czasowej = UTC
    ({"start": datetime(2026, 11, 11), "severity": "low"}, ["d3"]),
])
def test_time_filter(filters, expected):
    database.save_alerts([
        mk_alert("d1", "2026-11-10T10:00:00+00:00"),
        mk_alert("d2", "2026-11-11T10:00:00+00:00", severity="CRITICAL"),
        mk_alert("d3", "2026-11-12T10:00:00+00:00", severity="LOW"),
    ])
    assert [a["detection_id"] for a in database.get_alerts(**filters)] == expected


def test_traffic_stats_from_last_60_s():
    database.save_flows([
        mk_flow("old", 900.0),
        mk_flow("a", 1000.0, packets=3, size=300),
        mk_flow("b", 1030.0, dst="10.0.0.21", packets=3, size=300),
    ])
    database.save_alerts([mk_alert("d1", "2026-11-10T10:00:00+00:00"),
                          mk_alert("d2", "2026-11-11T10:00:00+00:00", type="DOS_LIKE", severity="CRITICAL")])
    assert api.current_traffic() == {
        "flows": 2,
        "packets_per_s": 0.1,
        "bytes_per_s": 10.0,
        "unique_destinations": 2,
        "alerts_by_type": {"PORT_SCAN": 1, "DOS_LIKE": 1},
        "alerts_by_severity": {"HIGH": 1, "CRITICAL": 1},
    }


def test_traffic_stats_empty_database():
    assert database.get_traffic_stats()["flows"] == 0
