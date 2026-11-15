from pathlib import Path

from src import api


def test_dashboard_serves_page_with_traffic_section_and_charts():
    page = Path(api.dashboard().path).read_text(encoding="utf-8")
    assert "/traffic/current" in page
    assert "/alerts?limit=" in page
    for element_id in ("flows", "packets_per_s", "bytes_per_s", "unique_destinations",
                       "packetsChart", "bytesChart", "typeChart", "severityChart", "alerts", "alertRows", "details"):
        assert f'id="{element_id}"' in page
