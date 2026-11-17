from pathlib import Path

from src import api


def test_dashboard_serves_page_with_traffic_section_and_charts():
    page = Path(api.dashboard().path).read_text(encoding="utf-8")
    assert "/traffic/current" in page
    assert "/alerts?" in page
    for element_id in ("flows", "packets_per_s", "bytes_per_s", "unique_destinations",
                       "packetsChart", "bytesChart", "typeChart", "severityChart", "alerts", "alertRows", "details"):
        assert f'id="{element_id}"' in page


def test_dashboard_includes_alert_filters_and_detection_details():
    page = Path(api.dashboard().path).read_text(encoding="utf-8")
    assert "/alerts/${encodeURIComponent(detectionId)}" in page
    for element_id in ("filterForm", "filterStart", "filterEnd", "filterType", "filterSeverity",
                       "filterSource", "filterLimit", "resetFilters",
                       "detailsContent", "detailExplanation", "detailMeta", "detailFeatures"):
        assert f'id="{element_id}"' in page