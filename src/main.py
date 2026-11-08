import logging
import sys

from src.extractor import extract_flows
from src.pipeline import run_flows

logger = logging.getLogger("NetGuard.Main")


def run_pipeline(pcap_path: str):
    logger.info("=== STARTING NETGUARD ===")
    logger.info("Step 1: loading and extraction from %s", pcap_path)
    flows = extract_flows(pcap_path)
    if not flows:
        logger.warning("No data for analysis.")
        return []

    logger.info("Step 2: windows, detection and classification")
    alerts = run_flows(flows)

    # Tymczasowo na ekran; docelowo broker i baza.
    logger.info("=== FINISHED. Alerts: %d ===", len(alerts))
    for a in alerts:
        print(f"\nALERT: {a.type} ({a.severity}), confidence {a.confidence}, method {a.method}")
        print(f"   Source: {a.source}  Destination: {a.destination}  Window: {a.time_window_s}s")
        print(f"   {a.explanation}")
    return alerts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    target_file = sys.argv[1] if len(sys.argv) > 1 else "data/http.cap"
    run_pipeline(target_file)