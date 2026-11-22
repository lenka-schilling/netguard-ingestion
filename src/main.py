import argparse
import logging
from typing import Optional

from src.broker import RedisStreamBroker
from src.config import load_config
from src.database import save_alerts, save_config, save_flows
from src.extractor import extract_flows
from src.pipeline import publish_windows_from_flows, run_detection_worker, run_flows

logger = logging.getLogger("NetGuard.Main")


def run_pipeline(pcap_path: str, persist: bool = True, to_broker: bool = False):
    logger.info("=== STARTING NETGUARD ===")
    logger.info("Step 1: loading and extraction from %s", pcap_path)
    flows = extract_flows(pcap_path)
    if not flows:
        logger.warning("No data for analysis.")
        return []

    cfg = load_config()

    if to_broker:
        logger.info("Step 2 (broker mode): publishing windows to Redis Streams")
        broker = RedisStreamBroker()
        published = publish_windows_from_flows(flows, broker=broker, config=cfg)
        if persist:
            save_flows(flows)
            save_config(cfg)
        logger.info("=== FINISHED (BROKER). Published windows: %d ===", published)
        return []

    logger.info("Step 2: windows, detection and classification")
    alerts = run_flows(flows, cfg)

    if persist:
        logger.info("Step 3: saving flows, configuration and alerts to PostgreSQL database")
        save_flows(flows)
        save_config(cfg)
        save_alerts(alerts)

    logger.info("=== FINISHED. Alerts: %d ===", len(alerts))
    for a in alerts:
        print(f"\nALERT: {a.type} ({a.severity}), confidence {a.confidence}, method {a.method}")
        print(f"   Source: {a.source}  Destination: {a.destination}  Window: {a.time_window_s}s")
        print(f"   {a.explanation}")
    return alerts


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetGuard PCAP / Broker Runner")
    parser.add_argument("pcap", nargs="?", help="Ścieżka do pliku PCAP (domyślnie data/http.cap)")
    parser.add_argument("--broker", action="store_true", help="Wyślij wyliczone okna przez Redis Streams")
    parser.add_argument("--worker", action="store_true", help="Uruchom workera konsumującego okna z brokera")
    parser.add_argument("--consumer-name", default="main-worker", help="Nazwa konsumenta w grupie Redis")
    parser.add_argument("--no-persist", action="store_true", help="Nie zapisuj do PostgreSQL")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    args = parse_args(argv)
    cfg = load_config()
    persist = not args.no_persist

    if args.worker:
        broker = RedisStreamBroker()
        logger.info("Starting broker detection worker as '%s'...", args.consumer_name)
        alerts = run_detection_worker(broker=broker, config=cfg, consumer_name=args.consumer_name)
        if persist and alerts:
            save_alerts(alerts)
        return

    target_file = args.pcap or "data/http.cap"
    run_pipeline(target_file, persist=persist, to_broker=args.broker)


if __name__ == "__main__":
    main()