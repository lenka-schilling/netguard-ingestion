import argparse
import logging
from typing import Optional

from src.broker import RedisStreamBroker, FLOWS_STREAM
from src.config import load_config
from src.database import save_alerts, save_config, save_flows
from src.extractor import extract_flows
from src.models import Flow
from src.pipeline import run_detection_worker, run_flows
from src.messages import DetectionResults
from src.persistor import run_flow_persister

logger = logging.getLogger("NetGuard.Main")


def run_producer(pcap_path: str, persist_config: bool = True) -> int:
    logger.info("=== STARTING NETGUARD PRODUCER (Flow Extractor) ===")
    logger.info("Streaming flows from %s to '%s'", pcap_path, FLOWS_STREAM)

    broker = RedisStreamBroker()
    if persist_config:
        save_config(load_config())

    published = 0
    for flow_dict in extract_flows(pcap_path):
        flow_model = Flow.model_validate(flow_dict)
        broker.publish_model(stream=FLOWS_STREAM, model=flow_model)
        published += 1
        if published % 500 == 0:
            logger.info("Published %d flows to broker", published)

    logger.info("=== FINISHED PRODUCER (total flows: %d) ===", published)
    return published

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetGuard Event-Driven Runner")
    parser.add_argument("pcap", nargs="?", help="Ścieżka do pliku PCAP (domyślnie data/http.cap)")
    parser.add_argument("--worker", action="store_true", help="Uruchom workera konsumującego okna z brokera")
    parser.add_argument("--persister", action="store_true", help="Uruchom Flow Persister (batch zapis do DB)")
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

    if args.persister:
        run_flow_persister(consumer_name=args.consumer_name)
        return

    if args.worker:
        broker = RedisStreamBroker()
        logger.info("Starting broker detection worker as '%s'...", args.consumer_name)

        def _persist_batch(batch: list[DetectionResults]) -> None:
            logger.info("Persisting %d new alert(s) to PostgreSQL...", len(batch))
            save_alerts(batch)

        run_detection_worker(
            broker=broker,
            config=cfg,
            consumer_name=args.consumer_name,
            on_alerts=_persist_batch if persist else None,
        )
        return

    target_file = args.pcap or "data/http.cap"
    run_producer(target_file, persist_config=persist)


if __name__ == "__main__":
    main()