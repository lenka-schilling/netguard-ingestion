"""Pełny obieg bez brokera i bazy: flowy -> okna -> detekcje -> alarmy.
Osobno od main.py (które czyta PCAP), żeby dało się to testować na gotowych flowach."""
import logging
from typing import Iterable, Optional

from src.alerts.service import AlertService
from src.config import Config, load_config
from src.detection.engine import DetectionEngine
from src.messages import DetectionResults
from src.stream_processor.windows import WindowProcessor

logger = logging.getLogger("NetGuard.Pipeline")


def _start(flow):
    return flow["start_timestamp"] if isinstance(flow, dict) else flow.start_timestamp


def run_flows(flows: Iterable, config: Optional[Config] = None) -> list[DetectionResults]:
    cfg = config or load_config()
    # Dwa profile zgodnie z Architecture Document: źródło (Port Scan, Brute Force, ...) i cel (DoS-like)
    processors = [WindowProcessor.from_config(k, cfg.windows) for k in ("src_ip", "dst_ip")]
    engine = DetectionEngine(cfg)
    service = AlertService(cfg.alerts)

    n_flows = n_windows = n_raw = 0

    def handle(windows):
        nonlocal n_windows, n_raw
        for w in windows:
            n_windows += 1
            raws = engine.process(w)
            n_raw += len(raws)
            service.process(raws)

    for flow in sorted(flows, key=_start):
        n_flows += 1
        for p in processors:
            handle(p.add(flow))
    for p in processors:
        handle(p.flush())

    result = service.detections
    logger.info("pipeline done: flows=%d windows=%d raw_detections=%d alerts=%d late_dropped=%d",
                n_flows, n_windows, n_raw, len(result), processors[0].late)
    return result