"""Pełny obieg bez brokera i bazy: flowy -> okna -> detekcje -> alarmy.
Osobno od main.py (które czyta PCAP), żeby dało się to testować na gotowych flowach."""
import logging
from typing import Iterable, Optional

from src.alerts.service import AlertService
from src.broker import ALERTS_STREAM, DEFAULT_GROUP, WINDOWS_STREAM, RedisStreamBroker
from src.config import Config, load_config
from src.detection.engine import DetectionEngine
from src.messages import DetectionResults, WindowFeatures
from src.stream_processor.windows import WindowProcessor

logger = logging.getLogger("NetGuard.Pipeline")


def _start(flow):
    if hasattr(flow, "flow"):
        flow = flow.flow
    return flow["start_timestamp"] if isinstance(flow, dict) else flow.start_timestamp

def _build_windows_from_flows(flows: Iterable, cfg: Config) -> tuple[list[WindowFeatures], int, int]:
    processors = [WindowProcessor.from_config(k, cfg.windows) for k in ("src_ip", "dst_ip")]
    windows_out: list[WindowFeatures] = []
    n_flows = 0

    for flow in sorted(flows, key=_start):
        n_flows += 1
        for p in processors:
            windows_out.extend(p.add(flow))
    for p in processors:
        windows_out.extend(p.flush())

    late_dropped = processors[0].late if processors else 0
    return windows_out, n_flows, late_dropped


def run_flows(flows: Iterable, config: Optional[Config] = None) -> list[DetectionResults]:
    cfg = config or load_config()
    windows, n_flows, late_dropped = _build_windows_from_flows(flows, cfg)
    engine = DetectionEngine(cfg)
    service = AlertService(cfg.alerts)

    n_raw = 0
    for w in windows:
        raws = engine.process(w)
        n_raw += len(raws)
        service.process(raws)

    result = service.detections
    logger.info(
        "pipeline done: flows=%d windows=%d raw_detections=%d alerts=%d late_dropped=%d",
        n_flows,
        len(windows),
        n_raw,
        len(result),
        late_dropped,
    )
    return result

def publish_windows_from_flows(
    flows: Iterable,
    broker: Optional[RedisStreamBroker] = None,
    config: Optional[Config] = None,
    stream: str = WINDOWS_STREAM,
) -> int:
    """Buduje okna z przepływów i publikuje WindowFeatures na strumień brokera."""
    cfg = config or load_config()
    b = broker or RedisStreamBroker()
    windows, n_flows, _ = _build_windows_from_flows(flows, cfg)

    published = 0
    for w in windows:
        b.publish_model(stream=stream, model=w)
        published += 1

    logger.info("published %d window(s) from %d flow(s) to stream '%s'", published, n_flows, stream)
    return published

def run_detection_worker(
    broker: Optional[RedisStreamBroker] = None,
    config: Optional[Config] = None,
    windows_stream: str = WINDOWS_STREAM,
    alerts_stream: str = ALERTS_STREAM,
    group: str = DEFAULT_GROUP,
    consumer_name: str = "worker-1",
    max_empty_polls: Optional[int] = None,
    block_ms: int = 500,
) -> list[DetectionResults]:
    """Konsumuje WindowFeatures z brokera, uruchamia detekcję i publikuje DetectionResults."""
    cfg = config or load_config()
    b = broker or RedisStreamBroker()
    engine = DetectionEngine(cfg)
    service = AlertService(cfg.alerts)

    empty_polls = 0
    while True:
        batch_items = list(
            b.consume_models(
                stream=windows_stream,
                model_cls=WindowFeatures,
                group=group,
                consumer=consumer_name,
                block_ms=block_ms,
            )
        )
        if not batch_items:
            empty_polls += 1
            if max_empty_polls is not None and empty_polls >= max_empty_polls:
                break
            continue

        empty_polls = 0
        for msg_id, window in batch_items:
            raws = engine.process(window)
            if raws:
                alerts = service.process(raws)
                for alert in alerts:
                    b.publish_model(stream=alerts_stream, model=alert)
            b.ack(windows_stream, group, msg_id)

    return service.detections