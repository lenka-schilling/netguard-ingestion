"""Pełny obieg bez brokera i bazy: flowy -> okna -> detekcje -> alarmy.
Osobno od main.py (które czyta PCAP), żeby dało się to testować na gotowych flowach."""
import logging
from typing import Callable, Iterable, Optional

from src.alerts.service import AlertService
from src.broker import DEFAULT_GROUP, FLOWS_STREAM, RedisStreamBroker
from src.config import Config, load_config
from src.detection.engine import DetectionEngine
from src.messages import DetectionResults, WindowFeatures
from src.stream_processor.windows import WindowProcessor
from src.models import Flow

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

def run_detection_worker(
    broker: Optional[RedisStreamBroker] = None,
    config: Optional[Config] = None,
    flows_stream: str = FLOWS_STREAM,
    group: str = DEFAULT_GROUP,
    consumer_name: str = "worker-1",
    max_empty_polls: Optional[int] = None,
    block_ms: int = 500,
    on_alerts: Optional[Callable[[list[DetectionResults]], None]] = None,
) -> list[DetectionResults]:
    """Konsumuje WindowFeatures z brokera, uruchamia detekcję, publikuje DetectionResults i wywołuje on_alerts."""
    cfg = config or load_config()
    b = broker or RedisStreamBroker()
    processors = [WindowProcessor.from_config(k, cfg.windows) for k in ("src_ip", "dst_ip")]
    engine = DetectionEngine(cfg)
    service = AlertService(cfg.alerts)
    seen_ids: set[str] = set()

    empty_polls = 0
    while True:
        batch_items = list(
            b.consume_models(
                stream=flows_stream,
                model_cls=Flow,
                group=group,
                consumer=consumer_name,
                count=64,
                block_ms=block_ms,
            )
        )
        if not batch_items:
            empty_polls += 1

            flushed_windows: list[WindowFeatures] = []
            for p in processors:
                flushed_windows.extend(p.flush())
            if flushed_windows:
                _process_windows(flushed_windows, engine, service, seen_ids, on_alerts)

            if max_empty_polls is not None and empty_polls >= max_empty_polls:
                break
            continue

        empty_polls = 0
        windows_to_check: list[WindowFeatures] = []
        for msg_id, flow_obj in batch_items:
            flow_dict = flow_obj.to_dict()
            for p in processors:
                windows_to_check.extend(p.add(flow_dict))
            b.ack(flows_stream, group, msg_id)

        if windows_to_check:
            _process_windows(windows_to_check, engine, service, seen_ids, on_alerts)            

    return service.detections

def _process_windows(
        windows: list[WindowFeatures],
        engine: DetectionEngine,
        service: AlertService,
        seen_ids: set[str],
        on_alerts: Optional[Callable[[list[DetectionResults]], None]],
) -> None:
    new_alerts: list[DetectionResults] = []
    for w in windows:
        raws = engine.process(w)
        if raws:
            alerts = service.process(raws)
            for alert in alerts:
                if alert.detection_id not in seen_ids:
                    seen_ids.add(alert.detection_id)
                    new_alerts.append(alert)

    if new_alerts and on_alerts is not None:
        on_alerts(new_alerts)