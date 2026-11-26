import logging
import time
from typing import Optional
from src.broker import FLOWS_STREAM, PERSISTER_GROUP, RedisStreamBroker
from src.database import save_flows
from src.models import Flow

logger = logging.getLogger("NetGuard.Persister")

def run_flow_persister(
        broker: Optional[RedisStreamBroker] = None,
        stream: str = FLOWS_STREAM,
        group: str = PERSISTER_GROUP,
        consumer_name: str = "persister-1",
        batch_size: int = 500,
        flush_interval_s: float = 1.0,
        block_ms: int = 500,
) -> None:
    b = broker or RedisStreamBroker()
    pending_flows: list[dict] = []
    pending_ids: list[str] = []
    last_flush = time.monotonic()

    logger.info("Flow Persister listening on stream '%s' (group='%s')...", stream, group)

    while True:
        items = list(
            b.consume_models(
                stream=stream,
                model_cls=Flow,
                group=group,
                consumer=consumer_name,
                count=batch_size,
                block_ms=block_ms,
            )
        )

        for msg_id, flow_obj in items:
            pending_flows.append(flow_obj.to_dict())
            pending_ids.append(msg_id)

        now = time.monotonic()
        should_flush = (
            len(pending_flows) >= batch_size
            or (pending_flows and (now - last_flush) >= flush_interval_s)
        )

        if should_flush:
            save_flows(pending_flows)
            for mid in pending_ids:
                b.ack(stream, group, mid)
            logger.info("Persisted batch of %d flow(s) to PostgreSQL", len(pending_flows))
            pending_flows.clear()
            pending_ids.clear()
            last_flush = now