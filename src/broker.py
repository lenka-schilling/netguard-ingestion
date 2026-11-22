import json
import logging
import os
from typing import Optional, Type, TypeVar

import redis
from pydantic import BaseModel

logger = logging.getLogger("NetGuard.Broker")

ModelT = TypeVar("ModelT", bound=BaseModel)

DEFAULT_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
WINDOWS_STREAM = os.getenv("NETGUARD_WINDOWS_STREAM", "netguard.windows")
ALERTS_STREAM = os.getenv("NETGUARD_ALERTS_STREAM", "netguard.alerts")
DEFAULT_GROUP = os.getenv("NETGUARD_CONSUMER_GROUP", "netguard-workers")


class RedisStreamBroker:
    """Lekki broker zdarzeń oparty o Redis Streams i grupy konsumenckie."""

    def __init__(self, url: str = DEFAULT_REDIS_URL):
        self.url = url
        self._client: Optional[redis.Redis] = None

    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.Redis.from_url(self.url, decode_responses=True)
        return self._client

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception as exc:
            logger.warning("Redis ping failed (%s): %s", self.url, exc)
            return False

    def ensure_group(self, stream: str, group: str = DEFAULT_GROUP) -> None:
        try:
            self.client.xgroup_create(name=stream, groupname=group, id="0", mkstream=True)
            logger.info("Created consumer group '%s' on stream '%s'.", group, stream)
        except redis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                return
            raise

    def publish_model(self, stream: str, model: BaseModel, maxlen: int = 100_000) -> str:
        payload = model.model_dump(mode="json")
        msg_id = self.client.xadd(
            name=stream,
            fields={"payload": json.dumps(payload)},
            maxlen=maxlen,
            approximate=True,
        )
        logger.debug("Published %s to %s (id=%s)", type(model).__name__, stream, msg_id)
        return msg_id

    def consume_models(
        self,
        stream: str,
        model_cls: Type[ModelT],
        group: str = DEFAULT_GROUP,
        consumer: str = "consumer-1",
        count: int = 16,
        block_ms: int = 500,
    ):
        """Generator zwracający krotki (msg_id, model_instance). Po przetworzeniu wywołaj ack()."""
        self.ensure_group(stream=stream, group=group)
        resp = self.client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=count,
            block=block_ms,
        )
        if not resp:
            return

        for _stream_name, entries in resp:
            for msg_id, fields in entries:
                raw_payload = fields.get("payload")
                if not raw_payload:
                    logger.warning("Empty payload in stream %s (id=%s), acking.", stream, msg_id)
                    self.ack(stream, group, msg_id)
                    continue
                try:
                    data = json.loads(raw_payload)
                    obj = model_cls.model_validate(data)
                except Exception as exc:
                    logger.error("Failed to decode message %s from %s: %s", msg_id, stream, exc)
                    self.ack(stream, group, msg_id)
                    continue
                yield msg_id, obj

    def ack(self, stream: str, group: str, msg_id: str) -> None:
        self.client.xack(stream, group, msg_id)