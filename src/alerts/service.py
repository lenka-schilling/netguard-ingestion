import logging
from datetime import datetime, timezone
from src.alerts.classification import confidence_from_ratio, explain, severity_from_ratio
from src.config import AlertConfig
from src.messages import DetectionResults, DetectionType, RawDetection

logger = logging.getLogger("NetGuard.Alerts")

"""tu dopiero tworzymy alerty - czyli bierzemy rawdetection i nadajemy mu severity, confidence itp"""

class _Active:
    __slots__ = ("detection_id", "methods", "best", "best_by_method", "last_end", "created_at", "latency_ms")

    def __init__(self, raw: RawDetection):
        self.detection_id = raw.detection_id
        self.methods = {raw.method}
        self.best = raw
        self.best_by_method = {raw.method: raw}
        self.last_end = raw.window_end
        self.created_at = datetime.now(timezone.utc)
        self.latency_ms = _latency_ms(raw.last_ingested_at, self.created_at)

    def add(self, raw: RawDetection):
        self.methods.add(raw.method)
        if raw.ratio > self.best.ratio:
            self.best = raw
        cur = self.best_by_method.get(raw.method)
        if cur is None or raw.ratio > cur.ratio:
            self.best_by_method[raw.method] = raw
        self.last_end = max(self.last_end, raw.window_end)

def _latency_ms(ingested_at, now):
    if not ingested_at:
        return None
    try:
        t = datetime.fromisoformat(ingested_at)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return round((now - t).total_seconds() * 1000, 1)

class AlertService:
    def __init__(self, cfg: AlertConfig):
        self.cfg = cfg
        self._active = {}
        self._results = {}

    @property
    def detections(self) -> list[DetectionResults]:
        return list(self._results.values())

    def process(self, raws: list[RawDetection]) -> list[DetectionResults]:
        touched = {}
        for raw in sorted(raws, key=lambda r: (r.window_end, r.window_size_s)):
            mk = self._merge_key(raw)
            act = self._active.get(mk)
            if act is None or raw.window_end - act.last_end > self.cfg.cooldown_s:
                act = self._active[mk] = _Active(raw)
                logger.info("new detection %s: %s key=%s window=%ss ratio=%.1f", act.detection_id[:8], raw.type, raw.key, raw.window_size_s, raw.ratio)
            else:
                act.add(raw)
            det = self._build(act)
            self._results[act.detection_id] = det
            touched[act.detection_id] = det
        if raws:
            self._expire(max(r.window_end for r in raws))
        return list(touched.values())

    @staticmethod
    def _merge_key(raw: RawDetection):
        dest = raw.destination if raw.type == DetectionType.BRUTE_FORCE else None
        return (raw.type, raw.key, dest)

    def _expire(self, now):
        stale = [k for k, a in self._active.items() if now - a.last_end > self.cfg.cooldown_s]
        for k in stale:
            del self._active[k]

    def _build(self, a: _Active) -> DetectionResults:
        r = a.best
        by_source = r.key_type == "src_ip"
        values = dict(r.observed)
        values.update({f"threshold_{k}": v for k, v in r.treshold.items()})
        values.update({k: float(v) for k, v in r.context.items() if isinstance(v, (int, float)) and not isinstance(v, bool)})
        return DetectionResults(
            detection_id=a.detection_id,
            timestamp=a.created_at.isoformat(),
            type=r.type,
            severity=severity_from_ratio(r.ratio, self.cfg.severity),
            confidence=confidence_from_ratio(r.ratio, both_methods=len(a.methods) > 1),
            source=r.key if by_source else None,
            destination=r.destination if by_source else r.key,
            time_window_s=r.window_size_s,
            window_start=r.window_start,
            window_end=a.last_end,
            method="+".join(sorted(a.methods)),
            feature_values=values,
            explanation=" ".join(explain(a.best_by_method[m]) for m in sorted(a.best_by_method)),
            latency_ms=a.latency_ms,
        )

        