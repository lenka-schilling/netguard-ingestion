import math
import logging
from src.messages import WindowFeatures, DetectionType, Method, RawDetection
from src.config import MLConfig

logger = logging.getLogger("NetGuard.ZScore")

FEATURES = {
    "src_ip": {
        "unique_dst_ports": DetectionType.PORT_SCAN,
        "unique_dst_addrs": DetectionType.ABNORMAL_CONN_PATTERN,
        "connections": DetectionType.ABNORMAL_CONN_PATTERN,
    },
    "dst_ip": {
        "connections": DetectionType.DOS_LIKE,
        "unique_src_addrs": DetectionType.ABNORMAL_CONN_PATTERN,
    },
}

class _Stat:
    __slots__ = ("mean", "var", "n", "last_seen")

    def __init__(self):
        self.mean = 0.0
        self.var = 0.0
        self.n = 0
        self.last_seen = 0.0

    def update(self, x, alpha):
        self.n += 1
        if self.n == 1:
            self.mean, self.var = x, 0.0
            return
        diff = x - self.mean
        incr = alpha * diff
        self.mean += incr
        self.var = (1 - alpha) * (self.var + diff * incr)

class ZScoreDetector:
    def __init__(self, config: MLConfig):
        self.cfg = config
        # Stan per klucz: (liczba_probek, srednia, suma_kwadratow_roznic)
        self._state = {}
        self._last_cleanup = None

    def evaluate(self, window: WindowFeatures) -> list[RawDetection]:
        w = window.window_size_s
        if w not in self.cfg.windows:
            return[]
        self._maybe_cleanup(window.window_end)
        tumbling = int(window.window_end) % w == 0
        out = []
        for feature, dtype in FEATURES.get(window.key_type, {}).items():
            x = window.features.get(feature)
            if x is None:
                continue
            st = self._state.setdefault((window.key_type, window.key, w, feature), _Stat())
            st.last_seen = window.window_end
            anomalous = False
            if st.n >= self.cfg.min_samples:
                sigma = max(math.sqrt(st.var), self.cfg.min_sigma)
                z = (x - st.mean) / sigma
                if z > self.cfg.z_score_threshold:
                    anomalous = True
                    out.append(RawDetection(
                        method=Method.ZSCORE, type=dtype, key_type=window.key_type, key=window.key,
                        destination=window.key if window.key_type == "dst_ip" else None,
                        window_size_s=w, window_start=window.window_start, window_end=window.window_end,
                        last_ingested_at=window.last_ingested_at, observed={feature: x}, 
                        treshold={feature: self.cfg.z_score_threshold}, ratio=z / self.cfg.z_score_threshold,
                        context={"feature": feature, "z_score": z, "mean": st.mean, "std": sigma},
                    ))
                    logger.debug("zscore hit: %s key=%s %s=%s z=%.1f", dtype, window.key, feature, x, z)
            if tumbling and not anomalous:
                st.update(x, self.cfg.alpha)
        return out

    def _maybe_cleanup(self, now):
        if self._last_cleanup is None:
            self._last_cleanup = now
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        stale = [k for k, st in self._state.items() if st.last_seen < now - self.cfg.ttl_s]
        for k in stale:
            del self._state[k]
        if stale:
            logger.debug("zscore: expired %d stale states", len(stale))