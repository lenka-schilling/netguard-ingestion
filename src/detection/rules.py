import logging
from src.config import RuleThresholds
from src.messages import DetectionType, Method, RawDetection, WindowFeatures

logger = logging.getLogger("NetGuard.Rules")

class RuleDetector:
    def __init__(self, rules: RuleThresholds):
        self.rules = rules

    def evaluate(self, window: WindowFeatures) -> list[RawDetection]:
        if window.key_type == "src_ip":
            found = [*self._port_scan(window), *self._brute_force(window), *self._abnormal(window)]
        elif window.key_type == "dst_ip":
            found = self._dos_like(window)
        else:
            found = []
        for r in found:
            logger.debug("rule hit: %s key=%s window=%ss ratio=%.2f", r.type, r.key, r.window_size_s, r.ratio)
        return found

    def _port_scan(self, w):
        thr = self.rules.port_scan.unique_dst_ports.get(w.window_size_s)
        val = w.features.get("unique_dst_ports", 0)
        if thr is None or val <= thr:
            return []
        return [self._make(w, DetectionType.PORT_SCAN, "unique_dst_ports", val, thr, destination=self._dominant_target(w,val))]

    def _brute_force(self, w):
        thr = self.rules.brute_force.attempts.get(w.window_size_s)
        if thr is None:
            return []
        out = []
        for t in w.targets:
            attempts = t.get("top_port_connections", 0)
            port = t.get("top_port")
            if port in self.rules.brute_force.ports and attempts > thr:
                out.append(self._make(w, DetectionType.BRUTE_FORCE, "attempts", attempts, thr, destination=t.get("dst_ip"), context={"port": port}))
        return out

    def _abnormal(self, w):
        thr = self.rules.abnormal.unique_dst_addrs.get(w.window_size_s)
        val = w.features.get("unique_dst_addrs", 0)
        if thr is None or val <= thr:
            return []
        return [self._make(w, DetectionType.ABNORMAL_CONN_PATTERN, "unique_dst_addrs", val, thr)]

    def _dos_like(self, w):
        thr = self.rules.dos_like.connections.get(w.window_size_s)
        val = w.features.get("connections", 0)
        if thr is None or val <= thr:
            return []
        ctx = {"unique_src_addrs": w.features.get("unique_src_addrs", 0)}
        return [self._make(w, DetectionType.DOS_LIKE, "connections", val, thr, destination=w.key, context=ctx)]

    @staticmethod
    def _dominant_target(w, total_ports):
        if not w.targets:
            return None
        top = max(w.targets, key=lambda t: t.get("unique_dst_ports", 0))
        return top["dst_ip"] if top.get("unique_dst_ports", 0) >= 0.5 * total_ports else None

    @staticmethod
    def _make(w, dtype, feature, value, thr, destination=None, context=None):
        return RawDetection(
            method=Method.RULE, type=dtype, key_type=w.key_type, key=w.key,
            destination=destination, window_size_s=w.window_size_s, window_start=w.window_start,
            window_end=w.window_end, last_ingested_at=w.last_ingested_at,
            observed={feature: value}, treshold={feature: thr}, 
            ratio=value / thr, context=context or {},
        )