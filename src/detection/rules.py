import logging
import ipaddress
from src.config import RuleThresholds
from src.messages import DetectionType, Method, RawDetection, WindowFeatures

logger = logging.getLogger("NetGuard.Rules")

class RuleDetector:
    def __init__(self, rules: RuleThresholds):
        self.rules = rules
        self._groups = [(ipaddress.ip_network(h, strict=False), name, g) for name, g in rules.abnormal.groups.items() for h in g.hosts]
        self._group_cache = {}

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
        cfg = self.rules.port_scan
        thr = cfg.unique_dst_ports.get(w.window_size_s)
        val = w.features.get("unique_dst_ports", 0)
        if thr is None or val <= thr:
            return []

        addrs = max(w.features.get("unique_dst_addrs", 1), 1)
        if (val / addrs) < cfg.min_ports_per_host:
            return []

        dst = self._dominant_target(w, val)
        if cfg.ignore_broadcast and dst and self._is_broadcast(dst):
            return []
        return [self._make(w, DetectionType.PORT_SCAN, "unique_dst_ports", val, thr, destination=dst)]

    @staticmethod
    def _is_broadcast(ip: str) -> bool:
        if ip.endswith(".255"):
            return True
        try: 
            ip = ipaddress.ip_address(ip)
            return ip.is_multicast or ip.is_unspecified or ip == "255.255.255.255"
        except ValueError:
            return False

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
        cfg = self.rules.abnormal
        if w.window_size_s not in cfg.windows:
            return []
        group_name, group = self._group_of(w.key)
        if group is not None and not group.enabled:
            return []
        mult = group.multiplier if group is not None else cfg.multiplier
        out = []
        for feature, per_window in cfg.baseline.items():
            normal = per_window.get(w.window_size_s)
            val = w.features.get(feature)
            if normal is None or val is None:
                continue
            thr = max(normal * mult, cfg.min_values.get(feature, 0.0))
            if thr <= 0 or val <= thr:
                continue
            out.append(self._make(w, DetectionType.ABNORMAL_CONN_PATTERN, feature, val, thr, context={"baseline_value": normal, "multiplier": mult, "group": group_name or ""}))
        return out

    GROUP_CACHE_MAX = 100_000

    def _group_of(self, key):
        if not self._groups:
            return (None, None)
        cached = self._group_cache.get(key)
        if cached is not None:
            return cached
        found = (None, None)
        try:
            addr = ipaddress.ip_address(key)
            for net, name, g in self._groups:
                if addr.version == net.version and addr in net:
                    found = (name, g)
                    break
        except ValueError:
            pass
        if len(self._group_cache) >= self.GROUP_CACHE_MAX:
            self._group_cache.clear()
        self._group_cache[key] = found
        return found

    def _dos_like(self, w):
        out = []
        ctx = {"unique_src_addrs": w.features.get("unique_src_addrs", 0)}
        for metric, thresholds in (
            ("connections", self.rules.dos_like.connections),
            ("packets_per_s", self.rules.dos_like.packets_per_s),
        ):
            thr = thresholds.get(w.window_size_s)
            val = w.features.get(metric, 0)
            if thr is not None and val > thr:
                out.append(self._make(w, DetectionType.DOS_LIKE, metric, val, thr, destination=w.key, context=ctx))
        return out

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
            ratio=value / thr, context=context or {}, flow_ids=list(w.flow_ids),
        )