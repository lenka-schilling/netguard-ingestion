from src.messages import WindowFeatures, DetectionResults
from src.config import RuleThresholds

class RuleDetector:
    def __init__(self, thresholds: RuleThresholds):
        self.thresholds = thresholds

    def evaluate(self, window: WindowFeatures) -> list[DetectionResults]:
        alerts = []

        if window.key_type != "src_ip":
            return alerts

        feats = window.features

        # 1. Port Scan
        if feats.get("unique_dst_ports", 0) > self.thresholds.port_scan_unique_ports:
            val = feats["unique_dst_ports"]
            thr = self.thresholds.port_scan_unique_ports
            conf = min(1.0, 0.5 + (val - thr) / (thr * 2))
            alerts.append(DetectionResults(
                type="Port Scan",
                severity="HIGH",
                confidence=round(conf, 2),
                source=window.key,
                time_window_s=window.window_size_s,
                feature_values={"unique_dst_ports": val},
                explanation=f"Excessive distinct destination ports ({val}) contacted within {window.window_size_s}s window (threshold: {thr})."
            ))

        # 2. DoS-like
        if feats.get("connections", 0) > self.thresholds.dos_connections:
            val = feats["connections"]
            thr = self.thresholds.dos_connections
            conf = min(1.0, 0.7 + (val - thr) / (thr * 5))
            alerts.append(DetectionResults(
                type="DoS-like",
                severity="CRITICAL",
                confidence=round(conf, 2),
                source=window.key,
                time_window_s=window.window_size_s,
                feature_values={"connections": val, "bytes_per_s": feats.get("bytes_per_s", 0)},
                explanation=f"Unusually high connection count ({val}) from a single source (threshold: {thr})."
            ))

        # 3. Abnormal Connection Pattern
        if feats.get("unique_dst_addrs", 0) > self.thresholds.abnormal_dst_addrs:
            val = feats["unique_dst_addrs"]
            thr = self.thresholds.abnormal_dst_addrs
            alerts.append(DetectionResults(
                type="Abnormal Connection Pattern",
                severity="MEDIUM",
                confidence=0.8,
                source=window.key,
                time_window_s=window.window_size_s,
                feature_values={"unique_dst_addrs": val},
                explanation=f"Source contacted an abnormal number of distinct IP addresses ({val}) (threshold: {thr})."
            ))

        # 4. Brute Force-like
        for target in window.targets:
            conn = target.get("top_port_connections", 0)
            if conn > self.thresholds.brute_force_connections:
                thr = self.thresholds.brute_force_connections
                conf = min(1.0, 0.6 + (conn - thr) / (thr * 2))
                alerts.append(DetectionResults(
                    type="Brute Force-like",
                    severity="HIGH",
                    confidence=round(conf, 2),
                    source=window.key,
                    destination=target.get("dst_ip"),
                    time_window_s=window.window_size_s,
                    feature_values={"top_port_connections": conn, "target_port": target.get("top_port", 0)},
                    explanation=f"High repeated connection attempts ({conn}) to port {target.get('top_port')} on {target.get('dst_ip')}."
                ))

        return alerts