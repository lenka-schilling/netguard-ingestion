import math
from src.messages import WindowFeatures, DetectionResults
from src.config import MLConfig

class ZScoreDetector:
    def __init__(self, config: MLConfig):
        self.config = config
        # Stan per klucz: (liczba_probek, srednia, suma_kwadratow_roznic)
        self.state = {}

    def evaluate(self, window: WindowFeatures) -> list[DetectionResults]:
        if window.key_type != "src_ip":
            return []

        val = window.features.get("connections", 0)
        key = (window.key, window.window_size_s)

        count, mean, m2 = self.state.get(key, (0, 0.0, 0.0))

        # Algorytm Welforda do przeliczania statystyk online (bez trzymania historii w pamięci)
        count += 1
        delta = val - mean
        mean += delta / count
        delta2 = val - mean
        m2 += delta * delta2
        self.state[key] = (count, mean, m2)

        alerts = []

        # Zaczynamy wykrywać anomalie dopiero gdy zbierzemy minimalną liczbę próbek (np. 10 okien)
        if count >= self.config.min_samples:
            variance = m2 / count
            std_dev = math.sqrt(variance)

            if std_dev > 0:
                z_score = (val - mean) / std_dev
                if z_score > self.config.z_score_threshold:
                    conf = min(1.0, 0.5 + (z_score - self.config.z_score_threshold) / 10.0)
                    alerts.append(DetectionResults(
                        type="Statistical Anomaly",
                        severity="MEDIUM",
                        confidence=round(conf, 2),
                        source=window.key,
                        time_window_s=window.window_size_s,
                        feature_values={"connections": val, "z_score": round(z_score, 2), "mean": round(mean, 2)},
                        explanation=f"Connection count ({val}) deviates significantly from the baseline (z-score: {z_score:.2f} > {self.config.z_score_threshold})."
                    ))

        return alerts
    