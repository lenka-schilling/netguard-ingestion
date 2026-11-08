from src.messages import WindowFeatures, DetectionResults
from src.config import Config
from src.detection.rules import RuleDetector
from src.detection.ml import ZScoreDetector

class DetectionEngine:
    def __init__(self, config: Config):
        self.rule_detector = RuleDetector(config.detection.rules)
        self.zscore_detector = ZScoreDetector(config.detection.ml)

    def process(self, window: WindowFeatures) -> list[DetectionResults]:
        """
        Przetwarza zagregowane okno czasowe (WindowFeatures) przez oba silniki
        i zwraca listę wygenerowanych alertów (DetectionResult).
        """
        alerts = []
        
        # 1. Przepuszczamy dane przez detektor regułowy
        alerts.extend(self.rule_detector.evaluate(window))
        
        # 2. Przepuszczamy dane przez detektor statystyczny (Z-Score)
        alerts.extend(self.zscore_detector.evaluate(window))
        
        return alerts