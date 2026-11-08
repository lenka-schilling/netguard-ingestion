from src.messages import WindowFeatures, RawDetection
from src.config import Config
from src.detection.rules import RuleDetector
from src.detection.ml import ZScoreDetector
import logging

logger = logging.getLogger("NetGuard.Engine")

class DetectionEngine:
    def __init__(self, config: Config):
        self.rule_detector = RuleDetector(config.detection.rules)
        self.zscore_detector = ZScoreDetector(config.detection.ml)

    def process(self, window: WindowFeatures) -> list[RawDetection]:
        found = self.rule_detector.evaluate(window)
        found.extend(self.zscore_detector.evaluate(window))
        return found