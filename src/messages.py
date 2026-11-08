from typing import Optional, Any
from pydantic import BaseModel, Field, ConfigDict, computed_field
import uuid
import hashlib
from enum import Enum
from datetime import datetime, timezone

"""Definicje komunikatow ktore beda przesylane przez broker"""

class DetectionType(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    DOS_LIKE = "DOS_LIKE"
    BRUTE_FORCE = "BRUTE_FORCE"
    ABNORMAL_CONN_PATTERN = "ABNORMAL_CONN_PATTERN"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Method(str, Enum):
    RULE = "rule"
    ZSCORE = "zscore"

class WindowFeatures(BaseModel):
    key_type: str   #czy src_ip czy dst_ip
    key: str        #konkretny ip ktorego dotyczy okno
    window_size_s: int
    window_start: float
    window_end: float
    last_ingested_at: Optional[str] = None   #najnowszy ingested_at NFR02
    features: dict[str, float]
    targets: list[dict] = Field(default_factory=list)  #tylko dla key_type=src_ip

"""Wynik detektora bez oceny - severity i confidence nadaje dopiero alert service"""
class RawDetection(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    method: Method
    type: DetectionType
    key_type: str
    key: str
    destination: Optional[str] = None
    window_size_s: int
    window_start: float
    window_end: float
    last_ingested_at: Optional[str] = None
    observed: dict[str, float]
    treshold: dict[str, float]
    ratio: float = Field(gt=0)
    context: dict[str, Any] = Field(default_factory=dict)

    """id - zgodnie a AD to samo okno przetworzone drugi raz daje to samo id (brak duplikatow)"""
    @computed_field
    @property
    def detection_id(self) -> str:
        raw = "|".join([self.type, self.method, self.key, self.destination or "", str(self.window_size_s), str(self.window_start)])
        return hashlib.sha1(raw.encode()).hexdigest()


class DetectionResults(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    detection_id: str 
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    type: DetectionType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source: Optional[str] = None
    destination: Optional[str] = None
    time_window_s: int
    window_start: float
    window_end: float
    method: str
    feature_values: dict[str, float]
    explanation: str
    latency_ms: Optional[float] = None
