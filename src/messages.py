from typing import Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

"""Definicje komunikatow ktore beda przesylane przez broker"""

class WindowFeatures(BaseModel):
    key_type: str   #czy src_ip czy dst_ip
    key: str        #konkretny ip ktorego dotyczy okno
    window_size_s: int
    window_start: float
    window_end: float
    last_ingested_at: Optional[str] = None   #najnowszy ingested_at NFR02
    features: dict[str, float]
    targets: list[dict] = Field(default_factory=list)  #tylko dla key_type=src_ip

class DetectionResults(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    destiantion: Optional[str] = None
    time_window_s: int
    feature_values: dict[str, float]
    explanation: str
