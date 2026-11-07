from typing import Optional
from pydantic import BaseModel, Field

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