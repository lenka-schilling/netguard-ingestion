import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class Flow(BaseModel):
    flow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    start_timestamp: float
    end_timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 1
    byte_count: int = 0
    tcp_flags: Optional[str] = None

    def to_dict(self):
        data = self.model_dump()
        data["duration"] = round(self.end_timestamp - self.start_timestamp, 6)
        
        return data