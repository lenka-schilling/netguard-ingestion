import uuid
from datetime import datetime

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
        self.flow_id = str(uuid.uuid4())
        self.ingested_at = datetime.utcnow().isoformat()
        self.start_timestamp = timestamp
        self.end_timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_count = 1
        self.byte_count = 0

    def to_dict(self):
        duration = round(self.end_timestamp - self.start_timestamp, 6)
        return {
            "flow_id": self.flow_id,
            "ingested_at": self.ingested_at,
            "start_timestamp": self.start_timestamp,
            "duration": duration,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count
        }