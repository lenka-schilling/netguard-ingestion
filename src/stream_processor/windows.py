import logging
import math
from collections import Counter, deque
from src.messages import WindowFeatures

logger = logging.getLogger("NetGuard.Windows")

TOP_TARGETS = 5

def is_new_connection(flow):
    flags = flow.get("tcp_flags")
    if flow.get("protocol") != "TCP" or not flags:
        return True
    return "SYN" in flags.split(",")

class Bucket:
    __slots__ = ("connections", "new_conns", "packets", "bytes", "dst_ports", "peers", "targets", "last_ingested_at")

    def __init__(self):
        self.connections = 0
        self.new_conns = 0
        self.packets = 0
        self.bytes = 0
        self.dst_ports = set()
        self.peers = set()
        self.targets = {}
        self.last_ingested_at = None

class WindowProcessor:
    def __init__(self, key_type="src_ip", window_sizes=(1, 10, 60), lateness_s=1, dedup_ttl_s=60):
        if key_type not in ("src_ip", "dst_ip"):
            raise ValueError("key_type must be 'src_ip' or 'dst_ip'")
        self.key_type = key_type
        self.window_sizes = tuple(sorted(window_sizes))
        self.max_window = self.window_sizes[-1]
        self.lateness_s = lateness_s
        self.state = {}
        self._next = None
        self._max_ts = None
        self.processed = 0
        self.late = 0
        self.duplicates = 0
        self.dedup_ttl_s = dedup_ttl_s
        self._seen = {}
        self._seen_order = deque()

    @classmethod
    def from_config(cls, key_type, windows_cfg):
        return cls(key_type, window_sizes=windows_cfg.sizes_s, lateness_s=windows_cfg.lateness_s, dedup_ttl_s=windows_cfg.dedup_ttl_s)


    """Dodaje flow, zwraca liste window features dla sekund ktore sie zamknely"""
    def add(self, flow):
        if hasattr(flow, "to_dict"):
            flow = flow.to_dict()

        ts = flow["start_timestamp"]
        sec = math.floor(ts)
        if self._next is None:
            self._next = sec
        if sec < self._next:
            self.late += 1
            logger.debug("Late flow dropped: %s (ts=%s)", flow.get("flow_id"), ts)
            return []

        flow_id = flow.get("flow_id")
        if flow_id is not None:
            if flow_id in self._seen:
                self.duplicates += 1
                logger.debug("Duplicate flow dropped: %s", flow_id)
                return []
            self._seen[flow_id] = sec
            self._seen_order.append((sec, flow_id))

        bucket = self.state.setdefault(flow[self.key_type], {}).setdefault(sec, Bucket())
        self._update(bucket, flow)
        self.processed += 1

        if self._max_ts is None or ts > self._max_ts:
            self._max_ts = ts
        return self._close_until(math.floor(self._max_ts - self.lateness_s))


    """koniec danych - zamykamy sekundy"""
    def flush(self):
        if self._next is None or not self.state:
            return []
        last = max(max(buckets) for buckets in self.state.values())
        return self._close_until(last + 1)

    def _update(self, b, flow):
        b.connections += 1
        if is_new_connection(flow):
            b.new_conns += 1
        b.packets += flow.get("packet_count", 1)
        b.bytes += flow.get("byte_count", 0)
        b.dst_ports.add(flow["dst_port"])
        if self.key_type == "src_ip":
            b.peers.add(flow["dst_ip"])
            b.targets.setdefault(flow["dst_ip"], Counter())[flow["dst_port"]] += 1
        else:
            b.peers.add(flow["src_ip"])
        ing = flow.get("ingested_at")
        if ing and (b.last_ingested_at is None or ing > b.last_ingested_at):
            b.last_ingested_at = ing

    def _close_until(self, limit):
        out = []
        while self._next < limit:
            s = self._next
            if not self.state:
                self._next = limit
                break
            out.extend(self._evaluate(s))
            self._expire(s)
            self._next = s + 1
        self._purge_seen()
        return out

    def _purge_seen(self):
        limit = self._next - self.dedup_ttl_s
        while self._seen_order and self._seen_order[0][0] < limit:
            _, flow_id = self._seen_order.popleft()
            self._seen.pop(flow_id, None)

    def _evaluate(self, s):
        out = []
        for key, buckets in self.state.items():
            if s not in buckets:
                continue
            for w in self.window_sizes:
                used = [buckets[x] for x in range(s - w + 1, s + 1) if x in buckets]
                out.append(self._build(key, w, s + 1 - w, s + 1, used))
        return out

    """Usuwamy koszyki ktore juz nie beda potrzebne do stworzenia najwiekszego okna"""
    def _expire(self, s):
        keep_from = s - self.max_window + 2
        for key in list(self.state):
            buckets = self.state[key]
            for sec in [x for x in buckets if x < keep_from]:
                del buckets[sec]
            if not buckets:
                del self.state[key]

    def _build(self, key, w, start, end, used):
        conns = sum(b.connections for b in used)
        new_conns = sum(b.new_conns for b in used)
        packets = sum(b.packets for b in used)
        nbytes = sum(b.bytes for b in used)
        ports, peers = set(), set()
        for b in used:
            ports |= b.dst_ports
            peers |= b.peers

        peer_name = "unique_dst_addrs" if self.key_type == "src_ip" else "unique_src_addrs"
        features = {
            "connections": conns,
            "packets_per_s": packets / w,
            "bytes_per_s": nbytes / w,
            "unique_dst_ports": len(ports),
            peer_name: len(peers),
            "new_conn_rate": new_conns / w    
        }
        targets = []
        if self.key_type == "src_ip":
            merged = {}
            for b in used:
                for dst, counter in b.targets.items():
                    merged.setdefault(dst, Counter()).update(counter)
            ranked = sorted(merged.items(), key=lambda kv: -sum(kv[1].values()))
            for dst, counter in ranked[:TOP_TARGETS]:
                port, cnt = counter.most_common(1)[0]
                targets.append({
                    "dst_ip": dst,
                    "connections": sum(counter.values()),
                    "unique_dst_ports": len(counter),
                    "top_port": port,
                    "top_port_connections": cnt,
                })
        ingested = [b.last_ingested_at for b in used if b.last_ingested_at]

        return WindowFeatures(
            key_type=self.key_type, key=key, window_size_s=w, window_start=float(start), window_end=float(end), 
            last_ingested_at=max(ingested) if ingested else None, features=features, targets=targets,
        )