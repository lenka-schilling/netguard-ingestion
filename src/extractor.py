import dpkt
import logging
import socket
import json
import sys
from typing import Iterator
from src.importer import load_pcap_file
from src.models import Flow

logger = logging.getLogger("NetGuard.Extractor")

TCP_FLAG_NAMES = (
    (dpkt.tcp.TH_SYN, "SYN"), (dpkt.tcp.TH_ACK, "ACK"), (dpkt.tcp.TH_FIN, "FIN"),
    (dpkt.tcp.TH_RST, "RST"), (dpkt.tcp.TH_PUSH, "PSH"), (dpkt.tcp.TH_URG, "URG"),
)

def inet_to_str(inet):
    """Converts a binary IP address to a string format with validation."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return None

def is_valid_port(port):
    """Validates that a port falls within the standard network range (0-65535)."""
    return isinstance(port, int) and 0 <= port <= 65535

def flags_to_str(mask: int):
    names = [name for bit, name in TCP_FLAG_NAMES if mask & bit]
    return ",".join(names) or None

def is_syn_ack(mask: int) -> bool:
    return bool(mask & dpkt.tcp.TH_SYN) and bool(mask & dpkt.tcp.TH_ACK)

def _finalize_flow(key, flows: dict, flow_flags: dict) -> dict:
    flow_obj = flows.pop(key)
    mask = flow_flags.pop(key, 0)
    flow_obj.tcp_flags = flags_to_str(mask)
    return flow_obj.to_dict()

def extract_flows(file_path: str, idle_timeout_s: float = 1.0, max_active_flows: int = 50_000) -> Iterator[dict]:
    logger.info(f"Starting flow extraction process for: {file_path}")
    
    try:
        file_obj, pcap_reader = load_pcap_file(file_path)
    except Exception:
        logger.error(f"Extraction aborted due to import failure for: {file_path}")
        return 

    flows: dict = {}
    flow_flags: dict = {}
    corrupted_packets = 0
    invalid_records = 0
    emitted_count = 0
    last_sweep_ts = None

    with file_obj:
        while True:
            try:
                # Odczyt kolejnego pakietu z pliku PCAP
                timestamp, buf = next(pcap_reader)
            except StopIteration:
                break
            except Exception as e:
                # Przechwytuje błędy struktury PCAP (np. obcięte ramki wewnątrz pliku)
                corrupted_packets += 1
                logger.warning(f"Corrupted packet structure encountered: {e}")
                continue

            # Sprawdzenie minimalnej długości nagłówka Ethernet (14 bajtów)
            if len(buf) < 14:
                corrupted_packets += 1
                logger.debug("Dropped packet: Ethernet header too short (< 14 bytes)")
                continue

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                corrupted_packets += 1
                logger.debug("Dropped packet: Failed to parse Ethernet frame")
                continue

            # Sprawdzenie, czy ramka to IP/IPv6
            is_ip_type = eth.type in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6)
            
            # Jeśli ramka powinna być IP, ale eth.data nie jest obiektem IP (uszkodzone bajty IP):
            if is_ip_type and not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                corrupted_packets += 1
                logger.debug("Dropped packet: Expected IP payload but found malformed data")
                continue
                
            if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
                
            ip = eth.data
            
            src_port, dst_port, protocol, flags = 0, 0, "OTHER", 0
            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol = "TCP"
                flags = ip.data.flags
            elif isinstance(ip.data, dpkt.udp.UDP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol = "UDP"
            
            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            
            if not src_ip or not dst_ip or not is_valid_port(src_port) or not is_valid_port(dst_port):
                invalid_records += 1
                logger.debug(f"Invalid record dropped: src={src_ip}, dst={dst_ip}, ports=({src_port}, {dst_port})")
                continue

            if last_sweep_ts is None:
                last_sweep_ts = timestamp
            elif (timestamp - last_sweep_ts) >= 1.0 or len(flows) > max_active_flows:
                expired_keys = [
                    k for k, f in flows.items()
                    if (timestamp - f.end_timestamp) >= idle_timeout_s
                ]
                for k in expired_keys:
                    emitted_count += 1
                    yield _finalize_flow(k, flows, flow_flags)
                last_sweep_ts = timestamp

            a, b = (src_ip, src_port), (dst_ip, dst_port)
            flow_key = (protocol,) + tuple(sorted((a,b)))
            
            flow_obj = flows.get(flow_key)
            if flow_obj is None:
                initiator, responder = (b, a) if is_syn_ack(flags) else (a, b)
                flow_obj = Flow(
                    src_ip=initiator[0], src_port=initiator[1],
                    dst_ip=responder[0], dst_port=responder[1],
                    protocol=protocol,
                    start_timestamp=timestamp,
                    end_timestamp=timestamp,
                )
                flow_obj.byte_count = len(buf)
                flows[flow_key] = flow_obj
            else:
                flow_obj.packet_count += 1
                flow_obj.byte_count += len(buf)
                flow_obj.start_timestamp = min(flow_obj.start_timestamp, timestamp)
                flow_obj.end_timestamp = max(flow_obj.end_timestamp, timestamp)
            flow_flags[flow_key] = flow_flags.get(flow_key, 0) | flags

            if protocol == "TCP" and (flags & dpkt.tcp.TH_RST):
                emitted_count += 1
                yield _finalize_flow(flow_key, flows, flow_flags)

    for k in list(flows.keys()):
        emitted_count += 1
        yield _finalize_flow(k, flows, flow_flags)

    logger.info(
        f"Extraction finished successfully. "
        f"Processed Flows: {emitted_count}, "
        f"Corrupted Packets Skipped: {corrupted_packets}, "
        f"Invalid Records Skipped: {invalid_records}"
    )

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    test_file = sys.argv[1] if len(sys.argv) > 1 else "data/sample.pcap"
    results = extract_flows(test_file)

    for flow_json in results:
        print(json.dumps(flow_json))