import dpkt
import logging
import socket
import json
from src.importer import load_pcap_file
from src.models import Flow

logger = logging.getLogger("NetGuard.Extractor")

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

def extract_flows(file_path: str):
    logger.info(f"Starting flow extraction process for: {file_path}")
    
    try:
        file_obj, pcap_reader = load_pcap_file(file_path)
    except Exception:
        logger.error(f"Extraction aborted due to import failure for: {file_path}")
        return []

    flows = {}
    corrupted_packets = 0
    invalid_records = 0

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
            
            src_port, dst_port, protocol = 0, 0, "OTHER"
            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol = "TCP"
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
            
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            
            if flow_key in flows:
                flow_obj = flows[flow_key]
                flow_obj.packet_count += 1
                flow_obj.byte_count += len(buf)
                flow_obj.end_timestamp = timestamp
            else:
                new_flow = Flow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    timestamp=timestamp
                )
                new_flow.byte_count = len(buf)
                flows[flow_key] = new_flow

    extracted_flows = [flow.to_dict() for flow in flows.values()]

    logger.info(
        f"Extraction finished successfully. "
        f"Processed Flows: {len(extracted_flows)}, "
        f"Corrupted Packets Skipped: {corrupted_packets}, "
        f"Invalid Records Skipped: {invalid_records}"
    )
    return extracted_flows

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    test_file = "data/tcp-ethereal-file1.trace"
    results = extract_flows(test_file)

    for flow_json in results:
        print(json.dumps(flow_json, indent=2))