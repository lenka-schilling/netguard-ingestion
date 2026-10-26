import dpkt
import socket
import json
import uuid
import sys

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

def process_pcap(file_path):
    print(f"Processing {file_path}...\n")
    flows = {}
    corrupted_packets = 0
    invalid_records = 0
    
    try:
        f = open(file_path, 'rb')
        pcap = dpkt.pcap.Reader(f)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error: Failed to parse PCAP file header ({e}).", file=sys.stderr)
        return

    with f:
        while True:
            try:
                # Odczyt kolejnego pakietu z pliku PCAP
                timestamp, buf = next(pcap)
            except StopIteration:
                break
            except Exception:
                # Przechwytuje błędy struktury PCAP (np. obcięte ramki wewnątrz pliku)
                corrupted_packets += 1
                continue

            # Sprawdzenie minimalnej długości nagłówka Ethernet (14 bajtów)
            if len(buf) < 14:
                corrupted_packets += 1
                continue

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                corrupted_packets += 1
                continue

            # Sprawdzenie, czy ramka to IP/IPv6
            is_ip_type = eth.type in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6)
            
            # Jeśli ramka powinna być IP, ale eth.data nie jest obiektem IP (uszkodzone bajty IP):
            if is_ip_type and not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                corrupted_packets += 1
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
                continue
            
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            
            if flow_key in flows:
                flows[flow_key]["packet_count"] += 1
                flows[flow_key]["byte_count"] += len(buf)
                flows[flow_key]["end_timestamp"] = timestamp
            else:
                flows[flow_key] = {
                    "flow_id": str(uuid.uuid4()),
                    "start_timestamp": timestamp,
                    "end_timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "byte_count": len(buf),
                    "packet_count": 1
                }

    for flow in flows.values():
        flow["duration"] = round(flow.pop("end_timestamp") - flow["start_timestamp"], 6)
        print(json.dumps(flow))

    print(f"\n--- Ingestion Summary ---")
    print(f"Processed Flows: {len(flows)}")
    print(f"Corrupted Packets Skipped: {corrupted_packets}")
    print(f"Invalid Records Skipped: {invalid_records}")

if __name__ == '__main__':
    process_pcap('zlip-1.pcap')