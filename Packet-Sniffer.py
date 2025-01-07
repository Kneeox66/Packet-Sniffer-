import socket
import struct
import threading
import time
from collections import defaultdict

connected_ips = defaultdict(int)
protocol_stats = defaultdict(int)
open_ports = defaultdict(set)
log_file = "advanced_packet_sniffer_log.txt"

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    threading.Thread(target=show_dashboard, daemon=True).start()
    with open(log_file, "w") as log:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                connected_ips[src] += 1
                connected_ips[target] += 1
                protocol_stats[proto] += 1
                if proto == 6:
                    src_port, dest_port, _, _, _, _, _, _, _, _, _ = tcp_segment(data)
                    open_ports[src].add(src_port)
                    open_ports[target].add(dest_port)
                elif proto == 17:
                    src_port, dest_port, _, _ = udp_segment(data)
                    open_ports[src].add(src_port)
                    open_ports[target].add(dest_port)
                log.write(f"IPv4 Packet: Src={src}, Target={target}, Protocol={proto}\n")
                log.flush()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def show_dashboard():
    while True:
        time.sleep(1)
        print("\033c", end="")
        print("=" * 60)
        print("Real-Time Network Dashboard")
        print("=" * 60)
        print("\n[Connected IPs]:")
        for ip, count in connected_ips.items():
            print(f" - {ip}: {count} packets")
        print("\n[Protocol Statistics]:")
        for proto, count in protocol_stats.items():
            proto_name = protocol_name(proto)
            print(f" - {proto_name}: {count} packets")
        print("\n[Open Ports]:")
        for ip, ports in open_ports.items():
            ports_list = ", ".join(map(str, sorted(ports)))
            print(f" - {ip}: {ports_list}")
        print("=" * 60)

def protocol_name(proto):
    if proto == 1:
        return "ICMP"
    elif proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    else:
        return f"Other ({proto})"

if __name__ == '__main__':
    main()
