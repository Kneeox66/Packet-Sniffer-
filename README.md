# Packet-Sniffer
Overview

This is a Python-based real-time packet sniffer that monitors network traffic, detects active connections, tracks open ports, and provides protocol statistics. It also logs packet details to a file for further analysis.

Features

Tracks connected IPs and counts packets for each.

Identifies open ports for TCP and UDP packets.

Displays real-time protocol usage statistics.

Logs all captured packets to a file.

Updates the dashboard every second.


Requirements

Python 3.x

Root or Administrator privileges (required for raw socket access)


Setup

1. Clone the repository:

git clone <repository-url>
cd <repository-folder>


2. Run the script:

sudo python3 packet_sniffer.py



How It Works

1. Connected IPs: Lists all IPs involved in the network traffic and the number of packets exchanged.


2. Open Ports: Displays active open ports for each connected IP (both source and destination ports).


3. Protocol Statistics: Shows the number of packets for TCP, UDP, ICMP, and other protocols.


4. Packet Logging: Captures all packet details and writes them to advanced_packet_sniffer_log.txt.



Output Example

Real-Time Dashboard

============================================================
Real-Time Network Dashboard
============================================================

[Connected IPs]:
 - 192.168.1.101: 12 packets
 - 8.8.8.8: 5 packets
 - 192.168.1.102: 7 packets

[Protocol Statistics]:
 - TCP: 15 packets
 - UDP: 10 packets
 - ICMP: 5 packets

[Open Ports]:
 - 192.168.1.101: 443, 80
 - 192.168.1.102: 5353
 - 8.8.8.8: 443

============================================================

Log File

IPv4 Packet: Src=192.168.1.101, Target=8.8.8.8, Protocol=6
IPv4 Packet: Src=192.168.1.102, Target=224.0.0.251, Protocol=17

License

This project is licensed under the MIT License. See the LICENSE file for details.

Disclaimer

Use this tool only on networks you own or have permission to monitor.
