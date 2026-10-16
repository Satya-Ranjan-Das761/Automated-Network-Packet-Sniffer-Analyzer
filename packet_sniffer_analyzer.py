
import argparse
import csv
import os
from collections import Counter
from datetime import datetime

from scapy.all import (
    sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, get_if_list
)


def identify_protocol(packet):
    if packet.haslayer(DNS):
        return "DNS"

    if packet.haslayer(TCP):
        ports = (packet[TCP].sport, packet[TCP].dport)
        if 443 in ports:
            return "HTTPS/TCP"
        if 80 in ports:
            return "HTTP/TCP"
        if 22 in ports:
            return "SSH/TCP"
        return "TCP"

    if packet.haslayer(UDP):
        ports = (packet[UDP].sport, packet[UDP].dport)
        if 53 in ports:
            return "DNS/UDP"
        if 67 in ports or 68 in ports:
            return "DHCP/UDP"
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6/Other"
    if packet.haslayer(IP):
        return "IPv4/Other"

    return "Other"


def get_addresses(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst

    return "", ""


def get_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport

    return "", ""


def main():
    parser = argparse.ArgumentParser(
        description="Automated Network Packet Sniffer and Analyzer"
    )

    parser.add_argument("--iface", help="Network interface name")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--out", default="reports")

    args = parser.parse_args()

    if args.count < 1 or args.timeout < 1:
        parser.error("Count and timeout must be positive.")

    interfaces = get_if_list()

    if args.iface and args.iface not in interfaces:
        print("Available interfaces:")
        for interface in interfaces:
            print("-", interface)
        parser.error("Choose an interface from the list above.")

    os.makedirs(args.out, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    packet_file = os.path.join(
        args.out, f"packets_{stamp}.csv"
    )
    protocol_file = os.path.join(
        args.out, f"protocol_summary_{stamp}.csv"
    )
    source_file = os.path.join(
        args.out, f"source_summary_{stamp}.csv"
    )

    rows = []
    protocol_counts = Counter()
    source_counts = Counter()
    total_bytes = 0

    print("=" * 60)
    print("AUTOMATED NETWORK PACKET SNIFFER & ANALYZER")
    print("=" * 60)
    print("Interface:", args.iface or "Scapy default")
    print("Packet limit:", args.count)
    print("Timeout:", args.timeout, "seconds")
    print("Capturing metadata only. Press Ctrl+C to stop.")

    def process_packet(packet):
        nonlocal total_bytes

        src, dst = get_addresses(packet)
        sport, dport = get_ports(packet)
        protocol = identify_protocol(packet)
        packet_size = len(packet)

        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).isoformat(timespec="milliseconds")

        row = {
            "timestamp": timestamp,
            "source": src,
            "destination": dst,
            "protocol": protocol,
            "source_port": sport,
            "destination_port": dport,
            "packet_length_bytes": packet_size
        }

        rows.append(row)
        protocol_counts[protocol] += 1

        if src:
            source_counts[src] += 1

        total_bytes += packet_size

        print(
            f"{timestamp} | {protocol:<12} | "
            f"{src or '-'}:{sport or '-'} -> "
            f"{dst or '-'}:{dport or '-'} | "
            f"{packet_size} bytes"
        )

    try:
        sniff(
            iface=args.iface,
            prn=process_packet,
            store=False,
            count=args.count,
            timeout=args.timeout
        )

    except KeyboardInterrupt:
        print("\nCapture stopped.")

    except (PermissionError, OSError) as error:
        print("\nCapture error:", error)
        print("Check Npcap, interface name, and permissions.")
        return

    fields = [
        "timestamp", "source", "destination", "protocol",
        "source_port", "destination_port",
        "packet_length_bytes"
    ]

    with open(
        packet_file, "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with open(
        protocol_file, "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["protocol", "packet_count"])
        writer.writerows(protocol_counts.most_common())

    with open(
        source_file, "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["source_address", "packet_count"])
        writer.writerows(source_counts.most_common())

    print("\nCAPTURE SUMMARY")
    print("Packets captured:", len(rows))
    print("Total bytes:", total_bytes)
    print("Protocol counts:", dict(protocol_counts))
    print("Reports saved in:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
