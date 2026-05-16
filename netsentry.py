#!/usr/bin/env python3
"""
NetSentry - A simple network intrusion detection system
Written by Harish Dhake

Monitors live traffic and flags suspicious patterns like:
  - Port scans
  - SYN floods
  - SSH brute-force attempts
  - ICMP floods (ping floods)

Usage:
  sudo python3 netsentry.py -i eth0
  sudo python3 netsentry.py -i wlan0 --log
  sudo python3 netsentry.py --help

Note: Needs root/sudo to capture raw packets.
"""

import argparse
import time
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, ICMP, UDP
except ImportError:
    print("[!] Scapy not found. Run: pip install scapy")
    sys.exit(1)

from modules.rules import check_port_scan, check_syn_flood, check_ssh_brute, check_icmp_flood
from modules.logger import Logger
from modules.display import print_banner, print_alert, print_status


# ---------- State tracking ----------
# These dicts hold per-IP counters for detecting patterns
port_tracker   = defaultdict(set)      # src_ip -> set of dst ports
syn_tracker    = defaultdict(list)     # src_ip -> list of timestamps
ssh_tracker    = defaultdict(list)     # src_ip -> list of failed timestamps
icmp_tracker   = defaultdict(list)     # src_ip -> list of timestamps

alerted_ips    = set()                 # avoid spamming alerts for same IP
packet_count   = 0
alert_count    = 0

logger = None


def process_packet(pkt):
    global packet_count, alert_count

    # only care about IP packets
    if not pkt.haslayer(IP):
        return

    packet_count += 1
    src = pkt[IP].src
    now = time.time()

    alerts = []

    # --- TCP checks ---
    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        flags    = pkt[TCP].flags

        # track which ports this IP has touched
        port_tracker[src].add(dst_port)
        syn_tracker[src].append(now)

        # port scan check
        alert = check_port_scan(src, port_tracker[src])
        if alert:
            alerts.append(alert)

        # SYN flood check
        alert = check_syn_flood(src, flags, syn_tracker[src], now)
        if alert:
            alerts.append(alert)

        # SSH brute-force check (port 22 with RST/ACK = rejected login)
        if dst_port == 22 and flags in ("RA", "R"):
            ssh_tracker[src].append(now)
            alert = check_ssh_brute(src, ssh_tracker[src], now)
            if alert:
                alerts.append(alert)

    # --- ICMP checks ---
    if pkt.haslayer(ICMP):
        icmp_tracker[src].append(now)
        alert = check_icmp_flood(src, icmp_tracker[src], now)
        if alert:
            alerts.append(alert)

    # --- Fire alerts ---
    for alert in alerts:
        # only print each IP once per alert type to keep output clean
        key = f"{src}_{alert['type']}"
        if key not in alerted_ips:
            alerted_ips.add(key)
            alert_count += 1
            print_alert(alert)
            if logger:
                logger.log(alert)

    # print a live packet counter every 100 packets
    if packet_count % 100 == 0:
        print_status(packet_count, alert_count)


def main():
    global logger

    parser = argparse.ArgumentParser(
        description="NetSentry — lightweight network intrusion detection system"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Network interface to sniff on (default: eth0)"
    )
    parser.add_argument(
        "--log",
        action="store_true",
        help="Save alerts to logs/alerts.log"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Stop after N seconds (0 = run forever)"
    )
    args = parser.parse_args()

    print_banner()

    if args.log:
        logger = Logger("logs/alerts.log")
        print(f"  [*] Logging alerts to logs/alerts.log\n")

    print(f"  [*] Sniffing on interface: {args.interface}")
    print(f"  [*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  [*] Press Ctrl+C to stop\n")
    print("  " + "-" * 52)

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            store=False,  # don't keep packets in memory
            timeout=args.timeout if args.timeout > 0 else None
        )
    except PermissionError:
        print("\n[!] Permission denied. Try running with sudo.")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n  [*] Stopped. Packets captured: {packet_count} | Alerts fired: {alert_count}")
        if logger:
            logger.close()


if __name__ == "__main__":
    main()
