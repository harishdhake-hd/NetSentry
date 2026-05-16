"""
modules/rules.py

Detection rules for NetSentry.
Each function returns an alert dict if the rule triggers, or None if it doesn't.

Thresholds are set to be practical for a home/lab environment.
Feel free to tweak them — too sensitive and you'll get flooded with
false positives, too loose and you'll miss real stuff.
"""

import time

# --- Thresholds ---
PORT_SCAN_THRESHOLD  = 15     # unique ports from one IP = likely scan
SYN_FLOOD_THRESHOLD  = 80     # SYN packets per second from one IP
SYN_FLOOD_WINDOW     = 1      # seconds to measure SYN rate over
SSH_BRUTE_THRESHOLD  = 10     # failed SSH attempts before alerting
SSH_BRUTE_WINDOW     = 30     # seconds
ICMP_FLOOD_THRESHOLD = 50     # ICMP packets per second
ICMP_FLOOD_WINDOW    = 1      # seconds


def check_port_scan(src_ip, ports_touched):
    """
    Simple port scan detection — if one IP has tried
    more than PORT_SCAN_THRESHOLD distinct ports, flag it.

    This catches both sequential scans (Nmap default) and
    random-order scans.
    """
    if len(ports_touched) >= PORT_SCAN_THRESHOLD:
        return {
            "type"    : "PORT_SCAN",
            "src_ip"  : src_ip,
            "detail"  : f"{len(ports_touched)} distinct ports probed",
            "severity": "HIGH",
        }
    return None


def check_syn_flood(src_ip, tcp_flags, timestamps, now):
    """
    SYN flood: lots of SYN packets in a short window from one source.
    Only triggered when the TCP flag is SYN (value 'S' in scapy).
    """
    if tcp_flags != "S":
        return None

    # keep only timestamps within the window
    recent = [t for t in timestamps if now - t <= SYN_FLOOD_WINDOW]

    if len(recent) >= SYN_FLOOD_THRESHOLD:
        return {
            "type"    : "SYN_FLOOD",
            "src_ip"  : src_ip,
            "detail"  : f"{len(recent)} SYN packets in {SYN_FLOOD_WINDOW}s",
            "severity": "CRITICAL",
        }
    return None


def check_ssh_brute(src_ip, timestamps, now):
    """
    SSH brute-force: count rejected SSH connections (RST/ACK from server
    back to src) within a time window. More than SSH_BRUTE_THRESHOLD = alert.

    Not a perfect heuristic — RST/ACK doesn't always mean wrong password,
    but it's a good signal for home-lab use.
    """
    recent = [t for t in timestamps if now - t <= SSH_BRUTE_WINDOW]

    if len(recent) >= SSH_BRUTE_THRESHOLD:
        return {
            "type"    : "SSH_BRUTE_FORCE",
            "src_ip"  : src_ip,
            "detail"  : f"{len(recent)} failed attempts in {SSH_BRUTE_WINDOW}s",
            "severity": "HIGH",
        }
    return None


def check_icmp_flood(src_ip, timestamps, now):
    """
    ICMP/ping flood detection. Simple rate check over a 1-second window.
    """
    recent = [t for t in timestamps if now - t <= ICMP_FLOOD_WINDOW]

    if len(recent) >= ICMP_FLOOD_THRESHOLD:
        return {
            "type"    : "ICMP_FLOOD",
            "src_ip"  : src_ip,
            "detail"  : f"{len(recent)} ICMP packets in {ICMP_FLOOD_WINDOW}s",
            "severity": "MEDIUM",
        }
    return None
