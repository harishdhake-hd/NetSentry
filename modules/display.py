from datetime import datetime

RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
CYAN="\033[96m"; WHITE="\033[97m"; DIM="\033[2m"; RESET="\033[0m"; BOLD="\033[1m"

SEVERITY_COLOUR = {"CRITICAL":RED,"HIGH":YELLOW,"MEDIUM":CYAN,"LOW":DIM}

def print_banner():
    print(f"\n{CYAN}{BOLD}  NetSentry — Network Intrusion Detection System{RESET}")
    print(f"  {DIM}by Harish Dhake | github.com/harishdhake-hd/NetSentry{RESET}\n")

def print_alert(alert):
    ts = datetime.now().strftime("%H:%M:%S")
    color = SEVERITY_COLOUR.get(alert['severity'], WHITE)
    print(f"  {DIM}[{ts}]{RESET} {color}{BOLD}[{alert['severity']}]{RESET} "
          f"{WHITE}{alert['type']}{RESET} {DIM}|{RESET} "
          f"src: {CYAN}{alert['src_ip']}{RESET} {DIM}|{RESET} {alert['detail']}")

def print_status(packets, alerts):
    print(f"  {DIM}--- packets: {packets:,} | alerts: {alerts} ---{RESET}")
