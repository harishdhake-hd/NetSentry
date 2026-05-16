# NetSentry 🛡️

A lightweight, terminal-based **Network Intrusion Detection System** written in Python.

Monitors live traffic on a network interface and flags suspicious activity like port scans, SYN floods, SSH brute-force attempts, and ICMP floods — all in real time.

Built this as a learning project while studying network security. It's not a replacement for Snort or Suricata, but it works surprisingly well for a home lab and helped me understand how detection logic actually works at the packet level.

\---

## What it detects

|Threat|How|
|-|-|
|**Port Scan**|One IP touches 15+ distinct ports|
|**SYN Flood**|80+ SYN packets/sec from one source|
|**SSH Brute Force**|10+ rejected SSH connections in 30s|
|**ICMP Flood**|50+ ICMP packets/sec from one source|

\---

## Requirements

* Python 3.8+
* Linux (tested on Ubuntu 22.04 and Kali)
* `sudo` / root access (needed for raw packet capture)

```bash
pip install -r requirements.txt
```

\---

## Usage

```bash
# Basic — sniff on eth0
sudo python3 netsentry.py -i eth0

# Use a different interface (e.g. Wi-Fi)
sudo python3 netsentry.py -i wlan0

# Save alerts to a log file
sudo python3 netsentry.py -i eth0 --log

# Run for 60 seconds then stop
sudo python3 netsentry.py -i eth0 --timeout 60

# See all options
python3 netsentry.py --help
```

\---

## Sample output

```
  \[14:32:01] \[HIGH]     PORT\_SCAN      | src: 192.168.1.88  | 23 distinct ports probed
  \[14:32:04] \[CRITICAL] SYN\_FLOOD      | src: 10.0.0.5      | 94 SYN packets in 1s
  \[14:32:19] \[HIGH]     SSH\_BRUTE\_FORCE| src: 192.168.1.102 | 12 failed attempts in 30s
  --- packets: 8,400 | alerts: 3 ---
```

\---

## Project structure

```
NetSentry/
├── netsentry.py          # entry point
├── requirements.txt
├── modules/
│   ├── rules.py          # detection logic (thresholds here)
│   ├── logger.py         # writes alerts to file
│   └── display.py        # terminal colours and formatting
└── logs/
    └── alerts.log        # created when --log flag is used
```

\---

## Tweaking thresholds

All detection thresholds are at the top of `modules/rules.py`. If you're getting too many false positives or missing things, edit them there:

```python
PORT\_SCAN\_THRESHOLD  = 15   # unique ports before flagging
SYN\_FLOOD\_THRESHOLD  = 80   # SYN packets/sec
SSH\_BRUTE\_THRESHOLD  = 10   # failed SSH attempts
SSH\_BRUTE\_WINDOW     = 30   # seconds
ICMP\_FLOOD\_THRESHOLD = 50   # ICMP packets/sec
```

\---

\---

## Legal disclaimer

Only use this on networks you own or have permission to monitor. Sniffing traffic on networks you don't have authorisation for is illegal in most countries.

\---

## Author

**Harish Dhake** — BCA student at Modern College Ganeshkhind, Pune  
[GitHub](https://github.com/harishdhake) · [LinkedIn](https://linkedin.com/in/harishdhake) · [TryHackMe](https://tryhackme.com/p/harishdhake)

