#!/usr/bin/env python3
"""
Live Port Scan Detector for Windows
-----------------------------------
Real-time detection of Nmap/port-scan reconnaissance against THIS machine.

Backends:
  state  (default, no admin required) - polls the Windows TCP state table via
          Get-NetTCPConnection and watches for half-open (SYN_RECEIVED)
          connections - the classic TCP SYN scan fingerprint.
  pcap   (optional, needs Npcap + admin) - sniffs packets with scapy and also
          detects stealth flag anomalies (NULL/FIN/XMAS) and UDP sweeps.

Alerts are appended to alerts/live_alerts.jsonl and served over a local HTTP
feed so the web workbench dashboard can display them in real time.

Usage:
  python live/detector.py                    # state backend, default settings
  python live/detector.py --backend pcap     # packet sniffing (needs Npcap)
  python live/detector.py --demo             # inject fake scans for testing
  python live/detector.py --port 8090        # custom HTTP feed port
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ALERTS_DIR = BASE_DIR / "alerts"
ALERT_LOG = ALERTS_DIR / "live_alerts.jsonl"
DEFAULT_WHITELIST = BASE_DIR / "live" / "scanner_whitelist.csv"

POLL_INTERVAL = 5          # seconds between TCP state table polls
WINDOW_SECONDS = 120       # sliding window for cardinality counting
SYN_SWEEP_THRESHOLD = 25   # distinct destination ports => alert
COOLDOWN_SECONDS = 300     # don't re-alert same source within this time


class AlertFeed:
    """Thread-safe in-memory buffer + JSONL log for alerts & events."""

    def __init__(self):
        self.lock = threading.Lock()
        self.alerts = []
        self.events = []
        self.max_alerts = 200
        self.max_events = 500

    def add_alert(self, alert):
        alert["ts"] = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.alerts.insert(0, alert)
            self.alerts = self.alerts[: self.max_alerts]
        ALERTS_DIR.mkdir(exist_ok=True)
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
        print(f"[!] ALERT: {alert['rule']} src={alert['src_ip']} "
              f"distinct_ports={alert['distinct_ports']} risk={alert['risk_score']}")

    def add_event(self, event):
        event["ts"] = datetime.now(timezone.utc).isoformat()
        with self.lock:
            self.events.insert(0, event)
            self.events = self.events[: self.max_events]

    def snapshot(self, kind, limit=100):
        with self.lock:
            items = list(getattr(self, kind))[:limit]
        return items


class SlidingWindow:
    """Track distinct destination ports per source IP over a time window."""

    def __init__(self, window_seconds):
        self.window = window_seconds
        self.tracker = defaultdict(dict)  # src_ip -> {dst_port: last_seen_ts}

    def add(self, src_ip, dst_port, now):
        self.tracker[src_ip][dst_port] = now
        self._prune(now)

    def _prune(self, now):
        cutoff = now - self.window
        for src in list(self.tracker):
            ports = self.tracker[src]
            stale = [p for p, t in ports.items() if t < cutoff]
            for p in stale:
                del ports[p]
            if not ports:
                del self.tracker[src]

    def distinct_ports(self, src_ip):
        return len(self.tracker.get(src_ip, {}))

    def ports(self, src_ip):
        return sorted(self.tracker.get(src_ip, {}).keys())

    def sources(self):
        return list(self.tracker.keys())


class Cooldown:
    """Prevent duplicate alerts for the same source within a period."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.last = {}

    def is_blocked(self, src_ip, now):
        return now - self.last.get(src_ip, 0) < self.seconds

    def mark(self, src_ip, now):
        self.last[src_ip] = now


def load_whitelist(path):
    whitelist = set()
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ip = (row.get("ip") or "").strip()
                if ip:
                    whitelist.add(ip)
    except FileNotFoundError:
        pass
    # Always ignore loopback + link-local noise.
    whitelist.update({"127.0.0.1", "::1", "0.0.0.0", "::"})
    return whitelist


def read_tcp_state_table():
    """Return half-open SYN_RECEIVED connections via PowerShell (no admin)."""
    ps = (
        "Get-NetTCPConnection -State SynReceived -ErrorAction SilentlyContinue "
        "| Select-Object RemoteAddress, RemotePort, LocalAddress, LocalPort, State "
        "| ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        if isinstance(data, dict):
            data = [data]
        return [c for c in data if c.get("RemoteAddress") and c.get("LocalPort")]
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def get_local_ips():
    """Return set of this machine's IPv4 addresses (ignored as scan sources)."""
    try:
        ps = ("Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
              "| Select-Object -ExpandProperty IPAddress")
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=10,
        )
        return set(proc.stdout.split())
    except (subprocess.TimeoutExpired, OSError):
        return set()


def scan_state_backend(feed, window, whitelist, cooldown, poll_interval,
                       threshold, local_ips):
    print(f"[+] state backend: polling TCP state table every {poll_interval}s "
          f"(threshold {threshold} distinct ports / {WINDOW_SECONDS}s window)")
    while True:
        now = time.time()
        conns = read_tcp_state_table()
        for c in conns:
            src = c["RemoteAddress"]
            if src in whitelist or src in local_ips:
                continue
            dst_port = int(c["LocalPort"])
            window.add(src, dst_port, now)
            feed.add_event({
                "kind": "syn_received", "src_ip": src,
                "dst_port": dst_port, "local": c.get("LocalAddress"),
            })

        for src in window.sources():
            distinct = window.distinct_ports(src)
            if distinct >= threshold and not cooldown.is_blocked(src, now):
                cooldown.mark(src, now)
                feed.add_alert({
                    "backend": "state", "rule": "TCP SYN Sweep (half-open)",
                    "src_ip": src, "distinct_ports": distinct,
                    "targeted_ports": window.ports(src),
                    "severity": "HIGH",
                    "risk_score": 90 if distinct > 500 else (70 if distinct > 100 else 40),
                    "window_sec": WINDOW_SECONDS,
                    "remediation": "Block source at firewall; check OwningProcess "
                                   "for half-open connections; isolate host if internal.",
                })
        time.sleep(poll_interval)


def scan_pcap_backend(feed, window, whitelist, cooldown, threshold, local_ips):
    try:
        from scapy.all import sniff, IP, TCP, UDP, Raw
    except ImportError:
        sys.exit("scapy not installed. Run: python -m pip install scapy")

    STEALTH_RULES = [
        ("NULL Scan", {"flags": 0}),
        ("XMAS Scan (FIN+PSH+URG)", {"flags": 0x29}),
        ("FIN Scan (unsolicited)", {"flags": 0x01}),
    ]

    def process(pkt):
        now = time.time()
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src
        if src in whitelist or src in local_ips:
            return
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            dst_port = int(tcp.dport)
            if not tcp.flags.S and flags in (0, 0x01, 0x29):
                for rule, match in STEALTH_RULES:
                    if flags == match["flags"] and not cooldown.is_blocked(f"{src}:{rule}", now):
                        cooldown.mark(f"{src}:{rule}", now)
                        feed.add_alert({
                            "backend": "pcap", "rule": f"Stealth {rule}",
                            "src_ip": src, "dst_port": int(dst_port),
                            "tcp_flags_hex": f"0x{flags:02x}",
                            "severity": "HIGH", "risk_score": 90,
                            "remediation": "Near-zero benign usage; capture PCAP and "
                                           "hunt for follow-up exploitation.",
                        })
            if tcp.flags.S and not tcp.flags.A:  # raw SYN probe
                window.add(src, int(dst_port), now)
                feed.add_event({
                    "kind": "syn_probe", "src_ip": src, "dst_port": int(dst_port),
                    "tcp_flags_hex": f"0x{flags:02x}",
                })
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if int(udp.dport) not in (53, 123, 137, 1900, 5353):
                window.add(src, int(udp.dport), now)
                feed.add_event({
                    "kind": "udp_probe", "src_ip": src, "dst_port": int(udp.dport),
                })

        for src_ip in window.sources():
            distinct = window.distinct_ports(src_ip)
            if distinct >= threshold and not cooldown.is_blocked(src_ip, now):
                cooldown.mark(src_ip, now)
                feed.add_alert({
                    "backend": "pcap", "rule": "High-Volume Port Sweep",
                    "src_ip": src_ip, "distinct_ports": distinct,
                    "targeted_ports": window.ports(src_ip),
                    "severity": "HIGH",
                    "risk_score": 90 if distinct > 500 else (70 if distinct > 100 else 40),
                    "window_sec": WINDOW_SECONDS,
                    "remediation": "Confirm whether source is an authorized scanner; "
                                   "if not, block at the firewall and raise a ticket.",
                })

    print(f"[+] pcap backend: sniffing live traffic (needs Npcap). "
          f"Threshold {threshold} distinct ports / {WINDOW_SECONDS}s window")
    sniff(prn=process, store=False)


def demo_mode(feed, whitelist):
    print("[+] demo mode: injecting synthetic scan events every 2s for 15s...")
    attackers = [("10.0.0.77", "attacker"), ("10.0.0.50", "nessus")]
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 9443,
             1111, 2222, 3333, 4444, 5555]
    for i in range(15):
        for src, tag in attackers:
            port = ports[(i + (0 if tag == "attacker" else 3)) % len(ports)]
            feed.add_event({
                "kind": "syn_received", "src_ip": src, "dst_port": port,
                "local": "192.168.1.150", "demo": True,
            })
            if i >= 12 and src not in whitelist:
                feed.add_alert({
                    "backend": "state", "rule": "TCP SYN Sweep (half-open)",
                    "src_ip": src, "distinct_ports": len(ports) if tag == "attacker" else 25,
                    "targeted_ports": ports[:25],
                    "severity": "HIGH", "risk_score": 70,
                    "window_sec": WINDOW_SECONDS,
                    "remediation": "Demo alert - block source and investigate.",
                })
        time.sleep(2)
    print("[+] demo events done (feed continues serving; press Ctrl+C to exit)")


def run_feed_server(feed, port):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, data, code=200, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/alerts":
                self._send(json.dumps(feed.snapshot("alerts")).encode("utf-8"))
            elif self.path == "/events":
                self._send(json.dumps(feed.snapshot("events")).encode("utf-8"))
            elif self.path == "/stats":
                self._send(json.dumps({
                    "alerts": len(feed.snapshot("alerts")),
                    "events": len(feed.snapshot("events")),
                }).encode("utf-8"))
            elif self.path == "/health":
                self._send(b'{"status":"ok"}')
            else:
                self._send(b'{"error":"not found"}', code=404)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[+] alert feed serving at http://127.0.0.1:{port}  "
          f"(endpoints: /alerts /events /stats /health)")
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Live Port Scan Detector (Windows)")
    ap.add_argument("--backend", choices=["state", "pcap"], default="state")
    ap.add_argument("--port", type=int, default=8090, help="HTTP alert feed port")
    ap.add_argument("--threshold", type=int, default=SYN_SWEEP_THRESHOLD,
                    help="distinct destination ports required to alert")
    ap.add_argument("--whitelist", default=str(DEFAULT_WHITELIST),
                    help="path to scanner whitelist CSV (columns: ip, comment)")
    ap.add_argument("--poll", type=int, default=POLL_INTERVAL,
                    help="state-table poll interval in seconds")
    ap.add_argument("--demo", action="store_true",
                    help="inject synthetic scan events instead of live polling")
    args = ap.parse_args()

    feed = AlertFeed()
    window = SlidingWindow(WINDOW_SECONDS)
    cooldown = Cooldown(COOLDOWN_SECONDS)
    whitelist = load_whitelist(args.whitelist)
    local_ips = get_local_ips()
    print(f"[+] detector started  |  whitelist entries: {len(whitelist)}  "
          f"|  local IPs: {sorted(local_ips)}")
    print(f"[+] threshold: {args.threshold} distinct ports / {WINDOW_SECONDS}s window")

    if args.demo:
        threading.Thread(target=demo_mode, args=(feed, whitelist), daemon=True).start()
    elif args.backend == "state":
        threading.Thread(
            target=scan_state_backend,
            args=(feed, window, whitelist, cooldown, args.poll, args.threshold, local_ips),
            daemon=True).start()
    else:
        threading.Thread(
            target=scan_pcap_backend,
            args=(feed, window, whitelist, cooldown, args.threshold, local_ips),
            daemon=True).start()

    try:
        run_feed_server(feed, args.port)
    except KeyboardInterrupt:
        print("\n[+] detector stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
