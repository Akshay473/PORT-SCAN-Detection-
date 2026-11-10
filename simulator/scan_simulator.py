#!/usr/bin/env python3
"""
Port Scan Log Generator & Simulator
-------------------------------------
Generates realistic security logs representing Nmap port scans (-sS, -sT, -sU, -sF, -sN, -sX, -sA, -sV)
and benign background traffic for testing Splunk, ELK Stack, and Suricata SIEM setups.

Author: Detection Engineering Lab
"""

import json
import time
import random
import argparse
from datetime import datetime, timezone

TARGET_IP = "192.168.1.150"
ATTACKER_IP = "10.0.0.77"
BENIGN_IPS = ["192.168.1.10", "192.168.1.25", "10.0.0.50"] # 10.0.0.50 is Nessus Scanner

SCAN_TYPES = {
    "syn": {"flags": "SYN", "flag_hex": "0x02", "desc": "TCP SYN Stealth Scan (-sS)"},
    "connect": {"flags": "SYN/ACK-RST", "flag_hex": "0x02", "desc": "TCP Connect Scan (-sT)"},
    "null": {"flags": "NONE", "flag_hex": "0x00", "desc": "Stealth NULL Scan (-sN)"},
    "fin": {"flags": "FIN", "flag_hex": "0x01", "desc": "Stealth FIN Scan (-sF)"},
    "xmas": {"flags": "FIN,PSH,URG", "flag_hex": "0x29", "desc": "Stealth Xmas Scan (-sX)"},
    "ack": {"flags": "ACK", "flag_hex": "0x10", "desc": "ACK Window Scan (-sA)"},
    "udp": {"flags": "UDP_PROBE", "flag_hex": "0x00", "desc": "UDP Port Sweep (-sU)"},
    "version": {"flags": "SYN", "flag_hex": "0x02", "desc": "Service Version Probes (-sV)"}
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

def generate_timestamp():
    return datetime.now(timezone.utc).isoformat()

def generate_suricata_event(src_ip, dest_ip, dest_port, scan_key):
    scan_info = SCAN_TYPES.get(scan_key, SCAN_TYPES["syn"])
    proto = "UDP" if scan_key == "udp" else "TCP"
    
    event = {
        "timestamp": generate_timestamp(),
        "event_type": "alert" if scan_key in ["null", "xmas", "fin"] else "flow",
        "src_ip": src_ip,
        "src_port": random.randint(32768, 61000),
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "tcp": {
            "tcp_flags": scan_info["flags"],
            "tcp_flags_hex": scan_info["flag_hex"],
            "syn": "SYN" in scan_info["flags"],
            "fin": "FIN" in scan_info["flags"],
            "psh": "PSH" in scan_info["flags"],
            "rst": "RST" in scan_info["flags"],
            "ack": "ACK" in scan_info["flags"],
            "urg": "URG" in scan_info["flags"]
        },
        "alert": {
            "action": "allowed" if src_ip in BENIGN_IPS else "blocked",
            "signature": f"Nmap Reconnaissance Activity ({scan_info['desc']})",
            "category": "Attempted Information Leak",
            "severity": 2 if scan_key in ["null", "xmas", "fin"] else 3
        }
    }
    if scan_key == "version" and dest_port in [80, 8080, 443]:
        event["http"] = {
            "hostname": dest_ip,
            "url": "/",
            "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
        }
    return event

def generate_iptables_log(src_ip, dest_ip, dest_port, scan_key):
    scan_info = SCAN_TYPES.get(scan_key, SCAN_TYPES["syn"])
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    proto = "UDP" if scan_key == "udp" else "TCP"
    src_port = random.randint(32768, 61000)
    flags = scan_info["flags"].replace(",", " ")
    return f"{ts} security-gateway kernel: [IPTABLES DROP] IN=eth0 OUT= SRC={src_ip} DST={dest_ip} LEN=40 TOS=0x00 TTL=64 PROTO={proto} SPT={src_port} DPT={dest_port} FLAGS={flags} WINDOW=1024"

def generate_splunk_ecs_json(src_ip, dest_ip, dest_port, scan_key):
    scan_info = SCAN_TYPES.get(scan_key, SCAN_TYPES["syn"])
    proto = "udp" if scan_key == "udp" else "tcp"
    return {
        "_time": generate_timestamp(),
        "event": {
            "action": "blocked" if src_ip == ATTACKER_IP else "allowed",
            "category": "network",
            "type": "connection",
            "outcome": "failure" if src_ip == ATTACKER_IP else "success"
        },
        "source": {"ip": src_ip, "port": random.randint(32768, 61000)},
        "destination": {"ip": dest_ip, "port": dest_port},
        "network": {"transport": proto, "tcp": {"flags": scan_info["flags"]}},
        "scan_type": scan_key,
        "scan_description": scan_info["desc"]
    }

def run_simulation(scan_type="syn", count=30, format_type="suricata", output_file=None, append=False):
    print(f"[+] Starting Port Scan Simulation...")
    print(f"[+] Attacker IP: {ATTACKER_IP} -> Target IP: {TARGET_IP}")
    print(f"[+] Scan Mode: {SCAN_TYPES.get(scan_type, {}).get('desc', scan_type)}")
    print(f"[+] Generating {count} scan events in '{format_type}' format...\n")

    events = []
    ports = random.sample(TOP_PORTS, min(count, len(TOP_PORTS)))
    if count > len(TOP_PORTS):
        ports += [random.randint(1024, 65535) for _ in range(count - len(TOP_PORTS))]

    # Interleave some benign traffic (Nessus scanner / web traffic) to test FP rules
    for i, port in enumerate(ports):
        # 1. Attacker Scan Event
        if format_type == "suricata":
            evt = generate_suricata_event(ATTACKER_IP, TARGET_IP, port, scan_type)
            events.append(json.dumps(evt))
        elif format_type == "syslog":
            events.append(generate_iptables_log(ATTACKER_IP, TARGET_IP, port, scan_type))
        elif format_type in ["splunk", "elastic"]:
            evt = generate_splunk_ecs_json(ATTACKER_IP, TARGET_IP, port, scan_type)
            events.append(json.dumps(evt))
        
        # 2. Add Benign Event every 5 ports (simulating background noise / authorized scanner)
        if i % 5 == 0:
            benign_src = random.choice(BENIGN_IPS)
            if format_type == "suricata":
                events.append(json.dumps(generate_suricata_event(benign_src, TARGET_IP, 80, "connect")))
            elif format_type == "syslog":
                events.append(generate_iptables_log(benign_src, TARGET_IP, 80, "connect"))
            elif format_type in ["splunk", "elastic"]:
                events.append(json.dumps(generate_splunk_ecs_json(benign_src, TARGET_IP, 80, "connect")))

    if output_file:
        with open(output_file, "a" if append else "w") as f:
            for item in events:
                f.write(item + "\n")
        print(f"[✔] Logs successfully saved to: {output_file}")
    else:
        for item in events[:10]:
            print(item)
        if len(events) > 10:
            print(f"... and {len(events) - 10} more log lines generated.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scan Log Generator & Simulator")
    parser.add_argument("--scan", choices=list(SCAN_TYPES.keys()) + ["all"], default="syn", help="Nmap scan type to simulate")
    parser.add_argument("--count", type=int, default=30, help="Number of ports to probe")
    parser.add_argument("--format", choices=["suricata", "syslog", "splunk", "elastic"], default="suricata", help="Output log format")
    parser.add_argument("--output", type=str, default=None, help="Output filename (e.g. eve.json or syslog.log)")
    
    args = parser.parse_args()
    
    if args.scan == "all":
        if args.output:
            open(args.output, "w").close()  # start a fresh combined file
        for st in SCAN_TYPES.keys():
            run_simulation(scan_type=st, count=args.count, format_type=args.format,
                           output_file=args.output, append=bool(args.output))
    else:
        run_simulation(scan_type=args.scan, count=args.count, format_type=args.format, output_file=args.output)
