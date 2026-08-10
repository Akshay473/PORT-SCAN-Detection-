# Port Scan Detection Engineering Lab

[![Technology: Kali Linux](https://img.shields.io/badge/OS-Kali%20Linux-blue.svg)](https://www.kali.org/)
[![Tool: Nmap](https://img.shields.io/badge/Recon-Nmap-cyan.svg)](https://nmap.org/)
[![SIEM: Splunk](https://img.shields.io/badge/SIEM-Splunk%20SPL-orange.svg)](https://www.splunk.com/)
[![SIEM: Elastic](https://img.shields.io/badge/SIEM-Elastic%20EQL%2FKQL-green.svg)](https://www.elastic.co/)
[![IDS: Suricata](https://img.shields.io/badge/IDS-Suricata-red.svg)](https://suricata.io/)

A production-grade **Detection Engineering Lab** designed for security operations center (SOC) analysts, detection engineers, and security researchers to analyze Nmap network reconnaissance techniques, build high-fidelity SIEM detection rules (**Splunk SPL** and **ELK / Elastic EQL/KQL**), and implement proven **False Positive (FP) reduction strategies**.

---

## 🚀 Quick Start

### 1. Launch the Interactive Web Workbench
Run the local web server to access the visual lab interface, scan mechanics visualizer, SIEM query workbench, and false positive calculator:

```bash
cd port-scan-detection-lab
python -m http.server 8080
```
Open **`http://localhost:8080`** in your browser.

### 2. Generate Synthetic Security Logs
Use the included Python simulator to produce realistic Suricata `eve.json`, Linux `iptables`, Splunk ECS, or Elastic Security logs:

```bash
# Generate sample Suricata JSON logs for all Nmap scan types
python simulator/scan_simulator.py --scan all --count 30 --format suricata --output eve_sample.json

# Generate Linux kernel iptables syslog entries for TCP SYN scans
python simulator/scan_simulator.py --scan syn --count 50 --format syslog --output iptables.log
```

---

## 🎯 Supported Nmap Scan Types & Mechanics

| Scan Technique | Nmap Command | Flag Mechanics / Header State | Detection Telemetry & Signature |
| :--- | :--- | :--- | :--- |
| **TCP SYN Stealth** | `nmap -sS -p 1-1000 <target>` | Sends `SYN`. Half-open teardown with `RST` upon receiving `SYN/ACK`. | High cardinality of dropped connection attempts (`dc(dest_port) > 25`). |
| **TCP Connect** | `nmap -sT -p 1-1000 <target>` | Full 3-way TCP handshake (`SYN` -> `SYN/ACK` -> `ACK`) via OS socket API. | OS socket creation telemetry & Web/App access logs. |
| **Stealth NULL Scan** | `nmap -sN <target>` | **Zero flags set** (`flags=0x00`). Violates RFC 793 specifications. | Suricata IDS signature `flags:0`. High-confidence IOC. |
| **Stealth FIN Scan** | `nmap -sF <target>` | **Only FIN set** (`flags=0x01`) without prior established session state. | Suricata IDS signature `flags:F` outside state table. |
| **Stealth Xmas Scan** | `nmap -sX <target>` | **FIN, PSH, & URG set** ("lit up like a Xmas tree", `flags=0x29`). | Suricata IDS signature `flags:FPU`. Zero benign FP usage. |
| **TCP ACK Scan** | `nmap -sA -p 1-500 <target>` | Sends unsolicited `ACK` to evaluate firewall rule filtering state. | Unsolicited `ACK` packets dropped by firewall state table. |
| **UDP Port Sweep** | `nmap -sU --top-ports 50 <target>` | Sends empty UDP headers; relies on target returning `ICMP Port Unreachable`. | Firewall ICMP Type 3 Code 3 responses + UDP port cardinality. |
| **Service Version Probing** | `nmap -sV -O <target>` | Sends protocol banner probes & payload requests to open ports. | HTTP requests containing `User-Agent: Nmap Scripting Engine`. |

---

## 🛡️ False Positive (FP) Reduction Framework

High-volume reconnaissance detection rule baselines often create severe alert fatigue due to benign network activity. This lab incorporates a multi-tiered tuning methodology:

```
[ Raw Network Connection Telemetry ]
                │
                ▼
  [ 1. Scanner Whitelist Lookup ] ──► Exclude authorized Nessus/Qualys/Rapid7 IPs
                │
                ▼
  [ 2. Cardinality Filter ] ───────► Require >= 25 distinct destination ports in 2m window
                │
                ▼
  [ 3. Noise Protocol Filter ] ────► Exclude UDP broadcast noise (DNS:53, NTP:123, mDNS:5353)
                │
                ▼
[ High-Fidelity Alert Triggered ] (Reduction Rate: ~99.78%)
```

---

## 🔍 SIEM Detection Rule Highlights

### Splunk SPL Example (Accelerated `tstats` + FP Lookup Exclusion)
```spl
| tstats summariesonly=true count dc(All_Traffic.dest_port) as distinct_ports values(All_Traffic.dest_port) as targeted_ports 
    from datamodel=Network_Traffic.All_Traffic 
    where All_Traffic.action="blocked" OR All_Traffic.action="dropped"
    by _time span=2m All_Traffic.src All_Traffic.dest All_Traffic.transport
| rename All_Traffic.src as src_ip, All_Traffic.dest as dest_ip, All_Traffic.transport as protocol
| filter distinct_ports >= 25
| lookup scanner_whitelist.csv ip as src_ip OUTPUT is_authorized_scanner
| search is_authorized_scanner!="true"
| eval risk_score=case(distinct_ports > 500, 90, distinct_ports > 100, 70, true(), 40)
| table _time, src_ip, dest_ip, protocol, distinct_ports, targeted_ports, risk_score
```

### Elastic Security EQL Example (Stealth TCP Flag Anomaly Sequence)
```eql
network where event.category == "network" and network.transport == "tcp" and (
  tcp.flags == "0x00" or tcp.flags == "0" or
  tcp.flags == "0x29" or tcp.flags == "FPU" or
  (tcp.flags == "0x01" and not event.dataset == "zeek.conn")
) and not (destination.port == 80 or destination.port == 443)
```

---

## 📁 Repository Structure

```
port-scan-detection-lab/
├── README.md                  # Main Project Overview & Documentation
├── index.html                 # Interactive Web Workbench & GUI Dashboard
├── style.css                  # Modern Cybersecurity Dark Theme Stylesheet
├── app.js                     # Workbench Logic, Visualizers & Live Terminal Streamer
├── simulator/
│   └── scan_simulator.py      # Python Log Generator for Nmap Scans & Noise
├── rules/
│   ├── splunk_queries.spl     # Production Splunk SPL Detections & RBA Queries
│   ├── elastic_rules.eql      # Elastic EQL Sequences & Kibana Detection JSON
│   ├── sigma_rules.yml        # Portable Vendor-Neutral Sigma Rules
│   └── suricata_rules.rules   # Suricata IDS Signatures for Flag Anomalies
└── docs/
    └── LAB_GUIDE.md           # Step-by-Step Lab Setup Manual & Kali Commands
```

---

## 📖 Lab Setup Manual

For detailed instructions on configuring Kali Linux, deploying Suricata IDS, installing Splunk/ELK forwarders, and conducting validation exercises, refer to **[`docs/LAB_GUIDE.md`](docs/LAB_GUIDE.md)**.

---

## 📜 License
This project is open-source and intended solely for educational, research, and defensive detection engineering purposes.
