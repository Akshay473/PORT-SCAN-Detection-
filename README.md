# 🛡️ Port Scan Detection Engineering Lab

[![Technology: Kali Linux](https://img.shields.io/badge/OS-Kali%20Linux-blue.svg)](https://www.kali.org/)
[![Tool: Nmap](https://img.shields.io/badge/Recon-Nmap-cyan.svg)](https://nmap.org/)
[![SIEM: Splunk](https://img.shields.io/badge/SIEM-Splunk%20SPL-orange.svg)](https://www.splunk.com/)
[![SIEM: Elastic](https://img.shields.io/badge/SIEM-Elastic%20EQL%2FKQL-green.svg)](https://www.elastic.co/)
[![IDS: Suricata](https://img.shields.io/badge/IDS-Suricata-red.svg)](https://suricata.io/)
[![Standard: Sigma](https://img.shields.io/badge/Standard-Sigma%20YAML-purple.svg)](https://sigmahq.io/)
[![MITRE: ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20T1046-darkred.svg)](https://attack.mitre.org/techniques/T1046/)

A production-grade **Detection Engineering Lab** for **SOC analysts**, **detection engineers**, and **security researchers**. It models real **Nmap network reconnaissance** against a target host, generates realistic security logs, and demonstrates how to build high-fidelity **SIEM detection rules** (Splunk SPL, Elastic EQL/KQL, Sigma) plus **Suricata IDS signatures** — all while applying proven **False Positive (FP) reduction** techniques used in real security operations centers.

---

## 🧭 Table of Contents

- [Real-Life Scenario: Why This Lab Matters](#-real-life-scenario-why-this-lab-matters)
- [What's Inside](#-whats-inside)
- [Technology Stack & Tools](#-technology-stack--tools)
- [Detection Engineering Keywords (Glossary)](#-detection-engineering-keywords-glossary)
- [Supported Nmap Scan Types & Mechanics](#-supported-nmap-scan-types--mechanics)
- [Quick Start](#-quick-start)
- [Log Simulator Reference (`scan_simulator.py`)](#-log-simulator-reference-scan_simulatorpy)
- [SIEM Detection Rule Highlights](#-siem-detection-rule-highlights)
- [False Positive (FP) Reduction Framework](#-false-positive-fp-reduction-framework)
- [End-to-End Detection Playbook (Practical Walkthrough)](#-end-to-end-detection-playbook-practical-walkthrough)
- [Repository Structure](#-repository-structure)
- [Lab Setup Manual](#-lab-setup-manual)
- [License](#-license)

---

## 🎬 Real-Life Scenario: Why This Lab Matters

> **The Situation (Daily SOC reality):**
> A Splunk **dashboard** shows **1,420 blocked-connection alerts in one day**. An analyst opens the queue and sees hundreds of "possible port scan" tickets — most of them are *false*. Why?
> - A **Nessus vulnerability scanner** (`10.0.0.50`) performs an authorized full-range sweep **every night**.
> - Office **DNS (53), NTP (123), mDNS (5353)** clients burst hundreds of UDP packets.
> - A web frontend opens many **ephemeral TCP connections** to load a dynamic page.

> **The Incident (What you must catch):**
> An attacker on `10.0.0.77` runs `nmap -sS -p 1-1000` against your web server `192.168.1.150`, then follows up with stealth `-sX` (Xmas) and `-sN` (NULL) probes to map filtered open ports for exploitation. **A basic alert rule fires — but so does every benign sweep above.** The attackers' alerts drown in noise.

> **The Outcome this Lab teaches:**
> Curate the noise, keep the signal. Apply **scanner whitelisting → cardinality filtering → infra-port suppression → FIN teardown filtering** to cut **1,420 alerts to exactly 3 true positives** (a **~99.78% reduction**), then surface them via **Risk-Based Alerting** for triage. That is *tuning a detection*, not just writing a query.

This entire journey — **reconnaissance mechanics → log generation → SIEM rule → FP tuning → validation** — is reproducible in this repository.

---

## 📦 What's Inside

| Component | Purpose |
| :--- | :--- |
| **Interactive Web Workbench** (`index.html`, `app.js`, `style.css`) | Visualize TCP flag mechanics, generate live SIEM queries, run an FP reduction calculator, and stream simulated logs — all in the browser. |
| **Log Simulator** (`simulator/scan_simulator.py`) | Python CLI that generates realistic **Suricata eve.json**, **iptables syslog**, **Splunk ECS**, and **Elastic Security** logs for 8 Nmap scan techniques + benign noise. |
| **Splunk Rules** (`rules/splunk_queries.spl`) | 5 production SPL detections incl. accelerated `tstats`, RBA correlation, and lookup-based scanner exclusion. |
| **Elastic Rules** (`rules/elastic_rules.eql`) | EQL sequences for sweeps and stealth flag anomalies + KQL threshold queries + a ready-to-import Kibana threshold rule JSON. |
| **Sigma Rules** (`rules/sigma_rules.yml`) | Vendor-neutral portable detections (Sigma) with MITRE ATT&CK mapping. |
| **Suricata Signatures** (`rules/suricata_rules.rules`) | IDS rules with `flags:` matching and `threshold` tracking for NULL/XMAS/FIN/SYN sweeps. |
| **Lab Manual** (`docs/LAB_GUIDE.md`) | Full lab setup: Kali + Nmap, Suricata, Splunk/ELK ingestion, and validation exercises. |

---

## 🛠️ Technology Stack & Tools

| Tool / Technology | Role in the Lab | Where It Appears |
| :--- | :--- | :--- |
| **Kali Linux** | Attacker host running Nmap (e.g. `10.0.0.77`) | Lab guide, simulations, IP constants |
| **Nmap** | Reconnaissance framework (`-sS -sT -sN -sF -sX -sA -sU -sV -O`) | Every scan card, signature, simulator |
| **Suricata IDS** | Network sensor emitting `eve.json` alerts (`flags:`, `threshold:`) | `rules/suricata_rules.rules`, simulator |
| **Snort (compatible)** | Source of `flags:`/`flow:` signature syntax lineage | Suricata rule comments |
| **Splunk Enterprise / ES** | SIEM with SPL, `tstats`, Data Models, Risk-Based Alerting | `rules/splunk_queries.spl`, `app.js` |
| **Splunk Add-on for Unix/Linux** | Indexing `iptables` syslog as `syslog:iptables` | `docs/LAB_GUIDE.md` |
| **Elastic Security / ELK** | SIEM with EQL/KQL, Kibana Threshold Engine, Elastic Agent/Filebeat | `rules/elastic_rules.eql`, `app.js` |
| **Filebeat** | Shipper enabling `suricata` and `iptables` modules | Lab guide, `index.html` |
| **Sigma** | Vendor-neutral rule format for detection portability | `rules/sigma_rules.yml` |
| **MITRE ATT&CK** | Threat framework; **T1046 (Network Service Scanning)** mapping | Sigma tags, Kibana JSON tags |
| **Python 3** | Runs the log simulator CLI | `simulator/scan_simulator.py` |
| **iptables / netfilter** | Linux firewall whose drop logs (`[IPTABLES DROP]`) feed firewalls | Simulator, SPL rule 4 |
| **Palo Alto / Check Point (NGFW)** | Firewall telemetry sources supported by SPL rule 2 (`paloalto:traffic`) | `rules/splunk_queries.spl` |
| **Zeek** | Referenced exclusion context for FIN false positives (`event.dataset == "zeek.conn"`) | `rules/elastic_rules.eql` |

---

## 📚 Detection Engineering Keywords (Glossary)

| Keyword | Meaning in this Lab |
| :--- | :--- |
| **Detection Engineering** | The discipline of writing, testing, and tuning repeatable signals that detect malicious behavior. |
| **SOC (Security Operations Center)** | The analyst team this lab is designed to support. |
| **Reconnaissance** | Phase 1 of the attack lifecycle — surveying hosts/ports before exploitation. |
| **Port Scan / Sweep** | Probing many ports on one host (`nmap -sS -p 1-1000`). |
| **Stealth Scan** | Flag-anomaly techniques (NULL/FIN/XMAS) designed to evade stateless sensors. |
| **Half-open connection** | SYN sent, SYN/ACK received, RST instead of ACK — the `-sS` fingerprint. |
| **RFC 793** | TCP spec violated by NULL/FIN/XMAS flag combinations. |
| **TCP Flags** | URG/ACK/PSH/RST/SYN/FIN bits; hex encodings `0x00`, `0x01`, `0x29`, `0x10`, `0x02`. |
| **Cardinality** | Count of *distinct* values — `dc(dest_port)` is the core sweep metric. |
| **False Positive (FP)** | Benign activity flagged as an attack; the primary tuning target. |
| **True Positive (TP)** | Actual attacker behavior correctly alerted on. |
| **Alert Fatigue** | Analyst desensitization caused by excessive FPs. |
| **Scanner Whitelist** | Lookup table (`scanner_whitelist.csv`) excluding approved Nessus/Qualys/Rapid7 IPs. |
| **Risk-Based Alerting (RBA)** | Splunk ES correlation of weighted signals into one notable event. |
| **SPL (Search Processing Language)** | Splunk query language (`tstats`, `lookup`, `eval`, `mvfilter`). |
| **EQL (Event Query Language)** | Elastic's sequence/correlation language. |
| **KQL (Kibana Query Language)** | Elastic's search syntax. |
| **ECS (Elastic Common Schema)** | Normalized field naming (`source.ip`, `destination.port`). |
| **Sigma** | Vendor-neutral detection rule YAML standard. |
| **IDS Signature** | Suricata/Snort rule matching packet flags and payload content. |
| **IOC** | Indicator of Compromise — e.g. NULL-flag packets are high-fidelity IOCs. |
| **Sliding Window** | Time bucket (`2m`, `5m`, `1h`) used to aggregate scan velocity. |
| **Suricata `threshold`** | Rate detection: *count* of events per *seconds* per *track by_src*. |
| **MITRE ATT&CK T1046** | "Network Service Scanning" technique. |
| **NSE (Nmap Scripting Engine)** | User-Agent-based service probing detection vector. |
| **ICMP Type 3 Code 3** | "Port Unreachable" used by `-sU` scans, and by Nmap to find closed UDP ports. |
| **Velocity** | Ports-per-minute metric for low-and-slow detection. |

---

## 🎯 Supported Nmap Scan Types & Mechanics

| Scan Technique | Nmap Command | Flag Mechanics / Header State | Detection Telemetry & Signature |
| :--- | :--- | :--- | :--- |
| **TCP SYN Stealth** | `nmap -sS -p 1-1000 <target>` | Sends `SYN`. Half-open teardown with `RST` upon receiving `SYN/ACK`. | High cardinality of dropped attempts (`dc(dest_port) > 25`). Suricata `flags:S,12` + `threshold: count 30, seconds 10`. |
| **TCP Connect** | `nmap -sT -p 1-1000 <target>` | Full 3-way handshake (`SYN` → `SYN/ACK` → `ACK`) via OS socket API. | OS socket creation & web/application access logs. |
| **Stealth NULL Scan** | `nmap -sN <target>` | **Zero flags set** (`flags=0x00`) — RFC 793 violation. | Suricata `flags:0`. High-confidence IOC. |
| **Stealth FIN Scan** | `nmap -sF <target>` | **Only FIN set** (`flags=0x01`) without established session state. | Suricata `flags:F,12` outside state table. |
| **Stealth Xmas Scan** | `nmap -sX <target>` | **FIN, PSH, & URG set** ("lit up like a Xmas tree", `flags=0x29`). | Suricata `flags:FPU`. ~Zero benign usage. |
| **TCP ACK Scan** | `nmap -sA -p 1-500 <target>` | Unsolicited `ACK` (`flags=0x10`) to map firewall filtering state. | Dropped/denied ACK events by firewall state table. |
| **UDP Port Sweep** | `nmap -sU --top-ports 50 <target>` | Empty UDP headers; relies on **ICMP Type 3 Code 3 (Port Unreachable)** responses. | ICMP unreachable drops + UDP port cardinality. |
| **Service / OS Probing** | `nmap -sV -O -A <target>` | Banner probes & payload requests to open ports. | HTTP logs with `User-Agent: Nmap Scripting Engine`. |

---

## 🚀 Quick Start

### 1. Launch the Interactive Web Workbench
Run the local web server to access the visual lab interface, scan mechanics visualizer, SIEM query workbench (live Splunk SPL / Elastic EQL code generation), and FP reduction calculator:

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

# Generate Elastic Security ECS network events for Xmas stealth scans
python simulator/scan_simulator.py --scan xmas --count 25 --format elastic --output es_xmas_events.json
```

### 3. Feed the Logs Into Your SIEM
- **Splunk:** Add Data → upload `eve_sample.json` with `sourcetype=suricata:eve` → run Rule 1 from `rules/splunk_queries.spl`.
- **Elastic:** Ingest via Filebeat and create a threshold rule from `rules/elastic_rules.eql` (KQL Query 1) or import the provided Kibana rule JSON.

---

## 🧪 Log Simulator Reference (`scan_simulator.py`)

A Python 3 CLI that interleaves **attacker events** (`10.0.0.77 → 192.168.1.150`) with **benign/hostile-noise events** (web client, Nessus scanner `10.0.0.50`) every 5 ports — purpose-built to test your FP filters.

| Argument | Values | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--scan` | `syn`, `connect`, `null`, `fin`, `xmas`, `ack`, `udp`, `version`, `all` | `syn` | Nmap scan pattern to emulate. |
| `--count` | integer | `30` | Number of destination ports probed. |
| `--format` | `suricata`, `syslog`, `splunk`, `elastic` | `suricata` | Output log dialect. |
| `--output` | filename | stdout preview | Write events to a file (e.g. `eve.json`, `iptables.log`). |

**Example — right-click quality check:**
```bash
python simulator/scan_simulator.py --scan null --count 20 --format suricata
```
Preview the first 10 lines directly in your terminal, then validate that a NULL scan (`flags: NONE`, `tcp_flags_hex: 0x00`) triggers Suricata signature `sid:1000001`.

---

## 🔍 SIEM Detection Rule Highlights

### Splunk SPL: High-Volume TCP SYN/Connect Sweep (Accelerated `tstats`)
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

### Elastic Security EQL: Stealth TCP Flag Anomaly Sequence
```eql
network where event.category == "network" and network.transport == "tcp" and (
  tcp.flags == "0x00" or tcp.flags == "0" or
  tcp.flags == "0x29" or tcp.flags == "FPU" or
  (tcp.flags == "0x01" and not event.dataset == "zeek.conn")
) and not (destination.port == 80 or destination.port == 443)
```

### Sigma: Vendor-Neutral (portable to Splunk, Elastic, QRadar…)
```yaml
detection:
    selection_flags_null:
        tcp_flags: ['0x00', '0']
    selection_flags_xmas:
        tcp_flags: ['0x29', 'FPU']
    selection_flags_fin:
        tcp_flags: ['0x01', 'F']
    filter_authorized_scanners:
        src_ip: ['10.0.0.50', '192.168.1.200']
    condition: (1 of selection_flags_*) and not filter_authorized_scanners
level: high
```

### Suricata IDS: Xmas Scan Signature (rate-limited)
```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap XMAS Scan Detected (FIN+PSH+URG)"; flags:FPU; threshold: type threshold, track by_src, count 5, seconds 60; reference:url,nmap.org/book/scan-methods-xmas-scan.html; classtype:attempted-recon; sid:1000002; rev:1;)
```

> The full suites live in `rules/` — **5 Splunk detections** (incl. low-and-slow, UDP sweep, RBA), **2 EQL + 2 KQL + 1 Kibana JSON**, **2 Sigma rules**, and **5 Suricata signatures**.

---

## 🛡️ False Positive (FP) Reduction Framework

High-volume recon baselines create severe alert fatigue from benign activity. This lab applies a multi-tiered tuning pipeline:

```
[ Raw Network Connection Telemetry ]
                │
                ▼
  [ 1. Scanner Whitelist Lookup ] ──► Exclude authorized Nessus/Qualys/Rapid7 IPs (scanner_whitelist.csv)
                │
                ▼
  [ 2. Cardinality Filter ] ────────► Require >= 25 distinct dest ports in a 2m window (dc(dest_port))
                │
                ▼
  [ 3. Noise Protocol Filter ] ─────► Exclude UDP broadcast noise (DNS:53, NTP:123, NetBIOS:137, SSDP:1900, mDNS:5353)
                │
                ▼
  [ 4. TCP Teardown Filter ] ───────► Suppress FIN-only packets toward open Web/SSL ports (80/443)
                │
                ▼
[ High-Fidelity Alert Triggered ]  (Reduction Rate: ~99.78%)
```

**Real-life example of each layer:**
1. **Whitelist** — Nessus runs nightly from `10.0.0.50`; the lookup suppresses ~950 alerts/day while real attacker `10.0.0.77` still triggers.
2. **Cardinality** — a web page fetches assets across *one* domain but *many* connections: still 1 distinct port → filtered; a sweep hits 100+ distinct ports → alerted.
3. **Noise Protocol** — NTP bursts to `123` are stripped by `mvfilter(not match(...))` before counting (~260 alerts/day suppressed).
4. **Teardown** — asymmetric FIN to port 80/443 from normal web clients is ignored; FIN sweeps across range ports still fire.

Try it live in the **False Positive Reduction Matrix** tab of the workbench.

---

## 📋 End-to-End Detection Playbook (Practical Walkthrough)

**Goal:** Detect `10.0.0.77` reconnaissance without drowning in Nessus/web noise.

1. **Recon (attacker):** `nmap -sS -p 1-1000 192.168.1.150` then `nmap -sX 192.168.1.150`.
2. **Generate telemetry:** 
   ```bash
   python simulator/scan_simulator.py --scan all --count 40 --format suricata --output eve.json
   ```
3. **Ingest:** Point Splunk `inputs.conf` at `/var/log/suricata/eve.json` (`index=ids`); point Filebeat at the `suricata` module for Elastic.
4. **Run Rule 1 (Sweep):** the `tstats` query flags `10.0.0.77 → 192.168.1.150` with `distinct_ports > 25`.
5. **Run Rule 2 (Stealth):** confirm `-sX` packet `FPU` (0x29) fires the flag-anomaly search with `severity="HIGH"`.
6. **Tune:** verify `10.0.0.50` (Nessus) is *suppressed* by the whitelist lookup while **Rule 5 (RBA)** aggregates the attacker's risk to `>= 100`.
7. **Correlate in Suricata:** load `rules/suricata_rules.rules` and confirm `sid:1000001-1000005` alert with `threshold` tracking.
8. **Report:** produce an incident ticket with the `targeted_ports` list, `risk_score`, scan velocity, and the FP-reduction stats.

---

## 📁 Repository Structure

```
port-scan-detection-lab/
├── README.md                  # Main Project Overview & Documentation (this file)
├── index.html                 # Interactive Web Workbench & GUI Dashboard
├── style.css                  # Modern Cybersecurity Dark Theme Stylesheet
├── app.js                     # Workbench Logic, Visualizers & Live Terminal Streamer
├── simulator/
│   └── scan_simulator.py      # Python Log Generator for Nmap Scans & Noise
├── rules/
│   ├── splunk_queries.spl     # Production Splunk SPL Detections & RBA Queries
│   ├── elastic_rules.eql      # Elastic EQL Sequences, KQL Queries & Kibana Detection JSON
│   ├── sigma_rules.yml        # Portable Vendor-Neutral Sigma Rules
│   └── suricata_rules.rules   # Suricata IDS Signatures for Flag Anomalies
└── docs/
    └── LAB_GUIDE.md           # Step-by-Step Lab Setup Manual & Kali Commands
```

---

## 📖 Lab Setup Manual

For detailed instructions on configuring **Kali Linux**, deploying **Suricata IDS**, installing **Splunk/ELK forwarders**, writing `inputs.conf` / Filebeat modules, and running validation exercises, refer to **[`docs/LAB_GUIDE.md`](docs/LAB_GUIDE.md)**.

---

## 📜 License
This project is open-source and intended solely for **educational, research, and defensive detection engineering** purposes. Always run scans and detections within authorized lab environments you own.