# 🛠️ Port Scan Detection Engineering Lab Manual

Welcome to the **Port Scan Detection Engineering Lab** manual. This guide walks you through building a complete detection engineering lab using **Kali Linux**, **Nmap**, **Suricata IDS**, and modern SIEM platforms (**Splunk Enterprise** and **ELK / Elastic Security**) — with real-life walkthroughs of each detection scenario.

---

## 📚 Table of Contents

1. [Lab Architecture & Topology](#1-lab-architecture--topology)
2. [Tools You'll Use](#2-tools-youll-use)
3. [Nmap Execution Matrix on Kali Linux](#3-nmap-execution-matrix-on-kali-linux)
4. [SIEM Ingestion Setup](#4-siem-ingestion-setup)
5. [False Positive (FP) Reduction Strategy](#5-false-positive-fp-reduction-strategy)
6. [Practical Lab Exercises](#6-practical-lab-exercises)
7. [Real-Life Scenario Walkthroughs](#7-real-life-scenario-walkthroughs)
8. [Validation & Verification Checklist](#8-validation--verification-checklist)

---

## 1. Lab Architecture & Topology

```
+-------------------+                  +-------------------------+
|  Attacker Host    |  Nmap Scans      |   Target System / GW    |
|   (Kali Linux)    | -------------->  |  (Ubuntu / Linux / Win) |
|   10.0.0.77       |                  |      192.168.1.150      |
+-------------------+                  +-------------------------+
                                                    |
                                            Suricata IDS / Syslog /
                                            Splunk Forwarder / Filebeat
                                                    |
                                                    v
                                       +-------------------------+
                                       |      SIEM Platform      |
                                       |     (Splunk / ELK)      |
                                       |  Detection & Alerting   |
                                       +-------------------------+
```

**Key hosts & roles**

| Host | IP | Role |
| :--- | :--- | :--- |
| Kali Linux (Attacker) | `10.0.0.77` | Runs `nmap` reconnaissance |
| Nessus Scanner (Authorized) | `10.0.0.50` | Legitimate vulnerability scanner (FP test case) |
| Web Client (Benign) | `192.168.1.10`, `192.168.1.25` | Normal traffic (FP test case) |
| Target Server | `192.168.1.150` | Runs web/SSH/SMB services under test |

---

## 2. Tools You'll Use

| Tool | Purpose | Setup Hint |
| :--- | :--- | :--- |
| **Kali Linux** | Attacker platform | `sudo apt update && sudo apt install -y nmap` |
| **Nmap** | Scan engine | Preinstalled on Kali |
| **Suricata** | IDS sensor | `sudo apt install suricata`; drop rules in `/etc/suricata/rules/local.rules` |
| **Splunk Enterprise / Free** | SIEM | Monitor `/var/log/suricata/eve.json` + `iptables.log` |
| **ELK / Elastic Security** | SIEM | Filebeat `suricata` + `iptables` modules |
| **Python 3** | Log simulator | `python simulator/scan_simulator.py` |

---

## 3. Nmap Execution Matrix on Kali Linux

Log into your Kali machine (`10.0.0.77`) and run these scans against the target IP (`192.168.1.150`):

| Scan Technique | Nmap Command | Flag Mechanics & Packet Structure | Detection Method |
| :--- | :--- | :--- | :--- |
| **TCP SYN Scan (Stealth)** | `nmap -sS -p 1-1000 192.168.1.150` | `SYN` packet; half-open teardown with `RST` on `SYN/ACK`. | Threshold on `action=blocked` distinct ports > 25 (`dc(dest_port)`). |
| **TCP Connect Scan** | `nmap -sT -p 1-1000 192.168.1.150` | Full 3-way handshake (`SYN` → `SYN/ACK` → `ACK`). | High-volume OS socket creation / application logs. |
| **UDP Scan** | `nmap -sU --top-ports 50 192.168.1.150` | Empty UDP headers; closed ports answer `ICMP Port Unreachable` (type 3 code 3). | Firewall ICMP-unreachable drops + UDP port cardinality. |
| **Stealth NULL Scan** | `nmap -sN 192.168.1.150` | **No TCP flags set** (`flags=0x00`) — RFC 793 violation. | Suricata signature `flags:0` (sid:1000001). |
| **Stealth FIN Scan** | `nmap -sF 192.168.1.150` | **Only FIN set** (`flags=0x01`). | IDS signature `flags:F,12` (sid:1000003). |
| **Stealth Xmas Scan** | `nmap -sX 192.168.1.150` | **FIN + PSH + URG** (`0x29`). | IDS signature `flags:FPU` (sid:1000002). |
| **TCP ACK Scan** | `nmap -sA -p 1-500 192.168.1.150` | **ACK set** (`0x10`) to map firewall filtering. | Firewall drops unsolicited ACK outside tracking table. |
| **Service/OS Detection** | `nmap -sV -O -A 192.168.1.150` | Payload probes + banner requests. | HTTP log matching `User-Agent: Nmap Scripting Engine` (sid:1000004). |

**Evasion technique (detection-avoidance):**
```bash
nmap -sS -T1 --scan-delay 15s -p 21,22,80,443,3389 192.168.1.150
```
"Low-and-slow" pacing (< 2 ports/min) evades short rate-limit thresholds — use the **1-hour sliding window** SPL rule (Rule 3) to catch it.

---

## 4. SIEM Ingestion Setup

### Option A: Splunk Enterprise
1. Install **Splunk Free** or **Splunk Enterprise** on your lab server.
2. Install the **Splunk Add-on for Unix and Linux** (or the Palo Alto / Suricata add-on).
3. Create or edit `inputs.conf` to monitor local firewall logs or Suricata JSON logs:
   ```ini
   [monitor:///var/log/suricata/eve.json]
   sourcetype = suricata:eve
   index = ids

   [monitor:///var/log/iptables.log]
   sourcetype = syslog:iptables
   index = firewall
   ```
4. Restart Splunk and confirm the index receives events:
   ```bash
   sudo /opt/splunk/bin/splunk restart
   ```
5. Load the SPL queries from `rules/splunk_queries.spl`.

### Option B: ELK Stack (Elasticsearch + Kibana)
1. Install **Elastic Agent** or **Filebeat** on the target server.
2. Enable the `suricata` or `iptables` module in Filebeat:
   ```bash
   sudo filebeat modules enable suricata iptables
   sudo filebeat setup -e
   sudo systemctl restart filebeat
   ```
3. Load the EQL/KQL detection rules from `rules/elastic_rules.eql`, or import the provided Kibana threshold rule JSON.

---

## 5. False Positive (FP) Reduction Strategy

Reconnaissance detection easily triggers high volumes of false alerts if not tuned properly. Apply these engineering techniques:

### 1. Scanner Whitelisting & Lookup Exclusion
- **Problem:** Vulnerability scanners (Nessus, Qualys, Rapid7 InsightVM) intentionally perform full-range sweeps daily.
- **Solution:** Maintain a dynamic lookup table (`scanner_whitelist.csv` in Splunk, or an Elastic Reference Set) of approved scanner IPs and exclude them:
  ```spl
  | lookup scanner_whitelist.csv ip as src_ip OUTPUT is_authorized_scanner
  | search is_authorized_scanner!="true"
  ```
- **Real-life:** `10.0.0.50` (Nessus) runs nightly. After whitelisting, it stops alerting; the attacker `10.0.0.77` still triggers.

### 2. Cardinality & Time Window Thresholding
- **Problem:** Web apps opening many connections to dynamic assets produce multi-connection bursts.
- **Solution:** Require **at least 20–30 distinct destination ports** (`dc(dest_port) >= 25`) within a tight sliding window (2–5 minutes), instead of raw packet counts.
- **Real-life:** A page fetches 50 assets from the *same* web server → 1 distinct port → ignored. An Nmap sweep touches 100 distinct ports → alerted.

### 3. Noise Protocol Suppression
- **Problem:** UDP broadcast/multicast traffic causes false UDP sweep triggers.
- **Solution:** Filter infra ports before computing cardinality:
  ```spl
  | eval non_noise_ports = mvfilter(not match(sample_ports, "^(53|123|137|1900|5353)$"))
  | where mvcount(non_noise_ports) > 8
  ```
- **Real-life:** NTP (123), DNS (53), NetBIOS (137), SSDP (1900), mDNS (5353) bursts are purged before counting.

### 4. TCP Teardown Noise Filtering
- **Problem:** Asymmetric routing can deliver FIN-only packets without established state.
- **Solution:** Suppress FIN anomalies toward open web/SSL ports (`80`, `443`) as in the EQL rule:
  ```eql
  ) and not (destination.port == 80 or destination.port == 443)
  ```

---

## 6. Practical Lab Exercises

### Exercise 1: Run Synthetic Simulation
Generate sample Suricata logs for all Nmap scan modes:
```bash
python simulator/scan_simulator.py --scan all --format suricata --output eve_sample.json
```

### Exercise 2: Validate Splunk SPL Queries
1. Add `eve_sample.json` into Splunk via **Settings → Data Inputs → Add Data** (`sourcetype=suricata:eve`, `index=ids`).
2. Run **Rule 2** from `rules/splunk_queries.spl` and confirm `-sN`, `-sX`, `-sF` are flagged with `severity="HIGH"`.

### Exercise 3: Tune False Positives
1. The simulator already seeds benign sources (`10.0.0.50` Nessus, web clients) into the logs.
2. Run Rule 1 without the whitelist → the Nessus IP alerts.
3. Add the lookup exclusion → the Nessus IP is suppressed, while attacker `10.0.0.77` still alerts.
4. Verify ~99.78% FP reduction metrics in the **False Positive Reduction Matrix** tab.

### Exercise 4: Deploy Suricata Rules
1. Copy `rules/suricata_rules.rules` into `/etc/suricata/rules/local.rules`.
2. Add `include: local.rules` to `/etc/suricata/suricata.yaml`.
3. Reload and watch `tail -f /var/log/suricata/eve.json` while replaying simulated scans.

---

## 7. Real-Life Scenario Walkthroughs

### Scenario A: Internal Attacker Full Port Sweep (SYN)
1. **Recon:** `nmap -sS -p 1-1000 -T4 192.168.1.150` from Kali.
2. **Telemetry:** ~1,000 blocked events from `10.0.0.77` in 2 minutes.
3. **Detection:** Rule 1 fires — `distinct_ports ≈ 1000`, `risk_score = 90`.
4. **Playbook response:** Isolate the host, pull its process list, check for lateral movement (ATT&CK **T1046** → **T1021**).

### Scenario B: Stealth Xmas Scan Against the DMZ
1. **Recon:** `nmap -sX 192.168.1.150`.
2. **Telemetry:** `flags=0x29` (FPU) packets; no established connection.
3. **Detection:** Rule 2 flags `HIGH`; Suricata `sid:1000002` alerts within `threshold: count 5, seconds 60`.
4. **Playbook response:** This flag combo has near-zero benign usage — escalate instantly, capture PCAP, hunt for follow-up exploitation.

### Scenario C: Low-and-Slow Evasive Scan
1. **Recon:** `nmap -sS -T1 --scan-delay 15s -p 21,22,80,443,3389 192.168.1.150`.
2. **Telemetry:** stretched across an hour; short 2-minute thresholds "miss" it.
3. **Detection:** Rule 3 (1-hour span) computes `scan_velocity_per_min` and fires.
4. **Playbook response:** Correlate with Rule 5 (RBA) — 5 different rules on the same `src_ip` cross the total risk threshold.

### Scenario D: False Positive Bunfight (Nessus vs. Attacker)
1. Both `10.0.0.50` (Nessus) and `10.0.0.77` (attacker) sweep the same day.
2. **Without tuning:** 1,420 alerts/day — analysts ignore everything.
3. **With tuning:** 3 true-positive alerts/day — attacker identified immediately.
4. **Lesson:** Tuning is a detection engineering skill itself; the caretaker whitelist converts alert fatigue into a clean triage queue.

---

## 8. Validation & Verification Checklist

- [ ] `python simulator/scan_simulator.py --scan all --count 30 --format suricata --output eve_sample.json` produces well-formed JSON Lines.
- [ ] Splunk indexes `eve_sample.json` (`index=ids`, `sourcetype=suricata:eve`).
- [ ] Rule 1 (Sweep) flags the attacker and (post-lookup) ignores Nessus `10.0.0.50`.
- [ ] Rule 2 (Stealth) flags NULL/XMAS/FIN with `HIGH` severity.
- [ ] Rule 3 (Low-and-slow) catches a `-T1 --scan-delay 15s` scan.
- [ ] Rule 4 (UDP) suppresses DNS/NTP/mDNS noise via `mvfilter`.
- [ ] Rule 5 (RBA) aggregates attacker risk ≥ 100 across rule hits.
- [ ] Suricata signatures `sid:1000001–1000005` alert in `eve.json`.
- [ ] Elastic EQL flag-anomaly rule fires while excluding ports 80/443.
- [ ] FP calculator in the workbench reports **~99.78%** reduction with all toggles on.

Happy detection engineering. Always test within isolated, owned lab environments.