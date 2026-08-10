# Port Scan Detection Engineering Lab Manual

Welcome to the **Port Scan Detection Engineering Lab** manual. This guide walks you through setting up a complete detection engineering lab using Kali Linux, Nmap, Suricata IDS, and modern SIEM platforms (**Splunk Enterprise** and **ELK / Elastic Security**).

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

---

## 2. Nmap Execution Matrix on Kali Linux

Log in to your Kali Linux machine (`10.0.0.77`) and execute the following Nmap scan commands against the target IP (`192.168.1.150`):

| Scan Technique | Nmap Command | Flag Mechanics & Packet Structure | Detection Method |
| :--- | :--- | :--- | :--- |
| **TCP SYN Scan (Stealth)** | `nmap -sS -p 1-1000 192.168.1.150` | Sends `SYN` packet. Half-open connection (teardown with `RST` if `SYN/ACK` received). | Threshold on `action=blocked` count > 25 distinct ports. |
| **TCP Connect Scan** | `nmap -sT -p 1-1000 192.168.1.150` | Completes full 3-way handshake (`SYN` -> `SYN/ACK` -> `ACK`). | High volume OS socket creation logs / Application logs. |
| **UDP Scan** | `nmap -sU --top-ports 50 192.168.1.150` | Sends empty UDP headers. Closed ports respond with `ICMP Port Unreachable`. | Firewall ICMP unreachable drops + UDP port cardinality. |
| **Stealth NULL Scan** | `nmap -sN 192.168.1.150` | Sends packet with **no TCP flags set** (`flags=0x00`). Violates RFC 793. | Suricata IDS signature `flags:0` or Firewall syslog filter. |
| **Stealth FIN Scan** | `nmap -sF 192.168.1.150` | Sends packet with **only FIN flag set** (`flags=0x01`). RFC 793 anomaly. | IDS signature `flags:F` without prior established session state. |
| **Stealth Xmas Scan** | `nmap -sX 192.168.1.150` | Sends packet with **FIN, PSH, and URG set** ("lit up like a Xmas tree", `0x29`). | IDS signature `flags:FPU`. High-fidelity anomaly signal. |
| **TCP ACK Scan** | `nmap -sA -p 1-500 192.168.1.150` | Sends packet with **ACK set** to determine firewall filtering state. | Firewall drops unsolicited `ACK` outside tracking table. |
| **Service/OS Detection** | `nmap -sV -O -A 192.168.1.150` | Sends probe payloads and checks for default User-Agent strings. | HTTP log matching `User-Agent: Nmap Scripting Engine`. |

---

## 3. SIEM Ingestion Setup

### Option A: Splunk Enterprise
1. Install **Splunk Free** or **Splunk Enterprise** on your lab server.
2. Install **Splunk Add-on for Unix and Linux** or **Palo Alto / Suricata Add-on**.
3. Create `inputs.conf` to monitor local firewall logs or Suricata JSON logs:
   ```ini
   [monitor:///var/log/suricata/eve.json]
   sourcetype = suricata:eve
   index = ids

   [monitor:///var/log/iptables.log]
   sourcetype = syslog:iptables
   index = firewall
   ```
4. Load the SPL queries from `rules/splunk_queries.spl`.

### Option B: ELK Stack (Elasticsearch + Kibana)
1. Install **Elastic Agent** or **Filebeat** on the target server.
2. Enable the `suricata` or `iptables` module in Filebeat:
   ```bash
   sudo filebeat modules enable suricata iptables
   sudo filebeat setup -e
   sudo systemctl restart filebeat
   ```
3. Load the EQL/KQL detection rules from `rules/elastic_rules.eql`.

---

## 4. False Positive (FP) Reduction Strategy

Reconnaissance detection easily triggers high volumes of false alerts if not tuned properly. Apply the following engineering techniques:

### 1. Scanner Whitelisting & Lookup Exclusion
- **Problem**: Vulnerability assessment tools (Nessus, Qualys, Rapid7 InsightVM) perform intentional full-range port sweeps daily.
- **Solution**: Maintain a dynamic lookup table (`scanner_whitelist.csv` in Splunk or Elastic Reference Set) containing approved internal scanner IPs and exclude them from detection pipelines:
  ```spl
  | lookup scanner_whitelist.csv ip as src_ip OUTPUT is_authorized_scanner
  | search is_authorized_scanner!="true"
  ```

### 2. Cardinality & Time Window Thresholding
- **Problem**: Legitimate web apps loading dynamic micro-assets or microservices can open multiple concurrent connections across various ephemeral ports.
- **Solution**: Require **at least 20-30 distinct destination ports** (`dc(dest_port) >= 25`) within a tight sliding window (2 to 5 minutes), rather than simple packet count thresholds.

### 3. Noise Protocol Suppression
- **Problem**: High-volume UDP protocol noise (NTP port 123, DNS port 53, NetBIOS port 137, SSDP 1900, mDNS 5353) causes false positive UDP sweep triggers.
- **Solution**: Filter out common infrastructure broadcast ports prior to calculating port cardinality.

---

## 5. Practical Lab Exercises

### Exercise 1: Run Synthetic Simulation
Run the included Python simulator script to generate sample Suricata logs for all Nmap scan modes:
```bash
python simulator/scan_simulator.py --scan all --format suricata --output eve_sample.json
```

### Exercise 2: Validate Splunk SPL Queries
1. Copy the contents of `eve_sample.json` into Splunk's Add Data pipeline.
2. Run Query #2 from `rules/splunk_queries.spl` to confirm stealth scans (`-sN`, `-sX`, `-sF`) are flagged with `HIGH` severity.

### Exercise 3: Tune False Positives
1. Modify `scan_simulator.py` to add IP `10.0.0.50` (Nessus Scanner).
2. Verify that running the baseline query flags `10.0.0.50`, but adding the lookup exclusion successfully suppresses the alert while retaining detections for attacker IP `10.0.0.77`.
