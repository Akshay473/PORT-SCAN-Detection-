/* ==============================================================================
   PORT SCAN DETECTION ENGINEERING LAB - JAVASCRIPT CONTROLLER
   ============================================================================== */

document.addEventListener('DOMContentLoaded', () => {

    // --------------------------------------------------------------------------
    // 1. DATA MODELS & DICTIONARIES
    // --------------------------------------------------------------------------
    
    const SCAN_MECHANICS_DATA = {
        syn: {
            name: "TCP SYN Stealth Scan",
            cmd: "nmap -sS -p 1-1000 -T4 192.168.1.150",
            flags: { URG: 0, ACK: 0, PSH: 0, RST: 0, SYN: 1, FIN: 0 },
            hex: "0x02",
            rfc: "Sends a SYN packet to initiate a 3-way handshake. If the port is open, target responds with SYN/ACK. Attacker immediately sends RST to tear down without completing connection, avoiding full socket creation in target OS.",
            footprint: "Generates high volume of dropped/blocked connection events or half-open state anomalies in firewall state tables.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap TCP SYN Sweep"; flags:S,12; threshold: type threshold, track by_src, count 30, seconds 10; sid:1000005;)',
            flow: [
                { from: "Attacker (10.0.0.77)", arrow: "SYN ➔", to: "Target:80", desc: "Probe packet sent" },
                { from: "Target:80", arrow: "⇦ SYN/ACK", to: "Attacker", desc: "Port OPEN response" },
                { from: "Attacker", arrow: "RST ➔", to: "Target:80", desc: "Half-open teardown (No ACK)" }
            ]
        },
        connect: {
            name: "TCP Connect Scan",
            cmd: "nmap -sT -p 1-1000 192.168.1.150",
            flags: { URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 1, FIN: 0 },
            hex: "0x12 / 0x02",
            rfc: "Uses standard operating system connect() socket call. Completes full 3-way handshake (SYN -> SYN/ACK -> ACK) before closing with RST or FIN/ACK. Easily logged by application servers.",
            footprint: "Leaves complete web server / system application access logs and standard socket creation telemetry.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap TCP Connect Handshake"; flow:established,to_server; sid:1000006;)',
            flow: [
                { from: "Attacker", arrow: "SYN ➔", to: "Target:80", desc: "Step 1: Handshake initiation" },
                { from: "Target:80", arrow: "⇦ SYN/ACK", to: "Attacker", desc: "Step 2: Server confirmation" },
                { from: "Attacker", arrow: "ACK ➔", to: "Target:80", desc: "Step 3: Handshake ESTABLISHED" }
            ]
        },
        null: {
            name: "Stealth NULL Scan",
            cmd: "nmap -sN 192.168.1.150",
            flags: { URG: 0, ACK: 0, PSH: 0, RST: 0, SYN: 0, FIN: 0 },
            hex: "0x00",
            rfc: "Direct violation of RFC 793. No TCP control flags are set. According to RFC 793, open ports must ignore the packet, while closed ports respond with a RST packet.",
            footprint: "Extremely high-fidelity indicator of compromise (IOC). Legitimate network stacks never produce packets with zero TCP flags.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap NULL Scan (Flags: 0)"; flags:0; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000001;)',
            flow: [
                { from: "Attacker", arrow: "[NO FLAGS] ➔", to: "Target:80", desc: "Null probe packet" },
                { from: "Target:80 (Closed)", arrow: "⇦ RST", to: "Attacker", desc: "RST returned if port closed" },
                { from: "Target:80 (Open)", arrow: "[IGNORED]", to: "Attacker", desc: "No response if open" }
            ]
        },
        fin: {
            name: "Stealth FIN Scan",
            cmd: "nmap -sF 192.168.1.150",
            flags: { URG: 0, ACK: 0, PSH: 0, RST: 0, SYN: 0, FIN: 1 },
            hex: "0x01",
            rfc: "Sends a packet with ONLY the FIN flag set without an active session. Per RFC 793, open ports drop the packet, closed ports reply with RST.",
            footprint: "Flagged by IDS sensors checking for FIN packets arriving outside established state tables.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap FIN Scan Probe"; flags:F,12; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000003;)',
            flow: [
                { from: "Attacker", arrow: "FIN ➔", to: "Target:22", desc: "Unsolicited FIN packet" },
                { from: "Target:22 (Closed)", arrow: "⇦ RST", to: "Attacker", desc: "RST returned if closed" },
                { from: "Target:22 (Open)", arrow: "[IGNORED]", to: "Attacker", desc: "No reply if port open" }
            ]
        },
        xmas: {
            name: "Stealth Xmas Scan",
            cmd: "nmap -sX 192.168.1.150",
            flags: { URG: 1, ACK: 0, PSH: 1, RST: 0, SYN: 0, FIN: 1 },
            hex: "0x29 (FIN+PSH+URG)",
            rfc: "Sets FIN, PSH, and URG flags simultaneously. Named because control flags are 'lit up like a Christmas tree'. Violates TCP state machine specifications.",
            footprint: "100% true positive detection signature. Zero legitimate software uses FIN+PSH+URG flag combinations.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Nmap XMAS Scan (FIN+PSH+URG)"; flags:FPU; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000002;)',
            flow: [
                { from: "Attacker", arrow: "FIN+PSH+URG ➔", to: "Target:443", desc: "Xmas probe packet" },
                { from: "Target:443 (Closed)", arrow: "⇦ RST", to: "Attacker", desc: "RST returned if closed" },
                { from: "Target:443 (Open)", arrow: "[IGNORED]", to: "Attacker", desc: "Dropped silently if open" }
            ]
        },
        ack: {
            name: "TCP ACK Scan",
            cmd: "nmap -sA -p 1-500 192.168.1.150",
            flags: { URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 0, FIN: 0 },
            hex: "0x10",
            rfc: "Used to map firewall rule sets and statefulness rather than port state. Target responds with RST regardless of open/closed status; un-filtered ports return RST, filtered ports drop packet.",
            footprint: "Triggers firewall drop/deny rules for unsolicted ACK packets not matching connection state table entries.",
            suricata: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN Unsolicited TCP ACK Probe"; flags:A,12; threshold: type threshold, track by_src, count 20, seconds 10; sid:1000007;)',
            flow: [
                { from: "Attacker", arrow: "ACK ➔", to: "Target:139", desc: "Unsolicited ACK probe" },
                { from: "Target:139 (Unfiltered)", arrow: "⇦ RST", to: "Attacker", desc: "RST returned" },
                { from: "Firewall (Filtered)", arrow: "[DROPPED]", to: "Attacker", desc: "ICMP unreachable or drop" }
            ]
        },
        udp: {
            name: "UDP Port Sweep",
            cmd: "nmap -sU --top-ports 50 192.168.1.150",
            flags: { URG: 0, ACK: 0, PSH: 0, RST: 0, SYN: 0, FIN: 0 },
            hex: "N/A (UDP)",
            rfc: "Sends empty UDP headers to target ports. If no service is listening, target OS responds with ICMP Type 3 Code 3 (Destination Unreachable: Port Unreachable).",
            footprint: "High volume of outgoing ICMP Port Unreachable logs or blocked UDP firewall events.",
            suricata: 'alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN UDP Port Sweep Probe"; threshold: type threshold, track by_src, count 15, seconds 30; sid:1000008;)',
            flow: [
                { from: "Attacker", arrow: "UDP Probe ➔", to: "Target:161", desc: "UDP packet sent" },
                { from: "Target:161 (Closed)", arrow: "⇦ ICMP Unreachable", to: "Attacker", desc: "ICMP Type 3 Code 3" },
                { from: "Target:53 (Open)", arrow: "UDP Response / Silence", to: "Attacker", desc: "Service reply or timeout" }
            ]
        },
        version: {
            name: "Service Version Probing",
            cmd: "nmap -sV -O --script banner 192.168.1.150",
            flags: { URG: 0, ACK: 1, PSH: 1, RST: 0, SYN: 1, FIN: 0 },
            hex: "0x02 / Payload",
            rfc: "After identifying open ports, Nmap connects to each port and sends protocol-specific payload probes (e.g. GET HTTP requests, SSH banner queries) to determine application versions.",
            footprint: "Web server access logs contain default User-Agent strings such as 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'.",
            suricata: 'alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"ET SCAN Nmap NSE User-Agent Header"; http.user_agent; content:"Nmap Scripting Engine"; sid:1000004;)',
            flow: [
                { from: "Attacker", arrow: "HTTP GET / ➔", to: "Target:80", desc: "Payload probe with NSE User-Agent" },
                { from: "Target:80", arrow: "⇦ Server: Apache/2.4", to: "Attacker", desc: "Banner details revealed" }
            ]
        }
    };


    // --------------------------------------------------------------------------
    // 2. TAB NAVIGATION
    // --------------------------------------------------------------------------
    
    const tabs = document.querySelectorAll('.nav-tab');
    const tabContents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            const target = tab.getAttribute('data-tab');
            document.getElementById(target).classList.add('active');
        });
    });


    // --------------------------------------------------------------------------
    // 3. TAB 1: SCAN MECHANICS CONTROLLER
    // --------------------------------------------------------------------------
    
    const scanCards = document.querySelectorAll('.scan-card');
    
    function renderScanMechanics(scanKey) {
        const data = SCAN_MECHANICS_DATA[scanKey];
        if (!data) return;

        // Render TCP Flag Boxes
        const flagContainer = document.getElementById('tcp-flags-container');
        flagContainer.innerHTML = '';
        Object.keys(data.flags).forEach(flagName => {
            const isSet = data.flags[flagName] === 1;
            const flagBox = document.createElement('div');
            flagBox.className = `flag-box ${isSet ? 'active' : ''}`;
            flagBox.innerHTML = `
                <span class="flag-name">${flagName}</span>
                <span class="flag-val">${data.flags[flagName]}</span>
            `;
            flagContainer.appendChild(flagBox);
        });

        // Update Text Elements
        document.getElementById('flag-hex-badge').innerText = `HEX: ${data.hex}`;
        document.getElementById('scan-cmd-text').innerText = data.cmd;
        document.getElementById('scan-rfc-text').innerText = data.rfc;
        document.getElementById('scan-footprint-text').innerText = data.footprint;
        document.getElementById('suricata-sig-text').innerText = data.suricata;

        // Render Flow Diagram
        const flowContainer = document.getElementById('flow-diagram-container');
        flowContainer.innerHTML = '';
        data.flow.forEach(step => {
            const stepEl = document.createElement('div');
            stepEl.className = 'flow-step';
            stepEl.innerHTML = `
                <span>${step.from}</span>
                <span class="arrow">${step.arrow}</span>
                <span>${step.to}</span>
                <span style="color: var(--text-muted); font-size: 0.75rem;">(${step.desc})</span>
            `;
            flowContainer.appendChild(stepEl);
        });
    }

    scanCards.forEach(card => {
        card.addEventListener('click', () => {
            scanCards.forEach(c => c.classList.remove('active'));
            card.classList.add('active');
            const scanKey = card.getAttribute('data-scan');
            renderScanMechanics(scanKey);
        });
    });

    // Initial render
    renderScanMechanics('syn');


    // --------------------------------------------------------------------------
    // 4. TAB 2: SIEM WORKBENCH CONTROLLER
    // --------------------------------------------------------------------------
    
    let currentSiem = 'splunk';
    let currentCategory = 'sweep';
    let thresholdPorts = 25;
    let thresholdSpan = 2;
    let isWhitelistEnabled = true;

    const siemToggleBtns = document.querySelectorAll('.toggle-btn');
    const categorySelect = document.getElementById('rule-category-select');
    const sliderPorts = document.getElementById('distinct-ports-slider');
    const sliderSpan = document.getElementById('time-window-slider');
    const chkWhitelist = document.getElementById('chk-whitelist');

    function generateQueryCode() {
        const queryTitle = document.getElementById('query-title-text');
        const codeContent = document.getElementById('query-code-content');
        const mechanicsList = document.getElementById('query-mechanics-list');
        const tuningList = document.getElementById('query-tuning-list');

        let code = "";
        let mechanics = [];
        let tuning = [];

        if (currentSiem === 'splunk') {
            if (currentCategory === 'sweep') {
                queryTitle.innerText = `Splunk SPL: High-Volume TCP SYN/Connect Sweep`;
                const wlFilter = isWhitelistEnabled ? `\n# Exclude Whitelisted Vulnerability Scanners\n| lookup scanner_whitelist.csv ip as src_ip OUTPUT is_authorized_scanner\n| search is_authorized_scanner!="true"` : "";
                
                code = `| tstats summariesonly=true count dc(All_Traffic.dest_port) as distinct_ports values(All_Traffic.dest_port) as targeted_ports 
    from datamodel=Network_Traffic.All_Traffic 
    where All_Traffic.action="blocked" OR All_Traffic.action="dropped"
    by _time span=${thresholdSpan}m All_Traffic.src All_Traffic.dest All_Traffic.transport
| rename All_Traffic.src as src_ip, All_Traffic.dest as dest_ip, All_Traffic.transport as protocol
| filter distinct_ports >= ${thresholdPorts}${wlFilter}
| eval risk_score=case(distinct_ports > 500, 90, distinct_ports > 100, 70, true(), 40)
| table _time, src_ip, dest_ip, protocol, distinct_ports, targeted_ports, risk_score`;

                mechanics = [
                    `Uses accelerated tstats query against Network_Traffic data model for sub-second execution.`,
                    `Groups events into sliding ${thresholdSpan}-minute buckets across blocked firewall attempts.`,
                    `Triggers when source IP accesses >= ${thresholdPorts} distinct destination ports.`
                ];
                tuning = [
                    isWhitelistEnabled ? `Lookup exclusion filter active for approved scanners (Nessus/Qualys).` : `Whitelist disabled (WARNING: High false positive rate).`,
                    `Cardinality filtering (dc(dest_port)) suppresses web multi-connection noise to single ports.`
                ];
            } else if (currentCategory === 'stealth') {
                queryTitle.innerText = `Splunk SPL: Stealth Flag Anomaly Detection (NULL/FIN/XMAS)`;
                code = `index=ids OR index=firewall sourcetype="suricata:eve" OR sourcetype="syslog:iptables"
| eval tcp_flags_str = case(
    sourcetype=="suricata:eve", 'tcp.tcp_flags',
    sourcetype=="syslog:iptables", 'tcp_flags',
    true(), 'flags'
)
| search (tcp_flags_str="0" OR tcp_flags_str="0x00" OR tcp_flags_str="FPU" OR tcp_flags_str="0x29" OR tcp_flags_str="F" OR tcp_flags_str="0x01")
| stats count, values(dest_port) as targeted_ports, dc(dest_port) as distinct_ports by _time span=${thresholdSpan}m, src_ip, dest_ip
| filter distinct_ports >= ${Math.max(2, Math.floor(thresholdPorts / 5))}`;

                mechanics = [
                    `Targets RFC 793 flag violations (NULL: 0x00, XMAS: FPU/0x29, FIN: 0x01).`,
                    `Inspects raw IDS/firewall packet flag headers.`
                ];
                tuning = [
                    `Requires multiple flag anomaly probes across sliding windows to prevent single-packet glitch alerts.`
                ];
            } else if (currentCategory === 'slow') {
                queryTitle.innerText = `Splunk SPL: Low-and-Slow Evasive Reconnaissance`;
                code = `| tstats summariesonly=true count dc(All_Traffic.dest_port) as distinct_ports
    from datamodel=Network_Traffic.All_Traffic 
    where All_Traffic.action="blocked"
    by _time span=1h All_Traffic.src All_Traffic.dest
| rename All_Traffic.src as src_ip, All_Traffic.dest as dest_ip
| filter distinct_ports >= ${thresholdPorts} AND distinct_ports <= 150
| eval scan_velocity = round(distinct_ports / 60, 2)`;

                mechanics = [
                    `Extends time window to 1-hour span to capture scans designed to bypass short 2-minute rate limits.`
                ];
                tuning = [
                    `Calculates scan velocity per minute to differentiate stealth attackers from high-speed sweeps.`
                ];
            } else if (currentCategory === 'udp') {
                queryTitle.innerText = `Splunk SPL: UDP Port Sweep & ICMP Probing`;
                code = `index=firewall transport=udp (action="blocked" OR reason="port-unreachable")
| stats count dc(dest_port) as distinct_udp_ports values(dest_port) as sample_ports by _time span=${thresholdSpan}m, src_ip, dest_ip
| filter distinct_udp_ports >= ${thresholdPorts}
| eval non_noise_ports = mvfilter(not match(sample_ports, "^(53|123|137|1900|5353)$"))
| where mvcount(non_noise_ports) >= ${Math.floor(thresholdPorts * 0.7)}`;

                mechanics = [
                    `Aggregates dropped UDP traffic and ICMP Port Unreachable events.`
                ];
                tuning = [
                    `Uses mvfilter() to strip common infrastructure UDP broadcast noise (DNS:53, NTP:123, NetBIOS:137, SSDP:1900).`
                ];
            } else if (currentCategory === 'rba') {
                queryTitle.innerText = `Splunk Enterprise Security: Risk-Based Alerting (RBA) Correlation`;
                code = `index=risk search_name="Nmap *"
| stats sum(risk_score) as total_risk, values(search_name) as triggered_rules, dc(dest_ip) as target_count by src_ip
| where total_risk >= 100
| table src_ip, total_risk, triggered_rules, target_count`;
                mechanics = [`Correlates multiple lower-fidelity signals into a single notable event when total risk score exceeds threshold.`];
                tuning = [`Prevents analyst fatigue by alerting only when aggregate risk score reaches critical threshold.`];
            }
        } else {
            // ELASTIC EQL/KQL
            if (currentCategory === 'sweep') {
                queryTitle.innerText = `Elastic EQL: High-Volume TCP SYN/Connect Sweep Sequence`;
                code = `sequence by source.ip, destination.ip with maxspan=${thresholdSpan}m
  [ network where event.category == "network" and event.type == "connection" and
    event.outcome == "failure" and network.transport == "tcp" ]
  [ network where event.category == "network" and event.type == "connection" and
    event.outcome == "failure" and network.transport == "tcp" ]
  until [ network where destination.port > 0 ]
  /* Threshold Rule: Cardinality of destination.port >= ${thresholdPorts} */`;

                mechanics = [
                    `Elastic Event Query Language (EQL) sequence rule tracking failed connection state transitions.`,
                    `Uses ECS (Elastic Common Schema) normalized fields.`
                ];
                tuning = [
                    `Combines Kibana Detection Engine threshold cardinality (destination.port >= ${thresholdPorts}).`
                ];
            } else if (currentCategory === 'stealth') {
                queryTitle.innerText = `Elastic EQL: Stealth Flag Anomaly Detection`;
                code = `network where event.category == "network" and network.transport == "tcp" and (
  tcp.flags == "0x00" or tcp.flags == "0" or
  tcp.flags == "0x29" or tcp.flags == "FPU" or
  tcp.flags == "0x01"
) and not (destination.port == 80 or destination.port == 443)`;
                mechanics = [`Filters TCP flag anomaly bitmasks directly within network telemetry.`];
                tuning = [`Excludes ports 80/443 to prevent edge-case web connection teardown false positives.`];
            } else {
                queryTitle.innerText = `Elastic KQL: Reconnaissance Detection Query`;
                code = `event.category: "network" AND event.outcome: ("failure" OR "deny" OR "block") AND NOT source.ip: (10.0.0.50 OR 192.168.1.200)`;
                mechanics = [`Kibana Query Language expression for search dashboards.`];
                tuning = [`Excludes known scanner IPs.`];
            }
        }

        codeContent.innerText = code;
        
        mechanicsList.innerHTML = '';
        mechanics.forEach(m => {
            const li = document.createElement('li');
            li.innerText = m;
            mechanicsList.appendChild(li);
        });

        tuningList.innerHTML = '';
        tuning.forEach(t => {
            const li = document.createElement('li');
            li.innerText = t;
            tuningList.appendChild(li);
        });
    }

    siemToggleBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            siemToggleBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentSiem = btn.getAttribute('data-siem');
            generateQueryCode();
        });
    });

    categorySelect.addEventListener('change', (e) => {
        currentCategory = e.target.value;
        generateQueryCode();
    });

    sliderPorts.addEventListener('input', (e) => {
        thresholdPorts = parseInt(e.target.value);
        document.getElementById('distinct-ports-val').innerText = `${thresholdPorts} distinct ports`;
        generateQueryCode();
    });

    sliderSpan.addEventListener('input', (e) => {
        thresholdSpan = parseInt(e.target.value);
        document.getElementById('time-window-val').innerText = `${thresholdSpan}m window`;
        generateQueryCode();
    });

    chkWhitelist.addEventListener('change', (e) => {
        isWhitelistEnabled = e.target.checked;
        generateQueryCode();
    });

    generateQueryCode();


    // --------------------------------------------------------------------------
    // 5. TAB 3: FALSE POSITIVE REDUCTION CALCULATOR
    // --------------------------------------------------------------------------
    
    const fpOptNessus = document.getElementById('fp-opt-nessus');
    const fpOptUdpNoise = document.getElementById('fp-opt-udpnoise');
    const fpOptCardinality = document.getElementById('fp-opt-cardinality');
    const fpOptFinTeardown = document.getElementById('fp-opt-finteardown');

    function updateFpMetrics() {
        let rawAlerts = 1420;
        let tunedAlerts = 1420;
        let fpSuppressed = 0;

        if (fpOptNessus.checked) tunedAlerts -= 950; // Nessus scanner generates ~950 alerts/day
        if (fpOptUdpNoise.checked) tunedAlerts -= 260; // UDP broadcast noise ~260 alerts/day
        if (fpOptCardinality.checked) tunedAlerts -= 140; // Web multi-connection bursts ~140 alerts/day
        if (fpOptFinTeardown.checked) tunedAlerts -= 67;  // TCP FIN teardown noise ~67 alerts/day

        tunedAlerts = Math.max(3, tunedAlerts); // 3 true positive attacker scans remaining
        const reductionPct = (((rawAlerts - tunedAlerts) / rawAlerts) * 100).toFixed(2);

        document.getElementById('fp-count-raw').innerText = rawAlerts.toLocaleString();
        document.getElementById('fp-count-tuned').innerText = tunedAlerts.toLocaleString();
        document.getElementById('fp-rate-reduced').innerText = `${reductionPct}%`;

        // Update progress bar
        const barTuned = document.getElementById('bar-fill-tuned');
        const barTunedText = document.getElementById('bar-text-tuned');
        const tunedPct = Math.max(2, (tunedAlerts / rawAlerts) * 100);

        barTuned.style.width = `${tunedPct}%`;
        barTunedText.innerText = `${tunedAlerts} Alerts (${tunedAlerts === 3 ? '100% True Positives' : 'Contains Noise'})`;

        const banner = document.getElementById('fidelity-status-banner');
        if (tunedAlerts === 3) {
            banner.style.background = 'rgba(0, 255, 157, 0.08)';
            banner.style.borderColor = 'var(--accent-green)';
            banner.innerHTML = `<h4>🛡️ Detection Engine Status: Optimal Fidelity</h4><p>All noise filters active. Vulnerability scanners excluded. High-confidence alerts guaranteed.</p>`;
        } else {
            banner.style.background = 'rgba(255, 42, 109, 0.08)';
            banner.style.borderColor = 'var(--accent-red)';
            banner.innerHTML = `<h4>⚠️ Alert Fatigue Warning</h4><p>Some noise filters are disabled! Expect high volumes of false positive alerts.</p>`;
        }
    }

    [fpOptNessus, fpOptUdpNoise, fpOptCardinality, fpOptFinTeardown].forEach(chk => {
        chk.addEventListener('change', updateFpMetrics);
    });

    updateFpMetrics();


    // --------------------------------------------------------------------------
    // 6. TAB 4: LIVE LOG STREAM SIMULATOR ENGINE
    // --------------------------------------------------------------------------
    
    let isStreaming = false;
    let streamInterval = null;
    const btnSimStart = document.getElementById('btn-sim-start');
    const btnSimClear = document.getElementById('btn-sim-clear');
    const btnSimDownload = document.getElementById('btn-sim-download');
    const terminalOutput = document.getElementById('terminal-output');
    const simStatusBadge = document.getElementById('sim-status-badge');

    const samplePorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080];

    function generateLogLine() {
        const format = document.getElementById('sim-format-select').value;
        const scan = document.getElementById('sim-scan-select').value;
        const port = samplePorts[Math.floor(Math.random() * samplePorts.length)];
        const ts = new Date().toISOString();
        
        let line = "";
        let isAlert = true;

        if (format === 'suricata') {
            const obj = {
                timestamp: ts,
                event_type: "alert",
                src_ip: "10.0.0.77",
                src_port: Math.floor(Math.random() * 20000) + 35000,
                dest_ip: "192.168.1.150",
                dest_port: port,
                proto: scan === 'udp' ? 'UDP' : 'TCP',
                alert: {
                    action: "blocked",
                    signature: `Nmap Reconnaissance Scan (${scan.toUpperCase()})`,
                    category: "Attempted Information Leak",
                    severity: scan === 'xmas' || scan === 'null' ? 1 : 2
                }
            };
            line = JSON.stringify(obj);
        } else if (format === 'syslog') {
            line = `${ts} security-gw kernel: [IPTABLES DROP] IN=eth0 SRC=10.0.0.77 DST=192.168.1.150 PROTO=${scan === 'udp' ? 'UDP' : 'TCP'} DPT=${port} FLAGS=${scan.toUpperCase()}`;
        } else {
            const obj = {
                _time: ts,
                source: { ip: "10.0.0.77", port: Math.floor(Math.random() * 20000) + 35000 },
                destination: { ip: "192.168.1.150", port: port },
                network: { transport: scan === 'udp' ? 'udp' : 'tcp' },
                event: { action: "blocked", outcome: "failure" },
                scan_mode: scan
            };
            line = JSON.stringify(obj);
        }

        const lineEl = document.createElement('div');
        lineEl.className = `terminal-line ${isAlert ? 'log-alert' : 'log-normal'}`;
        lineEl.innerText = line;
        terminalOutput.appendChild(lineEl);
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    btnSimStart.addEventListener('click', () => {
        if (isStreaming) {
            clearInterval(streamInterval);
            isStreaming = false;
            btnSimStart.innerText = "▶ Start Log Stream";
            simStatusBadge.innerText = "PAUSED";
            simStatusBadge.classList.remove('streaming');
        } else {
            isStreaming = true;
            btnSimStart.innerText = "⏸ Pause Stream";
            simStatusBadge.innerText = "STREAMING LIVE";
            simStatusBadge.classList.add('streaming');
            streamInterval = setInterval(generateLogLine, 600);
        }
    });

    btnSimClear.addEventListener('click', () => {
        terminalOutput.innerHTML = '<div class="terminal-line comment"># Console cleared. Click Start Log Stream to resume.</div>';
    });

    btnSimDownload.addEventListener('click', () => {
        const text = terminalOutput.innerText;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `port_scan_sample_logs_${Date.now()}.log`;
        a.click();
        URL.revokeObjectURL(url);
    });

});


// --------------------------------------------------------------------------
// 7. HELPER FUNCTIONS
// --------------------------------------------------------------------------

function copyText(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        alert("Copied to clipboard!");
    }).catch(err => {
        console.error("Failed to copy: ", err);
    });
}
