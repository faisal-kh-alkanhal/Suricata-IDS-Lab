# Suricata IDS Lab

A home network intrusion detection system built on Ubuntu Server 22.04, using custom Suricata rules to detect real attack patterns including port scans, brute-force attempts, and HTTP anomalies.

Built as a hands-on blue team project to demonstrate network threat detection and SOC analyst skills.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────┐
│                 HOME LAB NETWORK                │
│                                                 │
│  [Attack Machine]  ──────►  [Suricata VM]       │
│  Host / Kali Linux           Ubuntu Server      │
│  nmap, curl, hydra           22.04 LTS          │
│  (generates test traffic)   (monitors + alerts) │
└─────────────────────────────────────────────────┘
```

**Stack:** Suricata 8.0.5 · Ubuntu Server 22.04 · jq · custom detection rules

---

## Detection Rules

All rules were written from scratch in `/etc/suricata/rules/local.rules`. No community rule sets were used, every alert that fires is from logic written for this lab.

| # | Rule Name | Attack Simulated | Technique |
|---|-----------|-----------------|-----------|
| 1 | SCAN nmap SYN Sweep | `nmap -sS` port scan | TCP SYN flag + threshold |
| 2 | BRUTE FORCE SSH Login | Repeated SSH connections | Content match + rate threshold |
| 3 | DNS Query Suspicious TLD | DNS lookup to `.xyz` and other domains | DNS keyword match |
| 4 | HTTP Admin Panel Access | `curl /admin` endpoint probe | HTTP URI content match |

### Rule: Port Scan Detection

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"Nmap SYN Sweep";
  flags:S;
  threshold:type both, track by_src, count 20, seconds 3;
  sid:1000001; rev:1;
)
```

Fires when a single source sends 20+ SYN packets in 3 seconds, the signature of an nmap default scan. Threshold tuned to reduce false positives on legitimate traffic while catching automated scanners.

### Rule: SSH Brute Force

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
  msg:"SSH Brute Force Attack";
  flow:to_server,established;
  content:"SSH";
  threshold:type both, track by_src, count 5, seconds 60;
  sid:1000002; rev:1;
)
```

Detects repeated SSH login attempts from the same source IP. Tracks by source so distributed attacks from multiple IPs would require a separate detection approach (noted as a limitation below).

### Rule: Suspicious DNS Query

```
alert dns any any -> any any (
  msg: "DNS Query For Suspicious TLD";
  dns.query; pcre:"/\.(xyz|top|biz)/i"; 
  sid:1000003; rev:1;
)
```

Flags outbound DNS lookups for suspicious domains, a TLD commonly associated with malware C2 infrastructure. In a real environment this would be paired with a threat intel feed.

### Rule: HTTP Admin Panel Probe

```
alert http $EXTERNAL_NET any -> $HOME_NET any (
  msg:"HTTP Admin Panel Access Attempt";
  http.uri; content:"/admin"; nocase;
  sid:1000004; rev:1;
)
```

Detects requests to common admin paths. Uses the `http.uri` sticky buffer for accurate URI matching rather than raw content inspection.

---

## Attack Simulations & Results

Each rule was validated by generating matching traffic and confirming an alert fired in `fast.log`.

### Simulation Commands

```bash
# Rule 1: Port scan
nmap -sS <target-ip>

# Rule 2: SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>

# Rule 3: Suspicious DNS
nslookup test.malicious.xyz

# Rule 4: HTTP admin probe
curl http://<target-ip>/admin
```

### Sample Alert Output (`fast.log`)

```
05/24/2026-15:53:04.609359  [**] [1:1000001:1] Nmap SYN Sweep [**]
  [Classification:(null)]    [Priority: 3] {TCP} 192.168.32.131:62961 -> 192.168.32.130:106


05/24/2026-15:12:00.462001  [**] [1:1000002:1] SSH Brute Force Attack [**]
  [Classification(null)] [Priority: 3] {TCP} 192.168.32.131:48766 -> 192.168.32.130:22


05/24/2026-15:17:00.310172  [**] [1:1000003:1] DNS Query For Suspicious TLD [**]
  [Classification: (null)] [Priority: 3] {UDP} 192.168.32.131:56961 -> 192.168.32.2:53


05/24/2026-15:24:24.563944  [**] [1:1000004:1] HTTP Admin Panel Access Attempt [**] 
  [Classification: (null)] [Priority: 3] {TCP} 192.168.32.131:53482 -> 192.168.32.130:80

```

---

## Alert Analysis

Alerts were analysed using `jq` against the structured JSON log (`eve.json`).

```bash
# Count alerts by rule name
cat /var/log/suricata/eve.json \
  | jq -r 'select(.event_type=="alert") | .alert.signature' \
  | sort | uniq -c 

# Top attacking source IPs
cat /var/log/suricata/eve.json \
  | jq -r 'select(.event_type=="alert") | .src_ip' \
  | sort | uniq -c 
```

| Rule | Alerts Fired | Notes |
|------|-------------|-------|
| SCAN nmap SYN Sweep | 4 | Fired on first scan run as expected |
| BRUTE FORCE SSH | 4 | Multiple trigger windows during hydra run |
| DNS .xyz Query | 3 | Fired on each nslookup attempt |
| HTTP Admin Access | 1 | Fired on both curl requests |

---

## Key Findings & Limitations

**What worked well:**
- Threshold-based rules effectively distinguished attack traffic from noise
- `http.uri` sticky buffer gave more reliable HTTP matching than raw content
- `eve.json` JSON logging made post-analysis straightforward with jq

**Limitations identified:**
- SSH brute-force rule tracks by single source IP — a distributed attack spread across many IPs would evade it. A better approach would aggregate failed auth events at the application layer (e.g. via log correlation in a SIEM)
- The `.xyz` DNS rule generates false positives for legitimate `.xyz` domains. In production this would be replaced with a dynamic threat intel feed
- Running in IDS mode only, no blocking. Moving to IPS mode would require careful threshold tuning to avoid dropping legitimate traffic

---

## Repository Structure

```
suricata-ids-lab/
├── README.md
├── rules/
│   └── local.rules
├── screenshots/
│   ├── alerts-fast-log.png
│   └── jq-analysis.png
└── logs/
    └── sample-eve.json
```

---

## Skills Demonstrated

`Network Traffic Analysis` · `IDS Rule Writing` · `Threat Detection Logic` · `Log Analysis` · `Linux Administration` · `Attack Simulation` · `Blue Team / SOC`
