[splunk_README.md](https://github.com/user-attachments/files/29475723/splunk_README.md)
# Splunk SOC Home Lab — Threat Detection Dashboard

A home Security Operations Center (SOC) lab built with Splunk Enterprise, featuring a Python-based security event log generator and a multi-panel threat detection dashboard. Simulates real-world attack scenarios analyzed by a SOC analyst.

---

## What It Does

- Generates 200 realistic security events across 4 attack scenarios using a Python script
- Ingests logs into Splunk Enterprise for analysis
- Detects threats using SPL (Splunk Processing Language) queries
- Visualizes findings in a multi-panel SOC dashboard

---

## Attack Scenarios Simulated

| Scenario | Events | Description |
|---|---|---|
| Brute Force | ~35 | Multiple failed logins from attacker IPs, rapid failures, eventual success |
| Privilege Escalation | ~15 | User role changed to Administrator — critical severity |
| Data Exfiltration | ~40 | Large outbound transfers to threat-intel flagged IPs on non-standard ports |
| Account Lockout | ~30 | Repeated failures triggering account lockouts across multiple users |
| Ambient Noise | ~80 | Normal login activity to make the dataset realistic |

---

## Detections Built

### 1. Brute Force Detection
Identifies IP addresses with more than 5 failed login attempts — flags active attackers.

```spl
source="logs/security_logs.json"
| spath event_type
| search event_type="failed_login"
| stats count by src_ip
| where count > 5
| sort -count
```

### 2. Privilege Escalation Detection
Surfaces any user account that was elevated to Administrator — critical finding in any environment.

```spl
source="logs/security_logs.json"
| spath event_type
| search event_type="privilege_escalation"
| table _time, username, src_ip, severity, message
| sort _time
```

### 3. Data Exfiltration Detection
Identifies suspicious outbound connections and large data transfers to threat-intel flagged IPs.

```spl
source="logs/security_logs.json"
| spath event_type
| search event_type="suspicious_outbound_conn" OR event_type="suspicious_inbound_conn" OR event_type="data_exfiltration_attempt"
| table _time, username, src_ip, severity, message
| sort -severity
```

### 4. Account Lockout Detection
Tracks accounts locked due to repeated authentication failures.

```spl
source="logs/security_logs.json"
| spath event_type
| search event_type="account_lockout"
| table _time, username, src_ip, severity, message
| sort _time
```

---

## Dashboard Panels

| Panel | Visualization | Purpose |
|---|---|---|
| Brute Force — Attacker IPs | Bar Chart | Compare attack volume by source IP |
| Privilege Escalation — Compromised Accounts | Statistics Table | Show exact users, timestamps, and severity |
| Data Exfiltration — Suspicious Outbound Traffic | Bar Chart | Identify top exfiltration source IPs |
| Total Account Lockouts | Single Value | High-impact summary count |
| Security Event Overview | Pie Chart | Full breakdown of all event types |

---

## Key Findings From Lab Run

- **2 attacker IPs** identified in brute force detection with 5+ failed attempts
- **3 critical privilege escalations** detected — tmartin, bthompson, and svc_backup all elevated to Administrator
- **svc_backup** identified as fully compromised — connected to threat-intel IPs on ports 4444, 9001, and 1337 (known C2 ports), and exfiltrated 300MB+ of data
- **6 account lockouts** across the environment
- **data_exfiltration_attempt** and **brute_force_attempt** were the highest volume malicious event types

---

## Technologies Used

- **Splunk Enterprise** (free tier) — SIEM platform
- **Python 3.11** — log generation script
- **SPL** (Splunk Processing Language) — detection queries
- **JSON** — log format

---

## SOC Concepts Demonstrated

- SIEM log ingestion and indexing
- Threat detection using SPL queries
- Brute force, privilege escalation, lateral movement, and data exfiltration detection
- MITRE ATT&CK technique coverage:
  - T1110 — Brute Force
  - T1078 — Valid Accounts (privilege escalation)
  - T1041 — Exfiltration Over C2 Channel
  - T1531 — Account Access Removal (lockouts)
- SOC dashboard design and visualization
- Incident triage and alert prioritization

---

## Setup

### Prerequisites
- Splunk Enterprise (free at splunk.com — 500MB/day free tier)
- Python 3.8+

### Installation

```bash
git clone https://github.com/jawadraza786/splunk-soc-lab.git
cd splunk-soc-lab
python3 log_generator.py
```

This generates `logs/security_logs.json` with 200 security events.

### Load Into Splunk

1. Open Splunk at `http://localhost:8000`
2. Go to **Settings → Add Data → Monitor → Files & Directories**
3. Point to `logs/security_logs.json`
4. Set source type to `_json`
5. Click **Submit**
6. Run the SPL queries above in Search & Reporting

---

## Author

**Jawad Raza**
- GitHub: [jawadraza786](https://github.com/jawadraza786)
- LinkedIn: [linkedin.com/in/jawadraza2427](https://linkedin.com/in/jawadraza2427)

---

## Relevance to SOC Analyst Roles

This lab simulates core tasks performed daily by Tier 1 and Tier 2 SOC analysts:
- Monitoring SIEM alerts for suspicious activity
- Investigating brute force, privilege escalation, and data exfiltration events
- Building detection rules and dashboards
- Triaging and prioritizing incidents by severity
- Documenting findings for escalation
