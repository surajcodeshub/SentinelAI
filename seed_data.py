"""Populate the database with realistic demo data for the SOC dashboard."""
import random
from datetime import datetime, timedelta
from database import init_db, insert_event, insert_alert, insert_incident, insert_report, get_connection

ATTACK_IPS = ['192.168.1.100', '10.0.0.45', '203.0.113.77', '198.51.100.23', '172.16.0.99']
NORMAL_IPS = ['192.168.0.10', '192.168.0.11', '192.168.0.15', '10.0.0.5']
USERNAMES = ['admin', 'root', 'ubuntu', 'deploy', 'sysadmin', 'guest']

def random_time(days_back=7):
    base = datetime.now() - timedelta(days=days_back)
    offset = random.uniform(0, days_back * 86400)
    return (base + timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%S')

def seed():
    init_db()
    conn = get_connection()
    existing = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    conn.close()
    if existing > 10:
        return  # already seeded

    # SSH brute-force events
    for _ in range(40):
        ip = random.choice(ATTACK_IPS)
        user = random.choice(USERNAMES)
        ts = random_time(7)
        insert_event({
            'timestamp': ts, 'event_type': 'SSH_AUTH', 'source_ip': ip,
            'username': user, 'action': 'SSH_AUTH', 'outcome': 'FAILURE',
            'severity': 1.0, 'raw_log': f'Nov 21 {ts[11:19]} sshd Failed password for {user} from {ip} port 22222 ssh2'
        })

    # Normal events
    for _ in range(80):
        ip = random.choice(NORMAL_IPS)
        user = random.choice(['alice', 'bob', 'charlie', 'dave'])
        ts = random_time(7)
        insert_event({
            'timestamp': ts, 'event_type': 'SSH_AUTH', 'source_ip': ip,
            'username': user, 'action': 'SSH_AUTH', 'outcome': 'SUCCESS',
            'severity': 0.0, 'raw_log': f'Nov 21 {ts[11:19]} sshd Accepted password for {user} from {ip} port 22222 ssh2'
        })

    # Sudo events
    for _ in range(20):
        ip = random.choice(NORMAL_IPS)
        ts = random_time(7)
        insert_event({
            'timestamp': ts, 'event_type': 'SUDO', 'source_ip': ip,
            'username': 'alice', 'action': 'SUDO', 'outcome': 'INFO',
            'severity': 0.3, 'raw_log': f'Nov 21 {ts[11:19]} sudo alice COMMAND=/bin/systemctl'
        })

    # Invalid user
    for _ in range(15):
        ip = random.choice(ATTACK_IPS)
        ts = random_time(5)
        insert_event({
            'timestamp': ts, 'event_type': 'INVALID_USER', 'source_ip': ip,
            'username': 'oracle', 'action': 'INVALID_USER', 'outcome': 'FAILURE',
            'severity': 0.8, 'raw_log': f'Nov 21 {ts[11:19]} sshd Invalid user oracle from {ip}'
        })

    # Create alerts
    for ip in ATTACK_IPS[:3]:
        insert_alert('BRUTE_FORCE', 'HIGH', ip,
                     f"Brute-force detected from {ip}. 10 failed logins in 45s targeting 'admin'.")
    insert_alert('ANOMALY', 'MEDIUM', '10.0.0.45',
                 "Anomalous login pattern detected: unusual hour and high failure rate.")
    insert_alert('MULTIPLE_USERS', 'CRITICAL', '203.0.113.77',
                 "Password spray detected: single IP targeting 5 different accounts.")
    insert_alert('PORT_SCAN', 'MEDIUM', '198.51.100.23',
                 "Network port scan detected from 198.51.100.23 – 450 ports probed in 10s.")

    # Create a sample incident + report
    inc_id = insert_incident(1, "Brute-Force SSH Attack – 192.168.1.100",
                             "Automated brute-force attack targeting admin account from external IP.",
                             "HIGH")
    report_content = """
=============================================================
       SENTINELAI SECURITY INCIDENT REPORT
=============================================================
Incident ID    : INC-2026-0001
Generated At   : 2026-11-21 14:32:11
Severity       : HIGH

INCIDENT SUMMARY
----------------------------------------
  Source IP    : 192.168.1.100
  Attack Type  : Brute-Force SSH Authentication
  Detected At  : 2026-11-21 14:31:52

EVENT TIMELINE
----------------------------------------
  14:31:52  SSH_AUTH  FAILURE  user=admin
  14:31:55  SSH_AUTH  FAILURE  user=admin
  14:31:59  SSH_AUTH  FAILURE  user=admin
  14:32:03  SSH_AUTH  FAILURE  user=admin
  14:32:07  SSH_AUTH  FAILURE  user=admin  → ALERT TRIGGERED

RECOMMENDED ACTIONS
----------------------------------------
  1. Block 192.168.1.100 at network perimeter immediately.
  2. Lock user account 'admin' pending investigation.
  3. Enable 3-strike account lockout policy.
  4. Confirm no successful logins occurred from this IP.
  5. Escalate to Tier 2 if external IP confirmed malicious.

  STATUS: Open – Awaiting Analyst Action
=============================================================
""".strip()
    insert_report(inc_id, "INC-2026-0001 – Brute-Force SSH Attack", report_content)
    print("Demo data seeded successfully.")

if __name__ == '__main__':
    seed()
