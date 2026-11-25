from datetime import datetime
from database import get_connection, insert_incident, insert_report, get_config

def generate_incident_report(alert_id):
    conn = get_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        return None, None
    alert = dict(alert)
    # Get related events
    events = []
    if alert.get('event_id'):
        rows = conn.execute(
            "SELECT * FROM security_events WHERE source_ip=? ORDER BY timestamp LIMIT 20",
            (alert['source_ip'],)
        ).fetchall()
        events = [dict(r) for r in rows]
    conn.close()

    inc_id_str = f"INC-{datetime.now().year}-{alert_id:04d}"
    title = f"Security Incident Report – {alert['alert_type']} from {alert['source_ip']}"

    lines = [
        "=" * 62,
        "       SENTINELAI SECURITY INCIDENT REPORT",
        "=" * 62,
        f"Incident ID    : {inc_id_str}",
        f"Generated At   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Severity       : {alert['severity']}",
        f"Alert Type     : {alert['alert_type']}",
        f"Status         : {alert['status']}",
        "",
        "INCIDENT SUMMARY",
        "-" * 40,
        f"  Source IP    : {alert['source_ip']}",
        f"  Description  : {alert['description']}",
        f"  Detected At  : {alert['created_at']}",
        "",
        "EVENT TIMELINE",
        "-" * 40,
    ]
    for e in events[:15]:
        lines.append(f"  {e.get('timestamp','')}  {e.get('event_type','')}  "
                     f"{e.get('outcome','')}  user={e.get('username','')}")
    lines += [
        "",
        "RECOMMENDED ACTIONS",
        "-" * 40,
        "  1. Block source IP at network perimeter firewall.",
        "  2. Review and lock targeted user accounts.",
        "  3. Enable account lockout policy.",
        "  4. Investigate whether any attempts succeeded.",
        "  5. Correlate with threat intelligence feeds.",
        "",
        f"  STATUS: Open – Awaiting Analyst Action",
        "=" * 62,
    ]
    content = "\n".join(lines)
    inc_db_id = insert_incident(alert_id, title, f"Auto-generated from alert {alert_id}", alert['severity'])
    rep_id = insert_report(inc_db_id, title, content)
    return inc_db_id, content
