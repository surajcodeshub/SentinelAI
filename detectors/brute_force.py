from database import get_connection, insert_alert, get_config, is_whitelisted


def check_brute_force(source_ip: str, event_id=None):
    if is_whitelisted(source_ip):
        return False

    threshold = int(get_config('bf_threshold', 5))
    window    = int(get_config('bf_window', 60))

    conn  = get_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM security_events WHERE source_ip=? AND outcome='FAILURE' "
        "AND timestamp>=datetime('now',?)",
        (source_ip, f'-{window} seconds')
    ).fetchone()[0]

    row = conn.execute(
        "SELECT username FROM security_events WHERE source_ip=? AND outcome='FAILURE' "
        "ORDER BY id DESC LIMIT 1", (source_ip,)
    ).fetchone()

    # Count distinct usernames targeted — detect spray
    distinct_users = conn.execute(
        "SELECT COUNT(DISTINCT username) FROM security_events WHERE source_ip=? "
        "AND outcome='FAILURE' AND timestamp>=datetime('now',?)",
        (source_ip, f'-{window} seconds')
    ).fetchone()[0]

    conn.close()
    username = row['username'] if row else 'unknown'

    if count >= threshold:
        # Avoid duplicate open alert for same IP
        conn2 = get_connection()
        existing = conn2.execute(
            "SELECT id FROM alerts WHERE source_ip=? AND alert_type IN ('BRUTE_FORCE','MULTIPLE_USERS') "
            "AND status='Open' AND created_at>=datetime('now','-5 minutes')",
            (source_ip,)
        ).fetchone()
        conn2.close()
        if existing:
            return False

        if distinct_users >= 3:
            alert_type  = 'MULTIPLE_USERS'
            severity    = 'CRITICAL'
            description = (
                f"Password spray detected from {source_ip}. "
                f"{count} failures targeting {distinct_users} different accounts in {window}s."
            )
        else:
            alert_type  = 'BRUTE_FORCE'
            severity    = 'HIGH'
            description = (
                f"Password attack detected from {source_ip}. "
                f"{count} failed logins in {window}s targeting '{username}'."
            )

        alert_id = insert_alert(alert_type, severity, source_ip, description, event_id)

        # Fire email notification in background
        try:
            import threading
            from notifier import send_alert_email
            threading.Thread(
                target=send_alert_email,
                args=(alert_type, severity, source_ip, description),
                daemon=True
            ).start()
        except Exception:
            pass

        return True
    return False
