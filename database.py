import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
from functools import lru_cache

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sentinelai.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'analyst',
            last_login    TEXT,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            source_ip   TEXT,
            username    TEXT,
            action      TEXT,
            outcome     TEXT,
            severity    REAL DEFAULT 0.0,
            raw_log     TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type   TEXT NOT NULL,
            severity     TEXT NOT NULL,
            source_ip    TEXT,
            description  TEXT,
            event_id     INTEGER REFERENCES security_events(id),
            status       TEXT DEFAULT 'Open',
            analyst_note TEXT,
            assigned_to  TEXT,
            created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    INTEGER REFERENCES alerts(id),
            title       TEXT,
            description TEXT,
            analyst     TEXT DEFAULT 'analyst',
            status      TEXT DEFAULT 'Open',
            priority    TEXT DEFAULT 'Medium',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT
        );
        CREATE TABLE IF NOT EXISTS reports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id  INTEGER REFERENCES incidents(id),
            title        TEXT,
            content      TEXT,
            generated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT PRIMARY KEY,
            reason      TEXT,
            blocked_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            blocked_by  TEXT DEFAULT 'system'
        );
        CREATE TABLE IF NOT EXISTS ip_whitelist (
            ip         TEXT PRIMARY KEY,
            label      TEXT,
            added_at   TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id   INTEGER REFERENCES alerts(id),
            content    TEXT,
            author     TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS configurations (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_ip        ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_outcome   ON security_events(outcome);
        CREATE INDEX IF NOT EXISTS idx_events_type      ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_ip        ON alerts(source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_type      ON alerts(alert_type);

        INSERT OR IGNORE INTO configurations VALUES ('bf_threshold',        '5');
        INSERT OR IGNORE INTO configurations VALUES ('bf_window',           '60');
        INSERT OR IGNORE INTO configurations VALUES ('anomaly_sensitivity', '0.05');
        INSERT OR IGNORE INTO configurations VALUES ('log_path',            '');
        INSERT OR IGNORE INTO configurations VALUES ('email_alerts',        'false');
        INSERT OR IGNORE INTO configurations VALUES ('email_to',            '');
        INSERT OR IGNORE INTO configurations VALUES ('auto_block_enabled',  'false');
        INSERT OR IGNORE INTO configurations VALUES ('auto_block_threshold','10');
        INSERT OR IGNORE INTO configurations VALUES ('max_events_stored',   '100000');
    """)
    conn.commit()

    # Create default admin if no users exist
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        pw_hash = hash_password('admin123')
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            ('admin', 'admin@sentinelai.local', pw_hash, 'admin')
        )
        conn.commit()
        print("[SentinelAI] Default login: admin / admin123 — register your own account or change this password!")
    conn.close()

# ── Password helpers ──────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, h = stored_hash.split(':', 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False

# ── User functions ─────────────────────────────────────────────────────────────
def get_user(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_email(email):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None

def register_user(username, email, password):
    """Returns (True, None) on success or (False, error_message) on failure."""
    if get_user(username):
        return False, "Username already taken"
    if get_user_by_email(email):
        return False, "Email already registered"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
        (username, email.lower().strip(), hash_password(password), 'analyst')
    )
    conn.commit()
    conn.close()
    return True, None

def update_last_login(username):
    conn = get_connection()
    conn.execute("UPDATE users SET last_login=? WHERE username=?",
                 (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def change_password(username, new_password):
    conn = get_connection()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                 (hash_password(new_password), username))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    rows = conn.execute("SELECT id,username,email,role,last_login,created_at FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Event functions ───────────────────────────────────────────────────────────
def insert_event(event_dict):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO security_events (timestamp,event_type,source_ip,username,action,outcome,severity,raw_log) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (event_dict.get('timestamp', datetime.now().isoformat()),
         event_dict.get('event_type', 'UNKNOWN'),
         event_dict.get('source_ip', ''),
         event_dict.get('username', ''),
         event_dict.get('action', ''),
         event_dict.get('outcome', ''),
         float(event_dict.get('severity', 0.0)),
         event_dict.get('raw_log', ''))
    )
    eid = cur.lastrowid
    conn.commit()
    conn.close()
    return eid

def get_events(limit=100, offset=0, event_type=None, source_ip=None, outcome=None, search=None):
    conn = get_connection()
    q, p = "SELECT * FROM security_events WHERE 1=1", []
    if event_type: q += " AND event_type=?";       p.append(event_type)
    if source_ip:  q += " AND source_ip LIKE ?";   p.append(f'%{source_ip}%')
    if outcome:    q += " AND outcome=?";           p.append(outcome)
    if search:     q += " AND (raw_log LIKE ? OR username LIKE ?)"; p += [f'%{search}%', f'%{search}%']
    q += " ORDER BY id DESC LIMIT ? OFFSET ?";     p += [limit, offset]
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_event_count(event_type=None, source_ip=None, outcome=None, search=None):
    conn = get_connection()
    q, p = "SELECT COUNT(*) FROM security_events WHERE 1=1", []
    if event_type: q += " AND event_type=?";       p.append(event_type)
    if source_ip:  q += " AND source_ip LIKE ?";   p.append(f'%{source_ip}%')
    if outcome:    q += " AND outcome=?";           p.append(outcome)
    if search:     q += " AND (raw_log LIKE ? OR username LIKE ?)"; p += [f'%{search}%', f'%{search}%']
    c = conn.execute(q, p).fetchone()[0]
    conn.close()
    return c

# ── Alert functions ───────────────────────────────────────────────────────────
def insert_alert(alert_type, severity, source_ip, description, event_id=None):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO alerts (alert_type,severity,source_ip,description,event_id,status) VALUES (?,?,?,?,?,'Open')",
        (alert_type, severity, source_ip, description, event_id)
    )
    aid = cur.lastrowid
    conn.commit()
    conn.close()
    return aid

def get_alerts(limit=200, status=None, severity=None):
    conn = get_connection()
    q, p = "SELECT * FROM alerts WHERE 1=1", []
    if status:   q += " AND status=?";   p.append(status)
    if severity: q += " AND severity=?"; p.append(severity)
    q += " ORDER BY id DESC LIMIT ?";   p.append(limit)
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def resolve_alert(alert_id, note='', resolved_by='analyst'):
    conn = get_connection()
    conn.execute(
        "UPDATE alerts SET status='Resolved', analyst_note=?, resolved_at=datetime('now') WHERE id=?",
        (note, alert_id)
    )
    conn.commit()
    conn.close()

def get_alert_by_id(alert_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

# ── Blocked IPs ───────────────────────────────────────────────────────────────
def block_ip(ip, reason='Manual block', blocked_by='system'):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip,reason,blocked_at,blocked_by) VALUES (?,?,datetime('now'),?)",
        (ip, reason, blocked_by)
    )
    conn.commit()
    conn.close()

def unblock_ip(ip):
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

def get_blocked_ips():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def is_blocked(ip):
    conn = get_connection()
    row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row is not None

# ── Whitelist ─────────────────────────────────────────────────────────────────
def whitelist_ip(ip, label=''):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO ip_whitelist (ip,label) VALUES (?,?)", (ip, label))
    conn.commit()
    conn.close()

def get_whitelist():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ip_whitelist ORDER BY added_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def is_whitelisted(ip):
    conn = get_connection()
    row = conn.execute("SELECT 1 FROM ip_whitelist WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row is not None

# ── Notes ─────────────────────────────────────────────────────────────────────
def add_note(alert_id, content, author='analyst'):
    conn = get_connection()
    conn.execute("INSERT INTO notes (alert_id,content,author) VALUES (?,?,?)", (alert_id, content, author))
    conn.commit()
    conn.close()

def get_notes(alert_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM notes WHERE alert_id=? ORDER BY created_at", (alert_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Incidents & Reports ───────────────────────────────────────────────────────
def get_incidents(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT i.*, a.alert_type, a.severity as alert_severity, a.source_ip as alert_ip "
        "FROM incidents i LEFT JOIN alerts a ON i.alert_id=a.id ORDER BY i.id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def insert_incident(alert_id, title, description, priority='Medium'):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO incidents (alert_id,title,description,priority) VALUES (?,?,?,?)",
        (alert_id, title, description, priority)
    )
    iid = cur.lastrowid
    conn.commit()
    conn.close()
    return iid

def insert_report(incident_id, title, content):
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO reports (incident_id,title,content) VALUES (?,?,?)", (incident_id, title, content)
    )
    rid = cur.lastrowid
    conn.commit()
    conn.close()
    return rid

def get_reports(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT r.*, i.title as incident_title FROM reports r "
        "LEFT JOIN incidents i ON r.incident_id=i.id ORDER BY r.id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Dashboard stats ───────────────────────────────────────────────────────────
def get_dashboard_stats():
    conn = get_connection()
    cur = conn.cursor()
    def q(sql, *p): return cur.execute(sql, p).fetchone()[0]

    stats = {
        'total_events':  q("SELECT COUNT(*) FROM security_events"),
        'active_alerts': q("SELECT COUNT(*) FROM alerts WHERE status='Open'"),
        'today_events':  q("SELECT COUNT(*) FROM security_events WHERE timestamp>=datetime('now','-1 day')"),
        'brute_force':   q("SELECT COUNT(*) FROM alerts WHERE alert_type='BRUTE_FORCE' AND status='Open'"),
        'anomalies':     q("SELECT COUNT(*) FROM alerts WHERE alert_type='ANOMALY' AND status='Open'"),
        'blocked_ips':   q("SELECT COUNT(*) FROM blocked_ips"),
        'severity_counts': {
            'critical': q("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL' AND status='Open'"),
            'high':     q("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'    AND status='Open'"),
            'medium':   q("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'  AND status='Open'"),
            'low':      q("SELECT COUNT(*) FROM alerts WHERE severity='LOW'     AND status='Open'"),
        },
    }
    trend = cur.execute("""
        SELECT date(timestamp) day, COUNT(*) cnt FROM security_events
        WHERE timestamp>=datetime('now','-7 days')
        GROUP BY date(timestamp) ORDER BY day
    """).fetchall()
    stats['event_trend'] = [{'day': r['day'], 'count': r['cnt']} for r in trend]

    top_attackers = cur.execute("""
        SELECT source_ip, COUNT(*) cnt FROM security_events
        WHERE outcome='FAILURE' AND source_ip != ''
        GROUP BY source_ip ORDER BY cnt DESC LIMIT 5
    """).fetchall()
    stats['top_attackers'] = [{'ip': r['source_ip'], 'count': r['cnt']} for r in top_attackers]

    recent_alerts = cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall()
    stats['recent_alerts'] = [dict(r) for r in recent_alerts]

    event_types = cur.execute(
        "SELECT event_type, COUNT(*) cnt FROM security_events GROUP BY event_type ORDER BY cnt DESC LIMIT 6"
    ).fetchall()
    stats['event_types'] = [{'type': r['event_type'], 'count': r['cnt']} for r in event_types]

    hourly = cur.execute("""
        SELECT strftime('%H',timestamp) hr, COUNT(*) cnt FROM security_events
        WHERE timestamp>=datetime('now','-1 day')
        GROUP BY hr ORDER BY hr
    """).fetchall()
    stats['hourly_activity'] = [{'hour': r['hr'], 'count': r['cnt']} for r in hourly]

    conn.close()
    return stats

# ── Config helpers ────────────────────────────────────────────────────────────
def get_config(key, default=None):
    conn = get_connection()
    row = conn.execute("SELECT value FROM configurations WHERE key=?", (key,)).fetchone()
    conn.close()
    return row['value'] if row else default

def set_config(key, value):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO configurations (key,value) VALUES (?,?)", (key, str(value)))
    conn.commit()
    conn.close()

def get_all_configs():
    conn = get_connection()
    rows = conn.execute("SELECT key,value FROM configurations").fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}
