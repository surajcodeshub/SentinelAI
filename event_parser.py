import re
from datetime import datetime

# SSH auth.log patterns
PATTERNS = [
    # Failed password
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>[\d.]+)'
    ), 'SSH_AUTH', 'FAILURE'),
    # Accepted password
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Accepted password for (?P<username>\S+) from (?P<ip>[\d.]+)'
    ), 'SSH_AUTH', 'SUCCESS'),
    # Invalid user
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Invalid user (?P<username>\S+) from (?P<ip>[\d.]+)'
    ), 'INVALID_USER', 'FAILURE'),
    # Disconnected
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Disconnected from (?:invalid user )?(?P<username>\S+) (?P<ip>[\d.]+)'
    ), 'DISCONNECT', 'INFO'),
    # sudo
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*sudo.*COMMAND=(?P<cmd>\S+)'
    ), 'SUDO', 'INFO'),
    # Generic IP mention
    (re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*from (?P<ip>[\d.]+)'
    ), 'SYSTEM', 'INFO'),
]

def parse_log_line(line):
    for pattern, event_type, outcome in PATTERNS:
        m = pattern.search(line)
        if m:
            groups = m.groupdict()
            ip = groups.get('ip', '')
            username = groups.get('username', groups.get('cmd', ''))
            year = datetime.now().year
            try:
                ts = datetime.strptime(
                    f"{year} {groups.get('month','Jan')} {groups.get('day','1')} {groups.get('time','00:00:00')}",
                    '%Y %b %d %H:%M:%S'
                ).isoformat()
            except Exception:
                ts = datetime.now().isoformat()
            return {
                'timestamp': ts,
                'event_type': event_type,
                'source_ip': ip,
                'username': username,
                'action': event_type,
                'outcome': outcome,
                'severity': 1.0 if outcome == 'FAILURE' else 0.0,
                'raw_log': line,
            }
    return None
