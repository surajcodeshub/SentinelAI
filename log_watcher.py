"""
Real log file watcher — runs in a background thread.
Watches a file on disk and feeds every new line through the
detection pipeline automatically.
"""
import os
import time
import threading
import platform
from datetime import datetime

from event_parser import parse_log_line
from database import insert_event, get_config, is_whitelisted, block_ip, get_connection
from detectors.brute_force import check_brute_force
from alert_manager import create_alert

_watcher_thread = None
_stop_event = threading.Event()


def _get_windows_log_lines():
    """Pull recent Security/System events from Windows Event Log via wevtutil."""
    lines = []
    try:
        import subprocess
        # Get last 50 security events (logins)
        cmd = ['wevtutil', 'qe', 'Security', '/c:50', '/rd:true', '/f:text']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        raw = result.stdout
        # Convert to auth.log-style lines
        current = {}
        for line in raw.splitlines():
            line = line.strip()
            if 'Event ID:' in line:
                eid = line.split(':')[-1].strip()
                current['eid'] = eid
            elif 'Date:' in line:
                current['date'] = line.split('Date:')[-1].strip()
            elif 'Account Name:' in line and 'account_name' not in current:
                current['account_name'] = line.split(':')[-1].strip()
            elif 'Source Network Address:' in line:
                current['ip'] = line.split(':')[-1].strip().replace('-', '127.0.0.1')
            elif line == '' and current.get('eid'):
                eid = current.get('eid', '')
                user = current.get('account_name', 'unknown')
                ip = current.get('ip', '127.0.0.1')
                date = current.get('date', datetime.now().strftime('%b %d %H:%M:%S'))
                if eid == '4625':   # Logon failure
                    lines.append(f"{date} Windows sshd[0]: Failed password for {user} from {ip} port 0 win")
                elif eid == '4624': # Logon success
                    lines.append(f"{date} Windows sshd[0]: Accepted password for {user} from {ip} port 0 win")
                current = {}
    except Exception as e:
        pass
    return lines


def _process_line(line: str):
    """Parse one log line and run all detectors on it."""
    line = line.strip()
    if not line:
        return
    parsed = parse_log_line(line)
    if not parsed:
        return

    source_ip = parsed.get('source_ip', '')

    # Skip whitelisted IPs
    if source_ip and is_whitelisted(source_ip):
        return

    event_id = insert_event(parsed)

    # Run brute-force detector on every failure
    if parsed.get('outcome') == 'FAILURE' and source_ip:
        check_brute_force(source_ip, event_id)

    # Auto-block if enabled and IP has very high failure count
    auto_block = get_config('auto_block_enabled', 'false') == 'true'
    threshold  = int(get_config('auto_block_threshold', '10'))
    if auto_block and source_ip and parsed.get('outcome') == 'FAILURE':
        conn = get_connection()
        count = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE source_ip=? AND outcome='FAILURE' "
            "AND timestamp>=datetime('now','-300 seconds')", (source_ip,)
        ).fetchone()[0]
        conn.close()
        if count >= threshold:
            block_ip(source_ip, f'Auto-blocked: {count} failures in 5 min', 'system')


def _tail_file(log_path: str):
    """Watch a file and yield new lines as they appear."""
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(0, 2)          # seek to end
            while not _stop_event.is_set():
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.5)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[LogWatcher] Error reading {log_path}: {e}")


def _watch_loop():
    """Main background loop — switches between file-watch and Windows event log polling."""
    print("[LogWatcher] Background watcher started.")
    is_windows = platform.system() == 'Windows'
    seen_lines = set()   # dedup for Windows polling

    while not _stop_event.is_set():
        log_path = get_config('log_path', '')

        if log_path and os.path.exists(log_path):
            # Watch a real log file (Linux auth.log, custom file, etc.)
            for line in _tail_file(log_path):
                if _stop_event.is_set():
                    break
                _process_line(line)
        elif is_windows:
            # Windows: poll Event Log every 30 seconds
            lines = _get_windows_log_lines()
            for line in lines:
                if line not in seen_lines:
                    seen_lines.add(line)
                    _process_line(line)
            if len(seen_lines) > 5000:
                seen_lines = set(list(seen_lines)[-2000:])
            time.sleep(30)
        else:
            # No log path configured — sleep and retry
            time.sleep(10)


def start_watcher():
    global _watcher_thread, _stop_event
    _stop_event.clear()
    _watcher_thread = threading.Thread(target=_watch_loop, daemon=True, name='LogWatcher')
    _watcher_thread.start()


def stop_watcher():
    _stop_event.set()
