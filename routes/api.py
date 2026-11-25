from flask import Blueprint, jsonify, request, session
from database import (
    get_dashboard_stats, get_events, get_event_count, get_alerts,
    insert_event, resolve_alert, get_incidents, get_reports,
    get_config, set_config, get_all_configs,
    block_ip, unblock_ip, get_blocked_ips, is_blocked,
    whitelist_ip, get_whitelist, get_notes, add_note,
    get_alert_by_id, get_all_users
)
from detectors.brute_force import check_brute_force
from ai.threat_analyzer import analyzer
from report_generator import generate_incident_report
from ml.anomaly_detector import detector
from event_parser import parse_log_line
from datetime import datetime
import random, os

api_bp = Blueprint('api', __name__)

def current_user():
    return session.get('user', 'analyst')

# ── Stats ─────────────────────────────────────────────────────────────────────
@api_bp.route('/stats')
def stats():
    return jsonify(get_dashboard_stats())

# ── Events ────────────────────────────────────────────────────────────────────
@api_bp.route('/events')
def events():
    page    = int(request.args.get('page', 1))
    limit   = int(request.args.get('limit', 50))
    offset  = (page - 1) * limit
    kw      = dict(
        event_type = request.args.get('type')   or None,
        source_ip  = request.args.get('ip')     or None,
        outcome    = request.args.get('outcome')or None,
        search     = request.args.get('search') or None,
    )
    items = get_events(limit=limit, offset=offset, **kw)
    total = get_event_count(**kw)
    return jsonify({'events': items, 'total': total, 'page': page,
                    'pages': max(1, -(-total // limit))})

# ── Alerts ────────────────────────────────────────────────────────────────────
@api_bp.route('/alerts')
def alerts():
    items = get_alerts(
        status   = request.args.get('status')   or None,
        severity = request.args.get('severity') or None,
    )
    return jsonify({'alerts': items})

@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve(alert_id):
    note = (request.json or {}).get('note', '')
    resolve_alert(alert_id, note, current_user())
    return jsonify({'success': True})

@api_bp.route('/alerts/<int:alert_id>/notes', methods=['GET'])
def get_alert_notes(alert_id):
    return jsonify({'notes': get_notes(alert_id)})

@api_bp.route('/alerts/<int:alert_id>/notes', methods=['POST'])
def post_note(alert_id):
    content = (request.json or {}).get('content', '').strip()
    if not content:
        return jsonify({'error': 'Note is empty'}), 400
    add_note(alert_id, content, current_user())
    return jsonify({'success': True})

# ── AI Analysis ───────────────────────────────────────────────────────────────
@api_bp.route('/analyze', methods=['POST'])
def analyze():
    alert_id = (request.json or {}).get('alert_id')
    if not alert_id:
        return jsonify({'error': 'alert_id required'}), 400
    alert = get_alert_by_id(int(alert_id))
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    result = analyzer.analyze(alert['alert_type'], {
        'source_ip': alert.get('source_ip', 'Unknown'),
        'username':  alert.get('description', '').split("'")[1]
                     if "'" in (alert.get('description') or '') else 'unknown',
    })
    return jsonify(result)

# ── Reports ───────────────────────────────────────────────────────────────────
@api_bp.route('/report/generate', methods=['POST'])
def gen_report():
    alert_id = (request.json or {}).get('alert_id')
    if not alert_id:
        return jsonify({'error': 'alert_id required'}), 400
    inc_id, content = generate_incident_report(int(alert_id))
    if not inc_id:
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify({'incident_id': inc_id, 'content': content})

@api_bp.route('/incidents')
def incidents():
    return jsonify({'incidents': get_incidents()})

@api_bp.route('/reports')
def reports():
    return jsonify({'reports': get_reports()})

# ── Block / Whitelist ─────────────────────────────────────────────────────────
@api_bp.route('/block', methods=['POST'])
def api_block():
    data   = request.json or {}
    ip     = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual block')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    block_ip(ip, reason, current_user())
    return jsonify({'success': True, 'message': f'{ip} blocked'})

@api_bp.route('/unblock', methods=['POST'])
def api_unblock():
    ip = (request.json or {}).get('ip', '').strip()
    unblock_ip(ip)
    return jsonify({'success': True})

@api_bp.route('/blocked_ips')
def api_blocked():
    return jsonify({'blocked': get_blocked_ips()})

@api_bp.route('/whitelist', methods=['POST'])
def api_whitelist():
    data  = request.json or {}
    ip    = data.get('ip', '').strip()
    label = data.get('label', '')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    whitelist_ip(ip, label)
    return jsonify({'success': True})

@api_bp.route('/whitelist', methods=['GET'])
def api_get_whitelist():
    return jsonify({'whitelist': get_whitelist()})

# ── Settings ──────────────────────────────────────────────────────────────────
@api_bp.route('/settings', methods=['GET'])
def get_settings():
    return jsonify(get_all_configs())

@api_bp.route('/settings', methods=['POST'])
def save_settings():
    data = request.json or {}
    allowed = {
        'bf_threshold','bf_window','anomaly_sensitivity',
        'log_path','email_alerts','email_to',
        'smtp_host','smtp_port','smtp_user','smtp_pass',
        'auto_block_enabled','auto_block_threshold',
    }
    for key, val in data.items():
        if key in allowed:
            set_config(key, str(val))
    return jsonify({'success': True})

# ── ML ────────────────────────────────────────────────────────────────────────
@api_bp.route('/train_model', methods=['POST'])
def train_model():
    from database import get_events as ge
    events = ge(limit=1000)
    result = detector.train(events)
    return jsonify({'success': result,
                    'message': f'Model trained on {len(events)} events' if result
                               else f'Need at least 20 events (have {len(events)})'})

# ── Log ingestion ─────────────────────────────────────────────────────────────
@api_bp.route('/parse_log', methods=['POST'])
def parse_log():
    line = (request.json or {}).get('line', '').strip()
    if not line:
        return jsonify({'error': 'No line provided'}), 400
    parsed = parse_log_line(line)
    if not parsed:
        return jsonify({'error': 'Could not parse this log format'}), 400
    event_id = insert_event(parsed)
    parsed['id'] = event_id
    if parsed.get('outcome') == 'FAILURE' and parsed.get('source_ip'):
        check_brute_force(parsed['source_ip'], event_id)
    return jsonify({'parsed': parsed})

# ── Watcher status ────────────────────────────────────────────────────────────
@api_bp.route('/watcher/status')
def watcher_status():
    from log_watcher import _watcher_thread
    running = _watcher_thread is not None and _watcher_thread.is_alive()
    log_path = get_config('log_path', '')
    return jsonify({
        'running': running,
        'log_path': log_path,
        'log_exists': bool(log_path and os.path.exists(log_path)),
    })

# ── Simulations (demo) ────────────────────────────────────────────────────────
@api_bp.route('/simulate/attack', methods=['POST'])
def simulate_attack():
    ip   = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    user = random.choice(['admin', 'root', 'ubuntu', 'deploy', 'test'])
    for _ in range(7):
        eid = insert_event({
            'timestamp': datetime.now().isoformat(),
            'event_type': 'SSH_AUTH', 'source_ip': ip,
            'username': user, 'action': 'SSH_AUTH',
            'outcome': 'FAILURE', 'severity': 1.0,
            'raw_log': f'Simulated Failed password for {user} from {ip}'
        })
        check_brute_force(ip, eid)
    return jsonify({'message': f'Simulated attack from {ip}', 'ip': ip, 'user': user})

@api_bp.route('/simulate/anomaly', methods=['POST'])
def simulate_anomaly():
    from database import insert_alert as ia
    ip  = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    eid = insert_event({
        'timestamp': datetime.now().isoformat(),
        'event_type': 'SUSPICIOUS_LOGIN', 'source_ip': ip,
        'username': 'anomaly_user', 'action': 'LOGIN',
        'outcome': 'SUCCESS', 'severity': 0.9,
        'raw_log': f'Simulated anomalous login from {ip}'
    })
    ia('ANOMALY', 'MEDIUM', ip, f'Unusual login behaviour detected from {ip}.', eid)
    return jsonify({'message': f'Anomaly simulated from {ip}', 'ip': ip})
