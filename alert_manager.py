from database import insert_alert, resolve_alert, get_alerts

SEVERITY_RULES = {
    'BRUTE_FORCE': 'HIGH',
    'ANOMALY': 'MEDIUM',
    'MULTIPLE_USERS': 'CRITICAL',
    'PORT_SCAN': 'MEDIUM',
    'SUSPICIOUS_LOGIN': 'HIGH',
    'UNKNOWN': 'LOW',
}

def create_alert(alert_type, source_ip, description, event_id=None):
    severity = SEVERITY_RULES.get(alert_type, 'LOW')
    return insert_alert(alert_type, severity, source_ip, description, event_id)

def close_alert(alert_id, note=''):
    resolve_alert(alert_id, note)

def get_open_alerts():
    return get_alerts(status='Open')
