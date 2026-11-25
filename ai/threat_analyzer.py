from datetime import datetime

class ThreatAnalyzer:
    TEMPLATES = {
        'BRUTE_FORCE': {
            'title': 'Brute-Force Authentication Attack',
            'risk': 'HIGH',
            'mitre': 'T1110 – Brute Force',
            'description': (
                "A brute-force authentication attack was detected from source IP {source_ip}. "
                "Multiple failed login attempts indicate automated credential stuffing or password spray activity. "
                "The attack targeted username '{username}' with repeated authentication failures within a short time window."
            ),
            'recommended_actions': [
                "Immediately block source IP {source_ip} at the network perimeter firewall.",
                "Temporarily lock the targeted user account '{username}' pending investigation.",
                "Enable account lockout policy (lock after 3 consecutive failures).",
                "Review authentication logs for any successful logins from this IP.",
                "Correlate with threat intelligence feeds for known malicious IP reputation.",
                "Consider deploying multi-factor authentication for all privileged accounts.",
            ]
        },
        'ANOMALY': {
            'title': 'Anomalous Behavior Detected',
            'risk': 'MEDIUM',
            'mitre': 'T1078 – Valid Accounts (Anomalous Use)',
            'description': (
                "An anomalous security event was detected from source IP {source_ip}. "
                "The machine learning anomaly detection engine identified statistical deviation from baseline behavior. "
                "This may indicate unauthorized access, insider threat, or lateral movement activity."
            ),
            'recommended_actions': [
                "Review the full event context and surrounding log entries for {source_ip}.",
                "Verify the legitimacy of the detected activity with the account owner.",
                "Correlate with other recent events from the same source IP.",
                "Check for concurrent anomalies from other systems at the same timestamp.",
                "Escalate to Tier 2 SOC analyst if anomaly cannot be explained.",
            ]
        },
        'PORT_SCAN': {
            'title': 'Network Port Scan Detected',
            'risk': 'MEDIUM',
            'mitre': 'T1046 – Network Service Discovery',
            'description': (
                "A network port scan was detected originating from {source_ip}. "
                "Sequential or rapid probing of multiple ports indicates reconnaissance activity. "
                "This may precede an exploitation attempt against discovered open services."
            ),
            'recommended_actions': [
                "Block source IP {source_ip} at the network perimeter.",
                "Review firewall logs for other suspicious activity from this source.",
                "Assess exposed services and apply necessary hardening.",
                "Enable port scan detection rules on IDS/IPS systems.",
            ]
        },
        'MULTIPLE_USERS': {
            'title': 'Multiple User Account Attack',
            'risk': 'HIGH',
            'mitre': 'T1110.003 – Password Spraying',
            'description': (
                "Attacks targeting multiple user accounts were detected from {source_ip}. "
                "This pattern is consistent with password spraying, where a single password "
                "is attempted against many accounts to avoid lockout thresholds."
            ),
            'recommended_actions': [
                "Block source IP {source_ip} at all network ingress points.",
                "Audit all targeted accounts for successful authentication.",
                "Force password reset for all potentially compromised accounts.",
                "Review and tighten authentication logging and alerting thresholds.",
            ]
        }
    }

    def analyze(self, alert_type, context):
        template = self.TEMPLATES.get(alert_type, {
            'title': 'Unknown Threat',
            'risk': 'LOW',
            'mitre': 'Unknown',
            'description': "A security event was detected from {source_ip}. Manual investigation required.",
            'recommended_actions': ["Review event logs manually.", "Escalate if suspicious."]
        })
        source_ip = context.get('source_ip', 'Unknown IP')
        username = context.get('username', 'unknown')
        try:
            description = template['description'].format(source_ip=source_ip, username=username)
            actions = [a.format(source_ip=source_ip, username=username)
                       for a in template['recommended_actions']]
        except Exception:
            description = template['description']
            actions = template['recommended_actions']
        return {
            'title': template['title'],
            'risk_level': template['risk'],
            'mitre_technique': template['mitre'],
            'description': description,
            'recommended_actions': actions,
            'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': source_ip,
            'username': username,
        }

analyzer = ThreatAnalyzer()
