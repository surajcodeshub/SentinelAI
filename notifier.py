"""
Email notifier — sends alerts via Gmail SMTP or any SMTP server.
Configure in Settings page or via environment variables.
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from database import get_config


def send_alert_email(alert_type: str, severity: str, source_ip: str, description: str):
    """Send an email notification for a new alert."""
    if get_config('email_alerts', 'false') != 'true':
        return False

    smtp_host = os.environ.get('SMTP_HOST', get_config('smtp_host', 'smtp.gmail.com'))
    smtp_port = int(os.environ.get('SMTP_PORT', get_config('smtp_port', '587')))
    smtp_user = os.environ.get('SMTP_USER', get_config('smtp_user', ''))
    smtp_pass = os.environ.get('SMTP_PASS', get_config('smtp_pass', ''))
    email_to  = get_config('email_to', '')

    if not all([smtp_user, smtp_pass, email_to]):
        return False

    subject = f"[SentinelAI] {severity} Alert: {alert_type} from {source_ip}"
    body = f"""
SentinelAI Security Alert
==========================
Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Alert Type : {alert_type}
Severity   : {severity}
Source IP  : {source_ip}

Description:
{description}

---
Log in to your SentinelAI dashboard to investigate.
http://127.0.0.1:5000/alerts
"""
    try:
        msg = MIMEMultipart()
        msg['From']    = smtp_user
        msg['To']      = email_to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"[Notifier] Email sent to {email_to} for {alert_type}")
        return True
    except Exception as e:
        print(f"[Notifier] Email failed: {e}")
        return False
