from flask import Blueprint, render_template, session
from database import get_dashboard_stats, get_alerts, get_incidents, get_reports, get_blocked_ips, get_whitelist

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats, page='dashboard',
                           user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/events')
def events():
    return render_template('events.html', page='events',
                           user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/alerts')
def alerts():
    return render_template('alerts.html', page='alerts',
                           user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/analysis')
def analysis():
    alerts_list = get_alerts(status='Open', limit=50)
    return render_template('analysis.html', alerts=alerts_list, page='analysis',
                           user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/reports')
def reports():
    incidents   = get_incidents()
    report_list = get_reports()
    return render_template('reports.html', incidents=incidents, reports=report_list,
                           page='reports', user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/blocked')
def blocked():
    blocked = get_blocked_ips()
    whitelist = get_whitelist()
    return render_template('blocked.html', blocked=blocked, whitelist=whitelist,
                           page='blocked', user=session.get('user'), role=session.get('role'))

@dashboard_bp.route('/settings')
def settings():
    return render_template('settings.html', page='settings',
                           user=session.get('user'), role=session.get('role'))
