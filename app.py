import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, session, redirect, url_for, request, jsonify, render_template
from database import init_db
from routes.dashboard import dashboard_bp
from routes.api import api_bp

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))
app.permanent_session_lifetime = timedelta(hours=8)

# ── Blueprints ────────────────────────────────────────────────────────────────
app.register_blueprint(dashboard_bp)
app.register_blueprint(api_bp, url_prefix='/api')

# ── Auth middleware ───────────────────────────────────────────────────────────
PUBLIC_ROUTES = {'auth.login', 'auth.do_login', 'auth.register', 'auth.do_register', 'static'}

@app.before_request
def require_login():
    if request.endpoint and (
        request.endpoint in PUBLIC_ROUTES or
        request.endpoint.startswith('static')
    ):
        return
    if 'user' not in session:
        return redirect(url_for('auth.login', next=request.url))

# ── Rate limiting (simple in-memory) ─────────────────────────────────────────
from collections import defaultdict
import time as _time
_rate_buckets = defaultdict(list)
RATE_LIMIT = 60   # max requests per minute per IP

@app.before_request
def rate_limit():
    if request.path.startswith('/api'):
        ip  = request.remote_addr
        now = _time.time()
        _rate_buckets[ip] = [t for t in _rate_buckets[ip] if now - t < 60]
        if len(_rate_buckets[ip]) >= RATE_LIMIT:
            return jsonify({'error': 'Rate limit exceeded'}), 429
        _rate_buckets[ip].append(now)

# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api'):
        return jsonify({'error': 'Not found'}), 404
    return redirect(url_for('dashboard.index'))

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html', error='Something went wrong. Please try again.'), 500

# ── Startup ───────────────────────────────────────────────────────────────────
with app.app_context():
    init_db()
    try:
        from seed_data import seed
        seed()
    except Exception as e:
        print(f"[Seed] {e}")

    from routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from log_watcher import start_watcher
    start_watcher()

    try:
        from ml.anomaly_detector import detector
        from database import get_events
        if not detector.trained:
            evts = get_events(limit=500)
            if len(evts) >= 20:
                detector.train(evts)
                print("[ML] Anomaly model auto-trained on startup.")
    except Exception as e:
        print(f"[ML] Auto-train skipped: {e}")

if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("   SentinelAI – Security Monitor")
    print("   Open: http://127.0.0.1:5000")
    print("   Login: admin / admin123")
    print("=" * 55 + "\n")
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)
