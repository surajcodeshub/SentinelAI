import re
from flask import Blueprint, render_template, request, redirect, url_for, session
from database import (get_user, get_user_by_email, verify_password, update_last_login,
                      change_password, register_user)

auth_bp = Blueprint('auth', __name__)

def valid_email(email):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None

# ── Register ──────────────────────────────────────────────────────────────────
@auth_bp.route('/register', methods=['GET'])
def register():
    if 'user' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('register.html')

@auth_bp.route('/register', methods=['POST'])
def do_register():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm_password', '')

    # Validations
    if not username or not email or not password:
        return render_template('register.html', error='All fields are required')
    if len(username) < 3:
        return render_template('register.html', error='Username must be at least 3 characters', v=request.form)
    if not valid_email(email):
        return render_template('register.html', error='Enter a valid email address', v=request.form)
    if len(password) < 6:
        return render_template('register.html', error='Password must be at least 6 characters', v=request.form)
    if password != confirm:
        return render_template('register.html', error='Passwords do not match', v=request.form)

    ok, err = register_user(username, email, password)
    if not ok:
        return render_template('register.html', error=err, v=request.form)

    return render_template('register.html', success=True, username=username)

# ── Login ─────────────────────────────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('login.html')

@auth_bp.route('/login', methods=['POST'])
def do_login():
    identifier = request.form.get('identifier', '').strip()   # username or email
    password   = request.form.get('password', '')

    # Allow login with either username or email
    user = get_user(identifier) or get_user_by_email(identifier)

    if user and verify_password(password, user['password_hash']):
        session.permanent = True
        session['user']   = user['username']
        session['email']  = user['email']
        session['role']   = user['role']
        update_last_login(user['username'])
        return redirect(url_for('dashboard.index'))

    return render_template('login.html', error='Incorrect username/email or password',
                           identifier=identifier)

# ── Logout ────────────────────────────────────────────────────────────────────
@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

# ── Profile / Change Password ─────────────────────────────────────────────────
@auth_bp.route('/profile')
def profile():
    user = get_user(session['user'])
    return render_template('profile.html', page='profile',
                           user=session.get('user'),
                           email=user.get('email',''),
                           role=session.get('role'))

@auth_bp.route('/change_password', methods=['POST'])
def do_change_password():
    user   = get_user(session['user'])
    old_pw = request.form.get('old_password', '')
    new_pw = request.form.get('new_password', '')
    conf   = request.form.get('confirm_password', '')

    def err(msg):
        return render_template('profile.html', page='profile',
                               user=session.get('user'),
                               email=user.get('email',''),
                               role=session.get('role'), error=msg)

    if not verify_password(old_pw, user['password_hash']):
        return err('Current password is incorrect')
    if new_pw != conf:
        return err('New passwords do not match')
    if len(new_pw) < 6:
        return err('Password must be at least 6 characters')

    change_password(session['user'], new_pw)
    user2 = get_user(session['user'])
    return render_template('profile.html', page='profile',
                           user=session.get('user'),
                           email=user2.get('email',''),
                           role=session.get('role'),
                           success='Password changed successfully!')
