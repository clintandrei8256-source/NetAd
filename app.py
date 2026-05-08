import os
import cv2
import time
import secrets
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, Response, jsonify, abort, flash)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import bleach

# ─── APP INIT ─────────────────────────────────────────────────────────────────

app = Flask(__name__)

app.config['SECRET_KEY']                     = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI']        = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:4599@localhost:5432/netmon'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY']        = True
app.config['SESSION_COOKIE_SECURE']          = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SAMESITE']        = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME']     = timedelta(minutes=30)
app.config['WTF_CSRF_TIME_LIMIT']            = 3600

db_url = app.config['SQLALCHEMY_DATABASE_URI']
if db_url.startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace('postgres://', 'postgresql://', 1)

db      = SQLAlchemy(app)
bcrypt  = Bcrypt(app)
csrf    = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

ADMIN_USERNAME  = 'admin@8080'
ADMIN_PASSWORD  = 'group2binilat'
MAX_ATTEMPTS    = 3
LOCKOUT_MINUTES = 60

# ─── TIMEZONE HELPER ──────────────────────────────────────────────────────────

def now_ph():
    """Current Philippines Standard Time (UTC+8) as a naive datetime."""
    return datetime.now(timezone(timedelta(hours=8))).replace(tzinfo=None)

# ─── MODELS ───────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)
    role          = db.Column(db.String(20), default='viewer')
    auth_provider = db.Column(db.String(20), default='local')
    gmail         = db.Column(db.String(120), unique=True, nullable=True)
    created_at    = db.Column(db.DateTime, default=now_ph)
    is_active     = db.Column(db.Boolean, default=True)
    logs          = db.relationship('LoginLog', backref='user', lazy=True,
                                    foreign_keys='LoginLog.user_id')

class LoginLog(db.Model):
    __tablename__ = 'login_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username   = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(50),  nullable=False)
    status     = db.Column(db.String(20),  nullable=False)
    timestamp  = db.Column(db.DateTime, default=now_ph, nullable=False)
    user_agent = db.Column(db.String(300))

class NetworkEvent(db.Model):
    __tablename__ = 'network_events'
    id         = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    source_ip  = db.Column(db.String(50),  nullable=False)
    detail     = db.Column(db.String(500))
    severity   = db.Column(db.String(20), default='medium')
    logged_at  = db.Column(db.DateTime, default=now_ph, nullable=False)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def get_ip():
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def log_login(username, ip, status, ua, user_id=None):
    try:
        entry = LoginLog(
            user_id    = user_id,
            username   = username[:120],
            ip_address = ip[:50],
            status     = status,
            user_agent = (ua or '')[:300],
            timestamp  = now_ph(),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.error(f'[log_login] DB error: {exc}')

def log_event(event_type, source_ip, detail, severity='medium'):
    try:
        ev = NetworkEvent(
            event_type = event_type,
            source_ip  = source_ip,
            detail     = detail,
            severity   = severity,
            logged_at  = now_ph(),
        )
        db.session.add(ev)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app.logger.error(f'[log_event] DB error: {exc}')

def sanitize(value):
    return bleach.clean(str(value).strip(), tags=[], strip=True)

def is_valid_gmail(email):
    pattern = r'^[a-zA-Z0-9._%+\-]+@gmail\.com$'
    return bool(re.match(pattern, email))

def get_failed_attempts(username):
    cutoff = now_ph() - timedelta(minutes=LOCKOUT_MINUTES)
    return LoginLog.query.filter(
        LoginLog.username  == username,
        LoginLog.status.in_(['failed', 'locked']),
        LoginLog.timestamp >= cutoff,
    ).count()

def is_account_locked(username):
    if username == ADMIN_USERNAME:
        return False, None
    cutoff = now_ph() - timedelta(minutes=LOCKOUT_MINUTES)
    fails  = LoginLog.query.filter(
        LoginLog.username  == username,
        LoginLog.status.in_(['failed', 'locked']),
        LoginLog.timestamp >= cutoff,
    ).order_by(LoginLog.timestamp.desc()).all()
    if len(fails) >= MAX_ATTEMPTS:
        oldest_fail = fails[-1].timestamp
        unlock_at   = oldest_fail + timedelta(minutes=LOCKOUT_MINUTES)
        if now_ph() < unlock_at:
            return True, unlock_at
    return False, None

# ─── DECORATORS ───────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─── TEMPLATE GLOBALS ─────────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    return {
        'csrf_token': generate_csrf,
        'username':   session.get('username', ''),
        'role':       session.get('role', ''),
        'now':        now_ph(),
    }

# ─── CAMERA STREAM ────────────────────────────────────────────────────────────

CAMERA_SOURCE = os.environ.get('CAMERA_SOURCE', 0)

def generate_frames():
    cam = None
    try:
        source = int(CAMERA_SOURCE) if str(CAMERA_SOURCE).isdigit() else CAMERA_SOURCE
        cam = cv2.VideoCapture(source)
        cam.set(cv2.CAP_PROP_FRAME_WIDTH,  1280)
        cam.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        while True:
            success, frame = cam.read()
            if not success:
                break
            ts = now_ph().strftime('%Y-%m-%d  %H:%M:%S') + ' PST'
            cv2.putText(frame, ts,    (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 220, 255), 2)
            cv2.putText(frame, 'REC', (10, 60), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0,   255), 2)
            _, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 80])
            yield (b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + buf.tobytes() + b'\r\n')
            time.sleep(0.033)
    finally:
        if cam:
            cam.release()

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    error       = None
    lockout_msg = None

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        password     = request.form.get('password', '')
        ip           = get_ip()
        ua           = request.headers.get('User-Agent', '')[:300]
        username     = sanitize(raw_username)

        # 1. Injection detection
        bad_chars = ["'", '"', '--', ';', '<script', 'DROP ', 'SELECT ', 'OR 1=1']
        if any(b.lower() in username.lower() for b in bad_chars):
            log_login(username, ip, 'injection', ua)
            log_event('Injection Attempt', ip,
                      f'Suspicious login input: {username[:80]}', 'critical')
            error = 'Invalid input detected. This incident has been logged.'
            return render_template('login.html', error=error)

        # 2. Lockout check (non-admin only)
        if username != ADMIN_USERNAME:
            locked, unlock_at = is_account_locked(username)
            if locked:
                remaining = unlock_at - now_ph()
                mins = int(remaining.total_seconds() // 60)
                secs = int(remaining.total_seconds() % 60)
                log_login(username, ip, 'locked', ua)
                lockout_msg = (f'Account locked. Try again in {mins}m {secs}s.')
                return render_template('login.html', lockout_msg=lockout_msg)

        # 3. Authenticate
        user = User.query.filter_by(username=username).first()
        if user and user.is_active and user.password_hash and \
                bcrypt.check_password_hash(user.password_hash, password):
            session.permanent   = True
            session['user_id']  = user.id
            session['username'] = user.username
            session['role']     = user.role
            log_login(username, ip, 'success', ua, user_id=user.id)
            log_event('Successful Login', ip,
                      f'User "{username}" authenticated successfully.', 'low')
            return redirect(url_for('dashboard'))
        else:
            log_login(username, ip, 'failed', ua,
                      user_id=user.id if user else None)
            if username != ADMIN_USERNAME:
                fails = get_failed_attempts(username)
                remaining_tries = MAX_ATTEMPTS - fails
                if remaining_tries <= 0:
                    log_event('Account Locked', ip,
                              f'Account "{username}" locked after {MAX_ATTEMPTS} failed attempts.',
                              'critical')
                    lockout_msg = (f'Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.')
                    return render_template('login.html', lockout_msg=lockout_msg)
                elif fails >= 2:
                    log_event('Multiple Failed Logins', ip,
                              f'{fails} failed logins for "{username}"', 'high')
                    error = f'Invalid credentials. {remaining_tries} attempt(s) remaining before lockout.'
                else:
                    error = 'Invalid username or password.'
            else:
                error = 'Invalid username or password.'

    return render_template('login.html', error=error, lockout_msg=lockout_msg)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error   = None
    success = None
    if request.method == 'POST':
        gmail   = sanitize(request.form.get('gmail', '')).lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')
        ip       = get_ip()
        if not is_valid_gmail(gmail):
            error = 'Please enter a valid @gmail.com address.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif User.query.filter((User.username == gmail) | (User.gmail == gmail)).first():
            error = 'This Gmail address is already registered.'
        else:
            pw_hash  = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(
                username      = gmail,
                password_hash = pw_hash,
                role          = 'viewer',
                auth_provider = 'gmail',
                gmail         = gmail,
                is_active     = True,
            )
            db.session.add(new_user)
            db.session.commit()
            log_event('User Registered', ip,
                      f'New viewer account registered: "{gmail}"', 'low')
            success = 'Account created successfully! You can now log in.'
    return render_template('register.html', error=error, success=success)


@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    ip       = get_ip()
    log_event('User Logout', ip, f'User "{username}" logged out.', 'low')
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    recent_logs   = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(20).all()
    recent_events = NetworkEvent.query.order_by(NetworkEvent.logged_at.desc()).limit(10).all()
    stats = {
        'total_users':   User.query.count(),
        'total_logins':  LoginLog.query.filter_by(status='success').count(),
        'failed_logins': LoginLog.query.filter(
                             LoginLog.status.in_(['failed', 'blocked', 'injection', 'locked'])).count(),
        'total_events':  NetworkEvent.query.count(),
    }
    return render_template('dashboard.html',
                           logs=recent_logs, events=recent_events, stats=stats)


@app.route('/video_feed')
@login_required
def video_feed():
    return Response(generate_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/logs')
@login_required
def logs():
    page     = request.args.get('page', 1, type=int)
    per_page = 30
    if session.get('role') == 'admin':
        login_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False)
        net_events = NetworkEvent.query.order_by(NetworkEvent.logged_at.desc()).limit(50).all()
    else:
        login_logs = LoginLog.query.filter_by(
            username=session.get('username')
        ).order_by(LoginLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False)
        net_events = []
    return render_template('logs.html', login_logs=login_logs, net_events=net_events)


@app.route('/attacks')
@login_required
def attacks():
    page     = request.args.get('page', 1, type=int)
    per_page = 30
    attack_events = NetworkEvent.query.filter(
        NetworkEvent.severity.in_(['critical', 'high'])
    ).order_by(NetworkEvent.logged_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    return render_template('attacks.html', attacks=attack_events)


@app.route('/cctv')
@login_required
def cctv():
    return render_template('cctv.html')


@app.route('/users')
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)


@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username   = sanitize(request.form.get('username', ''))
    password   = request.form.get('password', '')
    role       = request.form.get('role', 'viewer')
    gmail_addr = sanitize(request.form.get('gmail', '')).lower() or None
    if role not in ('admin', 'viewer'):
        role = 'viewer'
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('users'))
    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" already exists.', 'error')
        return redirect(url_for('users'))
    if gmail_addr and not is_valid_gmail(gmail_addr):
        flash('Invalid Gmail address format.', 'error')
        return redirect(url_for('users'))
    pw_hash  = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        username      = username,
        password_hash = pw_hash,
        role          = role,
        auth_provider = 'gmail' if gmail_addr else 'local',
        gmail         = gmail_addr,
    )
    db.session.add(new_user)
    db.session.commit()
    log_event('User Created', get_ip(),
              f'Admin created user "{username}" with role "{role}".', 'low')
    flash(f'User "{username}" created successfully.', 'success')
    return redirect(url_for('users'))


@app.route('/users/set_role/<int:uid>', methods=['POST'])
@admin_required
def set_role(uid):
    user = User.query.get_or_404(uid)
    if user.username == ADMIN_USERNAME:
        flash('Cannot change the built-in admin role.', 'error')
        return redirect(url_for('users'))
    new_role = request.form.get('role', 'viewer')
    if new_role not in ('admin', 'viewer'):
        new_role = 'viewer'
    user.role = new_role
    db.session.commit()
    log_event('Role Changed', get_ip(),
              f'Admin set "{user.username}" role to "{new_role}".', 'medium')
    flash(f'Role updated to "{new_role}" for "{user.username}".', 'success')
    return redirect(url_for('users'))


@app.route('/users/toggle/<int:uid>')
@admin_required
def toggle_user(uid):
    user = User.query.get_or_404(uid)
    if user.username != ADMIN_USERNAME:
        user.is_active = not user.is_active
        db.session.commit()
        state = 'enabled' if user.is_active else 'disabled'
        log_event('User Toggled', get_ip(),
                  f'Admin {state} user "{user.username}".', 'medium')
    return redirect(url_for('users'))


@app.route('/users/delete/<int:uid>')
@admin_required
def delete_user(uid):
    user = User.query.get_or_404(uid)
    if user.username != ADMIN_USERNAME:
        log_event('User Deleted', get_ip(),
                  f'Admin deleted user "{user.username}".', 'medium')
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('users'))


# ─── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify({
        'total_users':    User.query.count(),
        'success_logins': LoginLog.query.filter_by(status='success').count(),
        'failed_logins':  LoginLog.query.filter(
                              LoginLog.status.in_(['failed', 'blocked', 'injection', 'locked'])).count(),
        'total_events':   NetworkEvent.query.count(),
    })

@app.route('/api/recent-logs')
@login_required
def api_recent_logs():
    query = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(10)
    if session.get('role') != 'admin':
        query = query.filter_by(username=session.get('username'))
    return jsonify([{
        'username':   l.username,
        'ip_address': l.ip_address,
        'status':     l.status,
        'timestamp':  l.timestamp.strftime('%Y-%m-%d %H:%M:%S') + ' PST',
    } for l in query.all()])

# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, msg='Access denied. Admins only.'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, msg='Page not found.'), 404

@app.errorhandler(429)
def rate_limited(e):
    ip = get_ip()
    log_event('Rate Limit Exceeded', ip, 'Too many requests.', 'high')
    return render_template('error.html', code=429,
                           msg='Too many requests. You have been temporarily blocked.'), 429

# ─── DB INIT ──────────────────────────────────────────────────────────────────

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=ADMIN_USERNAME).first():
            pw    = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')
            admin = User(username=ADMIN_USERNAME, password_hash=pw,
                         role='admin', auth_provider='local')
            db.session.add(admin)
            db.session.commit()
            print(f'✅ Admin created — username: {ADMIN_USERNAME} | password: {ADMIN_PASSWORD}')
        else:
            print(f'ℹ️  Admin "{ADMIN_USERNAME}" already exists.')

init_db()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
