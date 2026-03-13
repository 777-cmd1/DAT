"""DAT Mailer Web App v2 — with invite-only auth"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import re, csv, os, json, smtplib, random, threading, time, imaplib, secrets
import email as email_lib
from datetime import datetime, date, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header as decode_email_header
from collections import Counter
from functools import wraps

import bcrypt
from dotenv import load_dotenv
load_dotenv()

# ── DB extensions (models imported after app is created) ──────────────────
from app.extensions import db, migrate as flask_migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ── Database configuration ─────────────────────────────────────────────────
# Dev: SQLite  |  Prod (Railway): PostgreSQL via DATABASE_URL env var
_default_db = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dat_mailer_dev.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', _default_db)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── Session / Cookie security ───────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SECURE flag: active when DATABASE_URL is set (Railway/prod) OR FLASK_ENV=production.
# Dev with SQLite has no DATABASE_URL so cookies stay HTTP-safe locally.
_is_production = bool(os.environ.get('DATABASE_URL')) or os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = _is_production

db.init_app(app)
flask_migrate.init_app(app, db)

# ── CSRF helpers ─────────────────────────────────────────────────────────────
# Session-based CSRF token for HTML form pages (login, register, reset).
# JSON-only API routes are covered by SameSite=Lax cookie.

def _get_csrf_token() -> str:
    """Return (and lazily create) a per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf() -> bool:
    """Check X-CSRF-Token header or _csrf body field against session token."""
    expected = session.get('csrf_token', '')
    if not expected:
        return False
    received = (
        request.headers.get('X-CSRF-Token') or
        (request.get_json(silent=True) or {}).get('_csrf', '')
    )
    return bool(received) and secrets.compare_digest(expected, received)

def csrf_protected(fn):
    """Decorator: reject POST requests without a valid CSRF token."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            if not _validate_csrf():
                return jsonify({'error': 'Invalid CSRF token'}), 403
        return fn(*args, **kwargs)
    return wrapper

# ── Rate limiter ────────────────────────────────────────────────────────────
# Storage priority:
#   1. REDIS_URL env var (Railway Redis add-on sets this automatically)
#   2. RATELIMIT_STORAGE_URI env var (manual override)
#   3. memory:// fallback (dev / single-worker only)
_limiter_storage = (
    os.environ.get('REDIS_URL') or
    os.environ.get('RATELIMIT_STORAGE_URI') or
    'memory://'
)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],           # No global limit — apply per-route only
    storage_uri=_limiter_storage,
)

# Import models so Flask-Migrate can detect them
import app.models as _models  # noqa: F401

# ── Field-level encryption (Gmail credentials at rest) ───────────────────────
# Requires ENCRYPTION_KEY env var set to a valid Fernet key.
# Generate one with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# If ENCRYPTION_KEY is not set, credentials are stored unencrypted (dev mode only).
from cryptography.fernet import Fernet, InvalidToken as _FernetInvalidToken

_fernet_instance = None

def _get_fernet():
    global _fernet_instance
    if _fernet_instance is None:
        raw = os.environ.get('ENCRYPTION_KEY', '')
        if raw:
            try:
                _fernet_instance = Fernet(raw.encode() if isinstance(raw, str) else raw)
            except Exception:
                pass   # bad key — fall through to unencrypted mode
    return _fernet_instance

def encrypt_field(value: str) -> str:
    """Encrypt a plaintext string. Returns encrypted token or original if no key configured."""
    if not value:
        return value
    f = _get_fernet()
    if f is None:
        return value   # no ENCRYPTION_KEY — dev mode, store as-is
    return f.encrypt(value.encode('utf-8')).decode('utf-8')

def decrypt_field(value: str) -> str:
    """Decrypt a Fernet token. Returns plaintext or original if not encrypted / no key."""
    if not value:
        return value
    f = _get_fernet()
    if f is None:
        return value   # no key — assume plaintext
    try:
        return f.decrypt(value.encode('utf-8')).decode('utf-8')
    except (_FernetInvalidToken, Exception):
        return value   # not a Fernet token (legacy plaintext) — return as-is

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Your admin email
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'your@email.com')

# ── SaaS PLAN QUOTAS (emails/day; None = unlimited) ──────────────────────────
PLAN_QUOTAS = {
    'free':    50,
    'starter': 300,
    'pro':     None,   # unlimited
}

# ── SCHEDULED FOLLOW-UP DELAYS (days after last contact/send) ────────────────
FU_AUTO_DELAYS = {'FU1': 3, 'FU2': 5, 'FU3': 7}

# ── Per-user send state ───────────────────────────────────────────────────────
# Keyed by user_id so concurrent users cannot see or overwrite each other's progress.
_send_states: dict = {}

def _user_send_state(uid: str) -> dict:
    """Get (or initialise) the send-progress dict for a specific user."""
    if uid not in _send_states:
        _send_states[uid] = {
            "running": False, "done": False,
            "total": 0, "current": 0,
            "sent": 0, "errors": 0, "skipped": 0, "log": [],
        }
    return _send_states[uid]
DEFAULT_CONFIG = {"gmail_address":"","gmail_app_password":"","your_name":"","your_company":"","your_phone":"","delay_min":20,"delay_max":45}

# ─── AUTH HELPERS ──────────────────────────────────────────────────────────────

def hash_password(password):
    """Hash password with bcrypt (12 rounds). Returns str."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def verify_password(password, stored):
    """Verify against bcrypt hash. Accepts both bcrypt and legacy sha256:salt format."""
    try:
        if stored.startswith('$2b$') or stored.startswith('$2a$'):
            return bcrypt.checkpw(password.encode('utf-8'), stored.encode('utf-8'))
        # Legacy SHA-256 fallback (auto-upgrades on next login — see api_login)
        import hashlib
        salt, h = stored.split(':')
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False

def load_users():
    """Return all users as list of dicts (legacy shape for auth routes)."""
    from app.models import User
    return [{'email': u.email, 'name': u.name, 'password': u.password,
             'invited_by': u.invited_by,
             'created_at': u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else ''}
            for u in User.query.all()]

def save_users(users):
    """Upsert list-of-dicts into User table."""
    from app.models import User
    for u in users:
        existing = User.query.filter_by(email=u['email'].lower()).first()
        if existing:
            existing.name = u.get('name', existing.name)
            existing.password = u.get('password', existing.password)
            existing.invited_by = u.get('invited_by', existing.invited_by)
        else:
            db.session.add(User(
                email=u['email'].lower(), name=u.get('name', ''),
                password=u['password'], invited_by=u.get('invited_by'),
            ))
    db.session.commit()

def get_user(email):
    from app.models import User
    u = User.query.filter(User.email == email.strip().lower()).first()
    if not u: return None
    return {'email': u.email, 'name': u.name, 'password': u.password,
            'invited_by': u.invited_by}

def load_invites():
    from app.models import Invitation
    return [i.to_dict() for i in Invitation.query.order_by(Invitation.created_at.desc()).all()]

def save_invites(invites):
    """Upsert invite list into Invitation table."""
    from app.models import Invitation
    for inv in invites:
        existing = Invitation.query.filter_by(token=inv['token']).first()
        if existing:
            existing.status = 'accepted' if inv.get('used') else 'pending'
            if inv.get('used_at'):
                from datetime import datetime as _dt
                try: existing.used_at = _dt.strptime(inv['used_at'], '%Y-%m-%d %H:%M')
                except: pass
        else:
            db.session.add(Invitation(
                token=inv['token'], email=inv['email'].lower(),
                invited_by=inv.get('invited_by'),
                status='accepted' if inv.get('used') else 'pending',
            ))
    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            if request.is_json:
                return jsonify({'error': 'Not authenticated'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_email', '').lower() != ADMIN_EMAIL.lower():
            if request.is_json:
                return jsonify({'error': 'Admin only'}), 403
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET'])
def login_page():
    if 'user_email' in session:
        return redirect(url_for('index'))
    return render_template('login.html', csrf_token=_get_csrf_token())

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute; 30 per hour")   # brute-force protection
@csrf_protected
def api_login():
    data = request.json
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    user = get_user(email)
    if not user or not verify_password(password, user['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    # Auto-upgrade legacy SHA-256 hash to bcrypt on successful login
    stored = user['password']
    if not (stored.startswith('$2b$') or stored.startswith('$2a$')):
        users = load_users()
        for u in users:
            if u['email'].lower() == email:
                u['password'] = hash_password(password)
                break
        save_users(users)
    session.clear()   # prevent session fixation
    session['user_email'] = user['email']
    session['user_name'] = user.get('name', email)
    audit_log('login', resource_type='user', detail={'email': email})
    return jsonify({'ok': True, 'name': user.get('name', email)})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})

# ── PASSWORD RESET ────────────────────────────────────────────────────────────

@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    """Show the "forgot password" form. ?token=... shows the new-password form."""
    token = request.args.get('token', '').strip()
    if token:
        from app.models import PasswordResetToken
        from datetime import timedelta
        pr = PasswordResetToken.query.filter_by(token=token, used_at=None).first()
        expired = pr and (datetime.utcnow() - pr.created_at > timedelta(hours=1))
        if not pr or expired:
            return render_template('reset_password.html', mode='invalid')
        return render_template('reset_password.html', mode='new_password', token=token,
                               csrf_token=_get_csrf_token())
    return render_template('reset_password.html', mode='request', csrf_token=_get_csrf_token())


@app.route('/api/auth/reset-request', methods=['POST'])
@csrf_protected
def api_reset_request():
    """Create a reset token and email it via the admin's Gmail account."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').lower().strip()
    if not email:
        return jsonify({'error': 'Email required'}), 400

    from app.models import User, PasswordResetToken, EmailAccount
    user = User.query.filter_by(email=email).first()
    # Always return success to prevent email enumeration
    if not user:
        return jsonify({'ok': True, 'msg': 'If that email exists, a reset link has been sent.'})

    # Invalidate old unused tokens for this email
    PasswordResetToken.query.filter_by(email=email, used_at=None).delete()
    token = secrets.token_urlsafe(48)
    db.session.add(PasswordResetToken(email=email, token=token))
    db.session.commit()

    # Build reset URL
    base_url = request.host_url.rstrip('/')
    reset_url = f"{base_url}/reset-password?token={token}"

    # Try to send via admin's Gmail account
    admin_acct = EmailAccount.query.join(User, User.id == EmailAccount.user_id)\
        .filter(User.email == ADMIN_EMAIL).first()

    if admin_acct and admin_acct.gmail_address and admin_acct.gmail_password:
        gmail = admin_acct.gmail_address
        pw    = decrypt_field(admin_acct.gmail_password)
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'DAT Mailer — Password Reset'
            msg['From']    = f'DAT Mailer <{gmail}>'
            msg['To']      = email
            html_body = f"""<div style="font-family:Inter,sans-serif;background:#0a0a0f;color:#e2e2f0;padding:32px;max-width:480px">
<h2 style="color:#6366f1;margin-bottom:8px">Password Reset</h2>
<p style="color:#9999bb;margin-bottom:24px">Click the button below to reset your DAT Mailer password. This link expires in <strong>1 hour</strong>.</p>
<a href="{reset_url}" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,#6366f1,#22c55e);color:#fff;text-decoration:none;border-radius:8px;font-weight:600">Reset Password</a>
<p style="margin-top:24px;font-size:12px;color:#6b6b8a">Or copy this link:<br><span style="color:#6366f1">{reset_url}</span></p>
<p style="margin-top:24px;font-size:11px;color:#444466">If you didn't request this, ignore this email.</p>
</div>"""
            msg.attach(MIMEText(html_body, 'html'))
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.starttls()
                s.login(gmail, pw)
                s.sendmail(gmail, [email], msg.as_string())
        except Exception as e:
            app.logger.error(f'Password reset email failed: {e}')
            # Fall through — token still saved, admin can share link manually

    return jsonify({'ok': True, 'msg': 'If that email exists, a reset link has been sent.'})


@app.route('/api/auth/reset-confirm', methods=['POST'])
@csrf_protected
def api_reset_confirm():
    """Validate reset token and set new password."""
    from datetime import timedelta
    data = request.get_json(silent=True) or {}
    token    = (data.get('token') or '').strip()
    password = data.get('password', '')

    if not token or not password:
        return jsonify({'error': 'Token and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if len(password) > 128:
        return jsonify({'error': 'Password too long'}), 400

    from app.models import PasswordResetToken, User
    pr = PasswordResetToken.query.filter_by(token=token, used_at=None).first()
    if not pr:
        return jsonify({'error': 'Invalid or already used reset link'}), 400
    if datetime.utcnow() - pr.created_at > timedelta(hours=1):
        return jsonify({'error': 'Reset link has expired. Please request a new one.'}), 400

    user = User.query.filter_by(email=pr.email).first()
    if not user:
        return jsonify({'error': 'Account not found'}), 400

    user.password = hash_password(password)
    pr.used_at = datetime.utcnow()
    db.session.commit()

    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if 'user_email' not in session:
        return jsonify({'authenticated': False}), 401
    is_admin = session['user_email'].lower() == ADMIN_EMAIL.lower()
    return jsonify({'authenticated': True, 'email': session['user_email'], 'name': session.get('user_name'), 'is_admin': is_admin})

@app.route('/register/<token>', methods=['GET'])
def register_page(token):
    from app.models import Invitation
    invite = Invitation.query.filter_by(token=token, status='pending').first()
    if not invite:
        return render_template('login.html', error='Invalid or expired invite link.')
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        invite.status = 'expired'
        db.session.commit()
        return render_template('login.html', error='This invite link has expired. Please request a new one.')
    return render_template('register.html', token=token, email=invite.email,
                           csrf_token=_get_csrf_token())

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
@csrf_protected
def api_register():
    data = request.json or {}
    token    = (data.get('token') or '').strip()
    password = data.get('password') or ''
    name     = (data.get('name') or '').strip()[:100]   # max 100 chars

    if not token:
        return jsonify({'error': 'Invite token required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if len(password) > 128:
        return jsonify({'error': 'Password too long (max 128 characters)'}), 400

    from app.models import Invitation, User as UserModel
    invite = Invitation.query.filter_by(token=token, status='pending').first()
    if not invite:
        return jsonify({'error': 'Invalid or expired invite'}), 400
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        invite.status = 'expired'
        db.session.commit()
        return jsonify({'error': 'This invite link has expired. Please request a new one.'}), 400

    email = invite.email.lower()
    if UserModel.query.filter_by(email=email).first():
        return jsonify({'error': 'Account already exists'}), 400

    user = UserModel(
        email=email, name=name or email,
        password=hash_password(password),
        invited_by=invite.invited_by,
    )
    db.session.add(user)
    invite.status = 'accepted'
    invite.used_at = datetime.now()
    db.session.flush()   # populate user.id
    get_or_create_workspace(user.id, name=f"{name or email}'s Workspace")
    db.session.commit()

    session.clear()   # prevent session fixation
    session['user_email'] = email
    session['user_name'] = name or email
    return jsonify({'ok': True})

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html')

@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def api_admin_users():
    users = load_users()
    safe = [{'email': u['email'], 'name': u.get('name'), 'created_at': u.get('created_at'), 'invited_by': u.get('invited_by')} for u in users]
    return jsonify(safe)

@app.route('/api/admin/invite', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per hour")    # prevent invite spam
def api_admin_invite():
    data = request.json
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400

    # Check if already a user
    if get_user(email):
        return jsonify({'error': 'User already exists'}), 400

    token = secrets.token_urlsafe(32)
    from app.models import Invitation
    # Remove old unused invites for same email
    Invitation.query.filter_by(email=email, status='pending').delete()
    db.session.add(Invitation(
        token=token, email=email, invited_by=current_user_id(),
        expires_at=datetime.utcnow() + timedelta(days=7),
    ))
    db.session.commit()

    # Send invite email
    base_url = request.host_url.rstrip('/')
    invite_url = f"{base_url}/register/{token}"
    _send_invite_email(email, invite_url)

    return jsonify({'ok': True, 'invite_url': invite_url})

@app.route('/api/admin/invites', methods=['GET'])
@login_required
@admin_required
def api_admin_invites():
    return jsonify(load_invites())

@app.route('/api/admin/users/delete', methods=['POST'])
@login_required
@admin_required
def api_admin_delete_user():
    email = (request.json.get('email') or '').lower()
    if email == ADMIN_EMAIL.lower():
        return jsonify({'error': 'Cannot delete admin'}), 400
    from app.models import User as UserModel
    UserModel.query.filter_by(email=email).delete()
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/stats/overview', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_overview():
    """System-wide aggregate stats for admin overview panel."""
    from app.models import User as UserModel, Workspace, Send, Reply, UsageEvent
    today = date.today()
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)

    total_users      = UserModel.query.count()
    total_workspaces = Workspace.query.count()
    sends_today      = Send.query.filter(Send.status == 'sent',
                           db.func.date(Send.sent_at) == today).count()
    replies_total    = Reply.query.count()
    active_users_24h = db.session.query(Send.user_id).filter(
                           Send.sent_at >= cutoff_24h).distinct().count()

    plan_counts = {}
    for ws in Workspace.query.all():
        p = ws.plan or 'free'
        plan_counts[p] = plan_counts.get(p, 0) + 1

    return jsonify({
        'total_users':      total_users,
        'total_workspaces': total_workspaces,
        'sends_today':      sends_today,
        'replies_total':    replies_total,
        'active_users_24h': active_users_24h,
        'plans':            plan_counts,
    })


@app.route('/api/admin/stats/accounts', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_accounts():
    """Per-account summary table for admin Accounts section."""
    from app.models import User as UserModel, Workspace, Send, Reply, FollowUp, EmailAccount, UsageEvent
    today = date.today()

    result = []
    for u in UserModel.query.order_by(UserModel.created_at.desc()).all():
        ws   = Workspace.query.filter_by(owner_id=u.id).first()
        acct = EmailAccount.query.filter_by(user_id=u.id).first()
        plan  = (ws.plan if ws else None) or 'free'
        limit = PLAN_QUOTAS.get(plan, 50)

        sends_total  = Send.query.filter_by(user_id=u.id, status='sent').count()
        sends_today  = Send.query.filter_by(user_id=u.id, status='sent').filter(
                           db.func.date(Send.sent_at) == today).count()
        replies_total   = Reply.query.filter_by(user_id=u.id).count()
        followups_total = FollowUp.query.filter_by(user_id=u.id).count()
        quota_used = db.session.query(db.func.sum(UsageEvent.count)).filter(
                         UsageEvent.user_id == u.id,
                         UsageEvent.event_type == 'email_sent',
                         UsageEvent.period_date == today).scalar() or 0

        last_send    = Send.query.filter_by(user_id=u.id).order_by(Send.sent_at.desc()).first()
        last_activity = (last_send.sent_at.strftime('%Y-%m-%d %H:%M')
                         if last_send and last_send.sent_at else None)

        result.append({
            'user_id':        u.id,
            'email':          u.email,
            'name':           u.name or '',
            'workspace_name': ws.name if ws else '—',
            'plan':           plan,
            'created_at':     u.created_at.strftime('%Y-%m-%d') if u.created_at else '',
            'sends_total':    sends_total,
            'sends_today':    sends_today,
            'replies_total':  replies_total,
            'followups_total': followups_total,
            'quota_used_today': int(quota_used),
            'quota_limit':    limit,
            'email_connected': bool(acct and acct.gmail_address),
            'last_activity':  last_activity,
        })
    return jsonify(result)


@app.route('/api/admin/stats/account/<user_id>', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_account(user_id):
    """Full drill-down for a single account. Never returns gmail_password."""
    from app.models import (User as UserModel, Workspace, Send, Reply,
                            FollowUp, EmailAccount, PipelineContact,
                            AuditLog, UsageEvent)
    today    = date.today()
    week_ago = datetime.utcnow() - timedelta(days=7)

    u = UserModel.query.get(user_id)
    if not u:
        return jsonify({'error': 'User not found'}), 404

    ws   = Workspace.query.filter_by(owner_id=u.id).first()
    acct = EmailAccount.query.filter_by(user_id=u.id).first()
    plan  = (ws.plan if ws else None) or 'free'
    limit = PLAN_QUOTAS.get(plan, 50)

    quota_used = db.session.query(db.func.sum(UsageEvent.count)).filter(
                     UsageEvent.user_id == u.id,
                     UsageEvent.event_type == 'email_sent',
                     UsageEvent.period_date == today).scalar() or 0

    sends_total = Send.query.filter_by(user_id=u.id, status='sent').count()
    sends_today = Send.query.filter_by(user_id=u.id, status='sent').filter(
                      db.func.date(Send.sent_at) == today).count()
    sends_week  = Send.query.filter_by(user_id=u.id, status='sent').filter(
                      Send.sent_at >= week_ago).count()

    replies = {
        'total':          Reply.query.filter_by(user_id=u.id).count(),
        'interested':     Reply.query.filter_by(user_id=u.id, status='interested').count(),
        'not_interested': Reply.query.filter_by(user_id=u.id, status='not_interested').count(),
        'new':            Reply.query.filter_by(user_id=u.id, status='new').count(),
    }
    followups = {
        'total':   FollowUp.query.filter_by(user_id=u.id).count(),
        'pending': FollowUp.query.filter_by(user_id=u.id, status='pending').count(),
        'sent':    FollowUp.query.filter_by(user_id=u.id, status='sent').count(),
        'closed':  FollowUp.query.filter_by(user_id=u.id, status='closed').count(),
    }
    pipeline_size = PipelineContact.query.filter_by(user_id=u.id).count()

    recent_audit = [a.to_dict() for a in
                    AuditLog.query.filter_by(user_id=u.id)
                    .order_by(AuditLog.created_at.desc()).limit(10).all()]
    recent_sends = [s.to_dict() for s in
                    Send.query.filter_by(user_id=u.id)
                    .order_by(Send.sent_at.desc()).limit(10).all()]

    return jsonify({
        'user': {
            'id': u.id, 'email': u.email, 'name': u.name, 'role': u.role,
            'created_at': u.created_at.strftime('%Y-%m-%d %H:%M') if u.created_at else '',
            'last_login':  u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else None,
        },
        'workspace': {
            'id': ws.id if ws else None,
            'name': ws.name if ws else '—',
            'plan': plan,
        },
        'email_connected': bool(acct and acct.gmail_address),
        'gmail_address':   acct.gmail_address if acct else None,  # address only — never password
        'quota': {
            'used': int(quota_used), 'limit': limit, 'unlimited': limit is None,
        },
        'sends_total': sends_total, 'sends_today': sends_today, 'sends_week': sends_week,
        'replies':    replies,
        'followups':  followups,
        'pipeline_size': pipeline_size,
        'recent_audit':  recent_audit,
        'recent_sends':  recent_sends,
    })


def _send_invite_email(to_email, invite_url):
    """Send invite email using the configured Gmail account."""
    try:
        cfg = load_config()
        if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'):
            return False
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']
        msg['To'] = to_email
        msg['Subject'] = "You've been invited to DAT Mailer"
        body = f"""Hi,

You've been invited to use DAT Mailer — a freight outreach automation tool.

Click the link below to create your account:
{invite_url}

This link expires after first use.

Best regards,
DAT Mailer Team"""
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, cfg['gmail_address'], to_email, cfg['gmail_app_password'])
        return True
    except:
        return False

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def current_user_id():
    """Return User.id for the logged-in session user, or None."""
    email = session.get('user_email')
    if not email: return None
    from app.models import User as _U
    u = _U.query.filter_by(email=email.lower()).first()
    return u.id if u else None

def audit_log(action, resource_type=None, resource_id=None, detail=None, uid=None):
    """Write an audit entry to the DB. Silent on failure — never breaks the main request.
    Pass uid explicitly when calling from background threads (no request context)."""
    try:
        from app.models import AuditLog as _AL
        # Safely get ip — only available in request context
        try:
            ip = request.remote_addr
        except RuntimeError:
            ip = None
        db.session.add(_AL(
            user_id=uid if uid is not None else current_user_id(),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=json.dumps(detail) if detail and not isinstance(detail, str) else detail,
            ip_address=ip,
        ))
        db.session.commit()
    except Exception:
        pass   # Audit must never crash the main flow

# ── WORKSPACE HELPERS ────────────────────────────────────────────────────────

def get_or_create_workspace(user_id, name='My Workspace'):
    """Get or auto-create a personal workspace for a user (idempotent)."""
    from app.models import Workspace
    ws = Workspace.query.filter_by(owner_id=user_id).first()
    if not ws:
        ws = Workspace(owner_id=user_id, name=name, plan='free')
        db.session.add(ws)
        db.session.commit()
    return ws

def current_workspace_id():
    """Return the current user's primary workspace ID (auto-creates if absent)."""
    uid = current_user_id()
    if not uid: return None
    return get_or_create_workspace(uid).id

# ── QUOTA HELPERS ─────────────────────────────────────────────────────────────

def get_daily_quota(uid=None):
    """Return quota status for today. Works from any context (pass uid explicitly in threads)."""
    if uid is None:
        uid = current_user_id()
    if not uid:
        return {'plan': 'free', 'limit': 0, 'used': 0, 'remaining': 0, 'pct': 0, 'unlimited': False}
    from app.models import Workspace, UsageEvent, User as _User
    user = _User.query.filter_by(id=uid).first()
    if user and (user.role == 'admin' or getattr(user, 'plan', 'free') == 'pro'):
        plan, limit = 'pro', None
    else:
        ws = Workspace.query.filter_by(owner_id=uid).first()
        plan = (ws.plan if ws else None) or 'free'
        limit = PLAN_QUOTAS.get(plan, 50)
    today = date.today()
    used = db.session.query(db.func.sum(UsageEvent.count)).filter(
        UsageEvent.user_id == uid,
        UsageEvent.event_type == 'email_sent',
        UsageEvent.period_date == today,
    ).scalar() or 0
    unlimited = limit is None
    remaining = None if unlimited else max(0, limit - int(used))
    pct = 0 if unlimited or not limit else min(100, round(100 * int(used) / limit))
    return {
        'plan': plan, 'limit': limit, 'used': int(used),
        'remaining': remaining, 'unlimited': unlimited, 'pct': pct,
    }

def _track_usage(uid, event_type, count=1):
    """Upsert a daily UsageEvent row. Silent on failure."""
    if not uid: return
    try:
        from app.models import UsageEvent
        today = date.today()
        ev = UsageEvent.query.filter_by(
            user_id=uid, event_type=event_type, period_date=today
        ).first()
        if ev:
            ev.count += count
        else:
            db.session.add(UsageEvent(
                user_id=uid, event_type=event_type,
                count=count, period_date=today,
            ))
        db.session.commit()
    except Exception:
        pass

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def load_config():
    uid = current_user_id()
    if not uid: return DEFAULT_CONFIG.copy()
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if not acct: return DEFAULT_CONFIG.copy()
    cfg = acct.to_config_dict()
    # Decrypt password at read time — transparent to all callers
    cfg['gmail_app_password'] = decrypt_field(cfg['gmail_app_password'])
    return cfg

def save_config(cfg):
    uid = current_user_id()
    if not uid: return
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    # Encrypt the password before storing; leave other fields plaintext
    new_pw = cfg.get('gmail_app_password')
    encrypted_pw = encrypt_field(new_pw) if new_pw else None
    if acct:
        acct.gmail_address  = cfg.get('gmail_address', acct.gmail_address)
        if encrypted_pw is not None:
            acct.gmail_password = encrypted_pw
        acct.your_name      = cfg.get('your_name', acct.your_name)
        acct.your_company   = cfg.get('your_company', acct.your_company)
        acct.your_phone     = cfg.get('your_phone', acct.your_phone)
        acct.delay_min      = int(cfg.get('delay_min', acct.delay_min))
        acct.delay_max      = int(cfg.get('delay_max', acct.delay_max))
    else:
        db.session.add(EmailAccount(
            user_id=uid,
            gmail_address  = cfg.get('gmail_address', ''),
            gmail_password = encrypted_pw or '',
            your_name      = cfg.get('your_name', ''),
            your_company   = cfg.get('your_company', ''),
            your_phone     = cfg.get('your_phone', ''),
            delay_min      = int(cfg.get('delay_min', 20)),
            delay_max      = int(cfg.get('delay_max', 45)),
        ))
    db.session.commit()

DEFAULT_TEMPLATES = [
    "Hi,\n\nAre you still working on this load?\nPlease provide more info.\n\nThanks,\n{name}\n{company} | {phone}",
    "Hello,\n\nLoad from {origin} to {destination}, is it still available?\nPlease provide more details.\n\nThank you,\n{name}\n{company} | {phone}",
    "Hello,\n\nSaw your load posting — is this still active?\nPlease advise details.\n\nThanks,\n{name}\n{company} | {phone}",
]

def load_templates():
    uid = current_user_id()
    if not uid: return DEFAULT_TEMPLATES.copy()
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='outreach', is_active=True)\
                         .order_by(Template.sort_order).all()
    if rows: return [r.body for r in rows]
    return DEFAULT_TEMPLATES.copy()

def save_templates_file(bodies):
    uid = current_user_id()
    if not uid: return
    from app.models import Template
    Template.query.filter_by(user_id=uid, type='outreach').delete()
    for i, body in enumerate(bodies):
        db.session.add(Template(user_id=uid, type='outreach', body=body, sort_order=i))
    db.session.commit()

def render_template_text(tmpl, load, cfg):
    return tmpl.format(name=cfg.get("your_name",""),company=cfg.get("your_company",""),
        phone=cfg.get("your_phone",""),origin=load.get("origin",""),
        destination=load.get("destination",""),date=load.get("date",""),equip=load.get("equip",""))

def load_stop_list():
    uid = current_user_id()
    be, bd = set(), set()
    if not uid: return be, bd
    from app.models import StopListEntry
    for e in StopListEntry.query.filter_by(user_id=uid).all():
        if e.type == 'email': be.add(e.value.lower())
        else: bd.add(e.value.lower())
    return be, bd

def get_stop_list_raw():
    uid = current_user_id()
    if not uid: return []
    from app.models import StopListEntry
    return [e.to_dict() for e in StopListEntry.query.filter_by(user_id=uid).all()]

def write_stop_list(entries):
    uid = current_user_id()
    if not uid: return
    from app.models import StopListEntry
    StopListEntry.query.filter_by(user_id=uid).delete()
    seen = set()
    for e in entries:
        key = (e['type'], e['value'].strip().lower())
        if key in seen: continue
        seen.add(key)
        db.session.add(StopListEntry(
            user_id=uid, type=e['type'],
            value=e['value'].strip().lower(),
            reason=e.get('reason', ''),
        ))
    db.session.commit()

def is_blocked(email, be, bd):
    em=email.strip().lower()
    if em in be: return True
    dom=em.split('@')[-1] if '@' in em else ''
    return bool(dom and dom in bd)

def load_sent_log(uid=None):
    """Pass uid explicitly when calling from background threads."""
    if uid is None:
        uid = current_user_id()
    all_sent, sent_today = set(), set()
    if not uid: return all_sent, sent_today
    from app.models import Send
    today = date.today()
    for s in Send.query.filter_by(user_id=uid, status='sent').all():
        em = s.recipient_email.lower()
        all_sent.add(f"{em}|{s.origin}|{s.destination}")
        if s.sent_at and s.sent_at.date() == today:
            sent_today.add(em)
    return all_sent, sent_today

def append_log(load, status, variant=0, uid=None):
    """Pass uid explicitly when calling from background threads."""
    if uid is None:
        uid = current_user_id()
    if not uid: return
    from app.models import Send
    db.session.add(Send(
        user_id=uid,
        recipient_email=load['email'],
        origin=load.get('origin', ''), destination=load.get('destination', ''),
        load_date=load.get('date', ''), equipment=load.get('equip', ''),
        weight=load.get('weight', ''), company=load.get('company', ''),
        template_variant=variant, status=status,
    ))
    db.session.commit()

def get_log_rows():
    uid = current_user_id()
    if not uid: return []
    from app.models import Send
    rows = Send.query.filter_by(user_id=uid).order_by(Send.sent_at.desc()).all()
    return [r.to_dict() for r in rows]

def load_replies():
    uid = current_user_id()
    if not uid: return []
    from app.models import Reply
    return [r.to_dict() for r in Reply.query.filter_by(user_id=uid)
                                             .order_by(Reply.received_at.desc()).all()]

def save_replies(replies):
    """Upsert reply list — used by legacy code paths."""
    uid = current_user_id()
    if not uid: return
    from app.models import Reply
    for r in replies:
        existing = Reply.query.filter_by(msg_id=r['msg_id']).first()
        if existing:
            existing.status = r.get('status', existing.status)
        else:
            db.session.add(Reply(
                user_id=uid, msg_id=r['msg_id'],
                from_email=r.get('email', ''), from_name=r.get('from', ''),
                subject=r.get('subject', ''), body=r.get('body', ''),
                route=r.get('route', ''), status=r.get('status', 'new'),
            ))
    db.session.commit()

def decode_str(s):
    if s is None: return ""
    parts=decode_email_header(s)
    result=[]
    for part,enc in parts:
        if isinstance(part,bytes): result.append(part.decode(enc or 'utf-8',errors='replace'))
        else: result.append(str(part))
    return " ".join(result)

def get_email_body(msg):
    body=""
    if msg.is_multipart():
        for part in msg.walk():
            ct=part.get_content_type()
            disp=str(part.get("Content-Disposition",""))
            if ct=="text/plain" and "attachment" not in disp:
                try: body=part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8',errors='replace'); break
                except: pass
    else:
        try: body=msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8',errors='replace')
        except: pass
    lines,clean=body.split('\n'),[]
    for line in lines:
        if line.startswith('>') or (line.startswith('On ') and 'wrote:' in line): break
        clean.append(line)
    return '\n'.join(clean).strip()[:1000]

def get_known_emails():
    uid = current_user_id()
    if not uid: return set()
    from app.models import Send
    rows = db.session.query(Send.recipient_email).filter_by(user_id=uid).distinct().all()
    return {r[0].lower() for r in rows}

def get_route_for_email(email_addr):
    uid = current_user_id()
    if not uid: return ""
    from app.models import Send
    last = Send.query.filter_by(user_id=uid, recipient_email=email_addr.lower())\
                     .order_by(Send.sent_at.desc()).first()
    if last: return f"{last.origin} → {last.destination}"
    return ""

_last_fetch_times: dict = {}   # per-user IMAP throttle: {user_id: timestamp}

def fetch_replies_from_gmail():
    cfg=load_config()
    if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'): return {'error':'Gmail not configured'}
    uid = current_user_id()
    now = time.time()
    last = _last_fetch_times.get(uid, 0)
    if now - last < 60:
        wait = int(60 - (now - last))
        return {'error': f'Please wait {wait}s before checking again', 'rate_limited': True}
    _last_fetch_times[uid] = now
    known=get_known_emails()
    existing=load_replies()
    existing_ids={r['msg_id'] for r in existing}
    new_replies=[]
    try:
        mail=imaplib.IMAP4_SSL('imap.gmail.com')
        mail.login(cfg['gmail_address'],cfg['gmail_app_password'])
        mail.select('INBOX')
        import email.utils
        since_date = (datetime.now() - timedelta(days=30)).strftime('%d-%b-%Y')
        _,data=mail.search(None, f'SINCE {since_date}')
        msg_ids=data[0].split()[-100:]
        for mid in reversed(msg_ids):
            try:
                _,msg_data=mail.fetch(mid,'(BODY.PEEK[])')
                if not msg_data or not msg_data[0]: continue
                raw=msg_data[0][1]
                msg=email_lib.message_from_bytes(raw)
                msg_id=msg.get('Message-ID',str(mid))
                if msg_id in existing_ids: continue
                from_addr=decode_str(msg.get('From',''))
                em=re.search(r'[\w.+\-]+@[\w.\-]+\.\w+',from_addr)
                if not em: continue
                sender=em.group().lower()
                if sender not in known: continue
                new_replies.append({'msg_id':msg_id,'email':sender,'from':from_addr,
                    'subject':decode_str(msg.get('Subject','')),'date':msg.get('Date',''),
                    'body':get_email_body(msg),'route':get_route_for_email(sender),
                    'status':'new','received_at':datetime.now().strftime('%Y-%m-%d %H:%M')})
            except Exception: continue
        mail.logout()
    except Exception as e: return {'error':str(e)}
    all_replies=new_replies+existing
    save_replies(all_replies)
    return {'new':len(new_replies),'total':len(all_replies)}

def get_stats():
    empty={"total":0,"sent":0,"errors":0,"today":0,"by_day":[],"by_variant":[],"by_hour":[],
           "top_recipients":[],"top_routes":[],"replied_emails":[],"replied_domains":[],"response_rate":{}}
    uid = current_user_id()
    if not uid: return empty
    from app.models import Send
    today_dt = date.today()
    today_str = today_dt.strftime('%Y-%m-%d')
    total=sent=errors=today_count=0
    by_day,by_var,by_em,by_route,by_hr=Counter(),Counter(),Counter(),Counter(),Counter()
    for row in Send.query.filter_by(user_id=uid).all():
        total += 1
        st = row.status or ''
        day = row.sent_at.strftime('%Y-%m-%d') if row.sent_at else 'unknown'
        hr  = row.sent_at.strftime('%H') if row.sent_at else '00'
        if st == 'sent':
            sent+=1; by_day[day]+=1; by_var[str(row.template_variant)]+=1; by_hr[hr]+=1
            if row.sent_at and row.sent_at.date() == today_dt: today_count+=1
            em = row.recipient_email.lower()
            if em: by_em[em]+=1
            if row.origin and row.destination: by_route[f"{row.origin} → {row.destination}"]+=1
        elif st=='error': errors+=1
    replies=load_replies()
    tr=len(replies)
    interested=sum(1 for r in replies if r.get('status')=='interested')
    not_int=sum(1 for r in replies if r.get('status')=='not_interested')
    new_r=sum(1 for r in replies if r.get('status')=='new')

    # Response rate = replies received / emails successfully sent
    # Interest rate = interested replies / total replies (quality metric)
    response_rate_pct = round(100 * tr / sent, 1) if sent > 0 else 0
    interest_rate_pct = round(100 * interested / tr, 1) if tr > 0 else 0

    rc,rs,dc=Counter(),{},Counter()
    for r in replies:
        em=r.get('email','').lower().strip()
        if em:
            rc[em]+=1; rs[em]=r.get('status','new')
            if '@' in em: dc[em.split('@')[1]]+=1
    return {
        "total":total,"sent":sent,"errors":errors,"today":today_count,
        "by_day":[{"date":d,"count":c} for d,c in sorted(by_day.items())[-14:]],
        "by_variant":[{"variant":v,"count":c} for v,c in sorted(by_var.items())],
        "by_hour":[{"hour":f"{h:02d}:00","count":by_hr.get(f"{h:02d}",0)} for h in range(24)],
        "top_recipients":[{"email":e,"count":c} for e,c in by_em.most_common(10)],
        "top_routes":[{"route":r,"count":c} for r,c in by_route.most_common(10)],
        "replied_emails":[{"email":e,"count":c,"status":rs.get(e,'new')} for e,c in rc.most_common()],
        "replied_domains":[{"domain":d,"count":c} for d,c in dc.most_common()],
        "response_rate":{
            "total_replies": tr,
            "interested": interested,
            "not_interested": not_int,
            "new": new_r,
            "pct": response_rate_pct,          # replies / sent
            "interest_pct": interest_rate_pct, # interested / replies
        },
    }

# ── AUTOMATION IMPACT ───────────────────────────────────────────────────────
# Only truly fixed constants live here.
# delay_per_email is always read from user config — never hardcoded.
AI_MANUAL_SEC     = 40   # Industry standard: 40s to find/copy/paste/send one email manually
AI_BATCH_SIZE     = 30   # Typical DAT text copy-paste block size
AI_BATCH_SETUP_SEC = 20  # Time to set up one batch (copy, paste, click Parse)
AI_ACTIONS_PER_EMAIL = 4 # Mouse actions per manual email
AI_WORKDAY_HOURS  = 8

def _ai_format_duration(seconds):
    seconds = max(0, float(seconds or 0))
    if seconds < 60: return f"{round(seconds)}s"
    if seconds < 3600:
        minutes = seconds / 60
        if abs(minutes - round(minutes)) < 0.05: return f"{int(round(minutes))} min"
        return f"{minutes:.1f} min"
    hours = seconds / 3600
    return f"{hours:.1f} hr"

def _ai_calc_from_count(emails_sent, delay_sec=None):
    """Calculate automation impact metrics.

    delay_sec — average seconds between emails (reads from config if None).
    This must always reflect the real configured delay to keep metrics honest.
    """
    if delay_sec is None:
        cfg = load_config()
        delay_sec = (cfg.get('delay_min', 20) + cfg.get('delay_max', 45)) / 2.0

    emails_sent = int(emails_sent or 0)
    batches = (emails_sent + AI_BATCH_SIZE - 1) // AI_BATCH_SIZE if emails_sent else 0
    manual_time_sec = emails_sent * AI_MANUAL_SEC
    auto_time_sec = batches * AI_BATCH_SETUP_SEC + emails_sent * delay_sec
    time_saved_sec = max(0, manual_time_sec - auto_time_sec)
    manual_actions_avoided = emails_sent * AI_ACTIONS_PER_EMAIL
    manual_speed = round(60 / AI_MANUAL_SEC, 1)                                          # emails/min manual
    auto_speed = round(emails_sent / (auto_time_sec / 60), 1) if auto_time_sec else 0    # emails/min automated
    # If auto is slower than manual (high delay), multiplier < 1 — show honestly
    speed_multiplier = round(manual_time_sec / auto_time_sec, 2) if auto_time_sec else 1.0
    hours_saved = round(time_saved_sec / 3600, 1)
    working_days_saved = round(hours_saved / AI_WORKDAY_HOURS, 1)
    return {
        'emails_sent': emails_sent, 'batches': batches,
        'manual_time_sec': manual_time_sec, 'auto_time_sec': auto_time_sec,
        'time_saved_sec': time_saved_sec, 'manual_actions_avoided': manual_actions_avoided,
        'manual_speed': manual_speed, 'auto_speed': auto_speed,
        'speed_multiplier': speed_multiplier, 'hours_saved': hours_saved,
        'working_days_saved': working_days_saved,
        'delay_avg_sec': round(delay_sec, 1),
        'manual_time_fmt': _ai_format_duration(manual_time_sec),
        'auto_time_fmt': _ai_format_duration(auto_time_sec),
        'time_saved_fmt': _ai_format_duration(time_saved_sec),
    }

def get_automation_impact():
    cfg = load_config()
    delay_avg = (cfg.get('delay_min', 20) + cfg.get('delay_max', 45)) / 2.0

    today = date.today()
    week_start = today - timedelta(days=today.weekday())
    daily_counts = Counter()
    hourly_counts = Counter()
    uid = current_user_id()
    if uid:
        from app.models import Send
        for row in Send.query.filter_by(user_id=uid, status='sent').all():
            if not row.sent_at: continue
            daily_counts[row.sent_at.strftime('%Y-%m-%d')] += 1
            hourly_counts[row.sent_at.strftime('%H')] += 1
    lifetime_count = sum(daily_counts.values())
    today_key = today.strftime('%Y-%m-%d')
    week_total = sum(c for d, c in daily_counts.items()
        if len(d) == 10 and datetime.strptime(d, '%Y-%m-%d').date() >= week_start)
    daily_rows = []
    for d in sorted(daily_counts.keys())[-14:]:
        calc = _ai_calc_from_count(daily_counts[d], delay_sec=delay_avg)
        calc.update({'date': d, 'emails': daily_counts[d], 'actions_avoided': calc['manual_actions_avoided']})
        daily_rows.append(calc)
    best_day = None
    if daily_rows:
        best = max(daily_rows, key=lambda r: r['time_saved_sec'])
        best_day = {'date': best['date'], 'emails': best['emails'], 'time_saved_fmt': best['time_saved_fmt']}
    peak_hour = None
    if hourly_counts:
        peak = max(hourly_counts.items(), key=lambda kv: kv[1])[0]
        peak_hour = f"{peak}:00"
    return {
        'today': _ai_calc_from_count(daily_counts.get(today_key, 0), delay_sec=delay_avg),
        'week': _ai_calc_from_count(week_total, delay_sec=delay_avg),
        'lifetime': _ai_calc_from_count(lifetime_count, delay_sec=delay_avg),
        'daily': daily_rows,
        'best_day': best_day,
        'peak_hour': peak_hour,
        'config': {'delay_min': cfg.get('delay_min', 20), 'delay_max': cfg.get('delay_max', 45), 'delay_avg': round(delay_avg, 1)},
    }

def parse_dat_text(text):
    loads = []
    email_pattern = re.compile(r'[\w.+\-]+@[\w.\-]+\.\w+')
    lines = text.strip().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        emails = email_pattern.findall(line)
        if emails:
            load = {'email': emails[0], 'origin': '', 'destination': '', 'date': '', 'equip': '', 'weight': '', 'length': '', 'company': ''}
            context = '\n'.join(lines[max(0, i-5):i+3])
            origin_match = re.search(r'([A-Z][a-zA-Z\s]+,\s*[A-Z]{2})\s*(?:to|→|->)\s*([A-Z][a-zA-Z\s]+,\s*[A-Z]{2})', context)
            if origin_match:
                load['origin'] = origin_match.group(1).strip()
                load['destination'] = origin_match.group(2).strip()
            date_match = re.search(r'\b(\d{1,2}/\d{1,2}(?:/\d{2,4})?)\b', context)
            if date_match: load['date'] = date_match.group(1)
            equip_match = re.search(r'\b(Van|Reefer|Flatbed|Step\s*Deck|RGN|Tanker|Auto|Dray|Power\s*Only)\b', context, re.I)
            if equip_match: load['equip'] = equip_match.group(1)
            weight_match = re.search(r'(\d[\d,]+)\s*(?:lbs?|pounds?)', context, re.I)
            if weight_match: load['weight'] = weight_match.group(1).replace(',', '')
            loads.append(load)
        i += 1
    return loads

_SMTP_RETRYABLE = (
    smtplib.SMTPServerDisconnected,
    smtplib.SMTPConnectError,
    ConnectionResetError,
    OSError,
)

def _smtp_send_with_retry(msg_obj, from_addr, to_addr, password, retries=3, base_delay=1.0):
    """
    Attempt to send via SMTP_SSL with exponential backoff on transient errors.
    Raises the last exception if all retries are exhausted.
    Non-retryable SMTP errors (auth failures, bad recipient) are raised immediately.
    """
    last_exc = None
    for attempt in range(retries):
        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as s:
                s.ehlo()
                s.starttls()
                s.ehlo()
                s.login(from_addr, password)
                s.sendmail(from_addr, to_addr, msg_obj.as_string())
            return  # success
        except smtplib.SMTPAuthenticationError:
            raise   # auth errors are permanent — don't retry
        except smtplib.SMTPRecipientsRefused:
            raise   # bad address — don't retry
        except Exception as e:
            last_exc = e
            app.logger.error(f'SMTP attempt {attempt+1}/{retries} failed: {type(e).__name__}: {e}')
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))  # 1s, 2s, 4s
    raise last_exc or RuntimeError('SMTP failed with no exception captured')


def send_one_email(to_email, subject, body, cfg):
    try:
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, cfg['gmail_address'], to_email, cfg['gmail_app_password'])
        return True, None
    except Exception as e: return False, str(e)

def run_send_job(loads, cfg, templates, uid=None):
    """Run in a background thread. uid must be passed explicitly — no session in threads."""
    state = _user_send_state(uid)
    state.update({"running":True,"done":False,"total":len(loads),"current":0,"sent":0,"errors":0,"skipped":0,"log":[]})
    with app.app_context():
        _, sent_today_set = load_sent_log(uid=uid)
        session_sent = set()
        for i, load in enumerate(loads):
            state["current"] = i + 1
            em = load['email'].lower().strip()
            if em in sent_today_set or em in session_sent:
                state["skipped"] += 1
                state["log"].append({"time":datetime.now().strftime('%H:%M:%S'),"status":"skipped","variant":0,"email":load["email"],"error":"already sent today"})
                continue
            tmpl = random.choice(templates); vi = templates.index(tmpl) + 1
            body = render_template_text(tmpl, load, cfg)
            parts = [load['origin'], load['destination'], load['date'], load['equip'], load.get('length',''), load.get('weight','')]
            subject = " | ".join(p for p in parts if p)
            ok, err = send_one_email(load['email'], subject, body, cfg)
            ts = datetime.now().strftime('%H:%M:%S'); st = 'sent' if ok else 'error'
            append_log(load, st, vi, uid=uid)
            if ok:
                session_sent.add(em)
                state["sent"] += 1
                _track_usage(uid, 'email_sent')   # ← quota tracking
            else:
                state["errors"] += 1
            state["log"].append({"time":ts,"status":st,"variant":vi,"email":load["email"],"error":err or ""})
            if i < len(loads) - 1:
                time.sleep(random.randint(cfg.get("delay_min", 20), cfg.get("delay_max", 45)))
        state.update({"running": False, "done": True})
        audit_log('send_batch', resource_type='send', uid=uid, detail={
            'total': state['total'], 'sent': state['sent'],
            'errors': state['errors'], 'skipped': state['skipped'],
        })

# ─── API ROUTES (all protected) ───────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
@login_required
def api_get_config():
    cfg = load_config(); safe = {k:v for k,v in cfg.items() if k != 'gmail_app_password'}
    safe['has_password'] = bool(cfg.get('gmail_app_password')); return jsonify(safe)

@app.route('/api/config', methods=['POST'])
@login_required
def api_save_config():
    data = request.json or {}
    # Validate delay range
    delay_min = data.get('delay_min')
    delay_max = data.get('delay_max')
    if delay_min is not None:
        try:
            delay_min = int(delay_min)
            if not (1 <= delay_min <= 300):
                return jsonify({'error': 'delay_min must be 1–300 seconds'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'delay_min must be an integer'}), 400
    if delay_max is not None:
        try:
            delay_max = int(delay_max)
            if not (1 <= delay_max <= 300):
                return jsonify({'error': 'delay_max must be 1–300 seconds'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'delay_max must be an integer'}), 400
    if delay_min and delay_max and delay_min > delay_max:
        return jsonify({'error': 'delay_min must be ≤ delay_max'}), 400
    # Validate email format if provided
    gmail = data.get('gmail_address', '')
    if gmail and not re.match(r'^[\w.+\-]+@[\w.\-]+\.\w{2,}$', gmail):
        return jsonify({'error': 'Invalid Gmail address format'}), 400
    cfg = load_config()
    for k in ['gmail_address','gmail_app_password','your_name','your_company','your_phone','delay_min','delay_max']:
        if k in data and data[k] != '': cfg[k] = data[k]
    save_config(cfg)
    audit_log('config_save', resource_type='email_account',
              detail={k: v for k, v in data.items() if k != 'gmail_app_password'})
    return jsonify({"ok": True})

@app.route('/api/templates', methods=['GET'])
@login_required
def api_get_templates(): return jsonify(load_templates())

@app.route('/api/templates', methods=['POST'])
@login_required
def api_save_templates():
    outreach = request.json.get("templates", [])
    save_templates_file(outreach)
    return jsonify({"ok": True})

@app.route('/api/stop-list', methods=['GET'])
@login_required
def api_get_stop(): return jsonify(get_stop_list_raw())

@app.route('/api/stop-list', methods=['POST'])
@login_required
def api_save_stop(): write_stop_list(request.json.get("entries", [])); return jsonify({"ok": True})

@app.route('/api/parse', methods=['POST'])
@login_required
def api_parse():
    raw = request.json.get("text", "")
    if not raw: return jsonify({"error": "No text"}), 400
    all_loads = parse_dat_text(raw)
    be, bd = load_stop_list(); all_sent, sent_today = load_sent_log()
    result = []; stats = {"total":len(all_loads),"new":0,"skip_today":0,"skip_dup":0,"skip_stop":0}
    for l in all_loads:
        key = f"{l['email']}|{l['origin']}|{l['destination']}"
        if is_blocked(l['email'], be, bd): l['skip'] = 'stop_list'; stats["skip_stop"] += 1
        elif l['email'].lower() in sent_today: l['skip'] = 'today'; stats["skip_today"] += 1
        elif key in all_sent: l['skip'] = 'duplicate'; stats["skip_dup"] += 1
        else: l['skip'] = None; stats["new"] += 1
        result.append(l)
    return jsonify({"loads": result, "stats": stats})

@app.route('/api/send', methods=['POST'])
@login_required
@limiter.limit("5 per minute")   # prevent accidental double-clicks / runaway loops
def api_send():
    uid = current_user_id()
    app.logger.info(f'API /api/send called — uid={uid}')
    state = _user_send_state(uid)
    if state["running"]: return jsonify({"error": "Already running"}), 400
    loads = request.json.get("loads", [])
    if not loads: return jsonify({"error": "No loads"}), 400
    cfg = load_config()
    has_email = bool(cfg.get("gmail_address"))
    has_pass  = bool(cfg.get("gmail_app_password"))
    app.logger.info(f'API /api/send cfg — has_email={has_email} has_pass={has_pass}')
    if not has_email or not has_pass:
        return jsonify({"error": "Gmail not configured"}), 400
    # ── Quota check ──────────────────────────────────────────────────────────
    quota = get_daily_quota(uid)
    if not quota['unlimited']:
        new_count = sum(1 for l in loads if not l.get('skip'))
        if quota['remaining'] is not None and new_count > quota['remaining']:
            return jsonify({
                'error': f"Daily quota exceeded — {quota['remaining']} sends remaining today "
                         f"({quota['used']}/{quota['limit']} used on {quota['plan']} plan).",
                'quota': quota,
            }), 429
    t = threading.Thread(target=run_send_job, args=(loads, cfg, load_templates(), uid))
    t.daemon = True; t.start()
    return jsonify({"ok": True, "total": len(loads), "quota": quota})

@app.route('/api/send-status', methods=['GET'])
@login_required
def api_send_status(): return jsonify(_user_send_state(current_user_id()))

@app.route('/api/automation-impact', methods=['GET'])
@login_required
def api_automation_impact(): return jsonify(get_automation_impact())

@app.route('/api/quota', methods=['GET'])
@login_required
def api_quota():
    """Return today's send quota status for the current user."""
    return jsonify(get_daily_quota())

@app.route('/api/smtp-test', methods=['GET'])
@login_required
def api_smtp_test():
    """Test SMTP connection using saved Gmail credentials. Returns detailed result."""
    cfg = load_config()
    gmail  = cfg.get('gmail_address', '')
    passwd = cfg.get('gmail_app_password', '')
    if not gmail or not passwd:
        return jsonify({'ok': False, 'step': 'config', 'error': 'Gmail not configured — save Settings first'})
    steps = []
    try:
        steps.append('connect smtp.gmail.com:587')
        import smtplib as _smtplib
        s = _smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        steps.append('ehlo')
        s.ehlo()
        steps.append('starttls')
        s.starttls()
        steps.append('ehlo2')
        s.ehlo()
        steps.append(f'login as {gmail}')
        s.login(gmail, passwd)
        steps.append('quit')
        s.quit()
        app.logger.info(f'SMTP-TEST OK for {gmail}')
        return jsonify({'ok': True, 'steps': steps, 'gmail': gmail})
    except Exception as e:
        app.logger.error(f'SMTP-TEST FAIL at step "{steps[-1] if steps else "?"}": {e}')
        return jsonify({'ok': False, 'step': steps[-1] if steps else 'unknown', 'error': str(e), 'steps': steps})

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats(): return jsonify(get_stats())

# ── OUTREACH INTELLIGENCE ─────────────────────────────────────────────────────

_RATE_KEYWORDS = [
    # explicit rate asks
    'send your rate', 'send me a rate', 'send me your rate', 'give me a rate',
    'what is your rate', "what's your rate", 'your rate', 'what rate',
    'send rate', 'best rate', 'need rate', 'rate per', 'rate?',
    # quote variants
    'quote', 'your quote', 'send quote', 'send a quote', 'send me a quote',
    'can you quote', 'can you send a quote',
    # price variants
    'price', 'pricing', 'what is your price', 'what are your prices',
    # amount / offer
    'how much', 'how much?', 'how much do you need',
    'what are you at', 'what can you do',
    'can you do', 'offer',
]
# Remove duplicate substrings to avoid redundant matching
_RATE_KEYWORDS = sorted(set(_RATE_KEYWORDS), key=len, reverse=True)

def _is_rate_request(body: str) -> bool:
    """Return True if the reply body contains rate-request language."""
    if not body:
        return False
    # Normalize: lowercase, collapse whitespace, strip extra punctuation
    b = ' '.join(body.lower().split())
    return any(kw in b for kw in _RATE_KEYWORDS)

@app.route('/api/intelligence', methods=['GET'])
@login_required
def api_intelligence():
    """Outreach Intelligence: rate requests, lane performance, broker profiles."""
    uid = current_user_id()
    if not uid:
        return jsonify({'error': 'Unauthorized'}), 401

    from app.models import Send, Reply
    from sqlalchemy import func

    # ── Reply & Rate Request aggregation ─────────────────────────────────────
    all_replies = Reply.query.filter_by(user_id=uid).all()
    # DISTINCT by from_email — avoids inflated counts from thread duplicates
    unique_reply_emails   = {r.from_email.lower() for r in all_replies if r.from_email}
    rate_request_emails   = {r.from_email.lower() for r in all_replies if _is_rate_request(r.body)}
    replies_total         = len(unique_reply_emails)
    rate_requests_total   = len(rate_request_emails)

    total_sent = Send.query.filter_by(user_id=uid, status='sent').count()
    emails_per_rr = round(total_sent / rate_requests_total, 1) if rate_requests_total > 0 else None

    # ── Lane Performance ──────────────────────────────────────────────────────
    # Get all sent emails grouped by origin→destination
    sent_rows = db.session.query(
        Send.origin, Send.destination,
        func.count(Send.id).label('emails_sent'),
        func.count(Send.recipient_email.distinct()).label('unique_contacts')
    ).filter(
        Send.user_id == uid, Send.status == 'sent',
        Send.origin.isnot(None), Send.destination.isnot(None),
        Send.origin != '', Send.destination != ''
    ).group_by(Send.origin, Send.destination)\
     .order_by(func.count(Send.id).desc())\
     .limit(20).all()

    # Build reply lookup: from_email → (has_reply, is_rate_request)
    reply_lookup = {r.from_email.lower(): r for r in all_replies}

    # For each lane, cross-ref with replies
    lanes = []
    for row in sent_rows:
        lane_key = f"{row.origin} → {row.destination}"
        # Get all emails sent on this lane
        lane_emails = db.session.query(Send.recipient_email).filter_by(
            user_id=uid, status='sent', origin=row.origin, destination=row.destination
        ).distinct().all()
        lane_email_set = {e[0].lower() for e in lane_emails}

        replies_count = sum(1 for e in lane_email_set if e in reply_lookup)
        rr_count = sum(1 for e in lane_email_set if e in rate_request_emails)

        reply_rate = round(100 * replies_count / row.emails_sent, 1) if row.emails_sent > 0 else 0
        rr_rate    = round(100 * rr_count    / row.emails_sent, 1) if row.emails_sent > 0 else 0

        lanes.append({
            'lane': lane_key,
            'origin': row.origin,
            'destination': row.destination,
            'emails_sent': row.emails_sent,
            'replies': replies_count,
            'rate_requests': rr_count,
            'reply_rate': reply_rate,
            'rate_request_rate': rr_rate,
        })

    # ── Broker Response Profile ───────────────────────────────────────────────
    # Group sends by domain
    sent_by_domain: dict = {}
    all_sends = Send.query.filter_by(user_id=uid, status='sent').all()
    for s in all_sends:
        if not s.recipient_email or '@' not in s.recipient_email:
            continue
        domain = s.recipient_email.lower().split('@')[1]
        sent_by_domain[domain] = sent_by_domain.get(domain, 0) + 1

    # Group replies by domain
    reply_by_domain: dict = {}
    rr_by_domain: dict = {}
    interested_by_domain: dict = {}
    for r in all_replies:
        if not r.from_email or '@' not in r.from_email:
            continue
        domain = r.from_email.lower().split('@')[1]
        reply_by_domain[domain] = reply_by_domain.get(domain, 0) + 1
        if _is_rate_request(r.body):
            rr_by_domain[domain] = rr_by_domain.get(domain, 0) + 1
        if r.status == 'interested':
            interested_by_domain[domain] = interested_by_domain.get(domain, 0) + 1

    brokers = []
    for domain, sent_count in sorted(sent_by_domain.items(), key=lambda x: -x[1]):
        replies_count = reply_by_domain.get(domain, 0)
        rr_count      = rr_by_domain.get(domain, 0)
        interested    = interested_by_domain.get(domain, 0)
        reply_rate    = round(100 * replies_count / sent_count, 1) if sent_count > 0 else 0
        brokers.append({
            'domain': domain,
            'emails_sent': sent_count,
            'replies': replies_count,
            'reply_rate': reply_rate,
            'rate_requests': rr_count,
            'interested': interested,
        })

    # Sort brokers: first those with replies (desc reply_rate), then rest
    brokers.sort(key=lambda b: (-b['replies'], -b['reply_rate']))
    brokers = brokers[:30]

    return jsonify({
        'total_sent': total_sent,
        'replies_total': replies_total,          # distinct sender count
        'rate_requests_total': rate_requests_total,
        'emails_per_rate_request': emails_per_rr,
        'lanes': lanes,
        'brokers': brokers,
    })

@app.route('/api/log', methods=['GET'])
@login_required
def api_log(): return jsonify(get_log_rows())

@app.route('/api/replies', methods=['GET'])
@login_required
def api_get_replies(): return jsonify(load_replies())

@app.route('/api/replies/fetch', methods=['POST'])
@login_required
@limiter.limit("2 per minute")   # IMAP is slow; prevent hammering Gmail
def api_fetch_replies(): return jsonify(fetch_replies_from_gmail())

@app.route('/api/replies/status', methods=['POST'])
@login_required
def api_reply_status():
    data = request.json; msg_id = data.get('msg_id'); status = data.get('status')
    add_to_stop = data.get('add_to_stop', False)
    replies = load_replies(); reply_obj = None
    for r in replies:
        if r['msg_id'] == msg_id:
            r['status'] = status; reply_obj = r; break
    save_replies(replies)
    if reply_obj:
        stage_map = {'new':'replied','interested':'interested','not_interested':'lost'}
        upsert_pipeline(reply_obj.get('email',''), {
            'stage': stage_map.get(status, 'replied'),
            'company': reply_obj.get('from','').split('<')[0].strip(),
            'route': reply_obj.get('route',''),
        })
    if status == 'interested' and reply_obj:
        add_to_followups(reply_obj)
    if add_to_stop and reply_obj:
        uid = current_user_id()
        em = reply_obj.get('email','')
        if uid and em:
            from app.models import StopListEntry
            from sqlalchemy.exc import IntegrityError
            try:
                db.session.add(StopListEntry(user_id=uid, type='email', value=em.lower()))
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
    audit_log('mark_reply', resource_type='reply',
              detail={'msg_id': msg_id, 'status': status, 'email': reply_obj.get('email') if reply_obj else None})
    return jsonify({'ok': True})

@app.route('/')
@login_required
def index(): return render_template('index.html')

# ── HEALTH CHECK ────────────────────────────────────────────────────────────
# Used by Railway deployment to verify the app is alive.

@app.route('/health')
def health():
    try:
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        db_ok = False
    status = 200 if db_ok else 503
    return jsonify({'status': 'ok' if db_ok else 'degraded', 'db': db_ok}), status

# ── GLOBAL ERROR HANDLERS ────────────────────────────────────────────────────
# Return clean JSON errors — never expose raw tracebacks to clients.

@app.errorhandler(400)
def err_400(e): return jsonify({'error': 'Bad request', 'detail': str(e)}), 400

@app.errorhandler(401)
def err_401(e): return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def err_403(e): return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def err_404(e): return jsonify({'error': 'Not found'}), 404

@app.errorhandler(429)
def err_429(e): return jsonify({'error': 'Too many requests — please slow down', 'retry_after': str(e.retry_after) if hasattr(e, 'retry_after') else '60s'}), 429

@app.errorhandler(500)
def err_500(e):
    # Log internally but never expose internals to client
    app.logger.error(f'500 error: {e}')
    return jsonify({'error': 'Internal server error'}), 500

# ─── FOLLOW-UPS ───────────────────────────────────────────────────────────────
def load_followups():
    uid = current_user_id()
    if not uid: return []
    from app.models import FollowUp
    return [f.to_dict() for f in FollowUp.query.filter_by(user_id=uid)
                                                .order_by(FollowUp.added_at.desc()).all()]

def save_followups(fus):
    """Upsert follow-up list — used by legacy send/update routes."""
    uid = current_user_id()
    if not uid: return
    from app.models import FollowUp
    for fu in fus:
        existing = FollowUp.query.filter_by(user_id=uid, contact_email=fu['email']).first()
        if existing:
            existing.level       = fu.get('level', existing.level)
            existing.status      = fu.get('status', existing.status)
            existing.notes       = fu.get('notes', existing.notes)
            existing.route       = fu.get('route', existing.route)
            existing.reply_subject = fu.get('reply_subject', existing.reply_subject)
            if fu.get('last_fu_sent'):
                try: existing.last_fu_sent = datetime.strptime(fu['last_fu_sent'], '%Y-%m-%d %H:%M')
                except: pass
            if fu.get('last_contact'):
                try: existing.last_contact = datetime.strptime(fu['last_contact'], '%Y-%m-%d %H:%M')
                except: pass
        else:
            db.session.add(FollowUp(
                user_id=uid, contact_email=fu['email'],
                contact_name=fu.get('from', ''), route=fu.get('route', ''),
                reply_subject=fu.get('reply_subject', ''),
                reply_msg_id=fu.get('reply_msg_id', ''),
                level=fu.get('level', 'FU1'), status=fu.get('status', 'pending'),
                notes=fu.get('notes', ''),
            ))
    db.session.commit()

def add_to_followups(reply):
    uid = current_user_id()
    if not uid: return
    from app.models import FollowUp
    existing = FollowUp.query.filter_by(user_id=uid, contact_email=reply['email']).first()
    if existing:
        existing.reply_subject = reply.get('subject', existing.reply_subject)
        existing.route = reply.get('route', existing.route)
    else:
        db.session.add(FollowUp(
            user_id=uid, contact_email=reply['email'],
            contact_name=reply.get('from', reply['email']),
            route=reply.get('route', ''),
            reply_subject=reply.get('subject', ''),
            reply_msg_id=reply.get('msg_id', ''),
            level='FU1', status='pending',
            last_contact=datetime.now(),
        ))
    db.session.commit()

def send_followup_email(fu, template_text, cfg):
    try:
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']; msg['To'] = fu['email']
        msg['Subject'] = 'Re: ' + fu['reply_subject'] if fu.get('reply_subject') else 'Follow-up'
        if fu.get('reply_msg_id'):
            msg['In-Reply-To'] = fu['reply_msg_id']; msg['References'] = fu['reply_msg_id']
        body = template_text.format(
            name=cfg.get('your_name',''), company=cfg.get('your_company',''),
            phone=cfg.get('your_phone',''), route=fu.get('route',''),
            origin=fu.get('route','').split('→')[0].strip() if '→' in fu.get('route','') else '',
            destination=fu.get('route','').split('→')[1].strip() if '→' in fu.get('route','') else '',
        )
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, cfg['gmail_address'], fu['email'], cfg['gmail_app_password'])
        return True, None
    except Exception as e: return False, str(e)

LEVEL_PROGRESSION = {'FU1': 'FU2', 'FU2': 'FU3', 'FU3': 'closed'}

DEFAULT_FU_TEMPLATES = {
    'FU1': "Hi,\n\nJust wanted to follow up — are you working on any loads this week?\n\nThank you,\n{name}\n{company} | {phone}",
    'FU2': "Hello,\n\nFollowing up again — do you have any loads available?\n\nThanks,\n{name}\n{company} | {phone}",
    'FU3': "Hi,\n\nLast follow-up — if you have loads in the future, please reach out.\n\nBest,\n{name}\n{company} | {phone}",
}

def get_fu_templates():
    uid = current_user_id()
    if not uid: return DEFAULT_FU_TEMPLATES.copy()
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if not rows: return DEFAULT_FU_TEMPLATES.copy()
    return {r.level: r.body for r in rows if r.level}

@app.route('/api/followups', methods=['GET'])
@login_required
def api_get_followups(): return jsonify(load_followups())

@app.route('/api/followups/send', methods=['POST'])
@login_required
def api_send_followup():
    data = request.json; emails = data.get('emails', [])
    cfg = load_config()
    if not cfg.get('gmail_address') or not cfg.get('gmail_app_password'):
        return jsonify({'error': 'Gmail not configured'}), 400
    fu_templates = get_fu_templates(); fus = load_followups(); results = []
    for fu in fus:
        if fu['email'] not in emails: continue
        if fu['status'] == 'closed': continue
        level = fu.get('level', 'FU1')
        tmpl = fu_templates.get(level, fu_templates.get('FU1', ''))
        ok, err = send_followup_email(fu, tmpl, cfg)
        if ok:
            fu['last_fu_sent'] = datetime.now().strftime('%Y-%m-%d %H:%M')
            fu['last_contact'] = fu['last_fu_sent']; fu['status'] = 'sent'
            next_level = LEVEL_PROGRESSION.get(level, 'closed')
            fu['level'] = next_level
            if next_level == 'closed': fu['status'] = 'closed'
        results.append({'email': fu['email'], 'ok': ok, 'error': err or '', 'new_level': fu.get('level')})
    save_followups(fus)
    sent_count = sum(1 for r in results if r['ok'])
    audit_log('followup_sent', resource_type='followup',
              detail={'sent': sent_count, 'total': len(results), 'emails': emails})
    return jsonify({'results': results})

@app.route('/api/followups/update', methods=['POST'])
@login_required
def api_update_followup():
    data = request.json; email = data.get('email'); fus = load_followups()
    for fu in fus:
        if fu['email'] == email:
            if 'status' in data: fu['status'] = data['status']
            if 'level' in data: fu['level'] = data['level']
            if 'notes' in data: fu['notes'] = data['notes']
            break
    save_followups(fus); return jsonify({'ok': True})

@app.route('/api/followups/delete', methods=['POST'])
@login_required
def api_delete_followup():
    email = (request.json.get('email') or '').lower().strip()
    uid = current_user_id()
    if uid and email:
        from app.models import FollowUp
        FollowUp.query.filter_by(user_id=uid, contact_email=email).delete()
        db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/fu-templates', methods=['GET'])
@login_required
def api_get_fu_templates(): return jsonify(get_fu_templates())

@app.route('/api/fu-templates', methods=['POST'])
@login_required
def api_save_fu_templates():
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    data = request.json  # {'FU1': '...', 'FU2': '...', 'FU3': '...'}
    Template.query.filter_by(user_id=uid, type='followup').delete()
    for level, body in data.items():
        db.session.add(Template(user_id=uid, type='followup', level=level, body=body))
    db.session.commit()
    return jsonify({'ok': True})

# ── PIPELINE ──────────────────────────────────────────────────────────────────
STAGES = ['new_lead', 'contacted', 'replied', 'interested', 'deal', 'lost']

def load_pipeline():
    uid = current_user_id()
    if not uid: return []
    from app.models import PipelineContact
    return [c.to_dict() for c in PipelineContact.query.filter_by(user_id=uid)
                                                       .order_by(PipelineContact.updated_at.desc()).all()]

def save_pipeline(contacts):
    """Full replace — used by delete route."""
    uid = current_user_id()
    if not uid: return
    from app.models import PipelineContact
    emails_to_keep = {c['email'].lower() for c in contacts}
    PipelineContact.query.filter(
        PipelineContact.user_id == uid,
        ~PipelineContact.email.in_(emails_to_keep)
    ).delete(synchronize_session=False)
    db.session.commit()

def upsert_pipeline(email, updates):
    uid = current_user_id()
    if not uid: return {}
    from app.models import PipelineContact
    existing = PipelineContact.query.filter_by(user_id=uid, email=email.lower()).first()
    if existing:
        for k, v in updates.items():
            if hasattr(existing, k): setattr(existing, k, v)
        existing.updated_at = datetime.now()
    else:
        existing = PipelineContact(
            user_id=uid, email=email.lower(),
            company=updates.get('company',''), route=updates.get('route',''),
            stage=updates.get('stage','new_lead'), notes='',
        )
        db.session.add(existing)
    db.session.commit()
    return existing.to_dict()

@app.route('/api/pipeline', methods=['GET'])
@login_required
def api_get_pipeline(): return jsonify(load_pipeline())

@app.route('/api/pipeline/add', methods=['POST'])
@login_required
def api_add_pipeline():
    d = request.json; contact = upsert_pipeline(d['email'], d)
    return jsonify({'ok': True, 'contact': contact})

@app.route('/api/pipeline/update', methods=['POST'])
@login_required
def api_update_pipeline():
    d = request.json
    email = (d.get('email') or '').lower().strip()
    if not email:
        return jsonify({'error': 'email required'}), 400
    updates = {k: v for k, v in d.items() if k != 'email'}
    contact = upsert_pipeline(email, updates)
    return jsonify({'ok': True, 'contact': contact})

@app.route('/api/pipeline/delete', methods=['POST'])
@login_required
def api_delete_pipeline():
    email = request.json.get('email')
    save_pipeline([c for c in load_pipeline() if c['email'].lower() != email.lower()])
    return jsonify({'ok': True})

# ── SCHEDULED FOLLOW-UP AUTOMATION ──────────────────────────────────────────

def _get_fu_templates_for_user(uid):
    """Fetch FU templates for a specific user — no session required (safe in threads)."""
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if not rows: return DEFAULT_FU_TEMPLATES.copy()
    return {r.level: r.body for r in rows if r.level}

def _run_scheduled_followups():
    """Find and auto-send all due follow-ups across all users. Called from daemon thread."""
    from app.models import FollowUp, EmailAccount
    now = datetime.utcnow()
    sent_total = 0
    pending = FollowUp.query.filter(
        FollowUp.status.in_(['pending', 'sent']),
        FollowUp.level.in_(['FU1', 'FU2', 'FU3']),
    ).all()
    for fu in pending:
        delay_days = FU_AUTO_DELAYS.get(fu.level)
        if not delay_days: continue
        # Reference point: last_contact for FU1, last_fu_sent for FU2/FU3
        ref = fu.last_fu_sent if fu.level != 'FU1' else (fu.last_contact or fu.added_at)
        if not ref or (now - ref).days < delay_days:
            continue
        # Load user's Gmail config (no session — direct DB lookup)
        acct = EmailAccount.query.filter_by(user_id=fu.user_id).first()
        if not acct or not acct.gmail_address or not acct.gmail_password:
            continue
        cfg = acct.to_config_dict()
        cfg['gmail_app_password'] = decrypt_field(cfg['gmail_app_password'])
        tmpl = _get_fu_templates_for_user(fu.user_id).get(fu.level, '')
        if not tmpl: continue
        ok, _ = send_followup_email(fu.to_dict(), tmpl, cfg)
        if ok:
            fu.last_fu_sent = now
            fu.last_contact = now
            fu.status = 'sent'
            next_level = LEVEL_PROGRESSION.get(fu.level, 'closed')
            fu.level = next_level
            if next_level == 'closed': fu.status = 'closed'
            sent_total += 1
    if sent_total:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        app.logger.info(f'[scheduler] Auto-sent {sent_total} follow-up(s)')
    return sent_total

def scheduled_followup_worker():
    """Daemon thread: checks for due follow-ups every 15 minutes."""
    time.sleep(60)   # initial delay so server finishes starting up
    while True:
        try:
            with app.app_context():
                _run_scheduled_followups()
        except Exception as e:
            app.logger.error(f'[scheduler] Error: {e}')
        time.sleep(900)   # 15 minutes

def auto_create_admin():
    """Auto-create admin account + workspace from env vars on startup (idempotent)."""
    admin_email    = os.environ.get('ADMIN_EMAIL', '')
    admin_password = os.environ.get('ADMIN_PASSWORD', '')
    if not admin_email or not admin_password:
        return
    from app.models import User as UserModel
    with app.app_context():
        existing = UserModel.query.filter_by(email=admin_email.lower()).first()
        if existing:
            # Ensure workspace exists even for pre-existing admin
            get_or_create_workspace(existing.id, name='Admin Workspace')
            # Ensure admin always has correct role + plan
            changed = False
            if getattr(existing, 'role', 'user') != 'admin':
                existing.role = 'admin'
                changed = True
            if getattr(existing, 'plan', 'free') != 'pro':
                existing.plan = 'pro'
                changed = True
            if changed:
                db.session.commit()
            return
        user = UserModel(
            email=admin_email.lower(), name='Admin',
            password=hash_password(admin_password),
            role='admin', plan='pro', invited_by='system',
        )
        db.session.add(user)
        db.session.flush()   # populate user.id before creating workspace
        get_or_create_workspace(user.id, name='Admin Workspace')
        db.session.commit()
        print(f"✓ Admin account + workspace auto-created for {admin_email}")

with app.app_context():
    db.create_all()   # Creates all tables if they don't exist (safe to run repeatedly)
    auto_create_admin()

# ── Start background follow-up scheduler ──────────────────────────────────────
_scheduler = threading.Thread(target=scheduled_followup_worker, daemon=True, name='fu-scheduler')
_scheduler.start()

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    # Default dev port: 8090 (8080 and 3001 reserved for other projects)
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8090)))
