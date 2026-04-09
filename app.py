"""DAT Mailer Web App v2 — with invite-only auth"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import re, csv, os, json, smtplib, random, threading, time, imaplib, secrets, base64
import urllib.parse, urllib.request
import email as email_lib
from datetime import datetime, date, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header as decode_email_header
from collections import Counter
from functools import wraps

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GRequest
from googleapiclient.discovery import build as gbuild

import bcrypt
from dotenv import load_dotenv
load_dotenv()

# ── Sentry error tracking ──────────────────────────────────────────────────────
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
_sentry_dsn = os.environ.get('SENTRY_DSN')
if _sentry_dsn:
    sentry_sdk.init(
        dsn=_sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
    )

# ── Structured JSON logging (Railway-friendly) ────────────────────────────────
import logging

class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line — parseable by Railway log viewer."""
    def format(self, record):
        entry = {
            'ts':    self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
            'level': record.levelname,
            'msg':   record.getMessage(),
            'src':   f'{record.filename}:{record.lineno}',
        }
        if record.exc_info:
            entry['exc'] = self.formatException(record.exc_info)
        return json.dumps(entry)

if os.environ.get('DATABASE_URL'):   # production only (Railway has DATABASE_URL set)
    _handler = logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    logging.root.handlers = [_handler]
    logging.root.setLevel(logging.INFO)

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
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,   # test connections before use (handles stale/dropped connections)
    'pool_recycle': 300,     # recycle connections every 5 min (prevents Railway PG idle timeout)
}

# ── Session / Cookie security ───────────────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SECURE flag: active when DATABASE_URL is set (Railway/prod) OR FLASK_ENV=production.
# Dev with SQLite has no DATABASE_URL so cookies stay HTTP-safe locally.
_is_production = bool(os.environ.get('DATABASE_URL')) or os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = _is_production

db.init_app(app)
flask_migrate.init_app(app, db)

# ── In-memory TTL cache (parse performance) ────────────────────────────────
# Caches DB-heavy reads that occur on every /api/parse call.
# Without this, every parse fetches the full sends table from Railway PG.
import threading as _threading
_cache_lock   = _threading.Lock()
_CACHE_STORE: dict = {}
_SENT_LOG_TTL  = 90   # seconds — covers rapid re-parses between sends
_STOP_LIST_TTL = 300  # 5 minutes — stop list rarely changes
_STATS_TTL     = 30   # seconds — dashboard stats (refreshed every 2 min by frontend)
_AI_IMPACT_TTL = 60   # seconds — automation impact (refreshed on nav to send page)

def _cache_get(key: str, ttl: float):
    """Return (value, hit). hit=False means expired or missing."""
    with _cache_lock:
        entry = _CACHE_STORE.get(key)
    if entry and (time.monotonic() - entry['t']) < ttl:
        return entry['v'], True
    return None, False

def _cache_set(key: str, value):
    with _cache_lock:
        _CACHE_STORE[key] = {'t': time.monotonic(), 'v': value}

def _cache_del(*keys: str):
    with _cache_lock:
        for k in keys:
            _CACHE_STORE.pop(k, None)

# ── Performance timing middleware ────────────────────────────────────────────
# Logs wall-clock time for every /api/ route — visible in Railway logs.
_PERF_SLOW_THRESHOLD_MS = 500   # log WARNING if route takes > 500ms

@app.before_request
def _perf_start():
    request._perf_start = time.monotonic()

@app.after_request
def _perf_end(response):
    start = getattr(request, '_perf_start', None)
    if start and request.path.startswith('/api/'):
        elapsed_ms = (time.monotonic() - start) * 1000
        level = logging.WARNING if elapsed_ms > _PERF_SLOW_THRESHOLD_MS else logging.DEBUG
        app.logger.log(level, f'PERF {request.method} {request.path} → {elapsed_ms:.0f}ms')
    return response

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

# ── Gmail API OAuth2 ───────────────────────────────────────────────────────────
_GMAIL_SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
]

def _get_gmail_service(uid):
    """Return an authenticated Gmail API service for the given user.
    Auto-refreshes the access token if expired. Raises RuntimeError if not connected."""
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if not acct or not acct.google_refresh_token:
        raise RuntimeError('Gmail OAuth not connected — please connect in Settings')
    refresh_token = decrypt_field(acct.google_refresh_token)
    client_id     = os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    creds = Credentials(
        token=decrypt_field(acct.google_access_token) if acct.google_access_token else None,
        refresh_token=refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=client_id,
        client_secret=client_secret,
        scopes=_GMAIL_SCOPES,
    )
    # Refresh if expired or no access token
    if not creds.valid:
        creds.refresh(GRequest())
        acct.google_access_token = encrypt_field(creds.token)
        acct.token_expiry = creds.expiry
        db.session.commit()
    return gbuild('gmail', 'v1', credentials=creds)

# ── SaaS PLAN QUOTAS (emails/day; None = unlimited) ──────────────────────────
PLAN_QUOTAS = {
    'free':    50,
    'starter': 300,
    'pro':     None,   # unlimited
}

# ── Follow-up v2: state machine ───────────────────────────────────────────────

VALID_STATES = {'active', 'paused', 'warm', 'loads', 'blocked', 'closed'}
TERMINAL_STATES = {'warm', 'loads', 'blocked', 'closed'}
VALID_STAGES = {'fu1_scheduled', 'fu1_sent', 'fu2_scheduled', 'fu2_sent',
                'fu3_scheduled', 'fu3_sent', 'completed_fu3'}

ALLOWED_TRANSITIONS = {
    'active': {'paused', 'warm', 'loads', 'blocked', 'closed'},
    'paused': {'active', 'warm', 'loads', 'blocked', 'closed'},
}

STAGE_PROGRESSION = {
    'fu1_scheduled': ('fu1_sent', 'fu2_scheduled'),
    'fu2_scheduled': ('fu2_sent', 'fu3_scheduled'),
    'fu3_scheduled': ('fu3_sent', None),  # None = completed_fu3
}

STAGE_TO_TEMPLATE = {
    'fu1_scheduled': 'FU1',
    'fu2_scheduled': 'FU2',
    'fu3_scheduled': 'FU3',
}

STAGE_SENT_FIELD = {
    'fu1_scheduled': 'fu1_sent_at',
    'fu2_scheduled': 'fu2_sent_at',
    'fu3_scheduled': 'fu3_sent_at',
}


def _get_fu_settings(workspace_id):
    """Get follow-up settings for workspace, with defaults."""
    from app.models import FollowupSettings
    s = FollowupSettings.query.filter_by(workspace_id=workspace_id).first()
    if s:
        return {'fu1': s.fu1_delay_days, 'fu2': s.fu2_delay_days, 'fu3': s.fu3_delay_days,
                'auto_stop_on_reply': s.auto_stop_on_reply, 'default_enabled': s.default_followup_enabled}
    return {'fu1': 3, 'fu2': 5, 'fu3': 7, 'auto_stop_on_reply': True, 'default_enabled': True}


def _get_stage_delay(stage, settings):
    """Return timedelta for the given scheduled stage."""
    from datetime import timedelta
    mapping = {'fu1_scheduled': settings['fu1'], 'fu2_scheduled': settings['fu2'], 'fu3_scheduled': settings['fu3']}
    days = mapping.get(stage, 3)
    return timedelta(days=days)


def _record_event(contact, event_type, actor_type='user', actor_user_id=None,
                  from_state=None, to_state=None, from_stage=None, to_stage=None,
                  metadata_json=None, notes=None):
    """Create a FollowupEvent record."""
    from app.models import FollowupEvent
    evt = FollowupEvent(
        followup_contact_id=contact.id,
        workspace_id=contact.workspace_id,
        event_type=event_type,
        from_state=from_state, to_state=to_state,
        from_stage=from_stage, to_stage=to_stage,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        metadata_json=metadata_json,
        notes=notes,
    )
    db.session.add(evt)
    return evt


def _transition_state(contact, new_state, reason=None, actor_user_id=None):
    """Transition contact state with validation. Returns (success, error_msg)."""
    old_state = contact.state
    if old_state in TERMINAL_STATES:
        return False, f'Cannot transition from terminal state: {old_state}'
    if new_state not in ALLOWED_TRANSITIONS.get(old_state, set()):
        return False, f'Invalid transition: {old_state} -> {new_state}'

    now = datetime.utcnow()
    contact.state = new_state
    contact.updated_at = now

    if new_state == 'paused':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.paused_at = now
        if reason:
            contact.pause_reason = reason
    elif new_state == 'active':  # resume
        contact.resumed_at = now
        contact.is_followup_enabled = True
        if contact.stage.endswith('_scheduled'):
            settings = _get_fu_settings(contact.workspace_id)
            contact.next_followup_at = now + _get_stage_delay(contact.stage, settings)
    elif new_state == 'warm':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.warm_at = now
    elif new_state == 'loads':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.loads_at = now
    elif new_state == 'blocked':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.blocked_at = now
        if reason:
            contact.block_reason = reason
    elif new_state == 'closed':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.closed_at = now
        if reason:
            contact.close_reason = reason

    _record_event(contact, 'state_change', actor_type='user', actor_user_id=actor_user_id,
                  from_state=old_state, to_state=new_state)
    return True, None

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

def _current_user_id():
    """Return current user's DB id from session email."""
    from app.models import User as _U
    u = _U.query.filter_by(email=session['user_email']).first()
    return u.id if u else None

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

    # Try to send via admin's Gmail account (supports both OAuth2 and SMTP)
    admin_user = User.query.filter_by(email=ADMIN_EMAIL).first()
    admin_acct = EmailAccount.query.filter_by(user_id=admin_user.id).first() if admin_user else None

    # Always log reset URL so admin can retrieve from Railway logs if email fails
    app.logger.warning(f'PASSWORD_RESET_LINK for={email} url={reset_url}')

    if admin_acct and admin_acct.gmail_address:
        body = (
            f"Reset your DAT Mailer password by clicking the link below.\n\n"
            f"{reset_url}\n\n"
            f"This link expires in 1 hour. If you didn't request this, ignore this email."
        )
        cfg = {'gmail_address': admin_acct.gmail_address}
        ok, err = send_one_email(email, 'DAT Mailer — Password Reset', body, cfg, uid=admin_user.id)
        if not ok:
            app.logger.error(f'Password reset email failed: {err}')
    else:
        app.logger.warning(f'PASSWORD_RESET no admin Gmail configured — link logged above')

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
    from app.models import Invitation, User as UserModel
    invite = Invitation.query.filter_by(token=token, status='pending').first()
    if not invite:
        # If invite is gone but user already exists → just redirect to login
        return redirect(url_for('login_page'))
    if invite.expires_at and invite.expires_at < datetime.utcnow():
        invite.status = 'expired'
        db.session.commit()
        # If user already registered via this invite → redirect to login
        if UserModel.query.filter_by(email=invite.email.lower()).first():
            return redirect(url_for('login_page'))
        return render_template('login.html', error='This invite link has expired. Please request a new one.',
                               csrf_token=_get_csrf_token())
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

    # Check if already a fully-functional user
    existing = get_user(email)
    if existing:
        # Allow re-invite if user exists but has no Gmail connected (broken onboarding)
        from app.models import EmailAccount
        acct = EmailAccount.query.filter_by(user_id=existing['id']).first()
        has_gmail = bool(acct and acct.google_refresh_token)
        if has_gmail:
            return jsonify({'error': 'User already exists and has Gmail connected'}), 400
        # User exists but no Gmail — return their login info instead of blocking
        return jsonify({'ok': True, 'detail': 'User account exists but Gmail not connected. User can log in and connect Gmail from Settings.',
                        'user_exists': True}), 200

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
    from app.models import (User as UserModel, EmailAccount, Send, Reply,
                            FollowUp, PipelineContact, StopListEntry, Template,
                            UsageEvent, AuditLog, Invitation, Workspace,
                            SendJob, PasswordResetToken)
    user = UserModel.query.filter_by(email=email).first()
    if not user:
        # Maybe just a pending invite — clean that up
        deleted_invites = Invitation.query.filter_by(email=email).delete()
        PasswordResetToken.query.filter_by(email=email).delete()
        if deleted_invites:
            db.session.commit()
            return jsonify({'ok': True, 'detail': 'Invite removed (no user account found)'})
        return jsonify({'error': 'User not found'}), 404

    uid = user.id
    # Delete all dependent records first (FK cascade)
    for model in [Send, Reply, FollowUp, PipelineContact, StopListEntry,
                  Template, UsageEvent, AuditLog, EmailAccount, SendJob]:
        model.query.filter_by(user_id=uid).delete()
    # Delete owned workspaces
    Workspace.query.filter_by(owner_id=uid).delete()
    # Reset invitations and password tokens for this email
    Invitation.query.filter_by(email=email).delete()
    PasswordResetToken.query.filter_by(email=email).delete()
    # Finally delete the user
    db.session.delete(user)
    db.session.commit()
    app.logger.info(f'Admin deleted user {email} and all related data')
    return jsonify({'ok': True})

@app.route('/api/admin/users/plan', methods=['POST'])
@login_required
@admin_required
def api_admin_change_plan():
    data = request.json or {}
    email = (data.get('email') or '').lower()
    plan  = (data.get('plan') or '').lower()
    if plan not in ('free', 'starter', 'pro'):
        return jsonify({'error': 'Invalid plan'}), 400
    from app.models import User as UserModel, Workspace
    user = UserModel.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    ws = Workspace.query.filter_by(owner_id=user.id).first()
    if ws:
        ws.plan = plan
        db.session.commit()
    return jsonify({'ok': True, 'email': email, 'plan': plan})

def _admin_date_range(period: str):
    """Return (start_dt, end_dt) for admin period filter. All times UTC."""
    now = datetime.utcnow()
    today = now.date()
    if period == 'today':
        return datetime.combine(today, datetime.min.time()), now
    elif period == 'yesterday':
        y = today - timedelta(days=1)
        return datetime.combine(y, datetime.min.time()), datetime.combine(today, datetime.min.time())
    elif period == '7d':
        return datetime.combine(today - timedelta(days=7), datetime.min.time()), now
    elif period == '30d':
        return datetime.combine(today - timedelta(days=30), datetime.min.time()), now
    else:  # 'total'
        return None, None

@app.route('/api/admin/users/reset-link', methods=['POST'])
@login_required
@admin_required
def api_admin_reset_link():
    """Generate a password reset link for a user and return it to the admin."""
    data = request.json or {}
    email = (data.get('email') or '').lower().strip()
    if not email:
        return jsonify({'error': 'Email required'}), 400
    from app.models import User as UserModel, PasswordResetToken
    if not UserModel.query.filter_by(email=email).first():
        return jsonify({'error': 'User not found'}), 404
    PasswordResetToken.query.filter_by(email=email, used_at=None).delete()
    token = secrets.token_urlsafe(48)
    db.session.add(PasswordResetToken(email=email, token=token))
    db.session.commit()
    base_url = request.host_url.rstrip('/')
    reset_url = f"{base_url}/reset-password?token={token}"
    app.logger.warning(f'ADMIN_RESET_LINK for={email} url={reset_url}')
    return jsonify({'ok': True, 'url': reset_url})


@app.route('/api/admin/stats/overview', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_overview():
    """System-wide aggregate stats for admin overview panel."""
    from app.models import User as UserModel, Workspace, Send, Reply, FollowUp
    from sqlalchemy import func

    period = request.args.get('period', 'today')
    start_dt, end_dt = _admin_date_range(period)

    total_users = UserModel.query.count()

    # --- active_users (distinct senders in period) ---
    active_q = db.session.query(func.count(func.distinct(Send.user_id))).filter(Send.status == 'sent')
    if start_dt is not None:
        active_q = active_q.filter(Send.sent_at >= start_dt, Send.sent_at <= end_dt)
    active_users = active_q.scalar() or 0

    # --- sends ---
    sends_q = db.session.query(func.count(Send.id)).filter(Send.status == 'sent')
    if start_dt is not None:
        sends_q = sends_q.filter(Send.sent_at >= start_dt, Send.sent_at <= end_dt)
    sends = sends_q.scalar() or 0

    # --- replies ---
    replies_q = db.session.query(func.count(Reply.id))
    if start_dt is not None:
        replies_q = replies_q.filter(Reply.received_at >= start_dt, Reply.received_at <= end_dt)
    replies = replies_q.scalar() or 0

    # --- followups ---
    fu_q = db.session.query(func.count(FollowUp.id)).filter(FollowUp.status == 'sent')
    if start_dt is not None:
        fu_q = fu_q.filter(FollowUp.last_fu_sent >= start_dt, FollowUp.last_fu_sent <= end_dt)
    followups = fu_q.scalar() or 0

    reply_rate = round(replies / sends * 100, 1) if sends else 0.0
    inactive_accounts = total_users - active_users

    # --- plan distribution ---
    plan_rows = db.session.query(
        func.coalesce(Workspace.plan, 'free'), func.count(Workspace.id)
    ).group_by(func.coalesce(Workspace.plan, 'free')).all()
    plans = {row[0]: row[1] for row in plan_rows}

    # --- top 3 users by sends ---
    top_q = db.session.query(Send.user_id, func.count(Send.id).label('cnt')).filter(Send.status == 'sent')
    if start_dt is not None:
        top_q = top_q.filter(Send.sent_at >= start_dt, Send.sent_at <= end_dt)
    top_rows = top_q.group_by(Send.user_id).order_by(func.count(Send.id).desc()).limit(3).all()

    top_users = []
    for user_id, send_cnt in top_rows:
        user = UserModel.query.get(user_id)
        r_q = db.session.query(func.count(Reply.id)).filter(Reply.user_id == user_id)
        if start_dt is not None:
            r_q = r_q.filter(Reply.received_at >= start_dt, Reply.received_at <= end_dt)
        user_replies = r_q.scalar() or 0
        top_users.append({
            'email': user.email if user else 'unknown',
            'sends': send_cnt,
            'replies': user_replies,
            'reply_rate': round(user_replies / send_cnt * 100, 1) if send_cnt else 0.0,
        })

    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'sends': sends,
        'replies': replies,
        'reply_rate': reply_rate,
        'followups': followups,
        'inactive_accounts': inactive_accounts,
        'plans': plans,
        'top_users': top_users,
    })


@app.route('/api/admin/stats/accounts', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_accounts():
    """Per-account summary table for admin Accounts section."""
    from app.models import User as UserModel, Workspace, Send, Reply, FollowUp, EmailAccount
    from sqlalchemy import func

    period = request.args.get('period', 'today')
    start_dt, end_dt = _admin_date_range(period)
    now = datetime.utcnow()

    # 1. Load all users
    users = UserModel.query.order_by(UserModel.created_at.desc()).all()
    user_ids = [u.id for u in users]

    if not user_ids:
        return jsonify([])

    # 2. Batch workspace lookup
    ws_rows = Workspace.query.filter(Workspace.owner_id.in_(user_ids)).all()
    ws_map = {ws.owner_id: ws for ws in ws_rows}

    # 3. Batch email accounts
    ea_rows = EmailAccount.query.filter(EmailAccount.user_id.in_(user_ids)).all()
    ea_map = {ea.user_id: ea for ea in ea_rows}

    # 4. Batch sends per user
    sends_q = db.session.query(Send.user_id, func.count(Send.id)).filter(
        Send.user_id.in_(user_ids), Send.status == 'sent')
    if start_dt is not None:
        sends_q = sends_q.filter(Send.sent_at >= start_dt, Send.sent_at <= end_dt)
    sends_map = dict(sends_q.group_by(Send.user_id).all())

    # 5. Batch replies per user
    replies_q = db.session.query(Reply.user_id, func.count(Reply.id)).filter(
        Reply.user_id.in_(user_ids))
    if start_dt is not None:
        replies_q = replies_q.filter(Reply.received_at >= start_dt, Reply.received_at <= end_dt)
    replies_map = dict(replies_q.group_by(Reply.user_id).all())

    # 6. Batch follow-ups per user
    fu_q = db.session.query(FollowUp.user_id, func.count(FollowUp.id)).filter(
        FollowUp.user_id.in_(user_ids), FollowUp.status == 'sent')
    if start_dt is not None:
        fu_q = fu_q.filter(FollowUp.last_fu_sent >= start_dt, FollowUp.last_fu_sent <= end_dt)
    fu_map = dict(fu_q.group_by(FollowUp.user_id).all())

    # 7. Batch last activity (always lifetime, NOT filtered)
    la_rows = db.session.query(Send.user_id, func.max(Send.sent_at)).filter(
        Send.user_id.in_(user_ids)).group_by(Send.user_id).all()
    la_map = {row[0]: row[1] for row in la_rows}

    # 8. Build result array
    result = []
    for u in users:
        ws = ws_map.get(u.id)
        ea = ea_map.get(u.id)
        plan = (ws.plan if ws else None) or 'free'
        s = sends_map.get(u.id, 0)
        r = replies_map.get(u.id, 0)
        f = fu_map.get(u.id, 0)
        last_act = la_map.get(u.id)

        days_inactive = None
        if last_act:
            days_inactive = (now - last_act).days

        result.append({
            'user_id': u.id,
            'email': u.email,
            'name': u.name or '',
            'workspace_name': ws.name if ws else '',
            'plan': plan,
            'created_at': u.created_at.strftime('%Y-%m-%d') if u.created_at else '',
            'sends': s,
            'replies': r,
            'reply_rate': round(r / s * 100, 1) if s else 0.0,
            'followups': f,
            'email_connected': bool(ea and ea.google_refresh_token),
            'last_activity': last_act.strftime('%Y-%m-%dT%H:%M:%S') if last_act else None,
            'days_inactive': days_inactive,
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

def load_stop_list(uid=None):
    if uid is None: uid = current_user_id()
    if not uid: return set(), set()
    cache_key = f'stop_list:{uid}'
    cached, hit = _cache_get(cache_key, _STOP_LIST_TTL)
    if hit: return cached
    from app.models import StopListEntry
    be, bd = set(), set()
    for e in StopListEntry.query.filter_by(user_id=uid).all():
        if e.type == 'email': be.add(e.value.lower())
        else: bd.add(e.value.lower())
    result = (be, bd)
    _cache_set(cache_key, result)
    return result

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
    _cache_del(f'stop_list:{uid}')  # invalidate so next parse sees updated list

def is_blocked(email, be, bd):
    em=email.strip().lower()
    if em in be: return True
    dom=em.split('@')[-1] if '@' in em else ''
    return bool(dom and dom in bd)

def load_sent_log(uid=None):
    """Pass uid explicitly when calling from background threads."""
    if uid is None:
        uid = current_user_id()
    if not uid: return set(), set()
    cache_key = f'sent_log:{uid}'
    cached, hit = _cache_get(cache_key, _SENT_LOG_TTL)
    if hit: return cached
    from app.models import Send
    today_start = datetime.combine(date.today(), datetime.min.time())
    # Fetch only the 4 columns needed — avoids transferring all 12+ columns over network
    rows = db.session.query(
        Send.recipient_email, Send.origin, Send.destination, Send.sent_at
    ).filter(Send.user_id == uid, Send.status == 'sent').all()
    all_sent, sent_today = set(), set()
    for em_raw, orig, dest, sent_at in rows:
        em = em_raw.lower()
        all_sent.add(f"{em}|{orig}|{dest}")
        if sent_at and sent_at >= today_start:
            sent_today.add(em)
    result = (all_sent, sent_today)
    _cache_set(cache_key, result)
    return result

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
    _cache_del(f'sent_log:{uid}', f'stats:{uid}', f'ai_impact:{uid}')  # invalidate caches

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
                thread_id=r.get('thread_id', '') or None,
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

def _bulk_routes_for_emails(uid, emails):
    """Batch-fetch routes for a set of emails — avoids N+1 queries in reply fetching."""
    if not uid or not emails: return {}
    from app.models import Send
    from sqlalchemy import func
    # For each email, get the latest send's origin → destination
    subq = db.session.query(
        Send.recipient_email,
        Send.origin,
        Send.destination,
        func.max(Send.sent_at).label('latest')
    ).filter(
        Send.user_id == uid,
        func.lower(Send.recipient_email).in_([e.lower() for e in emails])
    ).group_by(Send.recipient_email, Send.origin, Send.destination).all()
    # Keep only the latest per email
    routes = {}
    for em, orig, dest, ts in subq:
        key = em.lower()
        if key not in routes or (ts and routes[key][1] and ts > routes[key][1]):
            routes[key] = (f"{orig} → {dest}", ts)
    return {k: v[0] for k, v in routes.items()}

_last_fetch_times: dict = {}   # per-user IMAP throttle: {user_id: timestamp}

def fetch_replies_from_gmail():
    uid = current_user_id()
    # Rate-limit: once per 60 s per user
    now = time.time()
    last = _last_fetch_times.get(uid, 0)
    if now - last < 60:
        wait = int(60 - (now - last))
        return {'error': f'Please wait {wait}s before checking again', 'rate_limited': True}
    _last_fetch_times[uid] = now

    known        = get_known_emails()
    existing     = load_replies()
    existing_ids = {r['msg_id'] for r in existing}
    new_replies  = []

    try:
        service = _get_gmail_service(uid)
    except RuntimeError as e:
        return {'error': str(e)}

    try:
        since_epoch = int((datetime.now() - timedelta(days=30)).timestamp())
        results = service.users().messages().list(
            userId='me', q=f'after:{since_epoch} in:inbox', maxResults=100
        ).execute()
        messages = results.get('messages', [])

        # First pass: collect new reply data without route lookup (avoid N+1)
        _pending_replies = []
        for msg_ref in messages:
            try:
                msg_data = service.users().messages().get(
                    userId='me', id=msg_ref['id'], format='full'
                ).execute()

                headers = {h['name']: h['value']
                           for h in msg_data.get('payload', {}).get('headers', [])}
                msg_id   = headers.get('Message-ID', msg_ref['id'])
                if msg_id in existing_ids:
                    continue

                from_addr = headers.get('From', '')
                em = re.search(r'[\w.+\-]+@[\w.\-]+\.\w+', from_addr)
                if not em:
                    continue
                sender = em.group().lower()
                if sender not in known:
                    continue

                body = _gmail_get_body(msg_data.get('payload', {}))

                _pending_replies.append({
                    'msg_id':      msg_id,
                    'thread_id':   msg_data.get('threadId', ''),
                    'email':       sender,
                    'from':        from_addr,
                    'subject':     headers.get('Subject', ''),
                    'date':        headers.get('Date', ''),
                    'body':        body,
                    'route':       '',  # filled in bulk below
                    'status':      'new',
                    'received_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                })
            except Exception:
                continue

        # Bulk route lookup — 1 query instead of N
        if _pending_replies:
            sender_emails = {r['email'] for r in _pending_replies}
            route_map = _bulk_routes_for_emails(uid, sender_emails)
            for r in _pending_replies:
                r['route'] = route_map.get(r['email'], '')
            new_replies.extend(_pending_replies)

    except Exception as e:
        return {'error': str(e)}

    all_replies = new_replies + existing
    save_replies(all_replies)

    # Auto-stop follow-ups for contacts who replied
    if new_replies and uid:
        for r in new_replies:
            try:
                _check_reply_stops_followup(r['email'], uid)
            except Exception:
                pass
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return {'new': len(new_replies), 'total': len(all_replies)}


def _gmail_get_body(payload):
    """Recursively extract plain-text body from a Gmail API message payload."""
    mime_type = payload.get('mimeType', '')
    if mime_type == 'text/plain':
        data = payload.get('body', {}).get('data', '')
        if data:
            return base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='replace')
    for part in payload.get('parts', []):
        result = _gmail_get_body(part)
        if result:
            return result
    return ''

def get_stats():
    """Compute dashboard stats using SQL aggregation (not Python loops over all rows)."""
    empty={"total":0,"sent":0,"errors":0,"today":0,"by_day":[],"by_variant":[],"by_hour":[],
           "top_recipients":[],"top_routes":[],"replied_emails":[],"replied_domains":[],"response_rate":{}}
    uid = current_user_id()
    if not uid: return empty
    cache_key = f'stats:{uid}'
    cached, hit = _cache_get(cache_key, _STATS_TTL)
    if hit: return cached
    from app.models import Send, Reply
    from sqlalchemy import func, case, cast, Date

    today_dt = date.today()

    # ── Single aggregate query: total, sent, errors, today ────────────────
    agg = db.session.query(
        func.count(Send.id).label('total'),
        func.count(case((Send.status == 'sent', 1))).label('sent'),
        func.count(case((Send.status == 'error', 1))).label('errors'),
        func.count(case((
            db.and_(Send.status == 'sent', cast(Send.sent_at, Date) == today_dt), 1
        ))).label('today'),
    ).filter(Send.user_id == uid).first()
    total = agg.total or 0
    sent = agg.sent or 0
    errors = agg.errors or 0
    today_count = agg.today or 0

    # ── By-day (last 14 days) ─────────────────────────────────────────────
    cutoff = today_dt - timedelta(days=14)
    by_day_rows = db.session.query(
        func.date(Send.sent_at).label('day'),
        func.count(Send.id)
    ).filter(Send.user_id == uid, Send.status == 'sent', Send.sent_at >= cutoff)\
     .group_by(func.date(Send.sent_at)).order_by(func.date(Send.sent_at)).all()
    by_day = [{"date": str(d), "count": c} for d, c in by_day_rows if d]

    # ── By-variant ────────────────────────────────────────────────────────
    by_var_rows = db.session.query(
        Send.template_variant, func.count(Send.id)
    ).filter(Send.user_id == uid, Send.status == 'sent')\
     .group_by(Send.template_variant).all()
    by_variant = [{"variant": str(v), "count": c} for v, c in by_var_rows]

    # ── By-hour ───────────────────────────────────────────────────────────
    # Use extract for hour — works on both PostgreSQL and SQLite
    try:
        from sqlalchemy import extract
        by_hr_rows = db.session.query(
            extract('hour', Send.sent_at).label('hr'),
            func.count(Send.id)
        ).filter(Send.user_id == uid, Send.status == 'sent', Send.sent_at.isnot(None))\
         .group_by('hr').all()
        by_hr = {int(h): c for h, c in by_hr_rows if h is not None}
    except Exception:
        by_hr = {}
    by_hour = [{"hour": f"{h:02d}:00", "count": by_hr.get(h, 0)} for h in range(24)]

    # ── Top recipients (top 10) ───────────────────────────────────────────
    top_recip = db.session.query(
        func.lower(Send.recipient_email), func.count(Send.id)
    ).filter(Send.user_id == uid, Send.status == 'sent')\
     .group_by(func.lower(Send.recipient_email))\
     .order_by(func.count(Send.id).desc()).limit(10).all()

    # ── Top routes (top 10) ───────────────────────────────────────────────
    top_rt = db.session.query(
        Send.origin, Send.destination, func.count(Send.id)
    ).filter(
        Send.user_id == uid, Send.status == 'sent',
        Send.origin.isnot(None), Send.destination.isnot(None),
        Send.origin != '', Send.destination != ''
    ).group_by(Send.origin, Send.destination)\
     .order_by(func.count(Send.id).desc()).limit(10).all()

    # ── Reply stats (SQL aggregation) ─────────────────────────────────────
    reply_agg = db.session.query(
        func.count(Reply.id).label('total'),
        func.count(case((Reply.status == 'interested', 1))).label('interested'),
        func.count(case((Reply.status == 'not_interested', 1))).label('not_interested'),
        func.count(case((Reply.status == 'new', 1))).label('new_r'),
    ).filter(Reply.user_id == uid).first()
    tr = reply_agg.total or 0
    interested = reply_agg.interested or 0
    not_int = reply_agg.not_interested or 0
    new_r = reply_agg.new_r or 0

    response_rate_pct = round(100 * tr / sent, 1) if sent > 0 else 0
    interest_rate_pct = round(100 * interested / tr, 1) if tr > 0 else 0

    # ── Replied emails/domains (SQL) ──────────────────────────────────────
    reply_rows = db.session.query(
        func.lower(Reply.from_email), Reply.status, func.count(Reply.id)
    ).filter(Reply.user_id == uid, Reply.from_email != '')\
     .group_by(func.lower(Reply.from_email), Reply.status).all()

    rc, rs = Counter(), {}
    for em, status, cnt in reply_rows:
        if em:
            rc[em] += cnt
            rs[em] = status
    dc = Counter()
    for em in rc:
        if '@' in em:
            dc[em.split('@')[1]] += rc[em]

    result = {
        "total":total,"sent":sent,"errors":errors,"today":today_count,
        "by_day": by_day,
        "by_variant": by_variant,
        "by_hour": by_hour,
        "top_recipients":[{"email":e,"count":c} for e,c in top_recip],
        "top_routes":[{"route":f"{o} → {d}","count":c} for o,d,c in top_rt],
        "replied_emails":[{"email":e,"count":c,"status":rs.get(e,'new')} for e,c in rc.most_common()],
        "replied_domains":[{"domain":d,"count":c} for d,c in dc.most_common()],
        "response_rate":{
            "total_replies": tr,
            "interested": interested,
            "not_interested": not_int,
            "new": new_r,
            "pct": response_rate_pct,
            "interest_pct": interest_rate_pct,
        },
    }
    _cache_set(cache_key, result)
    return result

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
    """Compute automation impact metrics using SQL aggregation (not loading all rows)."""
    uid = current_user_id()
    cache_key = f'ai_impact:{uid}'
    cached, hit = _cache_get(cache_key, _AI_IMPACT_TTL)
    if hit: return cached

    cfg = load_config()
    delay_avg = (cfg.get('delay_min', 20) + cfg.get('delay_max', 45)) / 2.0

    today = date.today()
    week_start = today - timedelta(days=today.weekday())
    today_key = today.strftime('%Y-%m-%d')

    daily_counts = Counter()
    peak_hour = None
    if uid:
        from app.models import Send
        from sqlalchemy import func, extract

        # Daily counts (last 14 days only — all we display)
        cutoff = today - timedelta(days=14)
        day_rows = db.session.query(
            func.date(Send.sent_at).label('day'),
            func.count(Send.id)
        ).filter(
            Send.user_id == uid, Send.status == 'sent',
            Send.sent_at.isnot(None), Send.sent_at >= cutoff
        ).group_by(func.date(Send.sent_at)).all()
        for d, c in day_rows:
            if d:
                daily_counts[str(d)] = c

        # Lifetime + this week totals (single query)
        lifetime_count = db.session.query(func.count(Send.id)).filter(
            Send.user_id == uid, Send.status == 'sent'
        ).scalar() or 0

        week_total = db.session.query(func.count(Send.id)).filter(
            Send.user_id == uid, Send.status == 'sent',
            Send.sent_at >= week_start
        ).scalar() or 0

        # Peak hour
        try:
            hr_row = db.session.query(
                extract('hour', Send.sent_at).label('hr'),
                func.count(Send.id).label('cnt')
            ).filter(
                Send.user_id == uid, Send.status == 'sent', Send.sent_at.isnot(None)
            ).group_by('hr').order_by(func.count(Send.id).desc()).first()
            if hr_row and hr_row.hr is not None:
                peak_hour = f"{int(hr_row.hr):02d}:00"
        except Exception:
            pass
    else:
        lifetime_count = 0
        week_total = 0

    daily_rows = []
    for d in sorted(daily_counts.keys())[-14:]:
        calc = _ai_calc_from_count(daily_counts[d], delay_sec=delay_avg)
        calc.update({'date': d, 'emails': daily_counts[d], 'actions_avoided': calc['manual_actions_avoided']})
        daily_rows.append(calc)
    best_day = None
    if daily_rows:
        best = max(daily_rows, key=lambda r: r['time_saved_sec'])
        best_day = {'date': best['date'], 'emails': best['emails'], 'time_saved_fmt': best['time_saved_fmt']}
    result = {
        'today': _ai_calc_from_count(daily_counts.get(today_key, 0), delay_sec=delay_avg),
        'week': _ai_calc_from_count(week_total, delay_sec=delay_avg),
        'lifetime': _ai_calc_from_count(lifetime_count, delay_sec=delay_avg),
        'daily': daily_rows,
        'best_day': best_day,
        'peak_hour': peak_hour,
        'config': {'delay_min': cfg.get('delay_min', 20), 'delay_max': cfg.get('delay_max', 45), 'delay_avg': round(delay_avg, 1)},
    }
    _cache_set(cache_key, result)
    return result

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_DATE_RE  = re.compile(r'\d{1,2}/\d{1,2}(?:\s*-\s*\d{1,2}/\d{1,2})?')
_DATE_MONTH_RE = re.compile(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}')
_MONTH_TO_NUM = {'Jan':'1','Feb':'2','Mar':'3','Apr':'4','May':'5','Jun':'6',
                 'Jul':'7','Aug':'8','Sep':'9','Oct':'10','Nov':'11','Dec':'12'}
_LEN_RE   = re.compile(r'\d{2,3}\s*ft')
_WT_RE    = re.compile(r'[\d,]+\s*lbs')
_EQUIP_RE = re.compile(r'\b(VM|VR|FD|SD|V|F|R)\b')
# Detailed view uses full words: "Van", "Reefer", "Flatbed", "Van or Reefer", "Van Air-Ride"
_EQUIP_WORD_RE = re.compile(r'\b(Van Air-Ride|Van or Reefer|Flatbed|Reefer|Van)\b', re.IGNORECASE)
_EQUIP_WORD_MAP = {'van': 'V', 'reefer': 'R', 'flatbed': 'F', 'van or reefer': 'VR', 'van air-ride': 'V'}
# City pattern: "City Name, ST" optionally followed by "(0)" or "(123)"
_CITY_RE  = re.compile(r'^([A-Z][a-zA-Z\s\.]+,\s*[A-Z]{2})(?:\s*\(\d*\))?$')  # comma required, space optional
# Words that should NEVER be treated as city names
_NOT_CITY = frozenset({
    'Full', 'Partial', 'Canceled', 'Equipment', 'Load', 'Truck',
    'Length', 'Weight', 'Commodity', 'Reference ID', 'Van', 'Reefer',
    'Flatbed', 'CONTACT INFORMATION', 'COMMENTS', 'VIEW ROUTE',
    'Van Air-Ride', 'Van or Reefer', 'Post now', 'Trip',
    # DAT payment/service metadata tokens — appear in contact block, never company names
    'Factoring', 'Factoring Available', 'Quick Pay', 'Quick Pay Available',
    'Fuel Advance', 'Fuel Advance Available',
})

def parse_dat_text(text):
    """Parse both compact (list) and detailed (card) DAT board formats."""
    # Expand tab-separated lines into individual tokens so both
    # newline-per-field and tab-per-field DAT board formats work
    raw_lines = text.strip().splitlines()
    expanded = []
    for l in raw_lines:
        if '\t' in l:
            expanded.extend([t.strip() for t in l.split('\t') if t.strip()])
        elif l.strip():
            expanded.append(l.strip())
    # Join 3-line city format: "City Name" / "," / "ST" → "City Name, ST"
    # DAT board sometimes splits city and state onto separate lines
    lines = []
    i = 0
    while i < len(expanded):
        if (i + 2 < len(expanded) and
                re.match(r'^[A-Z][a-zA-Z\s\.]+$', expanded[i]) and
                expanded[i + 1] == ',' and
                re.match(r'^[A-Z]{2}$', expanded[i + 2])):
            lines.append(expanded[i] + ', ' + expanded[i + 2])
            i += 3
        else:
            lines.append(expanded[i])
            i += 1
    loads, seen = [], set()
    for i, line in enumerate(lines):
        m = _EMAIL_RE.search(line)
        if not m: continue
        email = m.group().lower()
        # Lookback 30 lines (detailed view has ~20 lines per load)
        block = lines[max(0, i-30):i]
        block_text = " ".join(block)

        # Helper: get LAST regex match in text (closest to email)
        def _last(regex, txt):
            ms = list(regex.finditer(txt))
            return ms[-1] if ms else None

        # ── Date: try numeric first (3/23), then month name (Mar 23)
        date_m = _last(_DATE_RE, block_text)
        if not date_m:
            month_m = _last(_DATE_MONTH_RE, block_text)
            if month_m:
                parts = month_m.group().split()
                date_str = f"{_MONTH_TO_NUM.get(parts[0], '?')}/{parts[1]}"
                class _M:
                    def __init__(self, s): self._s = s
                    def group(self, *a): return self._s
                date_m = _M(date_str)

        len_m   = _last(_LEN_RE, block_text)
        wt_m    = _last(_WT_RE, block_text)
        eq_m    = _last(_EQUIP_RE, block_text)
        # Fallback: try full words (Van, Reefer, Flatbed) — use last match
        if not eq_m:
            eq_word = _last(_EQUIP_WORD_RE, block_text)
            if eq_word:
                mapped = _EQUIP_WORD_MAP.get(eq_word.group().lower(), '')
                if mapped:
                    eq_m = _M(mapped)

        # ── Cities: match "City, ST" and strip optional "(0)"
        # Use the LAST two cities in the block (closest to this email)
        cities = []
        for bl in block:
            cm = _CITY_RE.match(bl.strip())
            if cm and len(cm.group(1)) < 35 and cm.group(1).strip() not in _NOT_CITY:
                cities.append(cm.group(1).strip())
        # Take last 2 cities (origin, destination) — they belong to THIS load
        if len(cities) >= 2:
            origin      = cities[-2]
            destination = cities[-1]
        elif len(cities) == 1:
            origin      = cities[-1]
            destination = ""
        else:
            origin = destination = ""

        # ── Company: walk backwards from email, skip phone/keywords/numbers
        company = ""
        for j in range(i-1, max(0, i-8), -1):
            cand = lines[j].strip()
            if not cand: continue
            # Skip phone numbers: (855) 956-1095, +1-800-555-0100, etc
            if re.match(r'^[\(\)\d\s\-\+\.x]+$', cand): continue
            # Skip known section headers
            if cand.upper() in ('CONTACT INFORMATION', 'COMMENTS', 'VIEW ROUTE'): continue
            # Skip emails
            if '@' in cand: continue
            # Skip number-heavy lines: 42,000 lbs, $1,200, 53 ft, 3/23, 0900, etc
            if re.match(r'^[\d\$,.\s/\-*%a-z]+$', cand): continue
            # Skip weights, lengths, dates
            if _WT_RE.match(cand) or _LEN_RE.match(cand): continue
            # Skip known DAT keywords
            if cand in _NOT_CITY: continue
            # Skip all-caps short codes: ANATXFL1, SSLARFL
            if re.match(r'^[A-Z0-9]{3,12}$', cand): continue
            # Skip commodity-like ALL-CAPS lines (CANNED FOOD, SNACKS) — but allow mixed case companies
            if re.match(r'^[A-Z\s]{3,30}$', cand) and not re.search(r'[a-z]', cand) and len(cand.split()) <= 3: continue
            # Skip EXT/ext lines (phone extension hints)
            if re.match(r'^(?:EXT|ext)\b', cand): continue
            company = cand
            break

        # ── Fallback origin (only if no cities found) — strict exclusion
        if not origin:
            for bl in block:
                bl_s = bl.strip()
                if bl_s in _NOT_CITY: continue
                if re.match(r'^[A-Z][a-zA-Z\s]{2,25}$', bl_s):
                    origin = bl_s; break

        key = f"{email}|{origin}|{destination}"
        if key in seen: continue
        seen.add(key)
        loads.append({"email": email, "origin": origin, "destination": destination,
            "date":    date_m.group()  if date_m  else "",
            "equip":   eq_m.group()    if eq_m    else "",
            "length":  len_m.group()   if len_m   else "",
            "weight":  wt_m.group()    if wt_m    else "",
            "company": company})
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


def _gmail_send_with_retry(service, raw_message, max_retries=3):
    """Send via Gmail API with exponential backoff on transient errors."""
    from googleapiclient.errors import HttpError
    last_exc = None
    for attempt in range(max_retries):
        try:
            return service.users().messages().send(
                userId='me', body={'raw': raw_message}
            ).execute()
        except HttpError as e:
            status_code = e.resp.status
            # Retry on 429 (rate limit), 500, 502, 503, 504
            if status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = (2 ** attempt) + random.uniform(0, 1)
                app.logger.warning(f'Gmail API {status_code} on attempt {attempt+1}, retrying in {wait:.1f}s')
                time.sleep(wait)
                last_exc = e
                continue
            raise  # non-retryable or final attempt
    raise last_exc  # should not reach here


def send_one_email(to_email, subject, body, cfg, uid=None):
    """Send email via Gmail API (primary) or SMTP (legacy fallback).
    uid is needed to load OAuth tokens; defaults to current_user_id() if not passed."""
    if uid is None:
        uid = current_user_id()
    app.logger.info(f'send_one_email START uid={uid} to={to_email}')
    try:
        # ── Primary: Gmail API ────────────────────────────────────────────────
        try:
            app.logger.info(f'send_one_email: attempting Gmail API for uid={uid}')
            service = _get_gmail_service(uid)
            mime_msg = MIMEText(body, 'plain')
            mime_msg['to']      = to_email
            mime_msg['from']    = cfg.get('gmail_address', '')
            mime_msg['subject'] = subject
            raw = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode('utf-8')
            result = _gmail_send_with_retry(service, raw)
            app.logger.info(f'send_one_email: Gmail API SUCCESS uid={uid} to={to_email} msgId={result.get("id")}')
            return True, None
        except RuntimeError as gmail_err:
            # Not connected via OAuth — fall through to SMTP legacy
            if 'not connected' not in str(gmail_err).lower():
                app.logger.error(f'send_one_email: Gmail API ERROR uid={uid} to={to_email}: {gmail_err}')
                raise  # real Gmail API error — don't silently fall back
            app.logger.warning(f'send_one_email: Gmail OAuth not connected uid={uid}, trying SMTP legacy')

        # ── Fallback: legacy SMTP (App Password) ─────────────────────────────
        passwd = cfg.get('gmail_app_password', '')
        if not passwd:
            raise RuntimeError('No sending method configured — connect Gmail in Settings')
        app.logger.info(f'send_one_email: attempting SMTP for uid={uid} to={to_email}')
        msg = MIMEMultipart()
        msg['From']    = cfg['gmail_address']
        msg['To']      = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, cfg['gmail_address'], to_email, passwd)
        app.logger.info(f'send_one_email: SMTP SUCCESS uid={uid} to={to_email}')
        return True, None

    except Exception as e:
        import traceback
        app.logger.error(f'send_one_email FAILED uid={uid} to={to_email}: {type(e).__name__}: {e}\n{traceback.format_exc()}')
        return False, str(e)

_EQUIP_LABELS = {
    'V': 'Van', 'F': 'Flatbed', 'R': 'Reefer', 'SD': 'Step Deck',
    'DD': 'Double Drop', 'RGN': 'RGN', 'LB': 'Lowboy', 'MX': 'Maxi',
    'HS': 'Hot Shot', 'AC': 'Auto Carrier', 'TN': 'Tanker', 'PO': 'Power Only',
    'FD': 'Flat/Drop', 'FSD': 'Flat/Step', 'C': 'Conestoga', 'B': 'Bulk',
}

def _build_subject(load):
    """Build a clean, human-readable email subject from a parsed load dict.
    Example: Laredo, TX to Conroe, TX, 3/19, Van, 53 ft, 40,913 lbs
    Missing fields are skipped — no double separators, no trailing separators."""
    origin      = (load.get('origin') or '').strip()
    destination = (load.get('destination') or '').strip()
    date        = (load.get('date') or '').strip()
    equip_raw   = (load.get('equip') or '').strip()
    length      = (load.get('length') or '').strip()
    weight      = (load.get('weight') or '').strip()

    equip = _EQUIP_LABELS.get(equip_raw.upper(), equip_raw)

    if origin and destination:
        route = f'{origin} to {destination}'
    elif origin:
        route = origin
    elif destination:
        route = destination
    else:
        route = ''

    parts = [p for p in [route, date, equip, length] if p]
    return ', '.join(parts)

def run_send_job(loads, cfg, templates, uid=None):
    """Run in a background thread. uid must be passed explicitly — no session in threads."""
    state = _user_send_state(uid)
    state.update({"running":True,"done":False,"total":len(loads),"current":0,"sent":0,"errors":0,"skipped":0,"log":[]})
    with app.app_context():
        from app.models import SendJob
        # Create DB record at job start
        job = SendJob(user_id=uid, status='running', total=len(loads))
        db.session.add(job)
        db.session.commit()
        state['job_id'] = job.id

        _, sent_today_set = load_sent_log(uid=uid)
        be, bd = load_stop_list(uid=uid)
        session_sent = set()
        for i, load in enumerate(loads):
            state["current"] = i + 1
            em = load['email'].lower().strip()
            if is_blocked(load['email'], be, bd):
                state["skipped"] += 1
                state["log"].append({"time":datetime.now().strftime('%H:%M:%S'),"status":"skipped","variant":0,"email":load["email"],"error":"stop list"})
                continue
            if em in sent_today_set or em in session_sent:
                state["skipped"] += 1
                state["log"].append({"time":datetime.now().strftime('%H:%M:%S'),"status":"skipped","variant":0,"email":load["email"],"error":"already sent today"})
                continue
            tmpl = random.choice(templates); vi = templates.index(tmpl) + 1
            body = render_template_text(tmpl, load, cfg)
            subject = _build_subject(load)
            ok, err = send_one_email(load['email'], subject, body, cfg, uid=uid)
            ts = datetime.now().strftime('%H:%M:%S'); st = 'sent' if ok else 'error'
            append_log(load, st, vi, uid=uid)
            if ok:
                session_sent.add(em)
                state["sent"] += 1
                _track_usage(uid, 'email_sent')   # ← quota tracking
            else:
                state["errors"] += 1
            state["log"].append({"time":ts,"status":st,"variant":vi,"email":load["email"],"error":err or ""})
            # Persist progress to DB every 10 emails
            if (i + 1) % 10 == 0:
                try:
                    job.sent    = state["sent"]
                    job.errors  = state["errors"]
                    job.skipped = state["skipped"]
                    db.session.commit()
                except Exception as _pe:
                    app.logger.warning(f'run_send_job: DB progress update failed: {_pe}')
                    db.session.rollback()
            if i < len(loads) - 1:
                time.sleep(random.randint(cfg.get("delay_min", 20), cfg.get("delay_max", 45)))
        state.update({"running": False, "done": True})
        # Mark job as done in DB
        try:
            job.status      = 'done'
            job.sent        = state["sent"]
            job.errors      = state["errors"]
            job.skipped     = state["skipped"]
            job.finished_at = datetime.utcnow()
            db.session.commit()
        except Exception as _fe:
            app.logger.warning(f'run_send_job: DB final update failed: {_fe}')
            db.session.rollback()
        audit_log('send_batch', resource_type='send', uid=uid, detail={
            'total': state['total'], 'sent': state['sent'],
            'errors': state['errors'], 'skipped': state['skipped'],
        })

# ── Gmail OAuth2 Routes ───────────────────────────────────────────────────────

@app.route('/api/gmail/auth-url')
@login_required
def api_gmail_auth_url():
    """Return Google OAuth consent URL. Frontend redirects user there."""
    client_id    = os.environ.get('GOOGLE_CLIENT_ID', '')
    redirect_uri = os.environ.get('GOOGLE_REDIRECT_URI', request.host_url.rstrip('/') + '/api/gmail/callback')
    if not client_id:
        return jsonify({'error': 'GOOGLE_CLIENT_ID not configured'}), 500
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    params = urllib.parse.urlencode({
        'client_id':     client_id,
        'redirect_uri':  redirect_uri,
        'response_type': 'code',
        'scope':         ' '.join(_GMAIL_SCOPES),
        'access_type':   'offline',
        'prompt':        'consent',   # force refresh_token every time
        'state':         state,
    })
    return jsonify({'url': f'https://accounts.google.com/o/oauth2/v2/auth?{params}'})


@app.route('/api/gmail/callback')
def api_gmail_callback():
    """Handle Google OAuth redirect. Exchanges code for tokens and saves them."""
    error = request.args.get('error')
    if error:
        return redirect(f'/?gmail_error={urllib.parse.quote(error)}')

    state = request.args.get('state', '')
    if state != session.get('oauth_state', ''):
        return redirect('/?gmail_error=state_mismatch')
    session.pop('oauth_state', None)

    code         = request.args.get('code', '')
    client_id    = os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    redirect_uri = os.environ.get('GOOGLE_REDIRECT_URI', request.host_url.rstrip('/') + '/api/gmail/callback')

    # Exchange code for tokens
    try:
        token_data = urllib.parse.urlencode({
            'code':          code,
            'client_id':     client_id,
            'client_secret': client_secret,
            'redirect_uri':  redirect_uri,
            'grant_type':    'authorization_code',
        }).encode('utf-8')
        req = urllib.request.Request(
            'https://oauth2.googleapis.com/token',
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_resp = json.loads(resp.read())
    except Exception as e:
        app.logger.error(f'Gmail OAuth token exchange failed: {e}')
        return redirect(f'/?gmail_error={urllib.parse.quote(str(e))}')

    refresh_token = token_resp.get('refresh_token', '')
    access_token  = token_resp.get('access_token', '')
    expires_in    = token_resp.get('expires_in', 3600)

    if not refresh_token:
        return redirect('/?gmail_error=no_refresh_token')

    # Build temporary credentials to get the user's Gmail address
    try:
        creds = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=client_id,
            client_secret=client_secret,
            scopes=_GMAIL_SCOPES,
        )
        svc     = gbuild('gmail', 'v1', credentials=creds)
        profile = svc.users().getProfile(userId='me').execute()
        gmail_address = profile.get('emailAddress', '')
    except Exception as e:
        app.logger.error(f'Gmail profile fetch failed: {e}')
        return redirect(f'/?gmail_error={urllib.parse.quote(str(e))}')

    # Save tokens to EmailAccount
    uid = current_user_id()
    if not uid:
        return redirect('/login')
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if not acct:
        acct = EmailAccount(user_id=uid)
        db.session.add(acct)
    acct.gmail_address       = gmail_address
    acct.google_refresh_token = encrypt_field(refresh_token)
    acct.google_access_token  = encrypt_field(access_token)
    acct.token_expiry         = datetime.utcnow() + timedelta(seconds=expires_in)
    db.session.commit()

    audit_log('gmail_oauth_connect', resource_type='email_account', uid=uid,
              detail={'email': gmail_address})
    return redirect('/?gmail_connected=1')


@app.route('/api/gmail/status')
@login_required
def api_gmail_status():
    """Return Gmail OAuth connection status for current user."""
    uid = current_user_id()
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    connected = bool(acct and acct.google_refresh_token)
    return jsonify({
        'connected': connected,
        'email': acct.gmail_address if (acct and connected) else None,
    })


@app.route('/api/gmail/disconnect', methods=['POST'])
@login_required
def api_gmail_disconnect():
    """Clear Gmail OAuth tokens for current user."""
    uid = current_user_id()
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if acct:
        acct.google_refresh_token = None
        acct.google_access_token  = None
        acct.token_expiry         = None
        db.session.commit()
    audit_log('gmail_oauth_disconnect', resource_type='email_account', uid=uid)
    return jsonify({'ok': True})


@app.route('/api/gmail/test-send', methods=['POST'])
@login_required
def api_gmail_test_send():
    """Minimal test: bypass all DAT logic, send one plain email via Gmail API only."""
    uid = current_user_id()
    to_email = request.json.get('to', '')
    if not to_email:
        return jsonify({'ok': False, 'error': 'Missing "to" field'}), 400
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    app.logger.info(f'gmail/test-send uid={uid} acct={acct} to={to_email}')
    if not acct:
        return jsonify({'ok': False, 'error': 'No email account row found for this user'}), 400
    app.logger.info(f'gmail/test-send acct.gmail_address={acct.gmail_address} '
                    f'has_refresh={bool(acct.google_refresh_token)} '
                    f'has_access={bool(acct.google_access_token)}')
    try:
        service = _get_gmail_service(uid)
        mime_msg = MIMEText('This is a test email from DAT Mailer Gmail OAuth.', 'plain')
        mime_msg['to']      = to_email
        mime_msg['from']    = acct.gmail_address or ''
        mime_msg['subject'] = 'DAT Mailer — Gmail OAuth test'
        raw = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode('utf-8')
        result = service.users().messages().send(userId='me', body={'raw': raw}).execute()
        app.logger.info(f'gmail/test-send SUCCESS uid={uid} msgId={result.get("id")}')
        return jsonify({'ok': True, 'message_id': result.get('id'), 'from': acct.gmail_address})
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        app.logger.error(f'gmail/test-send FAILED uid={uid}: {e}\n{tb}')
        return jsonify({'ok': False, 'error': str(e), 'traceback': tb}), 500


# ─── API ROUTES (all protected) ───────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
@login_required
def api_get_config():
    cfg = load_config()
    safe = {k: v for k, v in cfg.items() if k != 'gmail_app_password'}
    safe['has_password']    = bool(cfg.get('gmail_app_password'))
    safe['gmail_connected'] = bool(cfg.get('gmail_connected'))
    return jsonify(safe)

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

@app.route('/api/parse-context', methods=['GET'])
@login_required
def api_parse_context():
    be, bd = load_stop_list()           # TTL-cached (300s)
    all_sent, sent_today = load_sent_log()  # TTL-cached (90s)
    return jsonify({
        'all_sent':     list(all_sent),
        'sent_today':   list(sent_today),
        'stop_emails':  list(be),
        'stop_domains': list(bd),
    })

@app.route('/api/parse', methods=['POST'])
@login_required
def api_parse():
    raw = request.json.get("text", "")
    if not raw: return jsonify({"error": "No text"}), 400
    all_loads = parse_dat_text(raw)
    be, bd = load_stop_list(); all_sent, sent_today = load_sent_log()
    result = []; stats = {"total":len(all_loads),"new":0,"skip_today":0,"skip_dup":0,"skip_sent":0,"skip_stop":0}
    seen_in_batch = set()  # within-batch dedup by email (prevents sending twice in same paste)
    for l in all_loads:
        em = l['email'].lower().strip()
        key = f"{em}|{l['origin']}|{l['destination']}"
        if is_blocked(l['email'], be, bd):
            l['skip'] = 'stop_list'; stats["skip_stop"] += 1
        elif em in sent_today:
            l['skip'] = 'today'; stats["skip_today"] += 1
        elif em in seen_in_batch:
            l['skip'] = 'in_batch'; stats["skip_dup"] += 1   # same email twice in this paste
        elif key in all_sent:
            l['skip'] = 'sent'; stats["skip_sent"] += 1      # sent before (any previous session)
        else:
            l['skip'] = None; stats["new"] += 1; seen_in_batch.add(em)
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
    has_email   = bool(cfg.get("gmail_address"))
    has_pass    = bool(cfg.get("gmail_app_password"))
    has_oauth   = bool(cfg.get("gmail_connected"))   # OAuth2 token present
    app.logger.info(f'API /api/send cfg — has_email={has_email} has_pass={has_pass} has_oauth={has_oauth}')
    if not has_email or (not has_pass and not has_oauth):
        return jsonify({"error": "Gmail not configured — connect Gmail in Settings"}), 400
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
def api_send_status():
    uid = current_user_id()
    state = _user_send_state(uid)
    # If no active in-memory job, check DB for latest job (covers post-restart case)
    if not state.get('running') and not state.get('done'):
        from app.models import SendJob
        job = SendJob.query.filter_by(user_id=uid).order_by(SendJob.started_at.desc()).first()
        if job:
            return jsonify({
                'running': False, 'done': job.status == 'done',
                'total': job.total, 'current': job.sent + job.errors + job.skipped,
                'sent': job.sent, 'errors': job.errors, 'skipped': job.skipped,
                'log': [], 'status': job.status,
            })
    return jsonify(state)

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
    """Test email sending — Gmail API primary, SMTP legacy fallback."""
    uid = current_user_id()
    try:
        service = _get_gmail_service(uid)
        profile = service.users().getProfile(userId='me').execute()
        return jsonify({'ok': True, 'method': 'gmail_api', 'email': profile.get('emailAddress', '')})
    except RuntimeError as e:
        if 'not connected' not in str(e).lower():
            return jsonify({'ok': False, 'method': 'gmail_api', 'error': str(e)})
    # Fallback: test SMTP (legacy App Password)
    cfg    = load_config()
    gmail  = cfg.get('gmail_address', '')
    passwd = cfg.get('gmail_app_password', '')
    if not gmail or not passwd:
        return jsonify({'ok': False, 'method': 'none',
                        'error': 'Not configured — connect Gmail in Settings'})
    steps = []
    try:
        steps.append('connect smtp.gmail.com:587')
        s = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        steps.append('starttls'); s.ehlo(); s.starttls(); s.ehlo()
        steps.append(f'login {gmail}'); s.login(gmail, passwd)
        steps.append('quit'); s.quit()
        return jsonify({'ok': True, 'method': 'smtp_legacy', 'steps': steps})
    except Exception as e:
        return jsonify({'ok': False, 'method': 'smtp_legacy',
                        'step': steps[-1] if steps else '?',
                        'error': str(e), 'steps': steps})

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
    if status in ('interested', 'follow_up') and reply_obj:
        from app.models import Reply as ReplyModel
        reply_db = ReplyModel.query.filter_by(msg_id=reply_obj['msg_id']).first()
        if reply_db:
            add_to_followups(reply_db)
    if add_to_stop and reply_obj:
        uid = current_user_id()
        em = reply_obj.get('email','')
        if uid and em:
            from app.models import StopListEntry
            from sqlalchemy.exc import IntegrityError
            try:
                db.session.add(StopListEntry(user_id=uid, type='email', value=em.lower()))
                db.session.commit()
                _cache_del(f'stop_list:{uid}')  # invalidate so next parse sees updated list
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
    scheduler_ok = _scheduler.is_alive() if '_scheduler' in globals() else True
    ok = db_ok and scheduler_ok
    return jsonify({
        'status':    'ok' if ok else 'degraded',
        'db':        db_ok,
        'scheduler': scheduler_ok,
    }), 200 if ok else 503

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

def send_followup_email(fu, template_text, cfg, uid=None):
    try:
        to_email = fu.get('contact_email') or fu.get('email', '')
        route = fu.get('current_route') or fu.get('route', '')
        subject = ('Re: ' + fu['reply_subject']) if fu.get('reply_subject') else 'Follow-up'
        body = template_text.format(
            name=cfg.get('your_name', '') or cfg.get('name', ''),
            company=cfg.get('your_company', '') or cfg.get('company', ''),
            phone=cfg.get('your_phone', '') or cfg.get('phone', ''),
            route=route,
            origin=route.split('→')[0].strip() if '→' in route else '',
            destination=route.split('→')[1].strip() if '→' in route else '',
        )
        # Try Gmail API OAuth first
        _uid = uid or current_user_id()
        if _uid:
            try:
                service = _get_gmail_service(_uid)
                mime_msg = MIMEText(body, 'plain')
                mime_msg['to'] = to_email
                mime_msg['from'] = cfg.get('gmail_address', '')
                mime_msg['subject'] = subject
                if fu.get('reply_msg_id'):
                    mime_msg['In-Reply-To'] = fu['reply_msg_id']
                    mime_msg['References']  = fu['reply_msg_id']
                import base64 as _b64
                raw = _b64.urlsafe_b64encode(mime_msg.as_bytes()).decode('utf-8')
                _gmail_send_with_retry(service, raw)
                return True, None
            except RuntimeError as _e:
                if 'not connected' not in str(_e).lower():
                    raise
        # Fallback: SMTP
        msg = MIMEMultipart()
        msg['From'] = cfg['gmail_address']; msg['To'] = to_email
        msg['Subject'] = subject
        if fu.get('reply_msg_id'):
            msg['In-Reply-To'] = fu['reply_msg_id']; msg['References'] = fu['reply_msg_id']
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, cfg['gmail_address'], to_email, cfg.get('gmail_app_password', ''))
        return True, None
    except Exception as e: return False, str(e)

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

@app.route('/api/followups')
@login_required
def api_followups_list():
    from app.models import FollowupContact
    from sqlalchemy import func, case
    uid = _current_user_id()
    q = FollowupContact.query.filter_by(user_id=uid)

    state_f = request.args.get('state')
    stage_f = request.args.get('stage')
    special = request.args.get('filter')
    search  = request.args.get('q', '').strip().lower()

    if state_f and state_f in VALID_STATES:
        q = q.filter_by(state=state_f)
    if stage_f:
        stage_map = {'FU1': ['fu1_scheduled', 'fu1_sent'], 'FU2': ['fu2_scheduled', 'fu2_sent'],
                     'FU3': ['fu3_scheduled', 'fu3_sent'], 'Done': ['completed_fu3']}
        stages = stage_map.get(stage_f, [])
        if stages:
            q = q.filter(FollowupContact.stage.in_(stages))
    if search:
        q = q.filter(db.or_(
            FollowupContact.contact_email.ilike(f'%{search}%'),
            FollowupContact.contact_name.ilike(f'%{search}%'),
            FollowupContact.company_name.ilike(f'%{search}%'),
        ))

    now = datetime.utcnow()
    if special == 'needs_action':
        q = q.filter(FollowupContact.stage == 'completed_fu3', FollowupContact.state == 'active')
    elif special == 'overdue':
        q = q.filter(FollowupContact.next_followup_at < now, FollowupContact.state == 'active',
                     FollowupContact.is_followup_enabled == True)
    elif special == 'due_today':
        end_of_day = now.replace(hour=23, minute=59, second=59)
        q = q.filter(FollowupContact.next_followup_at <= end_of_day,
                     FollowupContact.next_followup_at >= now,
                     FollowupContact.state == 'active', FollowupContact.is_followup_enabled == True)
    elif special == 'scheduled':
        q = q.filter(FollowupContact.scheduled_once == True,
                     FollowupContact.next_followup_at > now)

    contacts = q.order_by(FollowupContact.created_at.desc()).all()

    count_q = db.session.query(
        func.count(FollowupContact.id).label('total'),
        func.count(case((FollowupContact.state == 'active', 1))).label('active'),
        func.count(case((FollowupContact.state == 'paused', 1))).label('paused'),
        func.count(case((FollowupContact.state == 'warm', 1))).label('warm'),
        func.count(case((FollowupContact.state == 'loads', 1))).label('loads'),
        func.count(case((FollowupContact.state == 'blocked', 1))).label('blocked'),
        func.count(case((FollowupContact.state == 'closed', 1))).label('closed'),
        func.count(case(((FollowupContact.stage == 'completed_fu3') & (FollowupContact.state == 'active'), 1))).label('needs_action'),
        func.count(case(((FollowupContact.next_followup_at < now) & (FollowupContact.state == 'active') & (FollowupContact.is_followup_enabled == True), 1))).label('overdue'),
        func.count(case(((FollowupContact.scheduled_once == True) & (FollowupContact.next_followup_at > now), 1))).label('scheduled'),
    ).filter(FollowupContact.user_id == uid).first()

    counts = {
        'total': count_q.total, 'active': count_q.active, 'paused': count_q.paused,
        'warm': count_q.warm, 'loads': count_q.loads, 'blocked': count_q.blocked,
        'closed': count_q.closed, 'needs_action': count_q.needs_action, 'overdue': count_q.overdue,
        'scheduled': count_q.scheduled,
    }
    return jsonify(contacts=[c.to_dict() for c in contacts], counts=counts)


@app.route('/api/followups/ids')
@login_required
def api_followups_ids():
    """Return all contact IDs matching current filters (for select-all-filtered)."""
    from app.models import FollowupContact
    uid = _current_user_id()
    q = FollowupContact.query.filter_by(user_id=uid)
    state_f = request.args.get('state')
    stage_f = request.args.get('stage')
    special = request.args.get('filter')
    search  = request.args.get('q', '').strip().lower()
    if state_f and state_f in VALID_STATES:
        q = q.filter_by(state=state_f)
    if stage_f:
        stage_map = {'FU1': ['fu1_scheduled', 'fu1_sent'], 'FU2': ['fu2_scheduled', 'fu2_sent'],
                     'FU3': ['fu3_scheduled', 'fu3_sent'], 'Done': ['completed_fu3']}
        stages = stage_map.get(stage_f, [])
        if stages:
            q = q.filter(FollowupContact.stage.in_(stages))
    if search:
        q = q.filter(db.or_(
            FollowupContact.contact_email.ilike(f'%{search}%'),
            FollowupContact.contact_name.ilike(f'%{search}%'),
            FollowupContact.company_name.ilike(f'%{search}%'),
        ))
    now = datetime.utcnow()
    if special == 'needs_action':
        q = q.filter(FollowupContact.stage == 'completed_fu3', FollowupContact.state == 'active')
    elif special == 'overdue':
        q = q.filter(FollowupContact.next_followup_at < now, FollowupContact.state == 'active',
                     FollowupContact.is_followup_enabled == True)
    elif special == 'due_today':
        end_of_day = now.replace(hour=23, minute=59, second=59)
        q = q.filter(FollowupContact.next_followup_at <= end_of_day,
                     FollowupContact.next_followup_at >= now,
                     FollowupContact.state == 'active', FollowupContact.is_followup_enabled == True)
    elif special == 'scheduled':
        q = q.filter(FollowupContact.scheduled_once == True,
                     FollowupContact.next_followup_at > now)
    ids = [row[0] for row in q.with_entities(FollowupContact.id).all()]
    return jsonify(ids=ids)


@app.route('/api/followups/add', methods=['POST'])
@login_required
def api_followups_add():
    from app.models import FollowupContact, Workspace
    uid = _current_user_id()
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify(error='Email required'), 400

    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return jsonify(error='No workspace'), 400

    exists = FollowupContact.query.filter_by(workspace_id=ws.id, contact_email=email).first()
    if exists:
        return jsonify(error='Contact already in follow-ups'), 409

    settings = _get_fu_settings(ws.id)
    now = datetime.utcnow()

    fc = FollowupContact(
        user_id=uid, workspace_id=ws.id, contact_email=email,
        contact_name=data.get('name', ''), company_name=data.get('company', ''),
        current_route=data.get('route', ''), state='active', stage='fu1_scheduled',
        is_followup_enabled=settings['default_enabled'],
        next_followup_at=now + _get_stage_delay('fu1_scheduled', settings),
        last_activity_at=now, source_reply_id=data.get('source_reply_id'),
        reply_subject=data.get('reply_subject', ''), reply_msg_id=data.get('reply_msg_id', ''),
        source_thread_id=data.get('source_thread_id', ''),
    )
    db.session.add(fc)
    db.session.flush()
    _record_event(fc, 'created', actor_user_id=uid)
    db.session.commit()
    return jsonify(ok=True, contact=fc.to_dict()), 201


@app.route('/api/followups/action', methods=['POST'])
@login_required
def api_followups_action():
    from app.models import FollowupContact, EmailAccount
    uid = _current_user_id()
    data = request.get_json()
    contact_id = data.get('id')
    action = data.get('action')
    reason = data.get('reason', '')

    fc = FollowupContact.query.get(contact_id)
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404

    if action == 'send-now':
        if fc.state != 'active':
            return jsonify(error='Contact must be active to send'), 400
        if fc.stage not in STAGE_TO_TEMPLATE:
            return jsonify(error='No scheduled follow-up to send'), 400

        template_text = _get_random_fu_template(uid)
        if not template_text:
            return jsonify(error='No active follow-up templates. Add at least one before sending.'), 400
        acct = EmailAccount.query.filter_by(user_id=uid).first()
        if not acct:
            return jsonify(error='No email account configured'), 400

        cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
               'phone': acct.your_phone or '', 'route': fc.current_route or ''}
        fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                   'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
        ok, err = send_followup_email(fu_dict, template_text, cfg, uid=uid)
        if not ok:
            _record_event(fc, 'manual_send', actor_user_id=uid,
                          metadata_json=json.dumps({'error': err}), notes='Send failed')
            db.session.commit()
            return jsonify(error=f'Send failed: {err}'), 500

        now = datetime.utcnow()
        old_stage = fc.stage
        setattr(fc, STAGE_SENT_FIELD[fc.stage], now)
        fc.last_followup_sent_at = now
        fc.last_activity_at = now

        sent_stage, next_scheduled = STAGE_PROGRESSION[fc.stage]
        if next_scheduled:
            settings = _get_fu_settings(fc.workspace_id)
            fc.stage = next_scheduled
            fc.next_followup_at = now + _get_stage_delay(next_scheduled, settings)
        else:
            fc.stage = 'completed_fu3'
            fc.is_followup_enabled = False
            fc.next_followup_at = None
            fc.completed_fu3_at = now

        _record_event(fc, 'manual_send', actor_user_id=uid,
                      from_stage=old_stage, to_stage=fc.stage)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'free-send':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot send to blocked or closed contact'), 400
        template_text = _get_random_fu_template(uid)
        if not template_text:
            return jsonify(error='No active follow-up templates. Add at least one before sending.'), 400
        acct = EmailAccount.query.filter_by(user_id=uid).first()
        if not acct:
            return jsonify(error='No email account configured'), 400
        cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
               'phone': acct.your_phone or '', 'route': fc.current_route or ''}
        fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                   'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
        ok, err = send_followup_email(fu_dict, template_text, cfg, uid=uid)
        if not ok:
            _record_event(fc, 'free_send', actor_user_id=uid,
                          metadata_json=json.dumps({'error': err}), notes='Send failed')
            db.session.commit()
            return jsonify(error=f'Send failed: {err}'), 500
        now = datetime.utcnow()
        fc.is_followup_enabled = False
        fc.last_followup_sent_at = now
        fc.last_activity_at = now
        _record_event(fc, 'free_send', actor_user_id=uid,
                      from_stage=fc.stage, to_stage=fc.stage)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'schedule-once':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot schedule blocked or closed contact'), 400
        dt_str = data.get('scheduled_at', '')
        if not dt_str:
            return jsonify(error='scheduled_at is required (ISO8601 UTC)'), 400
        try:
            scheduled_at = datetime.fromisoformat(dt_str.replace('Z', '+00:00')).replace(tzinfo=None)
            if scheduled_at < datetime.utcnow() + timedelta(minutes=1):
                return jsonify(error='scheduled_at must be at least 1 minute in the future'), 400
        except (ValueError, TypeError):
            return jsonify(error='Invalid scheduled_at format — use ISO8601 UTC'), 400
        fc.next_followup_at = scheduled_at
        fc.scheduled_once = True
        _record_event(fc, 'scheduled_once', actor_user_id=uid,
                      notes=f'Scheduled for {scheduled_at.strftime("%Y-%m-%d %H:%M")} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'set-recurring':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot set recurring for blocked or closed contact'), 400
        r_days = (data.get('recurring_days') or '').strip()
        r_time = (data.get('recurring_time') or '').strip()
        if not r_days:
            return jsonify(error='recurring_days is required'), 400
        try:
            parsed_days = [int(d) for d in r_days.split(',') if d.strip()]
            if not parsed_days or any(d < 0 or d > 6 for d in parsed_days):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify(error='recurring_days must be comma-separated integers 0-6'), 400
        import re as _re
        if not _re.match(r'^\d{2}:\d{2}$', r_time):
            return jsonify(error='recurring_time must be HH:MM'), 400
        fc.recurring_enabled = True
        fc.recurring_days    = r_days
        fc.recurring_time    = r_time
        fc.next_followup_at  = _next_recurring_datetime(r_days, r_time)
        _record_event(fc, 'recurring_set', actor_user_id=uid,
                      notes=f'Recurring days={r_days} time={r_time} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'stop-recurring':
        fc.recurring_enabled = False
        _record_event(fc, 'recurring_stopped', actor_user_id=uid)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'cancel-schedule':
        fc.scheduled_once = False
        fc.next_followup_at = None
        _record_event(fc, 'schedule_cancelled', actor_user_id=uid)
        db.session.commit()
        return jsonify(ok=True, contact=fc.to_dict())

    elif action == 'pause':
        ok, err = _transition_state(fc, 'paused', reason=reason, actor_user_id=uid)
    elif action == 'resume':
        ok, err = _transition_state(fc, 'active', actor_user_id=uid)
    elif action == 'warm':
        ok, err = _transition_state(fc, 'warm', actor_user_id=uid)
    elif action == 'loads':
        ok, err = _transition_state(fc, 'loads', actor_user_id=uid)
    elif action == 'block':
        ok, err = _transition_state(fc, 'blocked', reason=reason, actor_user_id=uid)
    elif action == 'close':
        ok, err = _transition_state(fc, 'closed', reason=reason, actor_user_id=uid)
    else:
        return jsonify(error=f'Unknown action: {action}'), 400

    if not ok:
        return jsonify(error=err), 400
    db.session.commit()
    return jsonify(ok=True, contact=fc.to_dict())


@app.route('/api/followups/bulk-action', methods=['POST'])
@login_required
def api_followups_bulk_action():
    from app.models import FollowupContact, EmailAccount
    uid = _current_user_id()
    data = request.get_json()
    ids = data.get('ids', [])
    action = data.get('action')
    reason = data.get('reason', '')

    results = []
    for cid in ids:
        fc = FollowupContact.query.get(cid)
        if not fc or fc.user_id != uid:
            results.append({'id': cid, 'ok': False, 'error': 'Not found'})
            continue

        if action in ('pause', 'resume', 'warm', 'loads', 'block', 'close'):
            target = 'active' if action == 'resume' else ('blocked' if action == 'block' else action)
            ok, err = _transition_state(fc, target, reason=reason, actor_user_id=uid)
            results.append({'id': cid, 'ok': ok, 'error': err})

        elif action == 'send-now':
            if fc.state != 'active' or fc.stage not in STAGE_TO_TEMPLATE or not fc.is_followup_enabled:
                results.append({'id': cid, 'ok': False, 'error': 'Not eligible for sequence send'})
                continue
            template_text = _get_random_fu_template(fc.user_id)
            if not template_text:
                results.append({'id': cid, 'ok': False, 'error': 'No active templates'})
                continue
            acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
            if not acct:
                results.append({'id': cid, 'ok': False, 'error': 'No email account'})
                continue
            cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                   'phone': acct.your_phone or '', 'route': fc.current_route or ''}
            fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                       'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
            ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)
            if ok:
                now_dt = datetime.utcnow()
                old_stage = fc.stage
                setattr(fc, STAGE_SENT_FIELD[fc.stage], now_dt)
                fc.last_followup_sent_at = now_dt
                fc.last_activity_at = now_dt
                sent_stage, next_scheduled = STAGE_PROGRESSION[fc.stage]
                if next_scheduled:
                    settings = _get_fu_settings(fc.workspace_id)
                    fc.stage = next_scheduled
                    fc.next_followup_at = now_dt + _get_stage_delay(next_scheduled, settings)
                else:
                    fc.stage = 'completed_fu3'
                    fc.is_followup_enabled = False
                    fc.next_followup_at = None
                    fc.completed_fu3_at = now_dt
                _record_event(fc, 'manual_send', actor_user_id=uid,
                              from_stage=old_stage, to_stage=fc.stage)
                results.append({'id': cid, 'ok': True})
            else:
                results.append({'id': cid, 'ok': False, 'error': err})

        elif action == 'free-send':
            if fc.state in ('blocked', 'closed'):
                results.append({'id': cid, 'ok': False, 'error': 'Blocked or closed'})
                continue
            template_text = _get_random_fu_template(fc.user_id)
            if not template_text:
                results.append({'id': cid, 'ok': False, 'error': 'No active templates'})
                continue
            acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
            if not acct:
                results.append({'id': cid, 'ok': False, 'error': 'No email account'})
                continue
            cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                   'phone': acct.your_phone or '', 'route': fc.current_route or ''}
            fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                       'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
            ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)
            if ok:
                now_dt = datetime.utcnow()
                fc.is_followup_enabled = False
                fc.last_followup_sent_at = now_dt
                fc.last_activity_at = now_dt
                _record_event(fc, 'free_send', actor_user_id=uid,
                              from_stage=fc.stage, to_stage=fc.stage)
                results.append({'id': cid, 'ok': True})
            else:
                results.append({'id': cid, 'ok': False, 'error': err})

        elif action == 'schedule-once':
            if fc.state in ('blocked', 'closed'):
                results.append({'id': cid, 'ok': False, 'error': 'Blocked or closed'})
                continue
            dt_str = data.get('scheduled_at', '')
            try:
                scheduled_at = datetime.fromisoformat(dt_str.replace('Z', '+00:00')).replace(tzinfo=None)
                if scheduled_at < datetime.utcnow() + timedelta(minutes=1):
                    results.append({'id': cid, 'ok': False, 'error': 'Date must be in future'})
                    continue
            except (ValueError, TypeError):
                results.append({'id': cid, 'ok': False, 'error': 'Invalid date format'})
                continue
            fc.next_followup_at = scheduled_at
            _record_event(fc, 'scheduled_once', actor_user_id=uid,
                          notes=f'Scheduled {scheduled_at.strftime("%Y-%m-%d %H:%M")} UTC')
            results.append({'id': cid, 'ok': True})

        elif action == 'set-recurring':
            if fc.state in ('blocked', 'closed'):
                results.append({'id': cid, 'ok': False, 'error': 'Blocked or closed'})
                continue
            r_days = (data.get('recurring_days') or '').strip()
            r_time = (data.get('recurring_time') or '').strip()
            try:
                fc.recurring_enabled = True
                fc.recurring_days    = r_days
                fc.recurring_time    = r_time
                fc.next_followup_at  = _next_recurring_datetime(r_days, r_time)
                _record_event(fc, 'recurring_set', actor_user_id=uid,
                              notes=f'Recurring days={r_days} time={r_time} UTC')
                results.append({'id': cid, 'ok': True})
            except ValueError as e:
                results.append({'id': cid, 'ok': False, 'error': str(e)})

        elif action == 'stop-recurring':
            fc.recurring_enabled = False
            _record_event(fc, 'recurring_stopped', actor_user_id=uid)
            results.append({'id': cid, 'ok': True})

        elif action == 'cancel-schedule':
            fc.scheduled_once = False
            fc.next_followup_at = None
            _record_event(fc, 'schedule_cancelled', actor_user_id=uid)
            results.append({'id': cid, 'ok': True})

        else:
            results.append({'id': cid, 'ok': False, 'error': f'Unknown action: {action}'})

    db.session.commit()
    ok_count   = sum(1 for r in results if r.get('ok'))
    skip_count = len(results) - ok_count
    return jsonify(results=results, sent=ok_count, skipped=skip_count)


@app.route('/api/followups/delete', methods=['POST'])
@login_required
def api_followups_delete():
    from app.models import FollowupContact
    uid = _current_user_id()
    data = request.get_json()
    fc = FollowupContact.query.get(data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    db.session.delete(fc)
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/followups/notes', methods=['POST'])
@login_required
def api_followups_notes():
    from app.models import FollowupContact
    uid = _current_user_id()
    data = request.get_json()
    fc = FollowupContact.query.get(data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    fc.notes = data.get('notes', '')
    fc.updated_at = datetime.utcnow()
    _record_event(fc, 'note_added', actor_user_id=uid, notes=fc.notes[:100])
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/followups/candidates')
@login_required
def api_followups_candidates():
    from app.models import FollowupContact, Workspace, Send
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return jsonify(candidates=[])

    search = request.args.get('q', '').strip().lower()
    existing = set(r[0] for r in db.session.query(FollowupContact.contact_email)
                   .filter_by(workspace_id=ws.id).all())

    q = Send.query.filter_by(user_id=uid).order_by(Send.sent_at.desc())
    if search:
        q = q.filter(db.or_(
            Send.to_email.ilike(f'%{search}%'),
            Send.company_name.ilike(f'%{search}%'),
        ))

    sends = q.limit(100).all()
    seen = set()
    candidates = []
    for s in sends:
        email = (s.to_email or '').lower()
        if email in existing or email in seen or not email:
            continue
        seen.add(email)
        candidates.append({
            'email': email,
            'name': getattr(s, 'contact_name', '') or '',
            'company': getattr(s, 'company_name', '') or '',
            'route': getattr(s, 'route', '') or '',
            'sent_at': s.sent_at.strftime('%Y-%m-%dT%H:%M:%SZ') if s.sent_at else None,
        })
        if len(candidates) >= 30:
            break

    return jsonify(candidates=candidates)


@app.route('/api/settings/followup', methods=['GET', 'POST'])
@login_required
def api_settings_followup():
    from app.models import FollowupSettings, Workspace
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return jsonify(error='No workspace'), 400

    s = FollowupSettings.query.filter_by(workspace_id=ws.id).first()

    if request.method == 'GET':
        if not s:
            return jsonify(fu1_delay_days=3, fu2_delay_days=5, fu3_delay_days=7,
                           auto_stop_on_reply=True, default_followup_enabled=True)
        return jsonify(fu1_delay_days=s.fu1_delay_days, fu2_delay_days=s.fu2_delay_days,
                       fu3_delay_days=s.fu3_delay_days, auto_stop_on_reply=s.auto_stop_on_reply,
                       default_followup_enabled=s.default_followup_enabled)

    data = request.get_json()
    if not s:
        s = FollowupSettings(workspace_id=ws.id)
        db.session.add(s)
    if 'fu1_delay_days' in data: s.fu1_delay_days = max(1, int(data['fu1_delay_days']))
    if 'fu2_delay_days' in data: s.fu2_delay_days = max(1, int(data['fu2_delay_days']))
    if 'fu3_delay_days' in data: s.fu3_delay_days = max(1, int(data['fu3_delay_days']))
    if 'auto_stop_on_reply' in data: s.auto_stop_on_reply = bool(data['auto_stop_on_reply'])
    if 'default_followup_enabled' in data: s.default_followup_enabled = bool(data['default_followup_enabled'])
    s.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(ok=True)

@app.route('/api/followups/analytics')
@login_required
def api_followups_analytics():
    from app.models import FollowupContact, FollowupEvent
    from sqlalchemy import func
    uid = _current_user_id()

    total = FollowupContact.query.filter_by(user_id=uid).count()

    def stage_count(stage_prefix):
        return db.session.query(func.count(func.distinct(FollowupEvent.followup_contact_id)))\
            .join(FollowupContact)\
            .filter(
                FollowupContact.user_id == uid,
                FollowupEvent.event_type.in_(['auto_send', 'manual_send']),
                FollowupEvent.from_stage.like(f'{stage_prefix}%'),
            ).scalar() or 0

    fu1_sent = stage_count('fu1')
    fu2_sent = stage_count('fu2')
    fu3_sent = stage_count('fu3')
    completed = FollowupContact.query.filter_by(user_id=uid)\
        .filter(FollowupContact.stage == 'completed_fu3').count()

    outcomes = {}
    for st in ('loads', 'warm', 'blocked', 'closed'):
        outcomes[st] = FollowupContact.query.filter_by(user_id=uid, state=st).count()

    conversion = {'fu1_to_loads': 0, 'fu2_to_loads': 0, 'fu3_to_loads': 0}
    loads_contacts = FollowupContact.query.filter_by(user_id=uid, state='loads').all()
    for lc in loads_contacts:
        last_send = FollowupEvent.query.filter_by(followup_contact_id=lc.id)\
            .filter(FollowupEvent.event_type.in_(['auto_send', 'manual_send']))\
            .order_by(FollowupEvent.event_at.desc()).first()
        if last_send and last_send.from_stage:
            if 'fu1' in last_send.from_stage: conversion['fu1_to_loads'] += 1
            elif 'fu2' in last_send.from_stage: conversion['fu2_to_loads'] += 1
            elif 'fu3' in last_send.from_stage: conversion['fu3_to_loads'] += 1

    return jsonify(
        funnel={'total': total, 'fu1_sent': fu1_sent, 'fu2_sent': fu2_sent,
                'fu3_sent': fu3_sent, 'completed_fu3': completed},
        outcomes=outcomes,
        conversion_by_stage=conversion,
    )


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

@app.route('/api/fu-templates/list', methods=['GET'])
@login_required
def api_list_fu_templates():
    """Return all FU templates for user as a list (for management UI)."""
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup').order_by(Template.sort_order, Template.created_at).all()
    return jsonify({'templates': [r.to_dict() for r in rows]})

@app.route('/api/fu-templates/add', methods=['POST'])
@login_required
def api_add_fu_template():
    """Add a new FU template (any name allowed)."""
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    data = request.json or {}
    name = (data.get('name') or '').strip()
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'error': 'Template body is required'}), 400
    tmpl = Template(user_id=uid, type='followup', level=name or 'General', name=name, body=body)
    db.session.add(tmpl)
    db.session.commit()
    return jsonify({'ok': True, 'template': tmpl.to_dict()})

@app.route('/api/fu-templates/<tmpl_id>', methods=['PUT'])
@login_required
def api_update_fu_template(tmpl_id):
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    tmpl = Template.query.filter_by(id=tmpl_id, user_id=uid, type='followup').first_or_404()
    data = request.json or {}
    if 'name' in data:
        tmpl.name = data['name'].strip()
        tmpl.level = data['name'].strip() or 'General'
    if 'body' in data:
        tmpl.body = data['body']
    if 'is_active' in data:
        tmpl.is_active = bool(data['is_active'])
    db.session.commit()
    return jsonify({'ok': True, 'template': tmpl.to_dict()})

@app.route('/api/fu-templates/<tmpl_id>', methods=['DELETE'])
@login_required
def api_delete_fu_template(tmpl_id):
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    tmpl = Template.query.filter_by(id=tmpl_id, user_id=uid, type='followup').first_or_404()
    tmpl.is_active = False
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

def add_to_followups(reply_obj):
    """Create FollowupContact from a Reply model object marked as 'follow_up' or 'interested'."""
    from app.models import FollowupContact, Workspace
    uid = reply_obj.user_id
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return

    email = (reply_obj.from_email or '').strip().lower()
    if not email:
        return

    exists = FollowupContact.query.filter_by(workspace_id=ws.id, contact_email=email).first()
    if exists:
        return

    settings = _get_fu_settings(ws.id)
    now = datetime.utcnow()

    fc = FollowupContact(
        user_id=uid, workspace_id=ws.id, contact_email=email,
        contact_name=getattr(reply_obj, 'from_name', '') or '',
        state='active', stage='fu1_scheduled',
        is_followup_enabled=settings['default_enabled'],
        next_followup_at=now + _get_stage_delay('fu1_scheduled', settings),
        last_activity_at=now, last_reply_at=now,
        reply_subject=reply_obj.subject or '',
        reply_msg_id=getattr(reply_obj, 'msg_id', '') or '',
        source_reply_id=reply_obj.id,
        source_thread_id=getattr(reply_obj, 'thread_id', '') or '',
        current_route=getattr(reply_obj, 'route', '') or '',
    )
    db.session.add(fc)
    db.session.flush()
    _record_event(fc, 'created', actor_type='user', actor_user_id=uid)
    db.session.commit()


def _check_reply_stops_followup(reply_email, user_id):
    """If a reply comes from a contact in followup_contacts, stop their FU."""
    from app.models import FollowupContact, Workspace
    ws = Workspace.query.filter_by(owner_id=user_id).first()
    if not ws:
        return
    settings = _get_fu_settings(ws.id)
    if not settings['auto_stop_on_reply']:
        return

    email = reply_email.strip().lower()
    fc = FollowupContact.query.filter_by(workspace_id=ws.id, contact_email=email).first()
    if not fc or not fc.is_followup_enabled:
        return

    now = datetime.utcnow()
    fc.is_followup_enabled = False
    fc.last_reply_at = now
    fc.last_activity_at = now
    fc.next_followup_at = None
    _record_event(fc, 'reply_detected', actor_type='system', notes=f'Reply from {email}')


def _get_fu_templates_for_user(uid):
    """Fetch FU templates for a specific user — no session required (safe in threads)."""
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if not rows: return DEFAULT_FU_TEMPLATES.copy()
    return {r.level: r.body for r in rows if r.level}

def _get_random_fu_template(uid):
    """Pick a random active follow-up template body for the given user.
    Falls back to DEFAULT_FU_TEMPLATES pool if no custom templates exist."""
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if rows:
        return random.choice(rows).body or ''
    return random.choice(list(DEFAULT_FU_TEMPLATES.values()))

def _next_recurring_datetime(recurring_days, recurring_time):
    """Return next UTC datetime matching one of recurring_days at recurring_time (UTC).
    recurring_days: comma-separated weekday ints string, 0=Mon...6=Sun
    recurring_time: "HH:MM" UTC
    Checks today first — if today matches and time is still future, schedules today.
    """
    days = [int(d) for d in recurring_days.split(',') if d.strip().isdigit()]
    if not days:
        raise ValueError(f'recurring_days is empty or invalid: {recurring_days!r}')
    h, m = map(int, recurring_time.split(':'))
    now = datetime.utcnow()
    for offset in range(0, 8):
        candidate = (now + timedelta(days=offset)).replace(
            hour=h, minute=m, second=0, microsecond=0)
        if candidate.weekday() in days and candidate > now:
            return candidate
    raise ValueError(f'No valid day found — unreachable with valid input: days={days}')

def _run_scheduled_followups():
    """Process due follow-up contacts and send emails. Called from daemon thread.
    Uses SELECT FOR UPDATE SKIP LOCKED on PostgreSQL to prevent duplicate sends."""
    from app.models import FollowupContact, EmailAccount
    now = datetime.utcnow()
    with app.app_context():
        try:
            q = FollowupContact.query.filter(
                FollowupContact.state == 'active',
                FollowupContact.is_followup_enabled == True,
                FollowupContact.next_followup_at <= now,
                FollowupContact.stage.in_(['fu1_scheduled', 'fu2_scheduled', 'fu3_scheduled']),
            )
            try:
                contacts = q.with_for_update(skip_locked=True).all()
            except Exception:
                contacts = q.all()
        except Exception as e:
            app.logger.error(f'FU scheduler query error: {e}')
            return 0

        sent_total = 0
        for fc in contacts:
            try:
                if fc.state != 'active' or not fc.is_followup_enabled:
                    continue
                if fc.stage not in STAGE_TO_TEMPLATE:
                    continue

                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue

                template_text = _get_random_fu_template(fc.user_id)
                if not template_text:
                    continue

                cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                       'phone': acct.your_phone or '', 'route': fc.current_route or ''}
                fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                           'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}

                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)

                if ok:
                    old_stage = fc.stage
                    setattr(fc, STAGE_SENT_FIELD[fc.stage], now)
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now

                    sent_stage, next_scheduled = STAGE_PROGRESSION[fc.stage]
                    if next_scheduled:
                        settings = _get_fu_settings(fc.workspace_id)
                        fc.stage = next_scheduled
                        fc.next_followup_at = now + _get_stage_delay(next_scheduled, settings)
                    else:
                        fc.stage = 'completed_fu3'
                        fc.is_followup_enabled = False
                        fc.next_followup_at = None
                        fc.completed_fu3_at = now

                    _record_event(fc, 'auto_send', actor_type='scheduler',
                                  from_stage=old_stage, to_stage=fc.stage)
                    sent_total += 1
                else:
                    _record_event(fc, 'auto_send', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage,
                                  metadata_json=json.dumps({'error': str(err)}),
                                  notes='Send failed - will retry')

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU scheduler error for {fc.contact_email}: {e}')

        if sent_total:
            app.logger.info(f'FU scheduler: sent {sent_total} follow-ups')

        # ── Path 0: One-time scheduled sends ────────────────────────────────
        processed_ids = {fc.id for fc in contacts}
        try:
            sq = FollowupContact.query.filter(
                FollowupContact.scheduled_once == True,
                FollowupContact.next_followup_at <= now,
            )
            try:
                sched_contacts = sq.with_for_update(skip_locked=True).all()
            except Exception:
                sched_contacts = sq.all()
        except Exception as e:
            app.logger.error(f'FU scheduled-once query error: {e}')
            sched_contacts = []

        sched_total = 0
        for fc in sched_contacts:
            if fc.id in processed_ids:
                continue
            try:
                template_text = _get_random_fu_template(fc.user_id)
                if not template_text:
                    continue
                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue
                cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                       'phone': acct.your_phone or '', 'route': fc.current_route or ''}
                fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                           'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}
                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)
                if ok:
                    fc.scheduled_once = False
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now
                    _record_event(fc, 'scheduled_once_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage)
                    processed_ids.add(fc.id)
                    sched_total += 1
                else:
                    _record_event(fc, 'scheduled_once_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage,
                                  metadata_json=json.dumps({'error': str(err)}),
                                  notes='Send failed - will retry')
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU scheduled-once error for {fc.contact_email}: {e}')

        if sched_total:
            app.logger.info(f'FU scheduler: sent {sched_total} one-time scheduled follow-ups')

        # ── Path 2: Recurring sends ──────────────────────────────────────────
        # processed_ids already includes Path 0 + 1
        try:
            rq = FollowupContact.query.filter(
                FollowupContact.state == 'active',
                FollowupContact.recurring_enabled == True,
                FollowupContact.next_followup_at <= now,
            )
            try:
                recurring = rq.with_for_update(skip_locked=True).all()
            except Exception:
                recurring = rq.all()
        except Exception as e:
            app.logger.error(f'FU recurring scheduler query error: {e}')
            return sent_total

        rec_total = 0
        for fc in recurring:
            if fc.id in processed_ids:
                continue  # already sent in Path 1 this run
            try:
                if fc.state != 'active' or not fc.recurring_enabled:
                    continue
                if not fc.recurring_days or not fc.recurring_time:
                    continue

                template_text = _get_random_fu_template(fc.user_id)
                if not template_text:
                    continue

                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue

                cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
                       'phone': acct.your_phone or '', 'route': fc.current_route or ''}
                fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                           'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or ''}

                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)

                if ok:
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now
                    try:
                        fc.next_followup_at = _next_recurring_datetime(fc.recurring_days, fc.recurring_time)
                    except ValueError as ve:
                        app.logger.error(f'FU recurring next-date error for {fc.contact_email}: {ve}')
                        fc.next_followup_at = None

                    _record_event(fc, 'recurring_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage)
                    rec_total += 1
                else:
                    _record_event(fc, 'recurring_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage,
                                  metadata_json=json.dumps({'error': str(err)}),
                                  notes='Send failed - will retry')

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU recurring scheduler error for {fc.contact_email}: {e}')

        if rec_total:
            app.logger.info(f'FU scheduler: sent {rec_total} recurring follow-ups')

        return sent_total + rec_total

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
            # Ensure admin always has correct role
            if getattr(existing, 'role', 'user') != 'admin':
                existing.role = 'admin'
                db.session.commit()
            return
        user = UserModel(
            email=admin_email.lower(), name='Admin',
            password=hash_password(admin_password),
            role='admin', invited_by='system',
        )
        db.session.add(user)
        db.session.flush()   # populate user.id before creating workspace
        get_or_create_workspace(user.id, name='Admin Workspace')
        db.session.commit()
        print(f"✓ Admin account + workspace auto-created for {admin_email}")

with app.app_context():
    db.create_all()   # Creates all tables if they don't exist (safe to run repeatedly)
    # Inline migrations — safe to run on every startup (idempotent ADD COLUMN IF NOT EXISTS)
    _migrations = [
        ('email_accounts', 'google_refresh_token', 'TEXT'),
        ('email_accounts', 'google_access_token',  'TEXT'),
        ('email_accounts', 'token_expiry',         'TIMESTAMP'),
        ('follow_ups',     'auto_enabled',          'BOOLEAN DEFAULT TRUE'),
        ('follow_ups',     'scheduled_at',          'TIMESTAMP'),
        ('follow_ups',     'last_error',            'TEXT'),
        ('workspaces',     'fu_auto_enabled',       'BOOLEAN DEFAULT TRUE'),
        ('followup_contacts', 'recurring_enabled',  'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('followup_contacts', 'recurring_days',     'VARCHAR(20)'),
        ('followup_contacts', 'recurring_time',     'VARCHAR(5)'),
        ('followup_contacts', 'scheduled_once',     'BOOLEAN NOT NULL DEFAULT FALSE'),
    ]
    try:
        with db.engine.connect() as _conn:
            for _tbl, _col, _type in _migrations:
                try:
                    _conn.execute(db.text(f'ALTER TABLE {_tbl} ADD COLUMN {_col} {_type}'))
                    _conn.commit()
                    print(f'✓ Migration: added {_tbl}.{_col}')
                except Exception:
                    _conn.rollback()  # column already exists — ignore
    except Exception as _e:
        print(f'Migration check skipped: {_e}')
    # Extend templates.level column to VARCHAR(50) to allow custom FU template names
    try:
        with db.engine.connect() as _conn:
            try:
                _conn.execute(db.text('ALTER TABLE templates ALTER COLUMN level TYPE VARCHAR(50)'))
                _conn.commit()
                print('✓ Migration: extended templates.level to VARCHAR(50)')
            except Exception:
                _conn.rollback()
    except Exception as _e:
        print(f'templates.level migration skipped: {_e}')
    # Ensure parse-critical index exists: (user_id, status) on sends
    try:
        with db.engine.connect() as _conn:
            _conn.execute(db.text(
                'CREATE INDEX IF NOT EXISTS ix_sends_user_status ON sends (user_id, status)'
            ))
            _conn.commit()
    except Exception:
        pass
    # Mark any DB jobs still "running" as "interrupted" (handles deploy mid-send)
    try:
        from app.models import SendJob
        stale = SendJob.query.filter_by(status='running').all()
        if stale:
            for _j in stale:
                _j.status = 'interrupted'
                _j.finished_at = datetime.utcnow()
            db.session.commit()
            print(f'✓ Marked {len(stale)} stale send job(s) as interrupted')
    except Exception as _e:
        print(f'Stale job cleanup skipped: {_e}')
    try:
        auto_create_admin()
    except Exception as _e:
        print(f'auto_create_admin skipped: {_e}')

# ── Start background follow-up scheduler ──────────────────────────────────────
_scheduler = threading.Thread(target=scheduled_followup_worker, daemon=True, name='fu-scheduler')
_scheduler.start()

# ── Legal pages ───────────────────────────────────────────────────────────────

@app.route('/privacy')
def privacy():
    """Privacy Policy — public, no login required."""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Terms of Service — public, no login required."""
    return render_template('terms.html')

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    # Default dev port: 8090 (8080 and 3001 reserved for other projects)
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8090)))
