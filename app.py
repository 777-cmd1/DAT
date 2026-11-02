"""DAT Mailer Web App v2 — with invite-only auth"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import re, csv, os, json, smtplib, random, threading, time, imaplib, secrets, base64
import urllib.parse, urllib.request
import email as email_lib
from datetime import datetime, date, timedelta, UTC
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
from app import ladder as _ladder
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)


def _proxy_hops(env=os.environ):
    """Reverse proxies to trust for X-Forwarded-For/-Proto. Railway fronts the
    app with one edge proxy; with no proxy (local) trust none, or clients could
    spoof their IP past the rate limiter. PROXY_HOPS overrides."""
    raw = (env.get('PROXY_HOPS') or '').strip()
    if raw.isdigit():
        return int(raw)
    railway = ('RAILWAY_ENVIRONMENT_NAME', 'RAILWAY_ENVIRONMENT', 'RAILWAY_PROJECT_ID', 'RAILWAY_SERVICE_ID')
    return 1 if any(env.get(k) for k in railway) else 0


def _apply_proxy_fix(flask_app, hops):
    if hops:
        from werkzeug.middleware.proxy_fix import ProxyFix
        flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_for=hops, x_proto=hops)


_apply_proxy_fix(app, _proxy_hops())

_is_prod_env = bool(os.environ.get('DATABASE_URL')) or os.environ.get('FLASK_ENV') == 'production'
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    if _is_prod_env:
        raise RuntimeError('SECRET_KEY env var is required in production — '
                           'a random fallback would invalidate all sessions on every restart')
    _secret_key = secrets.token_hex(32)   # dev only
app.secret_key = _secret_key

# ── Database configuration ─────────────────────────────────────────────────
# Dev: SQLite  |  Prod (Railway): PostgreSQL via DATABASE_URL env var
_default_db = 'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dat_mailer_dev.db')


def _sqlalchemy_db_url(raw):
    """Pin the PostgreSQL driver to psycopg2 (what requirements.txt ships).
    SQLAlchemy 2.1 maps a bare postgresql:// URL to psycopg 3, which is not
    installed — a fresh Railway build then cannot reach the DB and fails its
    healthcheck (deploy of 2026-10-01)."""
    if raw.startswith('postgres://'):
        raw = 'postgresql://' + raw[len('postgres://'):]
    if raw.startswith('postgresql://'):
        raw = 'postgresql+psycopg2://' + raw[len('postgresql://'):]
    return raw


app.config['SQLALCHEMY_DATABASE_URI'] = _sqlalchemy_db_url(os.environ.get('DATABASE_URL', _default_db))
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
app.config['SESSION_COOKIE_SECURE'] = _is_prod_env

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

@app.after_request
def _no_store_html(response):
    """Never cache HTML: every page embeds a session-bound CSRF token.

    A cached page carries a token from an older session, so the next POST is
    rejected with "Invalid CSRF token" — which is what locked a user out of
    /login on 2026-10-30. Responses here are user-specific anyway, so caching
    them was never safe.
    """
    if response.mimetype == 'text/html':
        response.headers['Cache-Control'] = 'no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
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
        if app.config.get('TESTING'):
            return fn(*args, **kwargs)
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
_limiter_shared = _limiter_storage != 'memory://'
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
        raw = os.environ.get('ENCRYPTION_KEY') or os.environ.get('FERNET_KEY', '')
        if raw:
            try:
                _fernet_instance = Fernet(raw.encode() if isinstance(raw, str) else raw)
            except Exception:
                if _is_prod_env:
                    raise RuntimeError('ENCRYPTION_KEY is set but is not a valid Fernet key')
                app.logger.warning('Invalid ENCRYPTION_KEY — falling back to unencrypted storage (dev only)')
        elif _is_prod_env:
            raise RuntimeError('ENCRYPTION_KEY env var is required in production — '
                               'without it Gmail credentials would be stored in plaintext')
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
    except _FernetInvalidToken:
        # Encrypted-looking values that fail to decrypt mean a wrong/rotated key —
        # surface that instead of silently using ciphertext as a credential.
        if value.startswith('gAAAA'):
            app.logger.error('decrypt_field: Fernet token failed to decrypt — ENCRYPTION_KEY mismatch?')
        return value   # legacy plaintext — return as-is
    except Exception:
        return value

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

# The FU1 -> FU2 -> FU3 stage drip is retired (warmth ladder, 2026-11): `stage` and the
# fu*_sent_at / completed_fu3_at columns stay as the record of what that engine did, and
# no code advances them any more. `is_followup_enabled` survives only as "not yet placed
# on the ladder by scripts/migrate_to_ladder.py": no engine sends a contact that carries it
# (schedule-once / set-recurring clear it when the owner takes control of a schedule, and the
# startup normalisation clears it on a row that already carries one of those dates).


# Minimum gap between manual follow-up sends to the same contact (anti-duplicate guard).
FU_DUPLICATE_GUARD_HOURS = 24


def _recent_followup_block(fc, now=None):
    """Anti-duplicate guard for manual sends.

    Returns a human-readable error string if a follow-up was already sent to
    this contact within the last FU_DUPLICATE_GUARD_HOURS, else None.
    Prevents rapid double-clicks / double-selection from firing 2-3 identical
    follow-ups before the queue reloads.
    """
    if not fc.last_followup_sent_at:
        return None
    now = now or _utcnow()
    elapsed = now - fc.last_followup_sent_at
    window = timedelta(hours=FU_DUPLICATE_GUARD_HOURS)
    if elapsed < window:
        remaining_secs = int((window - elapsed).total_seconds())
        remaining_h = max(1, (remaining_secs + 3599) // 3600)  # ceil to whole hours
        return (f'Already sent a follow-up to this contact in the last '
                f'{FU_DUPLICATE_GUARD_HOURS}h — try again in ~{remaining_h}h.')
    return None


LEGACY_STATE_MAP = {
    'pending': 'active',
    'sent': 'active',
    'failed': 'active',
    'done': 'closed',
}

LEGACY_STAGE_MAP = {
    'fu1': 'fu1_scheduled',
    'fu2': 'fu2_scheduled',
    'fu3': 'fu3_scheduled',
    'done': 'completed_fu3',
    'closed': 'completed_fu3',
    'completed': 'completed_fu3',
}


def _normalize_fu_state(value, stage=None):
    raw = (value or '').strip().lower()
    if raw in VALID_STATES:
        return raw
    if raw in LEGACY_STATE_MAP:
        return LEGACY_STATE_MAP[raw]
    if stage == 'completed_fu3':
        return 'active'
    return 'active'


def _normalize_fu_stage(value):
    raw = (value or '').strip()
    lowered = raw.lower()
    if lowered in VALID_STAGES:
        return lowered
    if raw in ('FU1', 'FU2', 'FU3'):
        return raw.lower() + '_scheduled'
    if lowered in LEGACY_STAGE_MAP:
        return LEGACY_STAGE_MAP[lowered]
    return 'fu1_scheduled'


def _restore_contact_schedule(contact, now=None):
    """Restore the next follow-up time from the contact's active scheduling mode."""
    now = now or _utcnow()
    if contact.state != 'active' or contact.auto_paused or contact.rung in _ladder.OFF_LADDER:
        # paused by the owner or off the ladder: no engine may date this contact
        contact.next_followup_at = None
        return
    if contact.scheduled_once:
        return
    if contact.recurring_enabled:
        if contact.recurring_days and contact.recurring_time:
            contact.next_followup_at = _next_recurring_datetime(contact.recurring_days, contact.recurring_time)
        else:
            contact.recurring_enabled = False
            contact.recurring_days = None
            contact.recurring_time = None
            contact.next_followup_at = None
        return
    # neither a one-time nor a recurring send is left: the ladder dates the contact
    # (nothing, if it is still unplaced or off the ladder)
    contact.next_followup_at = None
    _schedule_touch(contact, force=True)


def _normalize_followup_contact(contact):
    """Repair incompatible legacy/null values without deleting user data."""
    changed = False

    normalized_stage = _normalize_fu_stage(contact.stage)
    normalized_state = _normalize_fu_state(contact.state, stage=normalized_stage)
    if contact.stage != normalized_stage:
        contact.stage = normalized_stage
        changed = True
    if contact.state != normalized_state:
        contact.state = normalized_state
        changed = True

    if contact.is_followup_enabled is None:
        contact.is_followup_enabled = False       # born on the ladder: the stage drip is retired
        changed = True
    if contact.recurring_enabled is None:
        contact.recurring_enabled = False
        changed = True
    if contact.scheduled_once is None:
        contact.scheduled_once = False
        changed = True

    if contact.contact_email:
        normalized_email = contact.contact_email.strip().lower()
        if contact.contact_email != normalized_email:
            contact.contact_email = normalized_email
            changed = True

    if normalized_state in TERMINAL_STATES:
        if contact.is_followup_enabled:
            contact.is_followup_enabled = False
            changed = True
        if contact.next_followup_at is not None:
            contact.next_followup_at = None
            changed = True
        if contact.scheduled_once:
            contact.scheduled_once = False
            changed = True
        if contact.recurring_enabled:
            contact.recurring_enabled = False
            changed = True
    elif normalized_state == 'paused':
        if contact.is_followup_enabled:
            contact.is_followup_enabled = False
            changed = True
        if contact.next_followup_at is not None:
            contact.next_followup_at = None
            changed = True
    # (no completed_fu3 hand-over any more: a contact still flagged is unplaced, and only
    # scripts/migrate_to_ladder.py, which reads its history, puts it on a rung)
    if (contact.scheduled_once or contact.recurring_enabled) and contact.is_followup_enabled:
        # a date the owner set himself (before schedule-once/set-recurring cleared the flag)
        contact.is_followup_enabled = False
        changed = True
    elif contact.recurring_enabled and (not contact.recurring_days or not contact.recurring_time):
        contact.recurring_enabled = False
        contact.recurring_days = None
        contact.recurring_time = None
        changed = True

    # Iron rule (lazy self-heal on every listing): an active contact on the ladder
    # with no date gets the one its rung implies.
    try:
        if _schedule_touch(contact, stagger=True):
            changed = True
    except Exception:
        pass   # never let cadence scheduling break a listing

    if changed:
        contact.updated_at = _utcnow()
    return changed


def _upsert_legacy_followup_record(fu):
    """Safely migrate one legacy follow_ups record into followup_contacts."""
    from app.models import FollowupContact, Workspace

    email = (fu.contact_email or '').strip().lower()
    if not email:
        return False, 'skip:no_email'

    ws_id = fu.workspace_id
    if not ws_id:
        ws = Workspace.query.filter_by(owner_id=fu.user_id).first()
        if not ws:
            return False, 'skip:no_workspace'
        ws_id = ws.id

    existing = FollowupContact.query.filter_by(workspace_id=ws_id, contact_email=email).first()
    if existing:
        merged = False
        if not existing.contact_name and fu.contact_name:
            existing.contact_name = fu.contact_name
            merged = True
        if not existing.current_route and fu.route:
            existing.current_route = fu.route
            merged = True
        if not existing.reply_subject and fu.reply_subject:
            existing.reply_subject = fu.reply_subject
            merged = True
        if not existing.reply_msg_id and fu.reply_msg_id:
            existing.reply_msg_id = fu.reply_msg_id
            merged = True
        if not existing.last_followup_sent_at and fu.last_fu_sent:
            existing.last_followup_sent_at = fu.last_fu_sent
            merged = True
        if not existing.last_activity_at and fu.last_contact:
            existing.last_activity_at = fu.last_contact
            merged = True
        if not existing.created_at and fu.added_at:
            existing.created_at = fu.added_at
            merged = True
        if not existing.next_followup_at and fu.scheduled_at:
            existing.next_followup_at = fu.scheduled_at
            merged = True
        notes = (fu.notes or '').strip()
        if notes and notes not in (existing.notes or ''):
            existing.notes = ((existing.notes or '').strip() + '\n' + notes).strip()
            merged = True
        normalized = _normalize_followup_contact(existing)
        return merged or normalized, 'merged'

    if fu.status == 'paused':
        state = 'paused'
        enabled = False
    elif fu.status == 'closed' or (fu.level or '').lower() == 'closed':
        state = 'closed'
        enabled = False
    else:
        state = _normalize_fu_state(fu.status)
        enabled = bool(fu.auto_enabled)

    stage = _normalize_fu_stage(fu.level)
    if fu.status == 'sent' and stage in ('fu1_scheduled', 'fu2_scheduled', 'fu3_scheduled'):
        stage = stage.replace('_scheduled', '_sent')
    enabled = False                  # the stage drip is retired: a recovered row joins the ladder

    fc = FollowupContact(
        user_id=fu.user_id,
        workspace_id=ws_id,
        contact_email=email,
        contact_name=fu.contact_name or '',
        state=state,
        stage=stage,
        is_followup_enabled=enabled,
        next_followup_at=fu.scheduled_at,
        last_followup_sent_at=fu.last_fu_sent,
        last_activity_at=fu.last_contact,
        reply_subject=fu.reply_subject or '',
        reply_msg_id=fu.reply_msg_id or '',
        current_route=fu.route or '',
        notes=fu.notes or '',
        created_at=fu.added_at or _utcnow(),
        updated_at=_utcnow(),
    )
    db.session.add(fc)
    db.session.flush()
    _normalize_followup_contact(fc)
    _record_event(fc, 'created', actor_type='system', notes='Recovered from legacy follow_ups table')
    return True, 'created'


def _recover_followup_data():
    """Recover legacy Follow-up data and normalize v2 records on startup."""
    from app.models import FollowUp, FollowupContact, FollowupSettings, Workspace

    stats = {
        'legacy_created': 0,
        'legacy_merged': 0,
        'settings_created': 0,
        'normalized': 0,
    }

    for ws in Workspace.query.all():
        if not FollowupSettings.query.filter_by(workspace_id=ws.id).first():
            db.session.add(FollowupSettings(
                workspace_id=ws.id,
                default_followup_enabled=ws.fu_auto_enabled,
            ))
            stats['settings_created'] += 1

    for fu in FollowUp.query.all():
        changed, outcome = _upsert_legacy_followup_record(fu)
        if not changed:
            continue
        if outcome == 'created':
            stats['legacy_created'] += 1
        elif outcome == 'merged':
            stats['legacy_merged'] += 1

    for fc in FollowupContact.query.all():
        if _normalize_followup_contact(fc):
            stats['normalized'] += 1

    if any(stats.values()):
        db.session.commit()
        app.logger.info('FU recovery applied: %s', stats)
    else:
        db.session.rollback()
    return stats


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


def _slug(text):
    """Lowercase ascii slug for reply-filter keys."""
    import re as _re
    s = _re.sub(r'[^a-z0-9]+', '_', (text or '').strip().lower()).strip('_')
    return s or 'filter'


_HEX_COLOR_RE = re.compile(r'^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$')

def _norm_hex_color(c, fallback='#888888'):
    """Validate a hex color and normalize to 6-digit #rrggbb, so the UI's alpha-suffix
    tint (e.g. `${color}1f`) always yields a valid 8-digit color; fall back if malformed."""
    c = (c or '').strip()
    if not _HEX_COLOR_RE.match(c):
        return fallback
    if len(c) == 4:                       # #rgb → #rrggbb
        c = '#' + ''.join(ch * 2 for ch in c[1:])
    return c


def _kw_in_text(kw, t):
    """Word-boundary keyword match: 'dnu' must not fire inside 'sandnut'.
    Both args lowercase; kw may be a multi-word phrase or carry punctuation."""
    kw = str(kw or '').lower().replace('’', "'").strip()
    if not kw:
        return False
    return re.search(r'(?<!\w)' + re.escape(kw) + r'(?!\w)', t) is not None


def _match_reply_filters(text, filters, keywords):
    """Reply-filters whose keywords appear in text (case-insensitive, word-boundary),
    sorted by confidence desc. Pure: filters/keywords are passed in so callers can
    load workspace config once per request. Typographic apostrophes are normalized
    so "don’t" in real mail matches a "don't" keyword."""
    t = (text or '').lower().replace('’', "'")
    if not t.strip():
        return []
    out = []
    for f in filters or []:
        kw = (keywords or {}).get(f.get('key'), {}) or {}
        words = kw.get('keywords') or []
        if any(_kw_in_text(w, t) for w in words):
            out.append({
                'key': f.get('key'), 'label': f.get('label', ''),
                'color': f.get('color') or '#888888', 'emoji': f.get('emoji') or '🏷️',
                'confidence': kw.get('confidence', 0.8),
                'category': f.get('category'),
            })
    out.sort(key=lambda x: x['confidence'], reverse=True)
    return out


# ── Semi-automatic triage classifier ─────────────────────────────────────────
# Structural signals that a carrier is sharing load details (rate, weight,
# pickup/delivery, lane). Keyword filters alone can't catch free-form info dumps.
_TRIAGE_INFO_SIGNALS = [
    # $1,500 / $5400 / $900 — but not $5 or $50 (too small to be a load rate)
    ('rate_amount', re.compile(r'\$\s?\d{1,3}(?:[,.]\d{3})+\b|\$\s?\d{3,6}\b')),
    ('weight',      re.compile(r'(?i)\b\d{1,3}(?:,\d{3})+\s*(?:lbs?|#)|\b\d{4,6}\s*(?:lbs?|#)')),
    ('pickup',      re.compile(r'(?i)\b(?:pu|pick\s?up|pickup)\b')),
    ('delivery',    re.compile(r'(?i)\b(?:del|delv|deliver(?:y|s|ed)?)\b')),
    ('fcfs',        re.compile(r'(?i)\bfcfs\b')),
    ('city_state',  re.compile(r'\b[A-Z][a-zA-Z .]+,\s*[A-Z]{2}\b')),
    ('date',        re.compile(r'(?i)\b(?:mon|tues?|wed(?:nes)?|thur?s?|fri|sat(?:ur)?|sun)(?:day)?\b|\b\d{1,2}/\d{1,2}\b')),
    # bare numbers must carry a length marker (' or ft) so plain digits don't count
    ('equipment',   re.compile(r"(?i)\b(?:dry\s?van|reefer|flatbed|step\s?deck|hazmat|conestoga|hotshot|\d{2,3}\s?(?:ft\b|'))")),
]

# Minimum confidence for an 'auto' mode to actually fire — below it we only suggest.
# Default keyword confidences mostly sit above these floors; the gate matters when a
# workspace lowers a keyword's confidence in pipeline settings (then auto stops firing
# for it without having to flip the whole category to 'suggest').
TRIAGE_AUTO_MIN_CONF = {'negative': 0.85, 'auto_reply': 0.85, 'gave_info': 0.7, 'rate_request': 0.7}

# Quoted-mail markers: everything from the first marker on is the sender's own
# outreach echoed back (full of lane/date/rate signals) — never classify it.
_QUOTE_MARKERS = [
    re.compile(r'(?im)^\s*-{2,}\s*original message\s*-{2,}'),
    re.compile(r'(?im)^\s*-{2,}\s*forwarded message\s*-{2,}'),
    # "On Fri, Oct 2, 2026 at 9:29 AM Dispatch <d@x.com> wrote:" — Gmail wraps long
    # ones so "wrote:" can sit on the next line; the date / address keeps prose out
    re.compile(r'(?im)^on (?=[^\n]*[\d@])[^\n]{0,200}(?:\n[^\n]{0,120})?\bwrote:'),
    re.compile(r'(?im)^from:\s.+@'),
    re.compile(r'(?m)^_{8,}[ \t]*$'),        # Outlook rule above "From:"
    re.compile(r'(?m)^>'),                    # plain-text quoted lines
]
# a phone signature ends the reply's own text but is not quoted mail
_SIGNATURE_MARKERS = [re.compile(r'(?im)^sent from my ')]
_ADDR_RE = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')


def _strip_quoted(body):
    """Return only the reply's own text — cut at the first quoted-mail marker."""
    t = body or ''
    cut = len(t)
    for rx in _QUOTE_MARKERS + _SIGNATURE_MARKERS:
        mm = rx.search(t)
        if mm:
            cut = min(cut, mm.start())
    return t[:cut]


def _quote_split(body):
    """Where the quoted mail starts in a reply (char offset, or None) and the
    address in its attribution line — the Replies card shows the two apart."""
    t = body or ''
    hits = [mm.start() for mm in (rx.search(t) for rx in _QUOTE_MARKERS) if mm]
    if not hits:
        return None, ''
    cut = min(hits)
    head = '\n'.join(t[cut:].lstrip('\n').split('\n')[:2])
    mm = _ADDR_RE.search(head)
    return cut, (mm.group(0).lower() if mm else '')


def classify_reply_text(subject, body, filters, keywords):
    """Pure triage classifier over subject+body.

    Returns {'category', 'confidence', 'filter_key', 'signals'} or None (unknown).
    Precedence: auto_reply > negative > rate_request > gave_info — an opt-out
    buried in a load dump must still win, and a quoted $-rate means the carrier
    *gave* a rate rather than asked for one. Quoted original mail is stripped
    from the body first so the user's own outreach never counts as signals.
    """
    own_body = _strip_quoted(body)
    text = ((subject or '') + ' ' + own_body).strip()
    if not text:
        return None
    matches = _match_reply_filters(text, filters, keywords)
    by_cat = {}
    for m in matches:                       # matches sorted by confidence desc
        by_cat.setdefault(m.get('category'), m)

    for cat in ('auto_reply', 'negative'):
        if cat in by_cat:
            m = by_cat[cat]
            return {'category': cat, 'confidence': m['confidence'],
                    'filter_key': m['key'], 'signals': []}

    # Structural signals never come from a Re:/Fwd: subject — that's an echo of
    # the user's own outreach (lane, date, footage), not carrier-provided info.
    sig_text = own_body if re.match(r'(?i)\s*(?:re|fwd?)\s*:', subject or '') \
        else ((subject or '') + ' ' + own_body).strip()
    signals = [name for name, rx in _TRIAGE_INFO_SIGNALS if rx.search(sig_text)]
    has_money = 'rate_amount' in signals

    if 'rate_request' in by_cat and not has_money:
        m = by_cat['rate_request']
        return {'category': 'rate_request', 'confidence': m['confidence'],
                'filter_key': m['key'], 'signals': signals}

    # Structural gave_info: needs ≥3 points (keyword hit counts as 2) so a lone
    # "delivery" or city name doesn't misfile a plain conversational reply.
    kw_hit = by_cat.get('gave_info')
    score = len(signals) + (2 if kw_hit else 0)
    if score >= 3:
        conf = max(kw_hit['confidence'] if kw_hit else 0.0,
                   min(0.95, 0.45 + 0.1 * score))
        return {'category': 'gave_info', 'confidence': round(conf, 2),
                'filter_key': (kw_hit or {}).get('key') or 'gave_info',
                'signals': signals}
    return None


def _fc_by_email(workspace_id, email):
    """Case-insensitive FollowupContact lookup by email within a workspace."""
    from app.models import FollowupContact
    return FollowupContact.query.filter(
        FollowupContact.workspace_id == workspace_id,
        db.func.lower(FollowupContact.contact_email) == (email or '').lower()
    ).first()


def _sync_crm_stage(reply, stage):
    """Mirror a reply-status change into the PipelineContact CRM — the same side
    effect the manual /api/replies/status path performs (stage_map there:
    follow_up→interested, not_interested→lost, new→replied). Best-effort: CRM
    sync must never break triage."""
    try:
        email = (reply.from_email or '')
        if not email:
            return
        upsert_pipeline(email, {
            'stage': stage,
            'company': (reply.from_name or '').split('<')[0].strip(),
            'route': reply.route or '',
        }, uid=reply.user_id)
    except Exception:
        db.session.rollback()
        app.logger.exception('CRM stage sync failed for reply %s', reply.msg_id)


def _ooo_pause_contact(ws, reply, days=7):
    """An auto-reply/OOO from a pipeline contact: push their next touch out by
    ~a week (never pull it closer) and clear any 🔥 — a bounce needs no answer."""
    fc = _fc_by_email(ws.id, reply.from_email)
    if not fc or fc.state != 'active':
        return False
    target = _utcnow() + timedelta(days=days)
    fc.attention_at = None
    old = fc.next_followup_at
    if old is None or old < target:
        if fc.is_followup_enabled:
            fc.next_followup_at = target      # the FU drip keeps its own clock
        else:
            # through the ladder's choke point: client/dormant/excluded/paused are
            # never given a date, and the touch lands at the usual hour
            _ladder_set_next(fc, target, ws)
            if fc.next_followup_at is None:
                return False
            if old is not None and fc.next_followup_at < old:
                fc.next_followup_at = old     # never pull a touch closer
        _record_event(fc, 'ooo_pause', actor_type='system',
                      notes=f'auto-reply detected — next touch pushed +{days}d')
        return True
    return False


def _auto_triage_new_replies(uid, msg_ids):
    """Classify freshly ingested replies and apply the workspace's auto-actions.

    negative / auto_reply  → status 'not_interested' (never auto-Block/stop-list)
    gave_info / rate_request → status 'follow_up' + create pipeline contact if
    missing + forward-only advance to the filter's auto_advance_to stage (a
    filter configured with no auto_advance_to means "don't advance" — same
    semantics as the manual tag path).

    Replies that inherited a suppressed status at ingest are classified but never
    auto-actioned. Returns counters for the Check-Gmail toast.
    """
    from app.models import Reply, Workspace
    out = {'classified': 0, 'auto_ignored': 0, 'auto_followup': 0, 'detected': {}}
    if not msg_ids:
        return out
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return out
    filters = ws.get_reply_filters()
    kws     = ws.get_filter_keywords()
    modes   = ws.get_triage_modes()
    fcfg_by_key = {f.get('key'): f for f in filters}
    now = _utcnow()

    rows = Reply.query.filter(Reply.user_id == uid, Reply.msg_id.in_(msg_ids)).all()
    for r in rows:
        res = classify_reply_text(r.subject, r.body, filters, kws)
        r.classified_at = now
        if not res:
            continue
        r.triage_category = res['category']
        r.triage_confidence = res['confidence']
        # invisible system tag: persist the matched filter even in suggest mode so
        # the card badge can show the specific label ("MC request", not just the
        # category) and bulk follow-up knows the stage target
        r.reply_filter_key = r.reply_filter_key or res.get('filter_key')
        out['classified'] += 1

        # OOO pause fires on detection alone — the contact's schedule shifts no
        # matter what happens to the reply itself in the queue
        if res['category'] == 'auto_reply':
            try:
                if _ooo_pause_contact(ws, r):
                    out['ooo_paused'] = out.get('ooo_paused', 0) + 1
            except Exception:
                db.session.rollback()

        if r.status != 'new':
            continue
        cat = res['category']
        if modes.get(cat) != 'auto' or res['confidence'] < TRIAGE_AUTO_MIN_CONF.get(cat, 1.0):
            # left in the queue (suggest mode / below auto threshold) — surface
            # the detection in the Check-Gmail toast so it doesn't look missed
            out['detected'][cat] = out['detected'].get(cat, 0) + 1
            continue

        r.auto_processed = True

        if cat in ('negative', 'auto_reply'):
            r.status = 'not_interested'
            r.auto_action = 'ignored'
            _sync_crm_stage(r, 'lost')
            out['auto_ignored'] += 1
        else:  # gave_info / rate_request
            r.status = 'follow_up'
            r.auto_action = 'followup'
            try:
                add_to_followups(r)
            except Exception:
                db.session.rollback()
                continue
            _sync_crm_stage(r, 'interested')
            fcfg = fcfg_by_key.get(res.get('filter_key')) or {}
            target = fcfg.get('auto_advance_to')   # falsy = configured "don't advance"
            fc = _fc_by_email(ws.id, r.from_email) if target else None
            if fc and int(target) > (fc.pipeline_stage or 1):   # forward-only
                ok, _err = _apply_pipeline_stage(fc, target, actor_user_id=uid,
                                                 reason=f'auto_triage:{cat}')
                if ok:
                    r.auto_advanced = True
            out['auto_followup'] += 1
    db.session.commit()
    return out


def _backfill_triage(uid, limit=500):
    """Classify-only pass (no auto-actions) over:
    - never-classified replies (pre-existing backlog), and
    - the whole live queue (status new/viewed) — re-scanned on every Check Gmail
      and OVERWRITTEN, so classifier/keyword improvements both pick up untagged
      replies and correct previously mis-tagged ones without manual work.
    Auto-processed replies are never touched (their action already happened).
    """
    from app.models import Reply, Workspace
    from sqlalchemy import or_
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return 0
    rows = Reply.query.filter(
        Reply.user_id == uid,
        or_(
            Reply.classified_at.is_(None),
            Reply.status.in_(['new', 'viewed']),
        ),
    ).order_by(Reply.received_at.desc()).limit(limit).all()
    if not rows:
        return 0
    filters = ws.get_reply_filters()
    kws     = ws.get_filter_keywords()
    now = _utcnow()
    n = 0
    for r in rows:
        r.classified_at = now
        if r.auto_processed:
            continue
        res = classify_reply_text(r.subject, r.body, filters, kws)
        if res:
            r.triage_category = res['category']
            r.triage_confidence = res['confidence']
            r.reply_filter_key = res.get('filter_key')
            n += 1
        elif r.status in ('new', 'viewed'):
            # stale tag from an older ruleset — clear rather than mislead
            r.triage_category = None
            r.triage_confidence = None
            r.reply_filter_key = None
    db.session.commit()
    return n


def detect_reply_filters(text, ws):
    """Auto-detect reply-filters for a piece of text within a workspace."""
    if not ws:
        return []
    return _match_reply_filters(text, ws.get_reply_filters(), ws.get_filter_keywords())


def _latest_reply_filter_map(uid, emails=None):
    """Map {lower(email): latest non-empty reply_filter_key} for a user's replies.
    One query (no N+1). `emails` (lowercased) optionally restricts the scan."""
    from app.models import Reply
    from sqlalchemy import func as _f
    q = db.session.query(Reply.from_email, Reply.reply_filter_key).filter(
        Reply.user_id == uid,
        Reply.reply_filter_key.isnot(None),
        Reply.reply_filter_key != '',
    )
    if emails is not None:
        emails = list(emails)
        if not emails:
            return {}
        q = q.filter(_f.lower(Reply.from_email).in_(emails))
    out = {}
    # nulls-last + desc so a real timestamp always beats a NULL received_at
    # (Postgres orders NULLs first on DESC otherwise, picking a stale tag).
    for em, key in q.order_by(Reply.received_at.is_(None), Reply.received_at.desc()).all():
        k = (em or '').lower()
        if k not in out:          # first seen = latest
            out[k] = key
    return out


_BEST_HOUR_CACHE = {}   # uid -> (hour, computed_at)

def _best_reply_hour(uid):
    """Most common hour (UTC) carriers reply at, from this user's reply history.
    Cached ~1h per user; falls back to 14:00 UTC (~9am US Central) with little data."""
    import time as _t
    hit = _BEST_HOUR_CACHE.get(uid)
    if hit and _t.time() - hit[1] < 3600:
        return hit[0]
    from app.models import Reply
    from sqlalchemy import func
    try:
        rows = db.session.query(func.extract('hour', Reply.received_at), func.count()).filter(
            Reply.user_id == uid, Reply.received_at.isnot(None)
        ).group_by(func.extract('hour', Reply.received_at)).order_by(func.count().desc()).limit(1).all()
        hour = int(rows[0][0]) if rows and rows[0][1] >= 5 else 14
    except Exception:
        hour = 14
    _BEST_HOUR_CACHE[uid] = (hour, _t.time())
    return hour


def _at_touch_hour(nxt, ws, uid):
    """Move a due date to the hour carriers actually answer (config: 'auto' =
    computed from reply history as a UTC hour, or a fixed 0-23 hour in the
    user's time zone). Falls back to the date as given."""
    try:
        hour_cfg = (ws.pipeline_config or {}).get('touch_hour', 'auto') if ws else 'auto'
        if hour_cfg == 'auto':
            hour = max(0, min(23, _best_reply_hour(uid)))
            return nxt.replace(hour=hour, minute=0, second=0, microsecond=0)
        return _local_at_hour(nxt, max(0, min(23, int(hour_cfg))), _ws_tz(ws))
    except Exception:
        return nxt


# ── Warmth-ladder settings ────────────────────────────────────────────────────
# The owner's cadence and patience numbers live in Workspace.pipeline_config['ladder'].
# Every engine read goes through _ladder_cfg(ws); the code defaults in
# ladder.LADDER_DEFAULTS are only the base it merges the saved values over.
_LADDER_INT_MAX = {'first_touch_days': 365, 'second_touch_days': 365, 'weekly_days': 365,
                   'budget_no_load': 20, 'budget_engaged': 20,
                   'daily_cap': 500}                              # every one is at least 1
_LADDER_BOOL_KEYS = ('hot_weekly', 'higher_rung_patience')


def _ladder_clean(raw):
    """The valid, clamped part of a ladder settings dict: integers 1..max, real booleans,
    known keys only. Anything else is dropped, so a bad value falls back to the default."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for key, top in _LADDER_INT_MAX.items():
        val = raw.get(key)
        if isinstance(val, bool) or not isinstance(val, (int, float, str)):
            continue
        try:
            num = float(val)
        except ValueError:
            continue
        if num != num or num in (float('inf'), float('-inf')) or num != int(num):
            continue
        out[key] = max(1, min(top, int(num)))
    for key in _LADDER_BOOL_KEYS:
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    return out


def _ladder_cfg(ws):
    """The ladder settings in force for a workspace: the code defaults with the owner's
    saved values on top. A missing workspace gets the defaults."""
    merged = dict(_ladder.LADDER_DEFAULTS)
    if ws is not None:
        merged.update(_ladder_clean((ws.pipeline_config or {}).get('ladder')))
    return merged


def _schedule_touch(fc, ws=None, force=False, stagger=False):
    """Iron rule: an active contact on the warmth ladder always carries the next touch
    its rung implies (and none while it is paused or off the ladder).

    force=False only fills gaps (no reschedule churn on read paths); force=True
    re-bases from now (after a send / move / reply). A contact still carrying the
    legacy drip flag is unplaced and a one-time or recurring send owns its own date:
    neither is touched here. stagger=True (the gap-filling sweep only, never a fresh entry
    or a send) spreads a backlog of undated contacts over a deterministic, id-based window of
    the ladder's weekly interval, so they do not all come due on the same day.
    Returns True if a touch was set.
    """
    from app.models import Workspace
    if (fc.state != 'active' or fc.is_followup_enabled
            or fc.scheduled_once or fc.recurring_enabled):
        return False
    ws = ws or (db.session.get(Workspace, fc.workspace_id) if fc.workspace_id else None)
    if fc.rung in _ladder.OFF_LADDER or fc.rung == 'client' or fc.auto_paused:
        _ladder_set_next(fc, None)
        return False
    if fc.rung not in _ladder.RUNGS:
        return False                     # a rung we do not know: never guess a date
    if not force and fc.touch_enabled and fc.next_followup_at:
        return False                     # already scheduled: don't churn on read paths
    cfg = _ladder_cfg(ws)
    when = _ladder.next_touch_at(fc.rung, fc.touch_attempt or 0, _utcnow(), cfg)
    if stagger and when is not None and not force:
        try:
            when += timedelta(days=int(str(fc.id).replace('-', '')[:8], 16) % max(1, cfg['weekly_days']))
        except (ValueError, TypeError):
            pass
    _ladder_set_next(fc, when, ws)
    return fc.next_followup_at is not None


def _apply_pipeline_stage(fc, target_stage, actor_user_id=None, reason='manual'):
    """Move a follow-up contact to a Kanban pipeline stage (1..N).

    Validates the target against the workspace's configured stages and logs a
    'pipeline_move' FollowupEvent (so transition stats can be computed).
    Returns (ok, error_msg). Moving to the current stage is a no-op success.
    """
    from app.models import Workspace
    try:
        target = int(target_stage)
    except (TypeError, ValueError):
        return False, 'Invalid stage'
    ws = db.session.get(Workspace, fc.workspace_id) if fc.workspace_id else None
    valid_ids = [s['id'] for s in ws.get_stages()] if ws else [1, 2, 3, 4, 5]
    if target not in valid_ids:
        return False, 'Invalid stage'
    old = fc.pipeline_stage or 1
    if target != old:
        fc.pipeline_stage = target
        fc.last_activity_at = _utcnow()
        _record_event(fc, 'pipeline_move', actor_user_id=actor_user_id,
                      from_stage=str(old), to_stage=str(target),
                      notes=f'pipeline {old}->{target} ({reason})')
        _schedule_touch(fc, ws, force=True)   # a move re-bases the next touch on the rung's rhythm
    return True, None


def _transition_state(contact, new_state, reason=None, actor_user_id=None):
    """Transition contact state with validation. Returns (success, error_msg)."""
    old_state = contact.state
    if old_state in TERMINAL_STATES:
        return False, f'Cannot transition from terminal state: {old_state}'
    if new_state not in ALLOWED_TRANSITIONS.get(old_state, set()):
        return False, f'Invalid transition: {old_state} -> {new_state}'

    now = _utcnow()
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
        # back to the ladder, not to the retired drip: the rung dates the next touch
        # (a contact still unplaced keeps its flag and stays unsent until it is placed)
        _schedule_touch(contact, force=True)
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


def _restart_contact_from_fu1(contact, actor_user_id=None):
    """Restart a contact's follow-up: back onto the ladder with a fresh budget.

    The action keeps its old name (`restart-fu1`) for the API and the history, but the
    FU1 stage drip is gone: this revives the contact on the rung its loads earn, clears
    the attempts it spent and dates its next touch. It never lifts an opt-out."""
    if contact.rung == 'excluded':
        return False, _EXCLUDED_MSG
    # a refusal is a decision: the owner moves them back to a rung by hand first
    # (the ladder migration puts every broker who asked us to stop on `refused`,
    # so a bulk restart reaches them)
    if contact.exit_reason == 'refused':
        return False, _REFUSED_MSG
    from app.models import Workspace
    now = _utcnow()
    old_state = contact.state
    old_rung = contact.rung
    ws = db.session.get(Workspace, contact.workspace_id) if contact.workspace_id else None

    contact.state = 'active'
    contact.is_followup_enabled = False          # placed: the drip flag no longer applies
    contact.scheduled_once = False
    contact.recurring_enabled = False
    contact.recurring_days = None
    contact.recurring_time = None
    contact.updated_at = now                     # a pause the owner set stays: resume-auto lifts it
    if contact.rung in _LADDER_SENDABLE:
        if contact.exit_reason != 'send_failed':  # that one belongs to the pause
            contact.exit_reason = None
        contact.touch_attempt = 0
        _schedule_touch(contact, ws, force=True)
    elif contact.rung == 'client':
        contact.next_followup_at = None
        contact.touch_enabled = False
    else:                                        # dormant: back to the rung its loads earn
        _ladder_revive(contact, now, ws, _ladder_cfg(ws))

    _record_event(contact, 'restarted_fu1', actor_type='user', actor_user_id=actor_user_id,
                  from_state=old_state, to_state='active',
                  notes=f'follow-up restarted on the ladder ({old_rung} -> {contact.rung})')
    return True, None

# ── Per-user send state ───────────────────────────────────────────────────────
# Keyed by user_id so concurrent users cannot see or overwrite each other's progress.
_send_states: dict = {}
_scheduler = None
_scheduler_enabled = os.environ.get('DISABLE_SCHEDULER', '').strip() != '1'

def _user_send_state(uid: str) -> dict:
    """Get (or initialise) the send-progress dict for a specific user."""
    if uid not in _send_states:
        _send_states[uid] = {
            "running": False, "done": False,
            "total": 0, "current": 0,
            "sent": 0, "errors": 0, "skipped": 0, "log": [],
        }
    return _send_states[uid]

def _scheduler_owner_id():
    return f'{os.uname().nodename}:{os.getpid()}:{_threading.current_thread().name}'

def _acquire_system_lease(name, lease_seconds=840):
    """Acquire or renew a short-lived DB lease for singleton-style background work."""
    from app.models import SystemLease
    now = _utcnow()
    lease_until = now + timedelta(seconds=lease_seconds)
    owner = _scheduler_owner_id()

    try:
        lease = SystemLease.query.filter_by(name=name).first()
        if lease and lease.lease_until and lease.lease_until > now and lease.owner != owner:
            return False
        if not lease:
            lease = SystemLease(name=name, owner=owner, lease_until=lease_until)
            db.session.add(lease)
        else:
            lease.owner = owner
            lease.lease_until = lease_until
            lease.updated_at = now
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False

def _scheduler_is_healthy():
    if not _scheduler_enabled:
        return True
    return bool(_scheduler and _scheduler.is_alive())
DEFAULT_CONFIG = {"gmail_address":"","gmail_app_password":"","your_name":"","your_company":"","your_phone":"","delay_min":20,"delay_max":45,"daily_target":100}

def _utcnow():
    """Return a naive UTC datetime for DB compatibility, sourced from aware UTC."""
    return datetime.now(UTC).replace(tzinfo=None)


# ─── USER TIME ZONE ────────────────────────────────────────────────────────────
# Stored in Workspace.pipeline_config['timezone'] (IANA name, set from Settings or
# the browser). DB timestamps stay naive UTC; only "today", day buckets, the
# fixed touch hour and the digest time follow the user's zone.

def _valid_tz(name):
    from zoneinfo import ZoneInfo
    try:
        ZoneInfo(str(name))
        return bool(name)
    except Exception:
        return False


def _tz_named(name):
    from zoneinfo import ZoneInfo
    try:
        return ZoneInfo(name or 'UTC')
    except Exception:
        return ZoneInfo('UTC')


def _ws_tz(ws):
    return _tz_named(((ws.pipeline_config or {}) if ws else {}).get('timezone'))


def _user_tz(uid):
    from app.models import Workspace
    return _ws_tz(Workspace.query.filter_by(owner_id=uid).first() if uid else None)


def _local_date(dt, tz):
    """Local calendar date of a naive-UTC timestamp."""
    return dt.replace(tzinfo=UTC).astimezone(tz).date()


def _local_day_start(tz, days_ago=0, now=None):
    """Naive-UTC moment of local midnight `days_ago` days back (negative = ahead)."""
    d = _local_date(now or _utcnow(), tz) - timedelta(days=days_ago)
    return datetime(d.year, d.month, d.day, tzinfo=tz).astimezone(UTC).replace(tzinfo=None)


def _local_at_hour(dt, hour, tz):
    """Naive-UTC moment of `hour`:00 local time on dt's local date."""
    d = _local_date(dt, tz)
    return datetime(d.year, d.month, d.day, hour, tzinfo=tz).astimezone(UTC).replace(tzinfo=None)

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
    return {'id': u.id, 'email': u.email, 'name': u.name, 'password': u.password,
            'invited_by': u.invited_by, 'session_version': u.session_version or 0}

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

def _session_user():
    """The logged-in User for this request, or None. A session whose user was
    deleted, or whose version predates the latest logout / password reset, is
    cleared and treated as logged out."""
    email = session.get('user_email')
    if not email:
        return None
    from app.models import User as _U
    u = _U.query.filter_by(email=email.lower()).first()
    if not u or session.get('sv', 0) != (u.session_version or 0):
        session.clear()
        return None
    return u


def _bump_session_version(user):
    """End every existing session of this user (all devices)."""
    user.session_version = (user.session_version or 0) + 1


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _session_user():
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

def _is_admin_user():
    """Admin = role='admin' in DB; ADMIN_EMAIL env kept as legacy fallback."""
    email = session.get('user_email', '').lower()
    if not email:
        return False
    from app.models import User as _U
    u = _U.query.filter_by(email=email).first()
    if u and u.role == 'admin':
        return True
    return bool(ADMIN_EMAIL) and email == ADMIN_EMAIL.lower()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _is_admin_user():
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
    session['sv'] = user.get('session_version', 0)
    audit_log('login', resource_type='user', detail={'email': email})
    return jsonify({'ok': True, 'name': user.get('name', email)})

@app.route('/api/auth/logout', methods=['POST'])
@csrf_protected
def api_logout():
    u = _session_user()
    if u:
        _bump_session_version(u)
        db.session.commit()
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
        expired = pr and (_utcnow() - pr.created_at > timedelta(hours=1))
        if not pr or expired:
            return render_template('reset_password.html', mode='invalid')
        return render_template('reset_password.html', mode='new_password', token=token,
                               csrf_token=_get_csrf_token())
    return render_template('reset_password.html', mode='request', csrf_token=_get_csrf_token())


def _reset_email_key():
    """Rate-limit bucket per target address, so one inbox can't be flooded
    from many IPs."""
    email = ((request.get_json(silent=True) or {}).get('email') or '').strip().lower()
    return f'reset-email:{email}'


@app.route('/api/auth/reset-request', methods=['POST'])
@limiter.limit("5 per hour")
@limiter.limit("3 per hour", key_func=_reset_email_key)
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
    app.logger.info(f'PASSWORD_RESET requested for={email}')

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
    if _utcnow() - pr.created_at > timedelta(hours=1):
        return jsonify({'error': 'Reset link has expired. Please request a new one.'}), 400

    user = User.query.filter_by(email=pr.email).first()
    if not user:
        return jsonify({'error': 'Account not found'}), 400

    user.password = hash_password(password)
    _bump_session_version(user)
    pr.used_at = _utcnow()
    db.session.commit()

    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    if not _session_user():
        return jsonify({'authenticated': False}), 401
    return jsonify({'authenticated': True, 'email': session['user_email'], 'name': session.get('user_name'), 'is_admin': _is_admin_user()})

@app.route('/register/<token>', methods=['GET'])
def register_page(token):
    from app.models import Invitation, User as UserModel
    invite = Invitation.query.filter_by(token=token, status='pending').first()
    if not invite:
        # If invite is gone but user already exists → just redirect to login
        return redirect(url_for('login_page'))
    if invite.expires_at and invite.expires_at < _utcnow():
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
    if invite.expires_at and invite.expires_at < _utcnow():
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
    invite.used_at = _utcnow()
    db.session.flush()   # populate user.id
    get_or_create_workspace(user.id, name=f"{name or email}'s Workspace")
    db.session.commit()

    session.clear()   # prevent session fixation
    session['user_email'] = email
    session['user_name'] = name or email
    session['sv'] = user.session_version or 0
    return jsonify({'ok': True})

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('admin.html', csrf_token=_get_csrf_token())

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
@csrf_protected
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
        expires_at=_utcnow() + timedelta(days=7),
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
@csrf_protected
def api_admin_delete_user():
    email = (request.json.get('email') or '').lower()
    from app.models import User as _UCheck
    _target = _UCheck.query.filter_by(email=email).first()
    if email == ADMIN_EMAIL.lower() or (_target and _target.role == 'admin'):
        return jsonify({'error': 'Cannot delete admin'}), 400
    from app.models import (User as UserModel, EmailAccount, Send, Reply,
                            FollowUp, FollowupContact, FollowupSettings,
                            PipelineContact, StopListEntry, Template,
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
    ws = Workspace.query.filter_by(owner_id=uid).first()
    # Delete all dependent records first (FK cascade)
    # FollowupContact must go before Workspace (FK: workspace_id); FollowupEvents cascade from FollowupContact
    for model in [Send, Reply, FollowUp, FollowupContact,
                  PipelineContact, StopListEntry, Template,
                  UsageEvent, AuditLog, EmailAccount, SendJob]:
        model.query.filter_by(user_id=uid).delete(synchronize_session=False)
    # FollowupSettings is keyed by workspace_id, delete before workspace
    if ws:
        FollowupSettings.query.filter_by(workspace_id=ws.id).delete(synchronize_session=False)
    # Delete owned workspaces
    Workspace.query.filter_by(owner_id=uid).delete(synchronize_session=False)
    # Reset invitations and password tokens for this email
    Invitation.query.filter_by(email=email).delete(synchronize_session=False)
    PasswordResetToken.query.filter_by(email=email).delete(synchronize_session=False)
    # Finally delete the user
    db.session.delete(user)
    db.session.commit()
    app.logger.info(f'Admin deleted user {email} and all related data')
    return jsonify({'ok': True})

@app.route('/api/admin/contact/delete', methods=['POST'])
@login_required
@admin_required
@csrf_protected
def api_admin_delete_contact():
    """Delete all records for a contact email across all tables (not a platform user)."""
    contact_email = (request.json.get('email') or '').strip().lower()
    if not contact_email:
        return jsonify({'error': 'Email required'}), 400
    from app.models import (Send, Reply, FollowUp, FollowupContact,
                            PipelineContact, StopListEntry)
    counts = {}
    counts['replies']           = Reply.query.filter(db.func.lower(Reply.from_email) == contact_email).delete(synchronize_session=False)
    counts['sends']             = Send.query.filter(db.func.lower(Send.recipient_email) == contact_email).delete(synchronize_session=False)
    counts['follow_ups']        = FollowUp.query.filter(db.func.lower(FollowUp.contact_email) == contact_email).delete(synchronize_session=False)
    # FollowupEvents cascade on delete of FollowupContact
    counts['followup_contacts'] = FollowupContact.query.filter(db.func.lower(FollowupContact.contact_email) == contact_email).delete(synchronize_session=False)
    counts['pipeline_contacts'] = PipelineContact.query.filter(db.func.lower(PipelineContact.email) == contact_email).delete(synchronize_session=False)
    counts['stop_list']         = StopListEntry.query.filter(db.func.lower(StopListEntry.value) == contact_email).delete(synchronize_session=False)
    db.session.commit()
    app.logger.info(f'Admin purged contact {contact_email}: {counts}')
    return jsonify({'ok': True, 'email': contact_email, 'deleted': counts})

@app.route('/api/admin/users/plan', methods=['POST'])
@login_required
@admin_required
@csrf_protected
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
    now = _utcnow()
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
@csrf_protected
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
    from app.models import User as UserModel, Workspace, Send, Reply, FollowupEvent
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

    # --- followups sent ---
    fu_q = db.session.query(func.count(FollowupEvent.id)).filter(
        FollowupEvent.event_type.in_(['auto_send', 'manual_send', 'scheduled_once_sent', 'recurring_sent'])
    )
    if start_dt is not None:
        fu_q = fu_q.filter(FollowupEvent.event_at >= start_dt, FollowupEvent.event_at <= end_dt)
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
        user = db.session.get(UserModel, user_id)
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
    from app.models import User as UserModel, Workspace, Send, Reply, FollowupContact, FollowupEvent, EmailAccount, UsageEvent
    from sqlalchemy import func

    period = request.args.get('period', 'today')
    start_dt, end_dt = _admin_date_range(period)
    now = _utcnow()

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

    # 4b. Batch send errors per user
    errors_q = db.session.query(Send.user_id, func.count(Send.id)).filter(
        Send.user_id.in_(user_ids), Send.status == 'error')
    if start_dt is not None:
        errors_q = errors_q.filter(Send.sent_at >= start_dt, Send.sent_at <= end_dt)
    error_map = dict(errors_q.group_by(Send.user_id).all())

    # 5. Batch replies per user
    replies_q = db.session.query(Reply.user_id, func.count(Reply.id)).filter(
        Reply.user_id.in_(user_ids))
    if start_dt is not None:
        replies_q = replies_q.filter(Reply.received_at >= start_dt, Reply.received_at <= end_dt)
    replies_map = dict(replies_q.group_by(Reply.user_id).all())

    # 6. Batch follow-up send events per user
    fu_q = db.session.query(FollowupContact.user_id, func.count(FollowupEvent.id))\
        .join(FollowupContact, FollowupContact.id == FollowupEvent.followup_contact_id)\
        .filter(
            FollowupContact.user_id.in_(user_ids),
            FollowupEvent.event_type.in_(['auto_send', 'manual_send', 'scheduled_once_sent', 'recurring_sent'])
        )
    if start_dt is not None:
        fu_q = fu_q.filter(FollowupEvent.event_at >= start_dt, FollowupEvent.event_at <= end_dt)
    fu_map = dict(fu_q.group_by(FollowupContact.user_id).all())

    # 7. Batch last activity (always lifetime, NOT filtered)
    la_rows = db.session.query(Send.user_id, func.max(Send.sent_at)).filter(
        Send.user_id.in_(user_ids)).group_by(Send.user_id).all()
    la_map = {row[0]: row[1] for row in la_rows}

    # 7b. Batch today's quota usage
    today = date.today()
    quota_rows = db.session.query(UsageEvent.user_id, func.coalesce(func.sum(UsageEvent.count), 0)).filter(
        UsageEvent.user_id.in_(user_ids),
        UsageEvent.event_type == 'email_sent',
        UsageEvent.period_date == today
    ).group_by(UsageEvent.user_id).all()
    quota_map = {row[0]: int(row[1] or 0) for row in quota_rows}

    # 8. Build result array
    result = []
    for u in users:
        ws = ws_map.get(u.id)
        ea = ea_map.get(u.id)
        plan = (ws.plan if ws else None) or 'free'
        s = sends_map.get(u.id, 0)
        r = replies_map.get(u.id, 0)
        f = fu_map.get(u.id, 0)
        e = error_map.get(u.id, 0)
        last_act = la_map.get(u.id)
        quota_used = quota_map.get(u.id, 0)
        quota_limit = PLAN_QUOTAS.get(plan, 50)
        quota_pct = int(min(100, round((quota_used / quota_limit) * 100))) if quota_limit else 0

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
            'errors': e,
            'email_connected': bool(ea and ea.google_refresh_token),
            'last_activity': last_act.strftime('%Y-%m-%dT%H:%M:%S') if last_act else None,
            'days_inactive': days_inactive,
            'quota_used': quota_used,
            'quota_limit': quota_limit,
            'quota_pct': quota_pct,
        })
    return jsonify(result)


@app.route('/api/admin/stats/account/<user_id>', methods=['GET'])
@login_required
@admin_required
def api_admin_stats_account(user_id):
    """Full drill-down for a single account. Never returns gmail_password."""
    from app.models import (User as UserModel, Workspace, Send, Reply,
                            FollowupContact, FollowupEvent, EmailAccount, PipelineContact,
                            AuditLog, UsageEvent)
    today    = date.today()
    week_ago = _utcnow() - timedelta(days=7)

    u = db.session.get(UserModel, user_id)
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
    fu_total = FollowupContact.query.filter_by(user_id=u.id).count()
    fu_pending = FollowupContact.query.filter(
        FollowupContact.user_id == u.id,
        FollowupContact.state.in_(['active', 'paused'])
    ).count()
    fu_sent = FollowupEvent.query.join(
        FollowupContact, FollowupContact.id == FollowupEvent.followup_contact_id
    ).filter(
        FollowupContact.user_id == u.id,
        FollowupEvent.event_type.in_(['auto_send', 'manual_send', 'scheduled_once_sent', 'recurring_sent'])
    ).count()
    fu_outcomes = FollowupContact.query.filter(
        FollowupContact.user_id == u.id,
        FollowupContact.state.in_(['warm', 'loads', 'blocked', 'closed'])
    ).count()
    followups = {
        'total': fu_total,
        'pending': fu_pending,
        'sent': fu_sent,
        'skipped': fu_outcomes,
        'closed': FollowupContact.query.filter_by(user_id=u.id, state='closed').count(),
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
    except Exception as e:
        app.logger.warning(f'_send_invite_email failed for {to_email}: {e}')
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
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f'audit_log failed for action={action}: {e}')   # never crash the main flow

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
        # Atomic increment — safe under concurrent sends (no read-modify-write race)
        updated = UsageEvent.query.filter_by(
            user_id=uid, event_type=event_type, period_date=today
        ).update({UsageEvent.count: UsageEvent.count + count})
        if not updated:
            db.session.add(UsageEvent(
                user_id=uid, event_type=event_type,
                count=count, period_date=today,
            ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f'_track_usage failed uid={uid} type={event_type}: {e}')

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
        acct.daily_target   = int(cfg.get('daily_target', acct.daily_target or 100))
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
            daily_target   = int(cfg.get('daily_target', 100)),
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

_TMPL_FIELD_RE = re.compile(r'\{(\w+)\}')

def _safe_render(tmpl, values):
    """Substitute {name}-style placeholders without str.format.
    Unknown placeholders and stray braces are left as-is — a '{' in a
    user-edited template can no longer crash the send."""
    return _TMPL_FIELD_RE.sub(lambda m: str(values.get(m.group(1), m.group(0))), tmpl)

def render_template_text(tmpl, load, cfg):
    origin, dest = load.get("origin", ""), load.get("destination", "")
    return _safe_render(tmpl, {
        'name': cfg.get("your_name",""), 'company': cfg.get("your_company",""),
        'phone': cfg.get("your_phone",""), 'origin': origin,
        'destination': dest, 'date': load.get("date",""),
        'equip': load.get("equip",""),
        'route': f'{origin} → {dest}' if origin and dest else (origin or dest)})

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
        else: bd.add(e.value.lower().lstrip('@'))  # strip leading @ so 'landstarmail.com' and '@landstarmail.com' both match
    result = (be, bd)
    _cache_set(cache_key, result)
    return result


def _add_to_stop_list(uid, email, reason=''):
    """Add one address to the user's Stop List (no-op if already there).
    Flushes only — the caller commits."""
    from app.models import StopListEntry, Workspace
    email = (email or '').strip().lower()
    if not uid or not email:
        return False
    if StopListEntry.query.filter_by(user_id=uid, type='email', value=email).first():
        return False
    ws = Workspace.query.filter_by(owner_id=uid).first()
    db.session.add(StopListEntry(user_id=uid, workspace_id=ws.id if ws else None,
                                 type='email', value=email, reason=(reason or '')[:255]))
    db.session.flush()
    _cache_del(f'stop_list:{uid}')
    return True


def _remove_from_stop_list(uid, email):
    from app.models import StopListEntry
    email = (email or '').strip().lower()
    n = StopListEntry.query.filter_by(user_id=uid, type='email', value=email).delete()
    if n:
        _cache_del(f'stop_list:{uid}')
    return bool(n)


def _block_followup_contact(uid, email, reason):
    """Move the user's pipeline contact for this address to 'blocked' so no
    automatic or queued follow-up can reach it. Returns True if it changed."""
    from app.models import Workspace
    ws = Workspace.query.filter_by(owner_id=uid).first()
    fc = _fc_by_email(ws.id, email) if ws else None
    if not fc or fc.state not in ('active', 'paused'):
        return False
    ok, _err = _transition_state(fc, 'blocked', reason=reason, actor_user_id=uid)
    return ok

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
    today_start = _local_day_start(_user_tz(uid))
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
    rows = db.session.query(
        Send.id, Send.recipient_email, Send.origin, Send.destination,
        Send.load_date, Send.equipment, Send.weight, Send.company,
        Send.template_variant, Send.status, Send.error_msg, Send.sent_at
    ).filter_by(user_id=uid).order_by(Send.sent_at.desc()).all()
    result = []
    for row in rows:
        result.append({
            'id': row.id,
            'email': row.recipient_email,
            'origin': row.origin,
            'destination': row.destination,
            'date': row.load_date,
            'equip': row.equipment,
            'weight': row.weight,
            'company': row.company,
            'variant': row.template_variant,
            'status': row.status,
            'error': row.error_msg or '',
            'timestamp': row.sent_at.strftime('%Y-%m-%d %H:%M:%S') if row.sent_at else '',
        })
    return result

def get_log_page(page=1, per_page=100, search='', status='', date_from='', date_to=''):
    uid = current_user_id()
    if not uid:
        return {'items': [], 'total': 0, 'page': 1, 'pages': 0, 'per_page': per_page}
    from app.models import Send
    from sqlalchemy import or_, func

    page = max(1, int(page or 1))
    per_page = max(1, min(200, int(per_page or 100)))

    q = db.session.query(
        Send.id, Send.recipient_email, Send.origin, Send.destination,
        Send.load_date, Send.equipment, Send.weight, Send.company,
        Send.template_variant, Send.status, Send.error_msg, Send.sent_at
    ).filter(Send.user_id == uid)

    if search:
        like = f'%{search.lower()}%'
        q = q.filter(or_(
            func.lower(Send.recipient_email).like(like),
            func.lower(Send.origin).like(like),
            func.lower(Send.destination).like(like),
        ))
    if status:
        q = q.filter(Send.status == status)
    if date_from:
        try:
            start = datetime.fromisoformat(date_from)
            q = q.filter(Send.sent_at >= start)
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to) + timedelta(days=1)
            q = q.filter(Send.sent_at < end)
        except ValueError:
            pass

    total = q.count()
    rows = q.order_by(Send.sent_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for row in rows:
        items.append({
            'id': row.id,
            'email': row.recipient_email,
            'origin': row.origin,
            'destination': row.destination,
            'date': row.load_date,
            'equip': row.equipment,
            'weight': row.weight,
            'company': row.company,
            'variant': row.template_variant,
            'status': row.status,
            'error': row.error_msg or '',
            'timestamp': row.sent_at.strftime('%Y-%m-%d %H:%M:%S') if row.sent_at else '',
        })
    pages = (total + per_page - 1) // per_page if total else 0
    return {
        'items': items,
        'total': total,
        'page': page,
        'pages': pages,
        'per_page': per_page,
    }

def load_replies(uid=None):
    uid = uid or current_user_id()
    if not uid: return []
    from app.models import Reply
    rows = db.session.query(
        Reply.id, Reply.msg_id, Reply.from_email, Reply.from_name,
        Reply.subject, Reply.body, Reply.route, Reply.status,
        Reply.reply_filter_key, Reply.received_at
    ).filter_by(user_id=uid).order_by(Reply.received_at.desc()).all()
    result = []
    for row in rows:
        result.append({
            'id': row.id,
            'msg_id': row.msg_id,
            'email': row.from_email,
            'from': row.from_name,
            'subject': row.subject,
            'body': row.body,
            'route': row.route,
            'status': row.status,
            'reply_filter_key': row.reply_filter_key or '',
            'received_at': row.received_at.strftime('%Y-%m-%d %H:%M') if row.received_at else '',
        })
    return result

def get_reply_groups_page(page=1, per_page=25, search='', view='all', cat=''):
    uid = current_user_id()
    if not uid:
        return {'items': [], 'counts': {'all': 0, 'new': 0, 'viewed': 0, 'needs_action': 0, 'follow_up': 0, 'ignored': 0}, 'total': 0, 'page': 1, 'pages': 0}
    from app.models import Reply
    from sqlalchemy import case, func, or_

    page = max(1, int(page or 1))
    per_page = max(1, min(100, int(per_page or 25)))

    priority_case = case(
        (Reply.status == 'new', 0),
        (Reply.status == 'viewed', 1),
        (Reply.status.in_(['follow_up', 'interested']), 2),
        (Reply.status.in_(['ignored', 'not_interested']), 3),
        else_=4,
    )

    base = db.session.query(
        func.lower(Reply.from_email).label('email_key'),
        func.max(Reply.received_at).label('latest_at'),
        func.min(priority_case).label('priority'),
    ).filter(
        Reply.user_id == uid,
        Reply.from_email.isnot(None),
        Reply.from_email != '',
    )

    if search:
        like = f'%{search.lower()}%'
        base = base.filter(or_(
            func.lower(Reply.from_email).like(like),
            func.lower(Reply.from_name).like(like),
            func.lower(Reply.subject).like(like),
        ))

    grouped_rows = base.group_by(func.lower(Reply.from_email)).all()

    def priority_to_state(priority):
        if priority == 0:
            return 'new'
        if priority == 1:
            return 'viewed'
        if priority == 2:
            return 'follow_up'
        return 'ignored'

    counts = {'all': 0, 'new': 0, 'viewed': 0, 'needs_action': 0, 'follow_up': 0, 'ignored': 0}
    normalized_rows = []
    for row in grouped_rows:
        state = priority_to_state(row.priority)
        counts['all'] += 1
        counts[state] = counts.get(state, 0) + 1
        if state in ('new', 'viewed'):
            counts['needs_action'] += 1
        normalized_rows.append({
            'email': row.email_key,
            'latest_at': row.latest_at,
            'state': state,
        })

    # Per-category contact counts among unprocessed replies — drives the triage
    # category chips ("🚫 Negative (12)") independent of the current view.
    cat_rows = db.session.query(
        Reply.triage_category,
        func.count(func.distinct(func.lower(Reply.from_email))),
    ).filter(
        Reply.user_id == uid,
        Reply.status.in_(['new', 'viewed']),
        Reply.triage_category.isnot(None),
    ).group_by(Reply.triage_category).all()
    counts['categories'] = {c: n for c, n in cat_rows if c}

    def include_row(row):
        if view == 'all':
            return True
        if view == 'needs_action':
            return row['state'] in ('new', 'viewed')
        return row['state'] == view

    filtered_rows = [row for row in normalized_rows if include_row(row)]

    if cat:
        cat_emails = {e for (e,) in db.session.query(
            func.lower(Reply.from_email)
        ).filter(
            Reply.user_id == uid,
            Reply.status.in_(['new', 'viewed']),
            Reply.triage_category == cat,
        ).distinct().all()}
        filtered_rows = [row for row in filtered_rows if row['email'] in cat_emails]
    filtered_rows.sort(key=lambda row: (
        {'new': 0, 'viewed': 1, 'follow_up': 2, 'ignored': 3}.get(row['state'], 5),
        -(row['latest_at'].timestamp() if row['latest_at'] else 0),
    ))

    total = len(filtered_rows)
    pages = (total + per_page - 1) // per_page if total else 0
    email_keys = [row['email'] for row in filtered_rows[(page - 1) * per_page: page * per_page]]
    if not email_keys:
        return {'items': [], 'counts': counts, 'total': total, 'page': page, 'pages': pages}

    msg_rows = db.session.query(
        Reply.id, Reply.msg_id, Reply.from_email, Reply.from_name,
        Reply.subject, Reply.body, Reply.route, Reply.status,
        Reply.reply_filter_key, Reply.received_at,
        Reply.triage_category, Reply.triage_confidence,
        Reply.auto_processed, Reply.auto_action, Reply.matched_recipient,
    ).filter(
        Reply.user_id == uid,
        func.lower(Reply.from_email).in_(email_keys)
    ).order_by(func.lower(Reply.from_email), Reply.received_at.desc()).all()

    own_addr = _own_gmail_address(uid).lower()
    grouped = {}
    for row in msg_rows:
        key = (row.from_email or '').lower()
        quote_at, quote_from = _quote_split(row.body)
        grouped.setdefault(key, []).append({
            'id': row.id,
            'msg_id': row.msg_id,
            'email': row.from_email,
            'from': row.from_name,
            'subject': row.subject,
            'body': row.body,
            'route': row.route,
            'status': row.status,
            'reply_filter_key': row.reply_filter_key or '',
            'triage_category': row.triage_category or '',
            'triage_confidence': row.triage_confidence,
            'auto_processed': bool(row.auto_processed),
            'auto_action': row.auto_action or '',
            'matched_recipient': row.matched_recipient or '',
            'received_at': row.received_at.strftime('%Y-%m-%d %H:%M') if row.received_at else '',
            'quote_at': quote_at,
            'quote_from': quote_from,
            'quote_mine': bool(quote_from and quote_from == own_addr),
        })

    items = [grouped[email] for email in email_keys if email in grouped]
    return {'items': items, 'counts': counts, 'total': total, 'page': page, 'pages': pages}

def save_replies(replies, uid=None):
    """Upsert reply list — used by legacy code paths."""
    uid = uid or current_user_id()
    if not uid: return
    from app.models import Reply
    for r in replies:
        existing = Reply.query.filter_by(user_id=uid, msg_id=r['msg_id']).first()
        if existing:
            existing.status = r.get('status', existing.status)
        else:
            extra = {'received_at': r['received_dt'], 'date_checked': True} if r.get('received_dt') else {}
            db.session.add(Reply(
                user_id=uid, msg_id=r['msg_id'],
                thread_id=r.get('thread_id', '') or None,
                from_email=r.get('email', ''), from_name=r.get('from', ''),
                subject=r.get('subject', ''), body=r.get('body', ''),
                route=r.get('route', ''), status=r.get('status', 'new'),
                matched_recipient=r.get('matched_recipient') or None,
                **extra,
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

def get_known_emails(uid=None):
    uid = uid or current_user_id()
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

_BOUNCE_SENDERS = ('mailer-daemon@', 'postmaster@')
_PERMANENT_FAILURE_RE = re.compile(
    r'(?i)\b5\.\d\.\d{1,3}\b|\b55[0-4]\b|address not found|does not exist|user unknown|'
    r'no such user|recipient (?:address )?rejected|mailbox unavailable|account (?:is )?disabled')


def _bounced_recipient(from_addr, headers, body, known):
    """Address that hard-bounced, if this message is a permanent-failure notice
    for one of our recipients; else None. Delay notices are ignored."""
    sender = (from_addr or '').lower()
    failed_hdr = headers.get('X-Failed-Recipients', '')
    if not failed_hdr and not any(b in sender for b in _BOUNCE_SENDERS):
        return None
    if 'delay' in (headers.get('Subject', '') or '').lower():
        return None
    if not failed_hdr and not _PERMANENT_FAILURE_RE.search(body or ''):
        return None
    for addr in re.findall(r'[\w.+\-]+@[\w.\-]+\.\w+', f'{failed_hdr} {body or ""}'):
        if addr.lower() in known:
            return addr.lower()
    return None


def _gmail_internal_date(msg):
    """Gmail's own receive time of a message (internalDate, ms epoch) → naive UTC."""
    try:
        return datetime.fromtimestamp(int(msg.get('internalDate')) / 1000, UTC).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _backfill_reply_dates(service, uid, max_threads=60):
    """Replies stored before 2026-10 carry the time they were fetched, not when
    they arrived. Look their threads up in Gmail (a batch per Check Gmail) and
    store the real receive time. Returns the number of corrected rows."""
    from app.models import Reply
    rows = Reply.query.filter(Reply.user_id == uid, Reply.date_checked == False) \
        .order_by(Reply.received_at.desc()).limit(1000).all()
    if not rows:
        return 0
    by_thread = {}
    for r in rows:
        if r.thread_id:
            by_thread.setdefault(r.thread_id, []).append(r)
        else:
            r.date_checked = True          # legacy row without a Gmail thread — nothing to look up
    fixed = 0
    for tid in list(by_thread)[:max_threads]:
        try:
            th = service.users().threads().get(userId='me', id=tid, format='metadata',
                                               metadataHeaders=['Message-ID']).execute()
        except Exception as e:
            if getattr(getattr(e, 'resp', None), 'status', None) == 404:
                th = {'messages': []}      # thread deleted — keep the stored date
            else:
                break                      # transient API trouble — retry on the next fetch
        when = {}
        for m in th.get('messages', []):
            dt = _gmail_internal_date(m)
            if not dt:
                continue
            when[m.get('id')] = dt
            for h in m.get('payload', {}).get('headers', []):
                if h.get('name', '').lower() == 'message-id':
                    when[h.get('value')] = dt
        for r in by_thread[tid]:
            dt = when.get(r.msg_id)
            if dt and dt != r.received_at:
                r.received_at = dt
                fixed += 1
            r.date_checked = True
    db.session.commit()
    if fixed:
        _cache_del(f'stats:{uid}:today', f'stats:{uid}:week', f'stats:{uid}:lifetime', f'ai_impact:{uid}')
    return fixed


# ── Lane rate memory ───────────────────────────────────────────────────────────
_RATE_MONEY_RE = re.compile(r'\$\s?(\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)(\s?k\b)?', re.I)
_RATE_PER_MILE_TAIL = re.compile(
    r'\s*(?:/\s*(?:loaded\s+)?mi(?:le)?s?\b|per\s+(?:loaded\s+)?mile|a\s+mile|rpm\b|cpm\b)', re.I)
_RATE_PER_MILE_BARE = re.compile(
    r'(?<![\d$.,])(\d{1,2}\.\d{1,2})\s?(?:/\s*(?:loaded\s+)?mi(?:le)?s?\b|per\s+(?:loaded\s+)?mile|rpm\b|cpm\b)', re.I)
# accessorials, not the linehaul — judged within the amount's own clause
_RATE_NOT_LINEHAUL = re.compile(
    r'detention|lay\s?over|\btonu\b|truck order not used|lumper|per\s+hour|/\s*h(?:ou)?rs?\b|an\s+hour|'
    r'hourly|per\s+stop|extra\s+stop|stop\s+off|fuel\s+surcharge|deadhead|per\s+day|/\s*day\b', re.I)
_RATE_CLAUSE_BREAK = re.compile(r'[;\n!?]|,\s|\.\s')
RATE_MIN_FLAT, RATE_MAX_FLAT = 300, 50000


def _rate_clause(text, start, end):
    left = max([m.end() for m in _RATE_CLAUSE_BREAK.finditer(text, 0, start)] or [0])
    nxt = _RATE_CLAUSE_BREAK.search(text, end)
    return text[left:nxt.start() if nxt else len(text)]


def extract_rates(body):
    """Rates quoted in a reply's own text (quoted original mail ignored).
    Returns [{'rate': int|None, 'rate_per_mile': float|None, 'snippet': str}] —
    flat amounts below $300 and accessorials (detention, TONU, lumper, /hr…)
    are dropped; per-mile rates go to their own field."""
    own = _strip_quoted(body or '')
    out, seen = [], set()

    def add(kind, value, start, end):
        if (kind, value) in seen or len(out) >= 3:
            return
        seen.add((kind, value))
        snip = ' '.join(own[max(0, start - 60):end + 60].split())
        out.append({'rate': value if kind == 'flat' else None,
                    'rate_per_mile': value if kind == 'pm' else None, 'snippet': snip[:300]})

    for m in _RATE_MONEY_RE.finditer(own):
        num = float(m.group(1).replace(',', ''))
        if m.group(2):
            num *= 1000
        if _RATE_PER_MILE_TAIL.match(own, m.end()):
            if 0.5 <= num <= 20:
                add('pm', round(num, 2), m.start(), m.end())
            continue
        if _RATE_NOT_LINEHAUL.search(_rate_clause(own, m.start(), m.end())):
            continue
        if RATE_MIN_FLAT <= num <= RATE_MAX_FLAT:
            add('flat', int(round(num)), m.start(), m.end())
    for m in _RATE_PER_MILE_BARE.finditer(own):
        v = float(m.group(1))
        if 0.5 <= v <= 20:
            add('pm', round(v, 2), m.start(), m.end())
    return out


def _rate_quote_load(reply, uid):
    """The outreach email (Send) this reply answers: same recipient (or the
    address a colleague answered for), lane from the reply subject first."""
    from app.models import Send
    from sqlalchemy import func
    target = (reply.matched_recipient or reply.from_email or '').lower()
    if not target:
        return None
    q = Send.query.filter(Send.user_id == uid, Send.status == 'sent',
                          func.lower(Send.recipient_email) == target)
    if reply.received_at:
        q = q.filter(Send.sent_at <= reply.received_at + timedelta(minutes=5))
    sends = q.order_by(Send.sent_at.desc()).limit(50).all()
    subj = _REPLY_SUBJ_PREFIX.sub('', reply.subject or '').strip().lower()
    for snd in sends:
        if snd.origin and snd.destination and subj.startswith(f'{snd.origin} to {snd.destination}'.lower()):
            return snd
    if reply.route and '→' in reply.route:
        o, d = [x.strip() for x in reply.route.split('→', 1)]
        for snd in sends:
            if (snd.origin or '').strip() == o and (snd.destination or '').strip() == d:
                return snd
    return sends[0] if sends else None


def _equip_from_subject(subject):
    """Equipment code from a reply subject — it quotes our own subject
    ("Re: Laredo, TX to Doral, FL, 10/02, Van, 53 ft")."""
    for code, label in _EQUIP_LABELS.items():
        if re.search(r'(?:^|,\s*)' + re.escape(label) + r'(?:\s*,|\s*$)', subject or '', re.I):
            return code
    return ''


def _extract_rate_quotes(uid, limit=2000):
    """Parse not-yet-parsed replies of a user into RateQuote rows. Idempotent."""
    from app.models import Reply, RateQuote
    rows = Reply.query.filter(Reply.user_id == uid, Reply.rates_parsed == False).limit(limit).all()
    added = 0
    for r in rows:
        r.rates_parsed = True
        rates = extract_rates(r.body)
        if not rates:
            continue
        snd = _rate_quote_load(r, uid)
        origin = (snd.origin if snd else '') or ''
        dest = (snd.destination if snd else '') or ''
        if not (origin and dest) and r.route and '→' in r.route:
            origin, dest = [x.strip() for x in r.route.split('→', 1)]
        if not (origin and dest):
            continue                       # a rate with no lane can't go into lane memory
        equip = ((snd.equipment if snd else '') or '').strip().upper() or _equip_from_subject(r.subject)
        for q in rates:
            db.session.add(RateQuote(
                user_id=uid, reply_id=r.id, origin=origin, destination=dest,
                equipment=equip[:50],
                rate=q['rate'], rate_per_mile=q['rate_per_mile'],
                contact_email=(r.matched_recipient or r.from_email or '').lower(), snippet=q['snippet']))
            added += 1
    db.session.commit()
    return added


# Mailboxes shared by unrelated people — a domain match there means nothing.
_PUBLIC_MAIL_DOMAINS = frozenset({
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'rocketmail.com', 'outlook.com',
    'hotmail.com', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
    'comcast.net', 'att.net', 'sbcglobal.net', 'bellsouth.net', 'verizon.net', 'cox.net',
    'charter.net', 'protonmail.com', 'proton.me', 'gmx.com', 'mail.com', 'yandex.com', 'zoho.com',
})
_REPLY_SUBJ_PREFIX = re.compile(r'^\s*(?:(?:re|fw|fwd)\s*(?:\[\d+\])?\s*:\s*)+', re.I)
_colleague_misses = {}   # uid -> msg_ids already checked and not an answer to our outreach


def _own_gmail_address(uid):
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first() if uid else None
    return (acct.gmail_address or '') if acct else ''


class _ColleagueReplyMatcher:
    """Which of our outreach emails does a reply from an address we never
    emailed answer? In freight a colleague answering for a shared mailbox
    (we wrote to dispatch@abc.com, john@abc.com replied) is normal.

    1. Same Gmail thread as one of our sent emails to a known recipient —
       exact, works for any domain.
    2. Same corporate domain as a recipient and the subject carries that
       recipient's lane ("Re: Laredo, TX to Doral, FL, ...") — catches replies
       to an internally forwarded email. Never for public mail domains.
    Returns the original recipient (lowercased) or None."""

    def __init__(self, service, uid, known, own_email=''):
        self.service, self.uid, self.known = service, uid, known
        self.own_domain = (own_email or '').lower().rpartition('@')[2]
        self._sent_threads = None

    @staticmethod
    def looks_like_reply(headers):
        return bool(headers.get('In-Reply-To') or headers.get('References')
                    or _REPLY_SUBJ_PREFIX.match(headers.get('Subject') or ''))

    def _sent_thread_map(self):
        if self._sent_threads is None:
            self._sent_threads, token = {}, None
            try:
                for _ in range(4):   # ≤2000 sent messages from the last 30 days
                    kw = dict(userId='me', q='in:sent newer_than:30d', maxResults=500)
                    if token:
                        kw['pageToken'] = token
                    resp = self.service.users().messages().list(**kw).execute()
                    for m in resp.get('messages', []):
                        self._sent_threads.setdefault(m.get('threadId'), []).append(m['id'])
                    token = resp.get('nextPageToken')
                    if not token:
                        break
            except Exception:
                app.logger.exception('colleague match: listing sent mail failed for uid=%s', self.uid)
        return self._sent_threads

    def by_thread(self, thread_id):
        for mid in self._sent_thread_map().get(thread_id, [])[:5]:
            try:
                md = self.service.users().messages().get(
                    userId='me', id=mid, format='metadata', metadataHeaders=['To', 'Cc']).execute()
            except Exception:
                continue
            hdrs = {h['name'].lower(): h['value'] for h in md.get('payload', {}).get('headers', [])}
            for em in re.findall(r'[\w.+\-]+@[\w.\-]+\.\w+', f"{hdrs.get('to', '')} {hdrs.get('cc', '')}"):
                if em.lower() in self.known:
                    return em.lower()
        return None

    def by_lane(self, sender, subject):
        domain = sender.rpartition('@')[2]
        if not domain or domain in _PUBLIC_MAIL_DOMAINS or domain == self.own_domain:
            return None
        colleagues = [e for e in self.known if e.endswith('@' + domain)]
        subj = _REPLY_SUBJ_PREFIX.sub('', subject or '').strip().lower()
        if not colleagues or not subj:
            return None
        from app.models import Send
        from sqlalchemy import func
        rows = db.session.query(Send.recipient_email, Send.origin, Send.destination).filter(
            Send.user_id == self.uid, Send.status == 'sent',
            func.lower(Send.recipient_email).in_(colleagues),
        ).order_by(Send.sent_at.desc()).limit(300).all()
        for em, origin, dest in rows:
            if origin and dest and subj.startswith(f'{origin} to {dest}'.lower()):
                return em.lower()
        return None

    def match(self, sender, headers, thread_id):
        if not self.looks_like_reply(headers):
            return None
        return (thread_id and self.by_thread(thread_id)) or self.by_lane(sender, headers.get('Subject', ''))


def fetch_replies_from_gmail(uid=None, rate_limit=True):
    uid = uid or current_user_id()
    # Rate-limit manual checks: once per 60 s per user. The scheduler's pre-send
    # check passes rate_limit=False so it never makes the user's button wait.
    if rate_limit:
        now = time.time()
        last = _last_fetch_times.get(uid, 0)
        if now - last < 60:
            wait = int(60 - (now - last))
            return {'error': f'Please wait {wait}s before checking again', 'rate_limited': True}
        _last_fetch_times[uid] = now

    known        = get_known_emails(uid)
    existing     = load_replies(uid)
    existing_ids = {r['msg_id'] for r in existing}
    new_replies  = []
    bounced      = set()

    try:
        service = _get_gmail_service(uid)
    except RuntimeError as e:
        return {'error': str(e)}

    try:
        since_epoch = int((_utcnow() - timedelta(days=30)).timestamp())
        results = service.users().messages().list(
            userId='me', q=f'after:{since_epoch} in:inbox', maxResults=100
        ).execute()
        messages = results.get('messages', [])

        # First pass: collect new reply data without route lookup (avoid N+1)
        _pending_replies = []
        matcher = None   # built on the first reply from an address we never emailed
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
                matched = None
                if sender not in known:
                    if any(b in sender for b in _BOUNCE_SENDERS) or headers.get('X-Failed-Recipients'):
                        failed = _bounced_recipient(from_addr, headers,
                                                    _gmail_get_body(msg_data.get('payload', {})), known)
                        if failed:
                            bounced.add(failed)
                        continue
                    misses = _colleague_misses.setdefault(uid, set())
                    if msg_id in misses:
                        continue
                    if matcher is None:
                        matcher = _ColleagueReplyMatcher(service, uid, known, _own_gmail_address(uid))
                    matched = matcher.match(sender, headers, msg_data.get('threadId', ''))
                    if not matched:
                        if len(misses) > 5000:
                            misses.clear()
                        misses.add(msg_id)
                        continue

                body = _gmail_get_body(msg_data.get('payload', {}))
                received = _gmail_internal_date(msg_data) or _utcnow()

                _pending_replies.append({
                    'msg_id':      msg_id,
                    'thread_id':   msg_data.get('threadId', ''),
                    'email':       sender,
                    'matched_recipient': matched,
                    'from':        from_addr,
                    'subject':     headers.get('Subject', ''),
                    'date':        headers.get('Date', ''),
                    'body':        body,
                    'route':       '',  # filled in bulk below
                    'status':      'new',
                    'received_at': received.strftime('%Y-%m-%d %H:%M'),
                    'received_dt': received,
                })
            except Exception:
                continue

        # Bulk route lookup — 1 query instead of N
        if _pending_replies:
            sender_emails = {r['email'] for r in _pending_replies}
            route_map = _bulk_routes_for_emails(
                uid, sender_emails | {r['matched_recipient'] for r in _pending_replies if r.get('matched_recipient')})

            # Bulk status-inheritance lookup — if contact was ignored/not_interested,
            # inherit that status so they don't re-appear in the queue as 'new'.
            # 'follow_up'/'interested' contacts still get 'new' so the user sees the reply.
            from app.models import Reply as _ReplyModel
            from sqlalchemy import func as _func
            _suppressed_statuses = {'ignored', 'not_interested'}
            _inherited_status: dict = {}
            try:
                _status_rows = db.session.query(
                    _func.lower(_ReplyModel.from_email),
                    _ReplyModel.status,
                    _func.max(_ReplyModel.received_at),
                ).filter(
                    _ReplyModel.user_id == uid,
                    _func.lower(_ReplyModel.from_email).in_(sender_emails),
                    _ReplyModel.status.in_(list(_suppressed_statuses)),
                ).group_by(
                    _func.lower(_ReplyModel.from_email),
                    _ReplyModel.status,
                ).all()
                for em, st, _ in _status_rows:
                    if em not in _inherited_status or st in _suppressed_statuses:
                        _inherited_status[em] = st
            except Exception:
                pass  # if lookup fails, fall back to 'new' — safe default

            for r in _pending_replies:
                r['route'] = route_map.get(r['email']) or route_map.get(r.get('matched_recipient') or '', '')
                # Inherit suppressed status so ignored contacts stay quiet
                r['status'] = _inherited_status.get(r['email'], 'new')
            new_replies.extend(_pending_replies)

    except Exception as e:
        return {'error': str(e)}

    all_replies = new_replies + existing
    save_replies(all_replies, uid)

    # Hard bounces: the address can never be reached — stop-list it and stop
    # its follow-ups so nothing keeps retrying a dead mailbox.
    bounced_added = 0
    if bounced and uid:
        be, _bd = load_stop_list(uid)
        for addr in sorted(bounced):
            if addr in be:
                continue
            try:
                if _add_to_stop_list(uid, addr, reason='bounced'):
                    bounced_added += 1
                _block_followup_contact(uid, addr, 'bounced')
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception('bounce handling failed for %s', addr)

    # Auto-stop follow-ups for contacts who replied
    if new_replies and uid:
        reply_rows = _reply_rows_by_msg_id(uid, new_replies)
        for r in new_replies:
            row = reply_rows.get(r['msg_id'])
            # a colleague's answer counts as the emailed contact replying too
            for addr in {r['email'], r.get('matched_recipient')} - {None, ''}:
                try:
                    _check_reply_stops_followup(addr, uid, row)
                except Exception:
                    app.logger.exception('reply hook failed for %s', addr)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    # Semi-automatic triage: classify the new arrivals (applying auto-actions per
    # workspace modes) and backfill categories on the pre-existing backlog.
    triage = {}
    if uid:
        try:
            triage = _auto_triage_new_replies(uid, [r['msg_id'] for r in new_replies])
        except Exception:
            db.session.rollback()
            app.logger.exception('auto-triage of new replies failed')
        try:
            _backfill_triage(uid)
        except Exception:
            db.session.rollback()
            app.logger.exception('triage backfill failed')
        try:
            _backfill_reply_dates(service, uid)
        except Exception:
            db.session.rollback()
            app.logger.exception('reply date backfill failed')
        try:
            _extract_rate_quotes(uid)
        except Exception:
            db.session.rollback()
            app.logger.exception('rate extraction failed')

    return {'new': len(new_replies), 'total': len(all_replies),
            'auto_ignored': triage.get('auto_ignored', 0),
            'auto_followup': triage.get('auto_followup', 0),
            'ooo_paused': triage.get('ooo_paused', 0),
            'bounced': bounced_added,
            'detected': triage.get('detected', {})}


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

def get_stats(period='lifetime'):
    """Compute dashboard stats using SQL aggregation.
    period: 'today' | 'week' (last 7 days) | 'month' (last 30 days) | 'lifetime' (all time, default)
    """
    empty={"total":0,"sent":0,"errors":0,"today":0,"by_day":[],"by_variant":[],"by_hour":[],
           "top_recipients":[],"top_routes":[],"replied_emails":[],"replied_domains":[],"response_rate":{}}
    uid = current_user_id()
    if not uid: return empty
    period = period if period in ('today', 'week', 'month', 'lifetime') else 'lifetime'
    cache_key = f'stats:{uid}:{period}'
    cached, hit = _cache_get(cache_key, _STATS_TTL)
    if hit: return cached
    from app.models import Send, Reply
    from sqlalchemy import func, case

    tz = _user_tz(uid)                    # "today" = the user's local day
    today_start = _local_day_start(tz, 0)

    # ── Date cutoff for the selected period ───────────────────────────────
    if period == 'today':
        period_cutoff = today_start       # only today
    elif period == 'week':
        period_cutoff = _local_day_start(tz, 6)   # last 7 days inclusive
    elif period == 'month':
        period_cutoff = _local_day_start(tz, 29)  # last 30 days inclusive
    else:
        period_cutoff = None              # no filter = lifetime

    def _period_filter(q):
        """Apply period date filter to a Send query."""
        if period_cutoff is not None:
            q = q.filter(Send.sent_at >= period_cutoff)
        return q

    # ── Counts: sent, errors (period-scoped) + today always ──────────────
    base_q = db.session.query(
        func.count(Send.id).label('total'),
        func.count(case((Send.status == 'sent', 1))).label('sent'),
        func.count(case((Send.status == 'error', 1))).label('errors'),
    ).filter(Send.user_id == uid)
    agg = _period_filter(base_q).first()
    total = agg.total or 0
    sent  = agg.sent  or 0
    errors = agg.errors or 0

    # today count always shown as context
    today_count = db.session.query(
        func.count(case((db.and_(Send.status == 'sent', Send.sent_at >= today_start), 1)))
    ).filter(Send.user_id == uid).scalar() or 0

    # ── By-day: 14-day window (or just today when period=today) ──────────
    chart_cutoff = today_start if period == 'today' else _local_day_start(tz, 13)
    day_counts = Counter(_local_date(t, tz) for (t,) in db.session.query(Send.sent_at).filter(
        Send.user_id == uid, Send.status == 'sent', Send.sent_at >= chart_cutoff))
    by_day = [{"date": str(d), "count": c} for d, c in sorted(day_counts.items())]

    # ── By-variant (period-scoped) ────────────────────────────────────────
    by_var_q = db.session.query(
        Send.template_variant, func.count(Send.id)
    ).filter(Send.user_id == uid, Send.status == 'sent')
    by_variant = [{"variant": str(v), "count": c}
                  for v, c in _period_filter(by_var_q).group_by(Send.template_variant).all()]

    # ── By-hour (period-scoped) ───────────────────────────────────────────
    try:
        from sqlalchemy import extract
        by_hr_q = db.session.query(
            extract('hour', Send.sent_at).label('hr'),
            func.count(Send.id)
        ).filter(Send.user_id == uid, Send.status == 'sent', Send.sent_at.isnot(None))
        by_hr_rows = _period_filter(by_hr_q).group_by('hr').all()
        # UTC hour → user's hour at today's offset (DST drift of history is ignored)
        shift = int(datetime.now(tz).utcoffset().total_seconds() // 3600)
        by_hr = Counter()
        for h, c in by_hr_rows:
            if h is not None:
                by_hr[(int(h) + shift) % 24] += c
    except Exception:
        by_hr = {}
    by_hour = [{"hour": f"{h:02d}:00", "count": by_hr.get(h, 0)} for h in range(24)]

    # ── Top recipients (period-scoped) ────────────────────────────────────
    top_recip_q = db.session.query(
        func.lower(Send.recipient_email), func.count(Send.id)
    ).filter(Send.user_id == uid, Send.status == 'sent')
    top_recip = _period_filter(top_recip_q)\
        .group_by(func.lower(Send.recipient_email))\
        .order_by(func.count(Send.id).desc()).limit(10).all()

    # ── Top routes (period-scoped) ────────────────────────────────────────
    top_rt_q = db.session.query(
        Send.origin, Send.destination, func.count(Send.id)
    ).filter(
        Send.user_id == uid, Send.status == 'sent',
        Send.origin.isnot(None), Send.destination.isnot(None),
        Send.origin != '', Send.destination != ''
    )
    top_rt = _period_filter(top_rt_q)\
        .group_by(Send.origin, Send.destination)\
        .order_by(func.count(Send.id).desc()).limit(10).all()

    # ── Reply stats — contact-based (distinct from_email), same period ────
    # Count unique contacts, not messages — prevents multi-message threads
    # from inflating the numbers (1 broker sending 5 msgs = 1 reply, not 5).
    reply_contact_q = db.session.query(
        func.lower(Reply.from_email).label('em'),
        # Best status per contact: follow_up/interested > new/viewed > not_interested/ignored
        func.min(case(
            (Reply.status.in_(['follow_up', 'interested']), 0),
            (Reply.status.in_(['new', 'viewed']), 1),
            else_=2,
        )).label('priority'),
    ).filter(
        Reply.user_id == uid,
        Reply.from_email.isnot(None),
        Reply.from_email != '',
    )
    if period_cutoff is not None:
        reply_contact_q = reply_contact_q.filter(Reply.received_at >= period_cutoff)
    reply_contact_rows = reply_contact_q.group_by(func.lower(Reply.from_email)).all()

    tr = len(reply_contact_rows)                          # unique contacts who replied
    interested = sum(1 for r in reply_contact_rows if r.priority == 0)   # follow_up or interested
    not_int    = sum(1 for r in reply_contact_rows if r.priority == 2)   # ignored/not_interested
    new_r      = sum(1 for r in reply_contact_rows if r.priority == 1)   # new/viewed

    contacted, replied = _reply_cohort(uid, period_cutoff)
    response_rate_pct = _reply_rate(contacted, replied) or 0
    interest_rate_pct = round(100 * interested / tr, 1) if tr > 0 else 0

    # ── Replied emails/domains (lifetime) ────────────────────────────────
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
        "total": total, "sent": sent, "errors": errors, "today": today_count,
        "period": period,
        "by_day": by_day,
        "by_variant": by_variant,
        "by_hour": by_hour,
        "top_recipients": [{"email": e, "count": c} for e, c in top_recip],
        "top_routes":     [{"route": f"{o} → {d}", "count": c} for o, d, c in top_rt],
        "replied_emails": [{"email": e, "count": c, "status": rs.get(e, 'new')} for e, c in rc.most_common()],
        "replied_domains": [{"domain": d, "count": c} for d, c in dc.most_common()],
        "response_rate": {
            "contacted": contacted,
            "replied": replied,
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

    tz = _user_tz(uid)
    today = _local_date(_utcnow(), tz)
    week_start = _local_day_start(tz, today.weekday())
    today_key = today.strftime('%Y-%m-%d')

    daily_counts = Counter()
    peak_hour = None
    if uid:
        from app.models import Send
        from sqlalchemy import func, extract

        # Daily counts (last 14 days only — all we display)
        cutoff = _local_day_start(tz, 14)
        for (t,) in db.session.query(Send.sent_at).filter(
                Send.user_id == uid, Send.status == 'sent',
                Send.sent_at.isnot(None), Send.sent_at >= cutoff):
            daily_counts[str(_local_date(t, tz))] += 1

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
                shift = int(datetime.now(tz).utcoffset().total_seconds() // 3600)
                peak_hour = f"{(int(hr_row.hr) + shift) % 24:02d}:00"
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
# ── Truckstop loadboard parser ────────────────────────────────────────────────
_TS_CITY_RE   = re.compile(r'^([A-Z][a-zA-Z\.\'\-]*(?:\s+[A-Z][a-zA-Z\.\'\-]*)*,\s*[A-Z]{2})\b')
_TS_TRIPMI_RE = re.compile(r'^[\d,]+\s*mi$')
_TS_WT_RE     = re.compile(r'^([\d,]+)\s*lbs$', re.IGNORECASE)
_TS_LEN_RE    = re.compile(r"^([\d.]+)'\s*L$", re.IGNORECASE)
_TS_DATE_RE   = re.compile(r'(\d{1,2}/\d{1,2})')

def _ts_is_phone(s):
    core = re.sub(r'(?i)\bext\.?\s*\d+', '', s).strip()
    if not core: return False
    if not re.fullmatch(r'[\d\s\(\)\-\+\.]+', core): return False
    return len(re.sub(r'\D', '', core)) >= 7

def parse_truckstop_text(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    blocks, cur = [], []
    for l in lines:
        cur.append(l)
        if _EMAIL_RE.search(l):
            blocks.append(cur); cur = []
    loads, seen = [], set()
    for block in blocks:
        em_m = _EMAIL_RE.search(block[-1])
        if not em_m: continue
        email = em_m.group().lower()
        cities = []
        for bl in block:
            cm = _TS_CITY_RE.match(bl)
            if cm: cities.append(cm.group(1).strip())
            if len(cities) >= 2: break
        origin      = cities[0] if len(cities) >= 1 else ""
        destination = cities[1] if len(cities) >= 2 else ""
        equip = ""
        for idx, bl in enumerate(block):
            if _TS_TRIPMI_RE.match(bl) and idx + 1 < len(block):
                cand = block[idx + 1].strip()
                if re.fullmatch(r'[A-Z]{1,4}', cand): equip = cand
                break
        weight = length = ""
        for bl in block:
            if not weight:
                wm = _TS_WT_RE.match(bl)
                if wm: weight = f"{wm.group(1)} lbs"
            if not length:
                lm = _TS_LEN_RE.match(bl)
                if lm: length = f"{lm.group(1)} ft"
        date = ""
        for idx, bl in enumerate(block):
            if bl.lower() == 'pickup' and idx + 1 < len(block):
                dm = _TS_DATE_RE.search(block[idx + 1])
                if dm: date = dm.group(1)
                break
        company = ""
        for idx, bl in enumerate(block):
            if re.match(r'(?i)^days to pay\b', bl) and idx >= 1:
                company = block[idx - 1].strip(); break
        contact = ""
        em_idx = len(block) - 1
        prev = block[em_idx - 1].strip() if em_idx >= 1 else ""
        if _ts_is_phone(prev):
            name_line = block[em_idx - 2].strip() if em_idx >= 2 else ""
        else:
            name_line = prev
        if (name_line and re.search(r'[A-Za-z]', name_line)
                and not re.match(r'(?i)^(authority requirement|days to pay|additional stops)', name_line)
                and '@' not in name_line and not _ts_is_phone(name_line)):
            contact = name_line
        key = f"{email}|{origin}|{destination}"
        if key in seen: continue
        seen.add(key)
        loads.append({"email": email, "origin": origin, "destination": destination,
            "date": date, "equip": equip, "length": length, "weight": weight,
            "company": company, "contact": contact})
    return loads

def parse_dat_text(text):
    """Parse both compact (list) and detailed (card) DAT board formats.
    Delegates to the Truckstop parser when the text is a Truckstop loadboard export."""
    if re.search(r'(?i)\bdays to pay\b', text) and re.search(r'(?i)\b(?:additional stops|estimated fuel cost)\b', text):
        return parse_truckstop_text(text)
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
            # Skip single-character lines (equipment codes: F, V, R, etc.)
            if len(cand) == 1: continue
            # Skip all-caps short codes: ANATXFL1, SSLARFL
            if re.match(r'^[A-Z0-9]{3,12}$', cand): continue
            # Skip commodity-like ALL-CAPS lines (CANNED FOOD, SNACKS) — but allow
            # company names that contain a business suffix (LLC, INC, CORP, etc.)
            _BIZ_SUFFIX = r'\b(?:LLC|INC|CORP|LTD|LP|LLP|CO|GROUP|LOGISTICS|TRANSPORT|FREIGHT|TRUCKING|CARRIERS?|SOLUTIONS?|SYSTEMS?)\b'
            if (re.match(r'^[A-Z\s]{3,}$', cand) and not re.search(r'[a-z]', cand)
                    and len(cand.split()) <= 3 and not re.search(_BIZ_SUFFIX, cand)):
                continue
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


def _gmail_send_with_retry(service, raw_message, max_retries=3, thread_id=None):
    """Send via Gmail API with exponential backoff on transient errors.
    Pass thread_id to add message to an existing Gmail thread."""
    from googleapiclient.errors import HttpError
    last_exc = None
    body = {'raw': raw_message}
    if thread_id:
        body['threadId'] = thread_id
    for attempt in range(max_retries):
        try:
            return service.users().messages().send(
                userId='me', body=body
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

def run_send_job(job_id, loads, cfg, templates, uid=None):
    """Run a send job in a background thread with DB-backed job state."""
    state = _user_send_state(uid)
    state.update({"running":True,"done":False,"total":len(loads),"current":0,"sent":0,"errors":0,"skipped":0,"log":[],"job_id":job_id,
                  "next_at":None,"next_total":0,"next_email":"",
                  "delay_avg":(cfg.get("delay_min", 20) + cfg.get("delay_max", 45)) / 2})
    with app.app_context():
        from app.models import SendJob
        try:
            job = db.session.get(SendJob, job_id)
            if not job:
                state.update({"running": False, "done": True, "errors": 1})
                return
            job.status = 'running'
            job.started_at = _utcnow()
            job.finished_at = None
            job.error_msg = None
            db.session.commit()

            _, sent_today_set = load_sent_log(uid=uid)
            be, bd = load_stop_list(uid=uid)
            session_sent = set()
            for i, load in enumerate(loads):
                state["current"] = i + 1
                em = load['email'].lower().strip()
                if is_blocked(load['email'], be, bd):
                    state["skipped"] += 1
                    state["log"].append({"time":_utcnow().strftime('%H:%M:%S'),"at":_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),"status":"skipped","variant":0,"email":load["email"],"error":"stop list"})
                    continue
                if em in sent_today_set or em in session_sent:
                    state["skipped"] += 1
                    state["log"].append({"time":_utcnow().strftime('%H:%M:%S'),"at":_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),"status":"skipped","variant":0,"email":load["email"],"error":"already sent today"})
                    continue
                # Re-check quota at send time — the pre-flight check in /api/send can
                # race with parallel jobs or follow-up sends consuming the same quota
                quota_now = get_daily_quota(uid)
                if not quota_now['unlimited'] and (quota_now['remaining'] or 0) <= 0:
                    state["skipped"] += 1
                    state["log"].append({"time":_utcnow().strftime('%H:%M:%S'),"at":_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),"status":"skipped","variant":0,"email":load["email"],"error":"daily quota exhausted"})
                    continue
                tmpl = random.choice(templates); vi = templates.index(tmpl) + 1
                body = render_template_text(tmpl, load, cfg)
                subject = _build_subject(load)
                ok, err = send_one_email(load['email'], subject, body, cfg, uid=uid)
                ts = _utcnow().strftime('%H:%M:%S'); st = 'sent' if ok else 'error'
                append_log(load, st, vi, uid=uid)
                if ok:
                    session_sent.add(em)
                    state["sent"] += 1
                    _track_usage(uid, 'email_sent')   # ← quota tracking
                else:
                    state["errors"] += 1
                state["log"].append({"time":ts,"at":_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),"status":st,"variant":vi,"email":load["email"],"error":err or ""})
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
                    pause = random.randint(cfg.get("delay_min", 20), cfg.get("delay_max", 45))
                    # the Send page counts down to the next email
                    state.update(next_at=time.time() + pause, next_total=pause, next_email=loads[i + 1]['email'])
                    time.sleep(pause)
                    state.update(next_at=None, next_email='')
            state.update({"running": False, "done": True})
            # Mark job as done in DB
            try:
                job.status      = 'done'
                job.sent        = state["sent"]
                job.errors      = state["errors"]
                job.skipped     = state["skipped"]
                job.finished_at = _utcnow()
                db.session.commit()
            except Exception as _fe:
                app.logger.warning(f'run_send_job: DB final update failed: {_fe}')
                db.session.rollback()
            audit_log('send_batch', resource_type='send', uid=uid, detail={
                'total': state['total'], 'sent': state['sent'],
                'errors': state['errors'], 'skipped': state['skipped'],
            })
        except Exception as _job_err:
            # Never let a worker-thread crash leave the UI stuck on "sending…" with no
            # error: log the full traceback (visible in deploy logs), surface the error
            # on the job, and clear the in-memory running flag so the queue is freed.
            import traceback as _tb
            app.logger.error(
                f'run_send_job crashed uid={uid} job={job_id}: {_job_err}\n{_tb.format_exc()}'
            )
            state.update({"running": False, "done": True})
            try:
                db.session.rollback()
                _j = db.session.get(SendJob, job_id)
                if _j and _j.status != 'done':
                    _j.status      = 'error'
                    _j.error_msg   = f'Send job crashed: {_job_err}'[:480]
                    _j.finished_at = _utcnow()
                    db.session.commit()
            except Exception:
                db.session.rollback()

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

    # The state must match the one this browser's session issued — a missing
    # value on either side is a mismatch, never a match.
    state = request.args.get('state', '')
    expected = session.pop('oauth_state', None)
    if not state or not expected or not secrets.compare_digest(state, expected):
        return redirect('/?gmail_error=state_mismatch')
    if not _session_user():
        return redirect(url_for('login_page'))

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
    acct.token_expiry         = _utcnow() + timedelta(seconds=expires_in)
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
@csrf_protected
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
@csrf_protected
@limiter.limit("5 per minute")
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
        return jsonify({'ok': False, 'error': str(e)}), 500


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
@limiter.limit("20 per minute")
@csrf_protected
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
    daily_target = data.get('daily_target')
    if daily_target is not None:
        try:
            daily_target = int(daily_target)
            if not (1 <= daily_target <= 500):
                return jsonify({'error': 'daily_target must be 1–500'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'daily_target must be an integer'}), 400
    if delay_min and delay_max and delay_min > delay_max:
        return jsonify({'error': 'delay_min must be ≤ delay_max'}), 400
    # Validate email format if provided
    gmail = data.get('gmail_address', '')
    if gmail and not re.match(r'^[\w.+\-]+@[\w.\-]+\.\w{2,}$', gmail):
        return jsonify({'error': 'Invalid Gmail address format'}), 400
    cfg = load_config()
    for k in ['gmail_address','gmail_app_password','your_name','your_company','your_phone','delay_min','delay_max','daily_target']:
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
@limiter.limit("20 per minute")
@csrf_protected
def api_save_templates():
    outreach = request.json.get("templates", [])
    save_templates_file(outreach)
    return jsonify({"ok": True})

@app.route('/api/stop-list', methods=['GET'])
@login_required
def api_get_stop(): return jsonify(get_stop_list_raw())

@app.route('/api/stop-list', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf_protected
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
@csrf_protected
def api_send():
    uid = current_user_id()
    app.logger.info(f'API /api/send called — uid={uid}')
    state = _user_send_state(uid)
    if state.get("running"):
        return jsonify({"error": "Already running"}), 400
    from app.models import SendJob
    # Auto-recover stale jobs left over from a server restart / crash
    stale_cutoff = _utcnow() - timedelta(minutes=30)
    stale = SendJob.query.filter(
        SendJob.user_id == uid,
        SendJob.kind == 'outreach',
        SendJob.status.in_(['queued', 'running']),
        db.or_(
            SendJob.started_at < stale_cutoff,
            SendJob.started_at == None
        )
    ).all()
    for s in stale:
        s.status = 'error'
        s.error_msg = 'Stale job auto-recovered after server restart'
        s.finished_at = _utcnow()
    if stale:
        db.session.commit()
        app.logger.warning(f'api_send: auto-recovered {len(stale)} stale job(s) for uid={uid}')
    active_job = SendJob.query.filter(
        SendJob.user_id == uid,
        SendJob.kind == 'outreach',
        SendJob.status.in_(['queued', 'running'])
    ).order_by(SendJob.started_at.desc()).first()
    if active_job:
        return jsonify({"error": "Already running", "job_id": active_job.id}), 400
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
    templates = load_templates()
    job = SendJob(user_id=uid, status='queued', total=len(loads))
    db.session.add(job)
    db.session.commit()

    t = threading.Thread(target=run_send_job, args=(job.id, loads, cfg, templates, uid))
    t.daemon = True; t.start()
    return jsonify({"ok": True, "total": len(loads), "quota": quota, "job_id": job.id})

@app.route('/api/send/reset', methods=['POST'])
@login_required
@csrf_protected
def api_send_reset():
    """Manually clear any stuck/stale send jobs so the user can send again."""
    uid = current_user_id()
    from app.models import SendJob
    stuck = SendJob.query.filter(
        SendJob.user_id == uid,
        SendJob.kind == 'outreach',
        SendJob.status.in_(['queued', 'running'])
    ).all()
    for j in stuck:
        j.status = 'error'
        j.error_msg = 'Manually reset by user'
        j.finished_at = _utcnow()
    db.session.commit()
    # Also clear in-memory state
    state = _user_send_state(uid)
    state.update({"running": False, "done": True})
    app.logger.info(f'api_send_reset: cleared {len(stuck)} job(s) for uid={uid}')
    return jsonify({"ok": True, "cleared": len(stuck)})

@app.route('/api/send-status', methods=['GET'])
@login_required
def api_send_status():
    uid = current_user_id()
    state = _user_send_state(uid)
    from app.models import SendJob
    job = SendJob.query.filter_by(user_id=uid, kind='outreach').order_by(SendJob.started_at.desc()).first()
    if not job:
        return jsonify(state)

    if state.get('running') and state.get('job_id') == job.id:
        payload = dict(state)
        payload['status'] = job.status
        nxt = payload.pop('next_at', None)
        payload['next_in'] = max(0, round(nxt - time.time())) if nxt else None
        return jsonify(payload)

    return jsonify({
        'running': job.status in ('queued', 'running'),
        'done': job.status == 'done',
        'total': job.total,
        'current': job.sent + job.errors + job.skipped,
        'sent': job.sent,
        'errors': job.errors,
        'skipped': job.skipped,
        'log': [],
        'status': job.status,
        'job_id': job.id,
    })

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
def api_stats(): return jsonify(get_stats(period=request.args.get('period', 'lifetime')))

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

def _equip_label(code):
    code = (code or '').strip().upper()
    return _EQUIP_LABELS.get(code, code) if code else ''


@app.route('/api/intelligence/rates')
@login_required
def api_intelligence_rates():
    """Lane rate memory: quotes grouped by lane + equipment, newest first.
    Query: days (default 90, 0 = all time), equip (code), q (lane search)."""
    from app.models import RateQuote, Reply, FollowupContact, Workspace
    from email.utils import parseaddr
    uid = _current_user_id()
    try:
        _extract_rate_quotes(uid)          # pick up replies not parsed yet
    except Exception:
        db.session.rollback()
        app.logger.exception('rate extraction failed for uid=%s', uid)
    try:
        days = max(0, int(request.args.get('days', 90)))
    except ValueError:
        days = 90
    equip = (request.args.get('equip') or '').strip().upper()
    search = (request.args.get('q') or '').strip().lower()

    q = db.session.query(RateQuote, Reply).join(Reply, Reply.id == RateQuote.reply_id).filter(
        RateQuote.user_id == uid, RateQuote.hidden == False)
    all_equip = sorted({e for (e,) in q.with_entities(RateQuote.equipment).distinct() if e})
    if days:
        q = q.filter(Reply.received_at >= _utcnow() - timedelta(days=days))
    if equip:
        q = q.filter(RateQuote.equipment == equip)
    if search:
        q = q.filter(db.or_(RateQuote.origin.ilike(f'%{search}%'), RateQuote.destination.ilike(f'%{search}%')))
    rows = q.order_by(Reply.received_at.desc()).limit(3000).all()

    ws = Workspace.query.filter_by(owner_id=uid).first()
    names = {}
    if ws and rows:
        emails = {rq.contact_email for rq, _ in rows if rq.contact_email}
        for fc in FollowupContact.query.filter(FollowupContact.workspace_id == ws.id,
                                               db.func.lower(FollowupContact.contact_email).in_(emails)).all():
            names[fc.contact_email.lower()] = (fc.display_name, fc.company_name or '')

    fmt = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None
    groups = {}
    for rq, rp in rows:
        key = (rq.origin, rq.destination, rq.equipment or '')
        g = groups.setdefault(key, {'origin': rq.origin, 'destination': rq.destination,
                                    'lane': f'{rq.origin} → {rq.destination}',
                                    'equipment': rq.equipment or '', 'equipment_label': _equip_label(rq.equipment),
                                    'quotes': []})
        name, company = names.get(rq.contact_email, ('', ''))
        if not name:
            name = parseaddr(rp.from_name or '')[0].strip().strip('"') or rp.from_email
        colleague = rp.from_email if rp.matched_recipient and rp.from_email else ''
        g['quotes'].append({'id': rq.id, 'rate': rq.rate, 'rate_per_mile': rq.rate_per_mile,
                            'from': name, 'company': company, 'email': rq.contact_email,
                            'via': colleague, 'quoted_at': fmt(rp.received_at),
                            'snippet': rq.snippet or '', 'subject': rp.subject or ''})

    def stats(vals):
        vals = [v for v in vals if v is not None]
        if not vals:
            return None
        return {'avg': round(sum(vals) / len(vals), 2), 'min': min(vals), 'max': max(vals), 'count': len(vals)}

    out = []
    for g in groups.values():
        g['count'] = len(g['quotes'])
        g['last_quoted_at'] = g['quotes'][0]['quoted_at']
        g['flat'] = stats([x['rate'] for x in g['quotes']])
        g['per_mile'] = stats([x['rate_per_mile'] for x in g['quotes']])
        if g['flat']:
            g['flat']['avg'] = int(round(g['flat']['avg']))
        out.append(g)
    out.sort(key=lambda g: g['last_quoted_at'] or '', reverse=True)
    return jsonify(groups=out[:200], total=len(rows),
                   equipment=[{'code': e, 'label': _equip_label(e)} for e in all_equip])


@app.route('/api/intelligence/rates/hide', methods=['POST'])
@login_required
@limiter.limit("120 per minute")
@csrf_protected
def api_intelligence_rates_hide():
    """Remove a wrongly detected rate from the report (hidden=false restores it)."""
    from app.models import RateQuote
    data = request.get_json() or {}
    rq = db.session.get(RateQuote, str(data.get('id') or ''))
    if not rq or rq.user_id != _current_user_id():
        return jsonify(error='Not found'), 404
    rq.hidden = data.get('hidden', True) is not False
    db.session.commit()
    return jsonify(ok=True, id=rq.id, hidden=rq.hidden)


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
    all_replies = db.session.query(
        Reply.from_email, Reply.body, Reply.status, Reply.matched_recipient
    ).filter_by(user_id=uid).all()
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

    # Build reply lookup: emailed address → reply (its own, or a colleague's for it)
    reply_lookup = {r.from_email.lower(): r for r in all_replies if r.from_email}
    for r in all_replies:
        if r.matched_recipient:
            reply_lookup.setdefault(r.matched_recipient.lower(), r)

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

        reply_rate = _reply_rate(len(lane_email_set), replies_count) or 0
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
    contacted_by_domain: dict = {}
    all_sends = db.session.query(Send.recipient_email).filter_by(user_id=uid, status='sent').all()
    for s in all_sends:
        if not s.recipient_email or '@' not in s.recipient_email:
            continue
        em = s.recipient_email.lower()
        domain = em.split('@')[1]
        sent_by_domain[domain] = sent_by_domain.get(domain, 0) + 1
        contacted_by_domain.setdefault(domain, set()).add(em)

    # Unique contacts per domain (not messages) — same basis as the reply rate
    reply_by_domain: dict = {}
    rr_by_domain: dict = {}
    interested_by_domain: dict = {}
    for r in all_replies:
        if not r.from_email or '@' not in r.from_email:
            continue
        em = r.from_email.lower()
        domain = em.split('@')[1]
        answered_for = (r.matched_recipient or em).lower()
        if answered_for in contacted_by_domain.get(answered_for.split('@')[-1], ()):
            reply_by_domain.setdefault(answered_for.split('@')[-1], set()).add(answered_for)
        if _is_rate_request(r.body):
            rr_by_domain.setdefault(domain, set()).add(em)
        if r.status in ('follow_up', 'interested'):   # same "Follow-up" as Analytics
            interested_by_domain.setdefault(domain, set()).add(em)

    brokers = []
    for domain, sent_count in sorted(sent_by_domain.items(), key=lambda x: -x[1]):
        replies_count = len(reply_by_domain.get(domain, ()))
        rr_count      = len(rr_by_domain.get(domain, ()))
        interested    = len(interested_by_domain.get(domain, ()))
        reply_rate    = _reply_rate(len(contacted_by_domain.get(domain, ())), replies_count) or 0
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
def api_log():
    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 100)
    search = (request.args.get('search') or '').strip()
    status = (request.args.get('status') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()
    return jsonify(get_log_page(
        page=page, per_page=per_page, search=search,
        status=status, date_from=date_from, date_to=date_to,
    ))

@app.route('/api/replies', methods=['GET'])
@login_required
def api_get_replies():
    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 25)
    search = (request.args.get('search') or '').strip()
    view = (request.args.get('view') or 'all').strip()
    cat = (request.args.get('cat') or '').strip()
    return jsonify(get_reply_groups_page(page=page, per_page=per_page, search=search, view=view, cat=cat))

@app.route('/api/replies/fetch', methods=['POST'])
@login_required
@limiter.limit("2 per minute")   # IMAP is slow; prevent hammering Gmail
@csrf_protected
def api_fetch_replies(): return jsonify(fetch_replies_from_gmail())

@app.route('/api/replies/status', methods=['POST'])
@login_required
@limiter.limit("120 per minute")
@csrf_protected
def api_reply_status():
    data = request.json or {}
    msg_id = data.get('msg_id')
    status = data.get('status')
    valid_statuses = {'new', 'viewed', 'follow_up', 'interested', 'ignored', 'not_interested'}
    if not msg_id:
        return jsonify({'error': 'msg_id is required'}), 400
    if status not in valid_statuses:
        return jsonify({'error': 'Invalid reply status'}), 400
    add_to_stop = data.get('add_to_stop', False)
    replies = load_replies(); reply_obj = None
    for r in replies:
        if r['msg_id'] == msg_id:
            r['status'] = status; reply_obj = r; break
    save_replies(replies)
    if reply_obj:
        stage_map = {
            'new': 'replied',
            'viewed': 'replied',
            'follow_up': 'interested',
            'interested': 'interested',
            'ignored': 'lost',
            'not_interested': 'lost',
        }
        upsert_pipeline(reply_obj.get('email',''), {
            'stage': stage_map.get(status, 'replied'),
            'company': reply_obj.get('from','').split('<')[0].strip(),
            'route': reply_obj.get('route',''),
        })
    if status in ('interested', 'follow_up') and reply_obj:
        from app.models import Reply as ReplyModel
        reply_db = ReplyModel.query.filter_by(user_id=current_user_id(), msg_id=reply_obj['msg_id']).first()
        if reply_db:
            add_to_followups(reply_db)
    if add_to_stop and reply_obj:
        uid = current_user_id()
        em = reply_obj.get('email','')
        if uid and em:
            try:
                _add_to_stop_list(uid, em, reason='blocked from Replies')
                _block_followup_contact(uid, em, 'blocked from Replies')
                db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception('block from Replies failed for %s', em)
    audit_log('mark_reply', resource_type='reply',
              detail={'msg_id': msg_id, 'status': status, 'email': reply_obj.get('email') if reply_obj else None})
    return jsonify({'ok': True})

@app.route('/')
@login_required
def index(): return render_template('index.html', csrf_token=_get_csrf_token())

# ── HEALTH CHECK ────────────────────────────────────────────────────────────
# Used by Railway deployment to verify the app is alive.

@app.route('/health')
def health():
    try:
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        db_ok = False
    scheduler_ok = _scheduler_is_healthy()
    ok = db_ok and scheduler_ok
    return jsonify({
        'status':    'ok' if ok else 'degraded',
        'db':        db_ok,
        'scheduler': scheduler_ok,
        'scheduler_enabled': _scheduler_enabled,
        'rate_limit_shared': _limiter_shared,
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
        # Stop-list guard — covers scheduler, send-now and any future callers
        _uid_for_stop = uid or current_user_id()
        be, bd = load_stop_list(uid=_uid_for_stop)
        if is_blocked(to_email, be, bd):
            return False, 'blocked by stop list'
        route = fu.get('current_route') or fu.get('route', '')
        if fu.get('reply_subject'):
            subject = 'Re: ' + fu['reply_subject']
        elif fu.get('current_route'):
            subject = f'Following up — {fu["current_route"]}'
        else:
            subject = 'Following up'
        body = _safe_render(template_text, {
            'name': cfg.get('your_name', '') or cfg.get('name', ''),
            'company': cfg.get('your_company', '') or cfg.get('company', ''),
            'phone': cfg.get('your_phone', '') or cfg.get('phone', ''),
            'route': route,
            'origin': route.split('→')[0].strip() if '→' in route else '',
            'destination': route.split('→')[1].strip() if '→' in route else '',
        })
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
                _gmail_send_with_retry(service, raw, thread_id=fu.get('source_thread_id') or None)
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
    except Exception as e:
        app.logger.error('send_followup_email failed (to=%s): %s',
                         fu.get('contact_email') or fu.get('email', ''), e)
        return False, str(e)

DEFAULT_FU_TEMPLATES = {
    'FU1': "Hi,\n\nJust wanted to follow up — are you working on any loads this week?\n\nThank you,\n{name}\n{company} | {phone}",
    'FU2': "Hello,\n\nFollowing up again — do you have any loads available?\n\nThanks,\n{name}\n{company} | {phone}",
    'FU3': "Hi,\n\nLast follow-up — if you have loads in the future, please reach out.\n\nBest,\n{name}\n{company} | {phone}",
}

# Copy for the warmth ladder, one tuple of bodies per rung; the attempt number picks
# the body (attempt % len), so the next touch never repeats the last word for word and
# a different ask leads each time. A user's own Template(level=<RUNG>) replaces these.
# CLIENT is never scheduled, so it has no copy.
#
# Variables resolved at pick time (_render_rung_body): {route} {origin} {destination}
# {last_rate}. A line that mentions one the contact has no value for is dropped, so
# every email keeps at least one question on a line of its own. {name} {company}
# {phone} are the sender's and are filled in by send_followup_email.
_SIGNATURE = "{name}\n{company} | {phone}"
_RUNG_FIRST_LOAD = {'warm': 1, 'hot': 2}      # the load count that lands a contact on the rung
DEFAULT_RUNG_TEMPLATES = {
    # No reply yet: nothing to recall, so ask what is moving, offer the lanes out of
    # their city and the services they may not know we run.
    'cold': (
        "Hi,\n\n"
        "Do you have any loads open right now?\n"
        "We have trucks sitting in {origin}.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Do you have any hazmat, LTL, Mexico, Canada or high-value loads open? "
        "We run all of those.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Which lanes do you move most often?\n"
        "We have trucks sitting in {origin} and can look at other lanes from there.\n\n" + _SIGNATURE,
    ),
    # They answered but have not sent a load yet.
    'neutral': (
        "Hi,\n\n"
        "Do you have a load right now that we can quote?\n"
        "We have trucks sitting in {origin}.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Does any hazmat, LTL, Mexico, Canada or high-value freight come up on your side? "
        "We run those too.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Which lanes do you ship most often? Send us a couple and we will check them "
        "against our trucks.\n"
        "We have trucks sitting in {origin}.\n\n" + _SIGNATURE,
    ),
    # They sent load information. {route} is the lane of our first outreach to them (the
    # data does not say which lane they later sent), so the copy only claims we talked about it.
    'warm': (
        "Hi,\n\n"
        "Last time we talked about {route}. How often does that lane come up for you?\n"
        "Do you have another load coming up?\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Are there any other loads open on your side right now?\n"
        "We have trucks sitting in {origin}.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Do you have any hazmat, LTL, Mexico, Canada or high-value loads? "
        "We run all of those.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Is anything moving next week?\n"
        "If {route} is back on your board, send it over and we will quote it.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Are you covered on everything you have open right now?\n"
        "If not, send us the lane and we will see what we can do.\n\n" + _SIGNATURE,
    ),
    # More than one load: a working relationship, so ask for volume and the next load.
    'hot': (
        "Hi,\n\n"
        "Last time we talked about {route}.\n"
        "What do you have open this week?\n"
        "How many loads a week do you usually have?\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Which other lanes are you moving right now?\n"
        "We have trucks sitting in {origin}.\n"
        "If {route} comes up again, send it over and we will quote it.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Do you ever have hazmat, LTL, Mexico, Canada or high-value loads? "
        "We run those too, along with any lanes you already have.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Is there anything you need covered this week?\n"
        "Send over the lane and the pickup date and we will quote it.\n\n" + _SIGNATURE,

        "Hi,\n\n"
        "Which lanes are busiest for you right now?\n"
        "If anything leaves from {origin}, we have trucks sitting there.\n\n" + _SIGNATURE,
    ),
}


def _normalize_fu_template_level(value):
    raw = (value or '').strip()
    if not raw:
        return 'General'
    upper = raw.upper()
    return upper if upper in DEFAULT_FU_TEMPLATES else raw

def get_fu_templates():
    uid = current_user_id()
    if not uid: return DEFAULT_FU_TEMPLATES.copy()
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True).all()
    if not rows: return DEFAULT_FU_TEMPLATES.copy()
    core = DEFAULT_FU_TEMPLATES.copy()
    for r in rows:
        level = _normalize_fu_template_level(r.level)
        if level in core and r.body:
            core[level] = r.body
    return core

def _reply_rate(contacted, replied):
    """THE reply rate (Dashboard, Analytics, Intelligence, digest): the share of
    unique contacts emailed in a window who replied — themselves or through a
    colleague answering for them (Reply.matched_recipient) — always 0..100%."""
    return round(100.0 * replied / contacted, 1) if contacted else None


def _reply_cohort(uid, since=None):
    """(contacted, replied): unique recipients emailed since `since` (all time
    when None) and how many of them have replied since then."""
    from app.models import Send, Reply
    from sqlalchemy import func, distinct
    rq = db.session.query(func.lower(Send.recipient_email).label('em')).filter(
        Send.user_id == uid, Send.status == 'sent')
    if since is not None:
        rq = rq.filter(Send.sent_at >= since)
    recipients = rq.distinct().subquery()
    contacted = db.session.query(func.count()).select_from(recipients).scalar() or 0
    # who answered: the sender, plus the emailed address a colleague answered for
    answered = [db.select(func.lower(col).label('em')).where(Reply.user_id == uid, col.isnot(None))
                for col in (Reply.from_email, Reply.matched_recipient)]
    if since is not None:
        answered = [a.where(Reply.received_at >= since) for a in answered]
    responders = db.union(*answered).subquery()
    replied = db.session.query(func.count(distinct(recipients.c.em))).filter(
        recipients.c.em.in_(db.select(responders.c.em))).scalar() or 0
    return contacted, replied


def _fu_urgency(uid, now=None):
    """The one definition of the Follow-up urgency buckets, used by the list,
    its counters and select-all. A set date is a commitment regardless of which
    engine set it (ladder touch, manual schedule) — enabled flags only
    gate auto-sends. "Today" ends at the user's local midnight."""
    from app.models import FollowupContact as FC
    now = now or _utcnow()
    end_of_day = _local_day_start(_user_tz(uid), -1, now)
    active = FC.state == 'active'
    return {
        'needs_action': db.and_(FC.stage == 'completed_fu3', active),
        'overdue':      db.and_(FC.next_followup_at < now, active),
        'due_today':    db.and_(FC.next_followup_at >= now, FC.next_followup_at < end_of_day, active),
        'scheduled':    db.and_(FC.scheduled_once == True, FC.next_followup_at > now),
        # Today's touches: everything due by local midnight, plus hot (🔥) replies
        'touches':      db.and_(active, db.or_(FC.attention_at.isnot(None),
                                               FC.next_followup_at < end_of_day)),
    }


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
    rung_f  = request.args.get('rung', '').strip()

    if rung_f:
        if rung_f not in _LADDER_RUNG_VALUES:
            return jsonify(error=f'Unknown rung: {rung_f}'), 400
        q = q.filter_by(rung=rung_f)
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

    urg = _fu_urgency(uid)
    if special in urg:
        q = q.filter(urg[special])

    contacts = q.order_by(FollowupContact.created_at.desc()).all()

    count_q = db.session.query(
        func.count(FollowupContact.id).label('total'),
        func.count(case((FollowupContact.state == 'active', 1))).label('active'),
        func.count(case((FollowupContact.state == 'paused', 1))).label('paused'),
        func.count(case((FollowupContact.state == 'warm', 1))).label('warm'),
        func.count(case((FollowupContact.state == 'loads', 1))).label('loads'),
        func.count(case((FollowupContact.state == 'blocked', 1))).label('blocked'),
        func.count(case((FollowupContact.state == 'closed', 1))).label('closed'),
        func.count(case((urg['needs_action'], 1))).label('needs_action'),
        func.count(case((urg['overdue'], 1))).label('overdue'),
        func.count(case((urg['due_today'], 1))).label('due_today'),
        func.count(case((FollowupContact.attention_at.isnot(None) & (FollowupContact.state == 'active'), 1))).label('attention'),
        func.count(case((urg['scheduled'], 1))).label('scheduled'),
        func.count(case((urg['touches'], 1))).label('touches'),
    ).filter(FollowupContact.user_id == uid).first()

    counts = {
        'total': count_q.total, 'active': count_q.active, 'paused': count_q.paused,
        'warm': count_q.warm, 'state_warm': count_q.warm,   # state 'warm', not the rung
        'loads': count_q.loads, 'blocked': count_q.blocked,
        'closed': count_q.closed, 'needs_action': count_q.needs_action, 'overdue': count_q.overdue,
        'due_today': count_q.due_today,
        'scheduled': count_q.scheduled,
        'attention': count_q.attention,
        'touches': count_q.touches,
    }
    rmap = _latest_reply_filter_map(uid, {(c.contact_email or '').lower() for c in contacts})
    deferred = _ladder_deferred_ids(uid, contacts)
    contacts_out = []
    for c in contacts:
        d = _fu_row(c, c.id in deferred)
        d['last_reply_filter'] = rmap.get((c.contact_email or '').lower(), '')
        contacts_out.append(d)
    return jsonify(contacts=contacts_out, counts=counts, rung_counts=_ladder_rung_counts(uid))


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
    rung_f  = request.args.get('rung', '').strip()
    if rung_f:
        if rung_f not in _LADDER_RUNG_VALUES:
            return jsonify(error=f'Unknown rung: {rung_f}'), 400
        q = q.filter_by(rung=rung_f)
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
    urg = _fu_urgency(uid)          # same buckets as the list and its counters
    if special in urg:
        q = q.filter(urg[special])
    ids = [row[0] for row in q.with_entities(FollowupContact.id).all()]
    return jsonify(ids=ids)


@app.route('/api/followups/add', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
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

    now = _utcnow()

    # born on the ladder (cold): `stage` keeps its column default and means nothing now
    fc = FollowupContact(
        user_id=uid, workspace_id=ws.id, contact_email=email,
        contact_name=data.get('name', ''), company_name=data.get('company', ''),
        current_route=data.get('route', ''), state='active', stage='fu1_scheduled',
        is_followup_enabled=False, rung='cold',
        last_activity_at=now, source_reply_id=data.get('source_reply_id'),
        reply_subject=data.get('reply_subject', ''), reply_msg_id=data.get('reply_msg_id', ''),
        source_thread_id=data.get('source_thread_id', ''),
    )
    db.session.add(fc)
    db.session.flush()
    _schedule_touch(fc, ws)             # the first touch: the cold rung's rhythm
    _record_event(fc, 'created', actor_user_id=uid)
    db.session.commit()
    return jsonify(ok=True, contact=fc.to_dict()), 201


def _followup_send_args(fc, acct):
    """(fu_dict, cfg) for send_followup_email: the one place a follow-up's payload is
    built, shared by every path that sends one (ladder touch, one-time, recurring and
    the manual sends). The keys are exactly the ones send_followup_email reads; its
    `name`/`your_name` fallbacks exist because hand-copied dicts used to drift."""
    cfg = {'name': acct.your_name or '', 'company': acct.your_company or '',
           'phone': acct.your_phone or '', 'route': fc.current_route or '',
           'gmail_address': acct.gmail_address or '', 'gmail_app_password': acct.gmail_password or ''}
    fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
               'reply_msg_id': fc.reply_msg_id or '', 'current_route': fc.current_route or '',
               'source_thread_id': fc.source_thread_id or ''}
    return fu_dict, cfg


def _copy_rung(fc):
    """The rung whose copy a send to this contact uses: its own while it is on a live
    rung, otherwise the one its loads earn (a parked or client contact has none)."""
    if fc.rung in _LADDER_SENDABLE:
        return fc.rung
    return _ladder.rung_for(fc.load_count or 0, bool(fc.last_reply_at or fc.load_count))


def _followup_copy(uid, fc):
    """The body for a send that is not a scheduled ladder touch (manual one-off, a
    one-time or recurring date the owner set): the same per-rung copy the ladder
    sends, so there is one voice. None when nothing can be rendered."""
    return _template_for_rung(uid, _copy_rung(fc), fc)


def _followup_send_now_core(fc, uid, kind='touch'):
    """Send one follow-up to one contact by hand, with the rung's copy.

    Shared by the single 'send-now' / 'free-send' actions and the bulk worker so every
    path gets identical eligibility, dedupe and bookkeeping. A manual send spends no
    ladder attempt; it records the send, resolves the 🔥 flag and re-dates the next
    touch from the rung. kind='touch' ("send now") is for a contact on a live rung;
    kind='one_off' ("free-send") is the owner's deliberate one-off and also reaches a
    parked or client contact. Neither reaches an excluded contact, one who asked us
    to stop, or a blocked/closed one.
    Commits on success/failure. Returns (status, detail):
      'sent'      -> detail = None
      'skip'      -> detail = human reason (not eligible)
      'duplicate' -> detail = 24h-guard message
      'error'     -> detail = reason (no template / no account / send failure)
    """
    from app.models import EmailAccount
    one_off = kind == 'one_off'
    if one_off:
        if fc.state in ('blocked', 'closed'):
            return 'skip', 'Cannot send to blocked or closed contact'
    elif fc.state != 'active':
        return 'skip', 'Contact must be active to send'
    if fc.rung == 'excluded':
        return 'skip', _EXCLUDED_MSG
    # a deliberate one-off to a dormant contact is allowed; to someone who asked us to
    # stop it is not (the tier screen's own guard is only in the browser)
    if fc.exit_reason == 'refused':
        return 'skip', _REFUSED_MSG
    if not one_off and (fc.rung in _ladder.OFF_LADDER or fc.rung == 'client'):
        return 'skip', _OFF_LADDER_SEND_MSG[fc.rung]
    dup = _recent_followup_block(fc)
    if dup:
        return 'duplicate', dup

    template_text = _followup_copy(uid, fc)
    if not template_text:
        return 'error', 'No active follow-up templates. Add at least one before sending.'
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if not acct:
        return 'error', 'No email account configured'

    event = 'free_send' if one_off else 'manual_send'
    fu_dict, cfg = _followup_send_args(fc, acct)
    ok, err = send_followup_email(fu_dict, template_text, cfg, uid=uid)
    if not ok:
        _record_event(fc, event, actor_user_id=uid,
                      metadata_json=json.dumps({'error': err}), notes='Send failed')
        db.session.commit()
        return 'error', f'Send failed: {err}'

    now = _utcnow()
    fc.last_followup_sent_at = now
    fc.last_activity_at = now
    fc.attention_at = None              # touch delivered: 🔥 resolved
    _schedule_touch(fc, force=True)     # next touch from the rung; a parked contact gets none
    # no from_stage: the stage is the retired drip's record, and /api/followups/analytics
    # buckets manual_send events by it ("FU1 sent"), so writing it would invent drip history
    _record_event(fc, event, actor_user_id=uid)
    db.session.commit()
    return 'sent', None


@app.route('/api/followups/action', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
@csrf_protected
def api_followups_action():
    from app.models import FollowupContact, EmailAccount
    uid = _current_user_id()
    data = request.get_json()
    contact_id = data.get('id')
    action = data.get('action')
    reason = data.get('reason', '')

    fc = db.session.get(FollowupContact, contact_id)
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404

    if action in ('send-now', 'free-send'):
        status, detail = _followup_send_now_core(
            fc, uid, kind='one_off' if action == 'free-send' else 'touch')
        if status == 'skip':
            return jsonify(error=detail, skip=True), 400
        if status == 'duplicate':
            return jsonify(error=detail, duplicate=True), 409
        if status == 'error':
            code = 500 if detail.startswith('Send failed') else 400
            return jsonify(error=detail), code
        return jsonify(ok=True, contact=_fu_row_one(fc))

    elif action == 'schedule-once':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot schedule blocked or closed contact'), 400
        if fc.rung == 'excluded':
            return jsonify(error=_EXCLUDED_MSG), 400
        if fc.exit_reason == 'refused':      # a date would email someone who asked us to stop
            return jsonify(error=_REFUSED_MSG), 400
        dt_str = data.get('scheduled_at', '')
        if not dt_str:
            return jsonify(error='scheduled_at is required (ISO8601 UTC)'), 400
        try:
            scheduled_at = datetime.fromisoformat(dt_str.replace('Z', '+00:00')).replace(tzinfo=None)
            if scheduled_at < _utcnow() + timedelta(minutes=1):
                return jsonify(error='scheduled_at must be at least 1 minute in the future'), 400
        except (ValueError, TypeError):
            return jsonify(error='Invalid scheduled_at format — use ISO8601 UTC'), 400
        fc.next_followup_at = scheduled_at
        fc.scheduled_once = True
        fc.is_followup_enabled = False       # the owner took control of the schedule: not "unplaced" any more
        fc.updated_at = _utcnow()
        _record_event(fc, 'scheduled_once', actor_user_id=uid,
                      notes=f'Scheduled for {scheduled_at.strftime("%Y-%m-%d %H:%M")} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=_fu_row_one(fc))

    elif action == 'set-recurring':
        if fc.state in ('blocked', 'closed'):
            return jsonify(error='Cannot set recurring for blocked or closed contact'), 400
        if fc.rung == 'excluded':
            return jsonify(error=_EXCLUDED_MSG), 400
        if fc.exit_reason == 'refused':      # a date would email someone who asked us to stop
            return jsonify(error=_REFUSED_MSG), 400
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
        fc.scheduled_once    = False
        fc.is_followup_enabled = False       # the owner took control of the schedule
        fc.next_followup_at  = _next_recurring_datetime(r_days, r_time)
        fc.updated_at = _utcnow()
        _record_event(fc, 'recurring_set', actor_user_id=uid,
                      notes=f'Recurring days={r_days} time={r_time} UTC')
        db.session.commit()
        return jsonify(ok=True, contact=_fu_row_one(fc))

    elif action == 'stop-recurring':
        fc.recurring_enabled = False
        fc.recurring_days = None
        fc.recurring_time = None
        _restore_contact_schedule(fc)
        _record_event(fc, 'recurring_stopped', actor_user_id=uid)
        db.session.commit()
        return jsonify(ok=True, contact=_fu_row_one(fc))

    elif action == 'cancel-schedule':
        fc.scheduled_once = False
        _restore_contact_schedule(fc)
        _record_event(fc, 'schedule_cancelled', actor_user_id=uid)
        db.session.commit()
        return jsonify(ok=True, contact=_fu_row_one(fc))

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
        if ok:
            _add_to_stop_list(uid, fc.contact_email, reason='blocked from Follow-up')
    elif action == 'close':
        ok, err = _transition_state(fc, 'closed', reason=reason, actor_user_id=uid)
    elif action == 'restart-fu1':
        was_blocked = fc.state == 'blocked'
        ok, err = _restart_contact_from_fu1(fc, actor_user_id=uid)
        if ok and was_blocked:
            _remove_from_stop_list(uid, fc.contact_email)
    elif action == 'set-pipeline-stage':
        ok, err = _apply_pipeline_stage(fc, data.get('pipeline_stage'),
                                        actor_user_id=uid, reason=reason or 'manual')
    elif action in _LADDER_MANUAL_ACTIONS or action in _LADDER_SINGLE_ACTIONS:
        ok, err, info = _ladder_manual_action(fc, action, data, uid)
        if not ok:
            return jsonify(error=err), 400
        db.session.commit()
        return jsonify(ok=True, contact=_fu_row_one(fc), **info)
    else:
        return jsonify(error=f'Unknown action: {action}'), 400

    if not ok:
        return jsonify(error=err), 400
    db.session.commit()
    return jsonify(ok=True, contact=_fu_row_one(fc))


@app.route('/api/followups/bulk-action', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf_protected
def api_followups_bulk_action():
    from app.models import FollowupContact, EmailAccount
    uid = _current_user_id()
    data = request.get_json()
    ids = data.get('ids', [])
    action = data.get('action')
    reason = data.get('reason', '')

    if action in _LADDER_SINGLE_ACTIONS:
        return jsonify(error=f'{action} works on one contact at a time'), 400
    if action == 'set-rung':
        _, rung_err = _ladder_parse_rung(data.get('rung'))
        if rung_err:
            return jsonify(error=rung_err), 400

    results = []
    for cid in ids:
        fc = db.session.get(FollowupContact, cid)
        if not fc or fc.user_id != uid:
            results.append({'id': cid, 'ok': False, 'error': 'Not found'})
            continue

        if action in ('pause', 'resume', 'warm', 'loads', 'block', 'close'):
            target = 'active' if action == 'resume' else ('blocked' if action == 'block' else action)
            ok, err = _transition_state(fc, target, reason=reason, actor_user_id=uid)
            if ok and target == 'blocked':
                _add_to_stop_list(uid, fc.contact_email, reason='blocked from Follow-up')
            results.append({'id': cid, 'ok': ok, 'error': err})

        elif action == 'restart-fu1':
            was_blocked = fc.state == 'blocked'
            ok, err = _restart_contact_from_fu1(fc, actor_user_id=uid)
            if ok and was_blocked:
                _remove_from_stop_list(uid, fc.contact_email)
            results.append({'id': cid, 'ok': ok, 'error': err})

        elif action in ('send-now', 'free-send'):
            # Same core as the single action, so the same guards and bookkeeping
            status, detail = _followup_send_now_core(
                fc, uid, kind='one_off' if action == 'free-send' else 'touch')
            if status == 'sent':
                results.append({'id': cid, 'ok': True})
            elif status == 'duplicate':
                results.append({'id': cid, 'ok': False, 'skip': True, 'duplicate': True, 'error': detail})
            elif status == 'skip':
                results.append({'id': cid, 'ok': False, 'skip': True, 'error': detail})
            else:
                results.append({'id': cid, 'ok': False, 'error': detail})

        elif action == 'schedule-once':
            if fc.state in ('blocked', 'closed'):
                results.append({'id': cid, 'ok': False, 'error': 'Blocked or closed'})
                continue
            if fc.rung == 'excluded':
                results.append({'id': cid, 'ok': False, 'error': _EXCLUDED_MSG})
                continue
            if fc.exit_reason == 'refused':
                results.append({'id': cid, 'ok': False, 'error': _REFUSED_MSG})
                continue
            dt_str = data.get('scheduled_at', '')
            try:
                scheduled_at = datetime.fromisoformat(dt_str.replace('Z', '+00:00')).replace(tzinfo=None)
                if scheduled_at < _utcnow() + timedelta(minutes=1):
                    results.append({'id': cid, 'ok': False, 'error': 'Date must be in future'})
                    continue
            except (ValueError, TypeError):
                results.append({'id': cid, 'ok': False, 'error': 'Invalid date format'})
                continue
            fc.next_followup_at = scheduled_at
            fc.scheduled_once = True
            fc.is_followup_enabled = False
            fc.updated_at = _utcnow()
            _record_event(fc, 'scheduled_once', actor_user_id=uid,
                          notes=f'Scheduled {scheduled_at.strftime("%Y-%m-%d %H:%M")} UTC')
            results.append({'id': cid, 'ok': True})

        elif action == 'set-recurring':
            if fc.state in ('blocked', 'closed'):
                results.append({'id': cid, 'ok': False, 'error': 'Blocked or closed'})
                continue
            if fc.rung == 'excluded':
                results.append({'id': cid, 'ok': False, 'error': _EXCLUDED_MSG})
                continue
            if fc.exit_reason == 'refused':
                results.append({'id': cid, 'ok': False, 'error': _REFUSED_MSG})
                continue
            r_days = (data.get('recurring_days') or '').strip()
            r_time = (data.get('recurring_time') or '').strip()
            try:
                fc.recurring_enabled = True
                fc.recurring_days    = r_days
                fc.recurring_time    = r_time
                fc.scheduled_once    = False
                fc.is_followup_enabled = False
                fc.next_followup_at  = _next_recurring_datetime(r_days, r_time)
                fc.updated_at = _utcnow()
                _record_event(fc, 'recurring_set', actor_user_id=uid,
                              notes=f'Recurring days={r_days} time={r_time} UTC')
                results.append({'id': cid, 'ok': True})
            except ValueError as e:
                results.append({'id': cid, 'ok': False, 'error': str(e)})

        elif action == 'set-pipeline-stage':
            ok, err = _apply_pipeline_stage(fc, data.get('pipeline_stage'),
                                            actor_user_id=uid, reason=reason or 'manual')
            results.append({'id': cid, 'ok': ok, 'error': err})

        elif action in _LADDER_MANUAL_ACTIONS:
            ok, err, info = _ladder_manual_action(fc, action, data, uid)
            results.append({'id': cid, 'ok': ok, 'error': err, **info})

        elif action == 'stop-recurring':
            fc.recurring_enabled = False
            fc.recurring_days = None
            fc.recurring_time = None
            _restore_contact_schedule(fc)
            _record_event(fc, 'recurring_stopped', actor_user_id=uid)
            results.append({'id': cid, 'ok': True})

        elif action == 'cancel-schedule':
            fc.scheduled_once = False
            _restore_contact_schedule(fc)
            _record_event(fc, 'schedule_cancelled', actor_user_id=uid)
            results.append({'id': cid, 'ok': True})

        else:
            results.append({'id': cid, 'ok': False, 'error': f'Unknown action: {action}'})

    db.session.commit()
    ok_count     = sum(1 for r in results if r.get('ok'))
    skip_count   = sum(1 for r in results if not r.get('ok') and r.get('skip'))
    failed_count = sum(1 for r in results if not r.get('ok') and not r.get('skip'))
    return jsonify(results=results, sent=ok_count, skipped=skip_count, failed=failed_count)


# ── BULK FOLLOW-UP SEND (background job, SendJob kind='followup_bulk') ────────
# Mirrors the outreach run_send_job pattern: one HTTP request creates the job,
# a daemon thread does the sends server-side (no 60/min action-route limit, no
# open-tab requirement), progress lives in memory + DB, the UI polls status.
# Single gunicorn worker (see Procfile) keeps the in-memory state coherent.

_fu_bulk_states = {}

def _user_fu_bulk_state(uid):
    return _fu_bulk_states.setdefault(uid, {})

FU_BULK_LOG_CAP = 300   # keep the per-contact problem list bounded

def run_followup_bulk_job(job_id, ids, uid):
    """Send scheduled follow-ups for the given contact ids in a worker thread."""
    state = _user_fu_bulk_state(uid)
    state.update({'running': True, 'done': False, 'job_id': job_id,
                  'total': len(ids), 'current': 0,
                  'sent': 0, 'skipped': 0, 'failed': 0, 'failures': []})
    with app.app_context():
        from app.models import SendJob, FollowupContact
        try:
            job = db.session.get(SendJob, job_id)
            if not job:
                state.update({'running': False, 'done': True})
                return
            job.status = 'running'
            job.started_at = _utcnow()
            db.session.commit()

            for i, cid in enumerate(ids):
                state['current'] = i + 1
                fc = db.session.get(FollowupContact, cid)
                if not fc or fc.user_id != uid:
                    state['skipped'] += 1
                    _fu_bulk_note(state, cid, '(unknown)', 'skipped', 'Not found')
                else:
                    try:
                        status, detail = _followup_send_now_core(fc, uid)
                    except Exception as e:
                        db.session.rollback()
                        app.logger.error('bulk follow-up send crashed on %s: %s', cid, e)
                        status, detail = 'error', str(e)
                    if status == 'sent':
                        state['sent'] += 1
                    elif status in ('skip', 'duplicate'):
                        state['skipped'] += 1
                        _fu_bulk_note(state, cid, fc.contact_email, 'skipped', detail)
                    else:
                        state['failed'] += 1
                        _fu_bulk_note(state, cid, fc.contact_email, 'failed', detail)
                if (i + 1) % 10 == 0:
                    _fu_bulk_persist(job, state, final=False)

            _fu_bulk_persist(job, state, final=True)
            state.update({'running': False, 'done': True})
            audit_log('followup_bulk_send', resource_type='followup', uid=uid, detail={
                'total': state['total'], 'sent': state['sent'],
                'skipped': state['skipped'], 'failed': state['failed'],
            })
        except Exception as job_err:
            import traceback as _tb
            app.logger.error('run_followup_bulk_job crashed uid=%s job=%s: %s\n%s',
                             uid, job_id, job_err, _tb.format_exc())
            state.update({'running': False, 'done': True})
            try:
                db.session.rollback()
                j = db.session.get(SendJob, job_id)
                if j and j.status != 'done':
                    j.status = 'error'
                    j.error_msg = f'Bulk follow-up job crashed: {job_err}'[:480]
                    j.finished_at = _utcnow()
                    db.session.commit()
            except Exception:
                db.session.rollback()

def _fu_bulk_note(state, cid, email, kind, reason):
    if len(state['failures']) < FU_BULK_LOG_CAP:
        state['failures'].append({'id': cid, 'email': email, 'kind': kind,
                                  'reason': (reason or '')[:300]})

def _fu_bulk_persist(job, state, final):
    try:
        job.sent = state['sent']
        job.errors = state['failed']
        job.skipped = state['skipped']
        job.log_json = json.dumps(state['failures'])
        if final:
            job.status = 'done'
            job.finished_at = _utcnow()
        db.session.commit()
    except Exception as pe:
        app.logger.warning('followup bulk job progress update failed: %s', pe)
        db.session.rollback()


@app.route('/api/followups/bulk-send', methods=['POST'])
@login_required
@limiter.limit("5 per minute")   # one job at a time; guards runaway loops
@csrf_protected
def api_followups_bulk_send():
    from app.models import SendJob
    uid = _current_user_id()
    ids = [str(i) for i in ((request.get_json() or {}).get('ids') or []) if i]
    if not ids:
        return jsonify(error='No contacts selected'), 400

    # Auto-recover jobs stranded by a server restart/crash (mirrors api_send)
    stale_cutoff = _utcnow() - timedelta(minutes=60)
    stale = SendJob.query.filter(
        SendJob.user_id == uid,
        SendJob.kind == 'followup_bulk',
        SendJob.status.in_(['queued', 'running']),
        db.or_(SendJob.started_at < stale_cutoff, SendJob.started_at == None)
    ).all()
    for s in stale:
        s.status = 'error'
        s.error_msg = 'Stale job auto-recovered after server restart'
        s.finished_at = _utcnow()
    if stale:
        db.session.commit()

    active = SendJob.query.filter(
        SendJob.user_id == uid,
        SendJob.kind == 'followup_bulk',
        SendJob.status.in_(['queued', 'running'])
    ).first()
    if active:
        return jsonify(error='Bulk send already running', job_id=active.id), 409

    job = SendJob(user_id=uid, kind='followup_bulk', status='queued', total=len(ids))
    db.session.add(job)
    db.session.commit()
    t = threading.Thread(target=run_followup_bulk_job, args=(job.id, ids, uid),
                         daemon=True, name='fu-bulk-send')
    t.start()
    return jsonify(ok=True, job_id=job.id, total=len(ids))


@app.route('/api/followups/bulk-send/status')
@login_required
@limiter.limit("120 per minute")
def api_followups_bulk_send_status():
    from app.models import SendJob
    uid = _current_user_id()
    job = SendJob.query.filter_by(user_id=uid, kind='followup_bulk') \
                       .order_by(SendJob.started_at.desc()).first()
    if not job:
        return jsonify(exists=False, running=False, done=False)

    state = _user_fu_bulk_state(uid)
    if state.get('job_id') == job.id and state.get('running'):
        return jsonify(exists=True, job_id=job.id, running=True, done=False,
                       total=state['total'], current=state['current'],
                       sent=state['sent'], skipped=state['skipped'],
                       failed=state['failed'], failures=state['failures'])

    try:
        failures = json.loads(job.log_json) if job.log_json else []
    except ValueError:
        failures = []
    return jsonify(exists=True, job_id=job.id,
                   running=job.status in ('queued', 'running'),
                   done=job.status == 'done',
                   error=job.error_msg,
                   total=job.total, current=job.sent + job.errors + job.skipped,
                   sent=job.sent, skipped=job.skipped, failed=job.errors,
                   failures=failures)


# ── PIPELINE / KANBAN (shared data with the Follow-up table) ──────────────────

@app.route('/api/followups/pipeline-config')
@login_required
def api_followups_pipeline_config():
    """Stages + reply filters for the Kanban view, plus the user's saved view mode."""
    from app.models import (Workspace, User as _U,
                            PIPELINE_DEFAULT_STAGES, PIPELINE_DEFAULT_REPLY_FILTERS,
                            PIPELINE_DEFAULT_FILTER_KEYWORDS, TRIAGE_DEFAULT_MODES)
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    user = db.session.get(_U, uid)
    stages = ws.get_stages() if ws else [dict(s) for s in PIPELINE_DEFAULT_STAGES]
    filters = ws.get_reply_filters() if ws else [dict(f) for f in PIPELINE_DEFAULT_REPLY_FILTERS]
    keywords = ws.get_filter_keywords() if ws else {k: dict(v) for k, v in PIPELINE_DEFAULT_FILTER_KEYWORDS.items()}
    modes = ws.get_triage_modes() if ws else dict(TRIAGE_DEFAULT_MODES)
    _cfg = (ws.pipeline_config or {}) if ws else {}
    return jsonify(stages=stages, reply_filters=filters, filter_keywords=keywords,
                   triage_modes=modes,
                   touch_hour=_cfg.get('touch_hour', 'auto'),
                   digest_enabled=bool(_cfg.get('digest_enabled', True)),
                   drip_auto_enabled=bool(ws.fu_auto_enabled) if ws else False,
                   auto_send_enabled=bool(((ws.pipeline_config or {}) if ws else {}).get('auto_send_enabled', True)),
                   auto_send_preview=_auto_send_preview(ws),
                   ladder=_ladder_cfg(ws),
                   ladder_auto_enabled=bool(ws and ws.ladder_auto_enabled),
                   **_ladder_preview_fields(ws),
                   timezone=_cfg.get('timezone') or '',
                   view_mode=(user.followup_view_mode or 'table') if user else 'table')


@app.route('/api/followups/pipeline-stats')
@login_required
def api_followups_pipeline_stats():
    """Counts per Kanban stage + transition counts (from pipeline_move events)."""
    from app.models import FollowupContact, FollowupEvent, Workspace, PIPELINE_DEFAULT_STAGES
    from sqlalchemy import func
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    stages = ws.get_stages() if ws else [dict(s) for s in PIPELINE_DEFAULT_STAGES]

    by_stage = {s['id']: 0 for s in stages}
    total = 0
    rows = db.session.query(FollowupContact.pipeline_stage, func.count(FollowupContact.id))\
        .filter(FollowupContact.user_id == uid)\
        .group_by(FollowupContact.pipeline_stage).all()
    for stage_id, cnt in rows:
        sid = stage_id or 1
        by_stage[sid] = by_stage.get(sid, 0) + cnt
        total += cnt

    transitions = {}
    ev_rows = db.session.query(FollowupEvent.from_stage, FollowupEvent.to_stage, func.count(FollowupEvent.id))\
        .join(FollowupContact, FollowupContact.id == FollowupEvent.followup_contact_id)\
        .filter(FollowupContact.user_id == uid, FollowupEvent.event_type == 'pipeline_move')\
        .group_by(FollowupEvent.from_stage, FollowupEvent.to_stage).all()
    for frm, to, cnt in ev_rows:
        if frm and to:
            transitions[f'{frm}_to_{to}'] = cnt

    return jsonify(total=total, by_stage=by_stage, transitions=transitions)


@app.route('/api/user/preferences', methods=['POST'])
@login_required
@csrf_protected
def api_user_preferences():
    """Persist per-user UI preferences (currently the Follow-up view mode)."""
    from app.models import User as _U
    uid = _current_user_id()
    user = db.session.get(_U, uid)
    if not user:
        return jsonify(error='Not found'), 404
    data = request.get_json() or {}
    mode = data.get('followup_view_mode')
    if mode in ('table', 'kanban'):
        user.followup_view_mode = mode
        db.session.commit()
    return jsonify(ok=True, followup_view_mode=user.followup_view_mode or 'table')


@app.route('/api/followups/pipeline-config', methods=['PUT'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
def api_followups_pipeline_config_save():
    """Persist customized Kanban stages + reply filters for the workspace.

    Stage ids are preserved across edits; new stages get fresh ids. Removing a
    stage reassigns any contacts sitting in it to the first stage so nothing is
    orphaned.
    """
    from app.models import (FollowupContact, Workspace, PIPELINE_DEFAULT_REPLY_FILTERS,
                            PIPELINE_DEFAULT_FILTER_KEYWORDS, PIPELINE_BUILTIN_FILTER_KEYS,
                            TRIAGE_CATEGORIES, TRIAGE_MODES, TRIAGE_DEFAULT_MODES)
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    if not ws:
        return jsonify(error='No workspace'), 400
    data = request.get_json() or {}
    cfg = dict(ws.pipeline_config or {})

    stages = data.get('stages')
    norm_stages = None
    if stages is not None:
        if not isinstance(stages, list) or len(stages) < 2:
            return jsonify(error='At least 2 stages required'), 400
        old_ids = {s['id'] for s in ws.get_stages()}
        max_id = max(old_ids) if old_ids else 0
        norm_stages, used = [], set()
        for s in stages:
            name = (s.get('name') or '').strip()
            if not name:
                return jsonify(error='Every stage needs a name'), 400
            try:
                sid = int(s.get('id'))
            except (TypeError, ValueError):
                sid = None
            if not sid or sid in used:
                max_id += 1
                sid = max_id
            used.add(sid)
            color = (s.get('color') or '#888888').strip()[:9]
            norm_stages.append({'id': sid, 'name': name[:60], 'color': color})
        # reassign contacts whose stage was removed
        removed = old_ids - used
        if removed:
            first_id = norm_stages[0]['id']
            FollowupContact.query.filter(
                FollowupContact.user_id == uid,
                FollowupContact.pipeline_stage.in_(list(removed))
            ).update({'pipeline_stage': first_id}, synchronize_session=False)
        cfg['stages'] = norm_stages

    filters = data.get('reply_filters')
    if filters is not None:
        valid_ids = {s['id'] for s in (norm_stages or ws.get_stages())}
        existing_kw = ws.get_filter_keywords()
        norm_filters, norm_kw, used_keys = [], {}, set()
        for i, f in enumerate(filters if isinstance(filters, list) else []):
            label = (f.get('label') or '').strip()
            if not label:
                continue
            # Always slug the key (even client-supplied ones) so it stays a safe
            # [a-z0-9_] token — built-in keys are already slugs (idempotent). This
            # prevents the key from breaking out of single-quoted onclick handlers.
            key = _slug((f.get('key') or '').strip() or label)
            while key in used_keys:
                key = key + '_x'
            used_keys.add(key)
            adv = f.get('auto_advance_to')
            try:
                adv = int(adv)
            except (TypeError, ValueError):
                adv = None
            if adv is not None and adv not in valid_ids:
                adv = None
            key = key[:50]
            norm_filters.append({
                'key': key, 'label': label[:120], 'auto_advance_to': adv,
                'color': _norm_hex_color(f.get('color')),
                'emoji': (f.get('emoji') or '').strip()[:8],
                'is_custom': key not in PIPELINE_BUILTIN_FILTER_KEYS,   # authoritative by key
                'order': i + 1,
                'category': f.get('category') if f.get('category') in TRIAGE_CATEGORIES else None,
            })
            # keywords travel with each filter so brand-new (server-keyed) filters keep theirs
            words = [str(w).strip().lower() for w in (f.get('keywords') or []) if str(w).strip()][:50]
            try:
                conf = float(f.get('confidence', (existing_kw.get(key) or {}).get('confidence', 0.8)))
            except (TypeError, ValueError):
                conf = 0.8
            norm_kw[key] = {'keywords': words, 'confidence': min(1.0, max(0.0, conf))}
        # built-in filters can't be deleted — re-add any the client omitted (with their defaults)
        present = {f['key'] for f in norm_filters}
        for d in PIPELINE_DEFAULT_REPLY_FILTERS:
            if d['key'] not in present:
                nf = dict(d); nf['order'] = len(norm_filters) + 1
                if nf.get('auto_advance_to') not in valid_ids:   # stage may have been removed
                    nf['auto_advance_to'] = None
                norm_filters.append(nf)
                norm_kw.setdefault(d['key'], dict(PIPELINE_DEFAULT_FILTER_KEYWORDS.get(
                    d['key'], {'keywords': [], 'confidence': 0.8})))
        cfg['reply_filters'] = norm_filters
        cfg['filter_keywords'] = norm_kw

    modes = data.get('triage_modes')
    if isinstance(modes, dict):
        merged = dict(cfg.get('triage_modes') or {})
        for k, v in modes.items():
            if k in TRIAGE_DEFAULT_MODES and v in TRIAGE_MODES:
                merged[k] = v
        cfg['triage_modes'] = merged

    # (the per-Kanban-stage `cadence` is retired with the stage drip: a value sent is ignored,
    # and a stored one is left in place, unread)

    th = data.get('touch_hour')
    if th is not None:
        if th == 'auto':
            cfg['touch_hour'] = 'auto'
        else:
            try:
                cfg['touch_hour'] = max(0, min(23, int(th)))
            except (TypeError, ValueError):
                pass
    tz_new = data.get('timezone')
    if isinstance(tz_new, str) and (tz_new == '' or _valid_tz(tz_new)) \
            and tz_new != (cfg.get('timezone') or ''):
        # A fixed touch hour is stored as a local hour: re-express it in the new
        # zone so touches keep going out at the same moment.
        th_cur = cfg.get('touch_hour', 'auto')
        if th_cur != 'auto' and data.get('touch_hour') is None:
            try:
                old_tz, new_tz = _ws_tz(ws), _tz_named(tz_new)
                moment = datetime.now(old_tz).replace(hour=int(th_cur), minute=0, second=0, microsecond=0)
                cfg['touch_hour'] = moment.astimezone(new_tz).hour
            except (TypeError, ValueError):
                pass
        cfg['timezone'] = tz_new
        _cache_del(f'stats:{uid}:today', f'stats:{uid}:week', f'stats:{uid}:lifetime',
                   f'ai_impact:{uid}', f'sent_log:{uid}')
    if isinstance(data.get('digest_enabled'), bool):
        cfg['digest_enabled'] = data['digest_enabled']
    if isinstance(data.get('drip_auto_enabled'), bool):
        ws.fu_auto_enabled = data['drip_auto_enabled']   # scheduler drip kill switch
    if isinstance(data.get('auto_send_enabled'), bool):
        cfg['auto_send_enabled'] = data['auto_send_enabled']   # master switch, all auto paths
    if isinstance(data.get('ladder_auto_enabled'), bool):
        # the warmth ladder's own consent flag (default off). Saving it only sets the flag:
        # no date moves and nothing is sent here, the scheduler decides at its next tick
        ws.ladder_auto_enabled = data['ladder_auto_enabled']
    if isinstance(data.get('ladder'), dict):
        # cadence and patience numbers, clamped; later reads re-validate (_ladder_cfg), and
        # existing dates are left alone: the new numbers date the next touch that is set
        cfg['ladder'] = {**_ladder_clean(cfg.get('ladder')), **_ladder_clean(data['ladder'])}

    ws.pipeline_config = cfg   # reassign so SQLAlchemy detects the JSON change
    db.session.commit()

    return jsonify(ok=True, stages=ws.get_stages(),
                   reply_filters=ws.get_reply_filters(),
                   filter_keywords=ws.get_filter_keywords(),
                   triage_modes=ws.get_triage_modes(),
                   touch_hour=(ws.pipeline_config or {}).get('touch_hour', 'auto'),
                   digest_enabled=bool((ws.pipeline_config or {}).get('digest_enabled', True)),
                   drip_auto_enabled=bool(ws.fu_auto_enabled),
                   auto_send_enabled=bool((ws.pipeline_config or {}).get('auto_send_enabled', True)),
                   auto_send_preview=_auto_send_preview(ws),
                   ladder=_ladder_cfg(ws),
                   ladder_auto_enabled=bool(ws.ladder_auto_enabled),
                   **_ladder_preview_fields(ws),
                   timezone=(ws.pipeline_config or {}).get('timezone') or '')


@app.route('/api/replies/pipeline-tag', methods=['POST'])
@login_required
@limiter.limit("120 per minute")
@csrf_protected
def api_reply_pipeline_tag():
    """Tag a reply with a pipeline reply-filter and (optionally) auto-advance the
    matching follow-up contact forward to the filter's configured stage."""
    from app.models import Reply, Workspace
    uid = _current_user_id()
    data = request.get_json() or {}
    msg_id = data.get('msg_id')
    key = (data.get('filter_key') or '').strip()
    if not msg_id:
        return jsonify(error='msg_id required'), 400
    reply = Reply.query.filter_by(msg_id=msg_id, user_id=uid).first()
    if not reply:
        return jsonify(error='Reply not found'), 404

    ws = Workspace.query.filter_by(owner_id=uid).first()
    filters = ws.get_reply_filters() if ws else []
    fcfg = next((f for f in filters if f['key'] == key), None) if key else None
    if key and not fcfg:
        return jsonify(error='Unknown filter'), 400

    reply.reply_filter_key = key or None
    advanced, new_stage, stage_name = False, None, None
    if fcfg and fcfg.get('auto_advance_to') and ws:
        target = int(fcfg['auto_advance_to'])
        fc = _fc_by_email(ws.id, reply.from_email)
        if fc and target > (fc.pipeline_stage or 1):   # forward-only
            ok, _err = _apply_pipeline_stage(fc, target, actor_user_id=uid, reason=f'reply_tag:{key}')
            if ok:
                advanced, new_stage = True, target
                reply.auto_advanced = True
                stage_name = next((s['name'] for s in ws.get_stages() if s['id'] == target), None)
    db.session.commit()
    return jsonify(ok=True, filter_key=reply.reply_filter_key or '',
                   advanced=advanced, pipeline_stage=new_stage, stage_name=stage_name)


@app.route('/api/replies/bulk-triage', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf_protected
def api_replies_bulk_triage():
    """Bulk-resolve triaged replies. Shapes:
    {category, action:'ignore'}    — ignore every unprocessed reply in a category
    {category, action:'followup'}  — follow-up + pipeline contact + stage advance
    {msg_ids, action:'restore'}    — undo path: restore an explicit list to 'new'
    Returns affected msg_ids so the client can offer Undo."""
    from app.models import Reply, Workspace, TRIAGE_CATEGORIES
    uid = _current_user_id()
    data = request.get_json() or {}
    action = (data.get('action') or '').strip()
    if action not in ('ignore', 'followup', 'restore'):
        return jsonify(error="action must be 'ignore', 'followup' or 'restore'"), 400
    msg_ids = data.get('msg_ids')
    category = (data.get('category') or '').strip()

    q = Reply.query.filter(Reply.user_id == uid)
    if isinstance(msg_ids, list) and msg_ids:
        q = q.filter(Reply.msg_id.in_([str(m) for m in msg_ids][:500]))
    elif category:
        if category not in TRIAGE_CATEGORIES:
            return jsonify(error='Unknown category'), 400
        q = q.filter(Reply.status.in_(['new', 'viewed']),
                     Reply.triage_category == category)
    else:
        return jsonify(error='category or msg_ids required'), 400

    ws = Workspace.query.filter_by(owner_id=uid).first()
    fcfg_by_key = {f.get('key'): f for f in (ws.get_reply_filters() if ws else [])}
    # A reply may lack a filter key (e.g. structural detection while in suggest
    # mode) — fall back to its category's built-in filter for the stage target.
    _cat_default_key = {'gave_info': 'gave_info', 'rate_request': 'rate_request'}

    affected = []
    for r in q.all():
        if action == 'ignore':
            r.status = 'not_interested'
            _sync_crm_stage(r, 'lost')
        elif action == 'followup':
            r.status = 'follow_up'
            if not r.reply_filter_key:
                r.reply_filter_key = _cat_default_key.get(r.triage_category)
            try:
                add_to_followups(r)
            except Exception:
                db.session.rollback()
                continue
            _sync_crm_stage(r, 'interested')
            fcfg = fcfg_by_key.get(r.reply_filter_key) or {}
            target = fcfg.get('auto_advance_to')
            fc = _fc_by_email(ws.id, r.from_email) if (ws and target) else None
            if fc and int(target) > (fc.pipeline_stage or 1):   # forward-only
                _apply_pipeline_stage(fc, target, actor_user_id=uid, reason='bulk_triage')
        else:
            r.status = 'new'
            r.auto_processed = False
            r.auto_action = None
            _sync_crm_stage(r, 'replied')
        affected.append(r.msg_id)
    db.session.commit()
    audit_log('bulk_triage', resource_type='reply',
              detail={'action': action, 'category': category or None, 'count': len(affected)})
    return jsonify(ok=True, count=len(affected), msg_ids=affected)


@app.route('/api/replies/auto-processed', methods=['GET'])
@login_required
def api_replies_auto_processed():
    """Recent auto-triaged replies (last 7 days) for the Undo strip."""
    from app.models import Reply
    uid = _current_user_id()
    since = _utcnow() - timedelta(days=7)
    rows = Reply.query.filter(
        Reply.user_id == uid,
        Reply.auto_processed.is_(True),
        Reply.received_at >= since,
    ).order_by(Reply.received_at.desc()).limit(100).all()
    return jsonify(count=len(rows), items=[{
        'msg_id': r.msg_id, 'email': r.from_email, 'from': r.from_name,
        'subject': r.subject or '', 'category': r.triage_category or '',
        'action': r.auto_action or '', 'filter_key': r.reply_filter_key or '',
        'received_at': r.received_at.strftime('%Y-%m-%d %H:%M') if r.received_at else '',
    } for r in rows])


@app.route('/api/replies/undo-auto', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
@csrf_protected
def api_replies_undo_auto():
    """Undo a single auto-triage action: reply returns to 'new'; if the action
    auto-created the pipeline contact from this very reply and no follow-up was
    sent since, the contact is removed too (pre-existing contacts are left as-is)."""
    from app.models import Reply, Workspace
    uid = _current_user_id()
    data = request.get_json() or {}
    msg_id = data.get('msg_id')
    if not msg_id:
        return jsonify(error='msg_id required'), 400
    reply = Reply.query.filter_by(msg_id=msg_id, user_id=uid).first()
    if not reply:
        return jsonify(error='Reply not found'), 404
    if not reply.auto_processed:
        return jsonify(error='Reply was not auto-processed'), 400

    contact_removed = False
    if reply.auto_action == 'followup':
        ws = Workspace.query.filter_by(owner_id=uid).first()
        if ws:
            fc = _fc_by_email(ws.id, reply.from_email)
            if fc and fc.source_reply_id == reply.id and not fc.last_followup_sent_at:
                db.session.delete(fc)   # FollowupEvent rows cascade via relationship
                contact_removed = True

    reply.status = 'new'
    reply.auto_processed = False
    reply.auto_action = None
    reply.auto_advanced = False
    _sync_crm_stage(reply, 'replied')
    db.session.commit()
    return jsonify(ok=True, contact_removed=contact_removed)


def _dashboard_data(uid):
    """All main-page dashboard blocks: today's actions, funnel, base health,
    14-day activity, top lanes. Shared by the API and the weekly digest."""
    from app.models import Reply, Send, FollowupContact, FollowupEvent, Workspace
    from sqlalchemy import func, case, distinct
    now = _utcnow()
    tz = _user_tz(uid)
    sod = _local_day_start(tz, 0, now)
    eod = _local_day_start(tz, -1, now) - timedelta(microseconds=1)

    # Today's actions
    fc_active = FollowupContact.query.filter(FollowupContact.user_id == uid,
                                             FollowupContact.state == 'active')
    due_q = fc_active.filter(FollowupContact.next_followup_at <= eod)
    due_today = due_q.count()
    done_today = fc_active.filter(FollowupContact.last_followup_sent_at >= sod).count()
    nxt = due_q.order_by(FollowupContact.next_followup_at.asc()).first()
    attention = fc_active.filter(FollowupContact.attention_at.isnot(None)).count()

    pending_rows = db.session.query(Reply.triage_category, func.count()).filter(
        Reply.user_id == uid, Reply.status.in_(['new', 'viewed'])
    ).group_by(Reply.triage_category).all()
    replies_pending = {'total': sum(n for _, n in pending_rows),
                       'by_category': {(c or 'other'): n for c, n in pending_rows}}

    # Funnel per window: sends + distinct repliers from data; stage advances from the event log
    def _funnel(cutoff):
        """Funnel since `cutoff` (None = all time) — same local-day windows as /api/stats."""
        since = lambda col: [col >= cutoff] if cutoff is not None else []
        sent = Send.query.filter(Send.user_id == uid, Send.status == 'sent',
                                 *since(Send.sent_at)).count()
        replied = db.session.query(func.count(distinct(func.lower(Reply.from_email)))).filter(
            Reply.user_id == uid, *since(Reply.received_at)).scalar() or 0
        def moved(stage_id):
            return db.session.query(func.count(distinct(FollowupEvent.followup_contact_id))).join(
                FollowupContact, FollowupEvent.followup_contact_id == FollowupContact.id
            ).filter(FollowupContact.user_id == uid,
                     FollowupEvent.event_type == 'pipeline_move',
                     FollowupEvent.to_stage == str(stage_id),
                     *since(FollowupEvent.event_at)).scalar() or 0
        return {'sent': sent, 'replied': replied, 'got_info': moved(2),
                'repeat': moved(3), 'booked': moved(5)}

    # Base health
    no_next = fc_active.filter(FollowupContact.next_followup_at.is_(None),
                               FollowupContact.scheduled_once == False).count()
    rot_cut = now - timedelta(days=14)
    rotting = fc_active.filter(FollowupContact.pipeline_stage >= 2,
                               db.or_(FollowupContact.last_activity_at < rot_cut,
                                      FollowupContact.last_activity_at.is_(None))).count()
    f30 = _funnel(_local_day_start(tz, 29, now))
    contacted30, replied30 = _reply_cohort(uid, now - timedelta(days=30))
    reply_rate = _reply_rate(contacted30, replied30)

    booked_ids = [r[0] for r in db.session.query(distinct(FollowupEvent.followup_contact_id)).join(
        FollowupContact, FollowupEvent.followup_contact_id == FollowupContact.id
    ).filter(FollowupContact.user_id == uid, FollowupEvent.event_type == 'pipeline_move',
             FollowupEvent.to_stage == '5').all()]
    avg_touches = None
    if booked_ids:
        touches = db.session.query(func.count()).filter(
            FollowupEvent.followup_contact_id.in_(booked_ids),
            FollowupEvent.event_type.in_(['manual_send', 'free_send', 'touch_sent',
                                          'recurring_sent', 'scheduled_once_sent'])).scalar() or 0
        avg_touches = round(touches / len(booked_ids), 1)

    # 14-day activity
    cut14 = _local_day_start(tz, 13, now)
    s_rows = Counter(_local_date(t, tz) for (t,) in db.session.query(Send.sent_at).filter(
        Send.user_id == uid, Send.status == 'sent', Send.sent_at >= cut14))
    r_rows = Counter(_local_date(t, tz) for (t,) in db.session.query(Reply.received_at).filter(
        Reply.user_id == uid, Reply.received_at >= cut14))
    activity = []
    first = _local_date(cut14, tz)
    for i in range(14):
        d = first + timedelta(days=i)
        activity.append({'day': d.strftime('%b %d'), 'sends': s_rows.get(d, 0), 'replies': r_rows.get(d, 0)})

    # Top lanes by carrier replies (30d), enriched with gave-info counts
    cutoff30 = now - timedelta(days=30)
    lane_rows = db.session.query(
        Reply.route, func.count(),
        func.count(case((Reply.triage_category.in_(['gave_info', 'rate_request']), 1))),
    ).filter(Reply.user_id == uid, Reply.received_at >= cutoff30,
             Reply.route.isnot(None), Reply.route != ''
    ).group_by(Reply.route).order_by(func.count().desc()).limit(5).all()
    top_lanes = [{'lane': l, 'replies': n, 'gave_info': g} for l, n, g in lane_rows]

    return dict(
        touches={'due_today': due_today, 'done_today': done_today,
                 'next': ({'name': nxt.display_name,
                           'route': nxt.current_route or ''} if nxt else None)},
        attention=attention,
        replies_pending=replies_pending,
        # keyed like the Insights period switch: today / 7 / 30 days / all time
        funnel={'today': _funnel(sod), '7': _funnel(_local_day_start(tz, 6, now)), '30': f30, 'all': _funnel(None)},
        health={'no_next_step': no_next, 'rotting': rotting,
                'reply_rate': reply_rate, 'contacted_30d': contacted30, 'replied_30d': replied30,
                'sends_30d': f30['sent'],
                'replies_30d': f30['replied'], 'avg_touches_to_booked': avg_touches},
        activity=activity,
        top_lanes=top_lanes,
    )


@app.route('/api/dashboard')
@login_required
def api_dashboard():
    return jsonify(**_dashboard_data(_current_user_id()))


@app.route('/api/followups/timeline')
@login_required
def api_followups_timeline():
    """Full history of one contact merged chronologically: outreach sends,
    their replies (with text), pipeline/stage events, notes — newest first."""
    from app.models import FollowupContact, FollowupEvent, Reply, Send, Workspace
    uid = _current_user_id()
    fc = db.session.get(FollowupContact, request.args.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    email = (fc.contact_email or '').lower()
    items = []
    cut = False          # a source had more than it shows: the screen must not read as the whole story

    sends = Send.query.filter(Send.user_id == uid, db.func.lower(Send.recipient_email) == email
                              ).order_by(Send.sent_at.desc()).limit(51).all()
    cut = cut or len(sends) > 50
    for s in sends[:50]:
        items.append({'at': s.sent_at.isoformat() if s.sent_at else None, 'kind': 'send',
                      'title': 'Outreach sent' if s.status == 'sent' else f'Send {s.status}',
                      'detail': f'{s.origin} → {s.destination}'.strip(' →') or ''})

    replies = Reply.query.filter(Reply.user_id == uid, db.func.lower(Reply.from_email) == email
                                 ).order_by(Reply.received_at.desc()).limit(51).all()
    cut = cut or len(replies) > 50
    _reply_labels = {'negative': 'said no', 'gave_info': 'gave information',
                     'rate_request': 'asked for a rate', 'auto_reply': 'automatic reply'}
    for r in replies[:50]:
        cat = r.triage_category
        items.append({'at': r.received_at.isoformat() if r.received_at else None, 'kind': 'reply',
                      'title': 'Reply' + (f' · {_reply_labels.get(cat, cat.replace("_", " "))}' if cat else ''),
                      # their own words: the quoted copy of our mail below them is cut
                      'detail': ((_strip_quoted(r.body).strip() if r.body else '') or r.subject or '')[:400]})

    stage_names = {}
    if fc.workspace_id:
        ws = db.session.get(Workspace, fc.workspace_id)
        if ws:
            stage_names = {str(s['id']): s['name'] for s in ws.get_stages()}
    _ev_titles = {'created': 'Added to pipeline', 'pipeline_move': 'Stage moved',
                  'reply_detected': 'Reply detected — drip stopped', 'manual_send': 'Follow-up sent',
                  'free_send': 'Touch sent', 'touch_sent': 'Auto touch sent',
                  'recurring_sent': 'Recurring follow-up sent', 'scheduled_once_sent': 'Scheduled send',
                  'touch_snoozed': 'Snoozed', 'touch_skipped': 'Skipped',
                  'ooo_pause': 'Paused — out of office', 'note_added': 'Note',
                  'auto_send': 'Drip follow-up sent', 'state_change': 'Status changed',
                  'scheduled_once': 'One-time send scheduled', 'schedule_cancelled': 'Schedule cancelled',
                  'recurring_set': 'Recurring send set', 'recurring_stopped': 'Recurring send stopped',
                  # what the warmth ladder did on its own
                  'ladder_load': 'Sent load information', 'ladder_refusal': 'Asked us to stop',
                  'ladder_deferral': 'Asked to come back later', 'ladder_unknown': 'Reply needs a human look',
                  'ladder_exhausted': 'Every attempt used', 'ladder_parked': 'Automatic sending parked',
                  'ladder_optout_reply': 'Wrote in after opting out — your decision',
                  'ladder_blocked': 'Could not send',
                  # what the owner did by hand (Task 7 overrides)
                  'manual_pause_auto': 'Automation paused by you', 'manual_resume_auto': 'Automation resumed by you',
                  'manual_set_rung': 'Moved by you', 'manual_exclude': 'Excluded by you',
                  'manual_unexclude': 'Taken off the excluded list by you',
                  'migrated_to_ladder': 'Placed on the warmth ladder'}
    events = FollowupEvent.query.filter_by(followup_contact_id=fc.id
                                           ).order_by(FollowupEvent.event_at.desc()).limit(101).all()
    cut = cut or len(events) > 100
    events = events[:100]
    # A contact made from a load-bearing reply records the ladder step a moment BEFORE its
    # 'created' event (same transaction). Read as a history, "added" must come first: those
    # ladder steps sort as if they happened just after it.
    created_at = [e.event_at for e in events if e.event_type == 'created' and e.event_at]
    for it in items:
        it['_k'] = it['at'] or ''
    for e in events:
        detail = e.notes or ''
        if e.event_type == 'pipeline_move' and e.from_stage and e.to_stage:
            detail = f"{stage_names.get(e.from_stage, e.from_stage)} → {stage_names.get(e.to_stage, e.to_stage)}"
        elif (e.event_type.startswith('ladder_') and e.from_state and e.to_state
              and e.from_state != e.to_state):
            detail = f"{e.from_state.upper()} → {e.to_state.upper()}" + (f' · {detail}' if detail else '')
        elif e.event_type == 'state_change' and e.from_state and e.to_state:
            detail = f"{e.from_state} → {e.to_state}"
        # a failed send is logged under the type of the send it was meant to be, with the error in its
        # metadata (the same test the stats use): it must not read as a touch that went out
        failed = '"error"' in (e.metadata_json or '')
        key = e.event_at
        if e.event_type.startswith('ladder_') and e.event_at:
            for c_at in created_at:
                if 0 <= (c_at - e.event_at).total_seconds() <= 5:
                    key = c_at + timedelta(microseconds=1)
                    break
        items.append({'at': e.event_at.isoformat() if e.event_at else None, 'kind': 'event',
                      'type': e.event_type, '_k': key.isoformat() if key else '',
                      'title': 'Send failed' if failed else _ev_titles.get(e.event_type, e.event_type),
                      'failed': failed, 'detail': detail[:400]})

    items.sort(key=lambda x: x['_k'], reverse=True)
    for it in items:
        del it['_k']
    cut = cut or len(items) > 120
    return jsonify(contact=fc.to_dict(), items=items[:120], notes=fc.notes or '', truncated=cut)


@app.route('/api/followups/touch', methods=['POST'])
@login_required
@limiter.limit("120 per minute")
@csrf_protected
def api_followups_touch():
    """Today-queue quick actions on a cadence touch:
    snooze (+N days), skip (re-base from the rung's rhythm), clear_attention (resolve 🔥)."""
    from app.models import FollowupContact
    uid = _current_user_id()
    data = request.get_json() or {}
    fc = db.session.get(FollowupContact, data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    action = (data.get('action') or '').strip()

    if action == 'snooze':
        try:
            days = int(data.get('days') or 1)
        except (TypeError, ValueError):
            days = 1
        days = max(1, min(30, days))
        fc.next_followup_at = _utcnow() + timedelta(days=days)
        fc.touch_enabled = True
        fc.attention_at = None
        _record_event(fc, 'touch_snoozed', actor_user_id=uid, notes=f'+{days}d')
    elif action == 'skip':
        fc.attention_at = None
        if not _schedule_touch(fc, force=True):
            fc.next_followup_at = None
        _record_event(fc, 'touch_skipped', actor_user_id=uid)
    elif action == 'clear_attention':
        fc.attention_at = None
    else:
        return jsonify(error="action must be 'snooze', 'skip' or 'clear_attention'"), 400
    fc.updated_at = _utcnow()
    db.session.commit()
    return jsonify(ok=True, contact=fc.to_dict())


@app.route('/api/followups/delete', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
def api_followups_delete():
    from app.models import FollowupContact
    uid = _current_user_id()
    data = request.get_json()
    fc = db.session.get(FollowupContact, data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    db.session.delete(fc)
    db.session.commit()
    return jsonify(ok=True)


@app.route('/api/followups/notes', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
@csrf_protected
def api_followups_notes():
    from app.models import FollowupContact
    uid = _current_user_id()
    data = request.get_json()
    fc = db.session.get(FollowupContact, data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    text = (data.get('notes') or '').strip()[:2000]
    if data.get('append'):
        # Add a dated line under the existing notes instead of replacing them
        if not text:
            return jsonify(error='Note is empty'), 400
        line = f"[{_utcnow().strftime('%Y-%m-%d')}] {text}"
        fc.notes = f"{fc.notes.rstrip()}\n{line}" if (fc.notes or '').strip() else line
        logged = text
    else:
        fc.notes = text
        logged = fc.notes
    fc.updated_at = _utcnow()
    _record_event(fc, 'note_added', actor_user_id=uid, notes=logged[:100])
    db.session.commit()
    return jsonify(ok=True, notes=fc.notes)


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
@limiter.limit("20 per minute", methods=["POST"])
@csrf_protected
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
    s.updated_at = _utcnow()
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
            .filter(FollowupEvent.event_type.in_(['auto_send', 'manual_send']),
                    FollowupEvent.from_stage.isnot(None))\
            .order_by(FollowupEvent.event_at.desc()).first()   # the last send that carried a drip stage
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


# ─── Warmth-ladder scoreboard: funnel, "Needs you", last-day activity ─────────
# Read-only. Nothing here sends mail or schedules anything.

_FUNNEL_DAYS = 30
# Rank used to tell a rise from a fall in an event: dormant sits below cold, so a
# load that wakes a dormant contact counts as a raise.
_RUNG_RANK = {'dormant': -1, **{r: i for i, r in enumerate(_ladder.RUNGS)}}
_NEEDS_YOU_ORDER = ('unparsed_reply', 'promised_load_vanished',
                    'promised_not_delivered', 'client_silent')
# A ladder event of these kinds means the ladder (or the setup) dealt with the
# message that raised attention; a human is not needed for a broker's reply.
_LADDER_HANDLED = ('ladder_load', 'ladder_refusal', 'ladder_deferral',
                   'ladder_blocked', 'ladder_parked')


def _z(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None


def _snippet(text, limit=140):
    text = ' '.join((text or '').split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + '…'


def _local_month_start(tz, now):
    """Naive-UTC moment of local midnight on the 1st of the user's current month."""
    d = _local_date(now, tz)
    return datetime(d.year, d.month, 1, tzinfo=tz).astimezone(UTC).replace(tzinfo=None)


def _ladder_funnel(uid, now):
    from app.models import FollowupContact as FC, FollowupEvent as FE
    from sqlalchemy import func
    tz = _user_tz(uid)
    since = _local_day_start(tz, _FUNNEL_DAYS - 1, now)    # today + 29 local days back

    rungs = {r: 0 for r in _ladder.RUNGS + _ladder.OFF_LADDER}
    for rung, n in db.session.query(FC.rung, func.count()).filter(FC.user_id == uid).group_by(FC.rung):
        if rung in rungs:
            rungs[rung] = n

    # The cohort: every contact in play during the window, i.e. one that entered
    # follow-up in it or one that has any ladder event in it (so a base migrated long
    # ago still shows what it did this month).
    active_in_window = db.select(FE.followup_contact_id).where(
        FE.event_type.startswith('ladder_', autoescape=True), FE.event_at >= since)
    in_play = db.or_(FC.created_at >= since, FC.id.in_(active_in_window))
    cohort = FC.query.filter(FC.user_id == uid, in_play).order_by(FC.id).all()
    named = {}                          # contact id -> rungs its ladder events (ever) mention
    for cid, frm, to in db.session.query(FE.followup_contact_id, FE.from_state, FE.to_state).join(
            FC, FE.followup_contact_id == FC.id).filter(
            FC.user_id == uid, in_play, FE.event_type.startswith('ladder_', autoescape=True)):
        named.setdefault(cid, set()).update((frm, to))

    def top(fc):
        """Index of the highest rung this contact ever stood on."""
        seen = [_ladder.rung_for(fc.load_count or 0, False), fc.rung, *named.get(fc.id, ())]
        return max(_ladder.RUNGS.index(r) for r in seen if r in _ladder.RUNGS)

    person = lambda fc: {'id': fc.id, 'email': fc.contact_email, 'name': fc.display_name}
    peak = {fc.id: top(fc) for fc in cohort}
    rows, prev = [], None
    for i, rung in enumerate(_ladder.RUNGS):
        reached = [fc for fc in cohort if peak[fc.id] >= i]
        here = [fc for fc in reached if peak[fc.id] == i]
        lost = [fc for fc in here if fc.rung in _ladder.OFF_LADDER]
        by_reason = {}
        for fc in lost:
            reason = fc.exit_reason or ('excluded' if fc.rung == 'excluded' else 'unspecified')
            by_reason.setdefault(reason, []).append(person(fc))
        rows.append({
            'rung': rung,
            'reached': len(reached),
            'pct_of_previous': (round(100 * len(reached) / prev, 1) if prev else None),
            'lost': len(lost),
            'lost_reasons': [{'reason': r, 'count': len(people), 'contacts': people}
                             for r, people in sorted(by_reason.items(), key=lambda kv: (-len(kv[1]), kv[0]))],
            'still_here': len(here) - len(lost),
            'reached_contacts': [person(fc) for fc in reached],
        })
        prev = len(reached)

    by_contact = {}
    for cid, at in db.session.query(FE.followup_contact_id, FE.event_at).join(
            FC, FE.followup_contact_id == FC.id).filter(
            FC.user_id == uid, FE.event_type == _LADDER_LOAD_EVENT).order_by(FE.event_at):
        by_contact.setdefault(cid, []).append(at)
    gaps = [(b - a).total_seconds() / 86400
            for times in by_contact.values() for a, b in zip(times, times[1:])]
    month_start = _local_month_start(tz, now)
    entered = len(cohort)
    return {
        'rungs': rungs,
        'conversion': rows,
        'totals': {
            'entered': entered,
            'lost': sum(1 for fc in cohort if fc.rung in _ladder.OFF_LADDER),
            'end_to_end_pct': round(100 * rows[-1]['reached'] / entered, 1) if entered else None,
            'warm_or_better': rows[2]['reached'],       # sent at least one load
            'warm_or_better_pct': round(100 * rows[2]['reached'] / entered, 1) if entered else None,
            'avg_days_between_loads': round(sum(gaps) / len(gaps), 1) if gaps else None,
            'loads_this_month': sum(1 for times in by_contact.values() for t in times if t >= month_start),
        },
        'window': {'days': _FUNNEL_DAYS, 'since': _z(since),
                   'cohort': (f'Contacts in play over the last {_FUNNEL_DAYS} days: '
                              'entered follow-up in that time, or had ladder activity in it')},
    }


@app.route('/api/followups/funnel')
@login_required
def api_followups_funnel():
    """The scoreboard numbers. `rungs` is today's whole base; `conversion` follows the
    contacts in play in the last 30 local days (entered, or any ladder event), one row per
    rung (cold to client), each with whole-contact counts and the people behind them;
    `totals` rolls them up. The three switches that gate every automatic send ride along,
    so the screen can tell a quiet day from a switched-off engine."""
    from app.models import Workspace
    uid = _current_user_id()
    data = _ladder_funnel(uid, _utcnow())
    ws = Workspace.query.filter_by(owner_id=uid).first()
    data['fu_auto_enabled'] = bool(ws and ws.fu_auto_enabled)
    data['ladder_auto_enabled'] = bool(ws and ws.ladder_auto_enabled)
    data.update(_ladder_preview_fields(ws))           # what switching the ladder on would send
    data['ladder'] = _ladder_cfg(ws)                  # the rhythm the switch's label describes
    data['auto_send_enabled'] = bool(((ws.pipeline_config or {}) if ws else {}).get('auto_send_enabled', True))
    return jsonify(data)


def _replies_by_contact(uid, contacts, since=None, only=False):
    """Inbound replies grouped under the contact they concern, newest first. A
    colleague's answer (matched_recipient) belongs to the contact we wrote to.
    `only` narrows the query to these contacts' addresses (use it for a short list)."""
    from app.models import Reply
    by_email = {(fc.contact_email or '').lower(): fc for fc in contacts}
    q = Reply.query.filter(Reply.user_id == uid)
    if since is not None:
        q = q.filter(Reply.received_at >= since)
    if only:
        q = q.filter(db.or_(db.func.lower(Reply.from_email).in_(list(by_email)),
                            db.func.lower(Reply.matched_recipient).in_(list(by_email))))
    out = {}
    for r in q.order_by(Reply.received_at.desc()).all():
        for addr in {(r.from_email or '').lower(), (r.matched_recipient or '').lower()}:
            fc = by_email.get(addr)
            if fc is not None:
                out.setdefault(fc.id, []).append(r)
    return out


def _ladder_needs_you(uid, now):
    from app.models import FollowupContact as FC, FollowupEvent as FE
    tz = _user_tz(uid)
    contacts = FC.query.filter(FC.user_id == uid, FC.state == 'active', FC.rung != 'excluded').all()
    horizon = now - timedelta(days=_ladder.PROMISE_HORIZON_DAYS)
    replies = _replies_by_contact(uid, contacts, since=horizon)
    day = lambda dt: f'{_local_date(dt, tz).day} {_local_date(dt, tz):%b}'
    found = {}                                  # contact id -> (rank, since, reason, detail, contact)

    def add(fc, reason, since, detail):
        found.setdefault(fc.id, (_NEEDS_YOU_ORDER.index(reason), since, reason, detail, fc))

    # 1. A reply nobody dealt with: attention is up and the ladder did not act on it.
    flagged = [fc for fc in contacts if fc.attention_at is not None]
    last_ladder = {}
    if flagged:
        for cid, etype, at in db.session.query(FE.followup_contact_id, FE.event_type, FE.event_at).filter(
                FE.followup_contact_id.in_([fc.id for fc in flagged]),
                FE.event_type.startswith('ladder_', autoescape=True)).order_by(FE.event_at):
            last_ladder[cid] = (etype, at)      # ascending, so the last write is the newest
    for fc in flagged:
        etype, at = last_ladder.get(fc.id, (None, None))
        if etype in _LADDER_HANDLED and at >= fc.attention_at:
            continue
        latest = (replies.get(fc.id) or [None])[0]
        if latest is None:
            detail = 'Replied: needs your answer'
        else:
            own = _snippet(_strip_quoted(latest.body))
            detail = (f'Asked for a rate: "{own}"' if latest.triage_category == 'rate_request'
                      else f'Replied {day(latest.received_at)}: "{own}"')
        add(fc, 'unparsed_reply', fc.attention_at, detail)

    # 2. A promise made in a reply and not kept (older than the grace period).
    pending = []
    for fc in contacts:
        if fc.id in found or fc.exit_reason == 'refused':
            continue
        rows = replies.get(fc.id) or []
        for i, r in enumerate(rows):            # newest first
            kind = _ladder.promise_kind(_strip_quoted(r.body))
            if kind:
                pending.append((fc, r, kind, rows[:i]))   # rows[:i] came after the promise
                break
    grace = now - timedelta(days=_ladder.PROMISE_GRACE_DAYS)
    pending = [p for p in pending if p[1].received_at <= grace]
    counted = {}
    if pending:
        for cid, at, meta in db.session.query(FE.followup_contact_id, FE.event_at, FE.metadata_json).filter(
                FE.followup_contact_id.in_([p[0].id for p in pending]),
                FE.event_type == _LADDER_LOAD_EVENT):
            try:
                conv = json.loads(meta or '{}').get('conv')
            except ValueError:
                conv = None
            counted.setdefault(cid, []).append((at, conv))
    for fc, promise, kind, later in pending:
        if kind == 'load':
            own_conv = _ladder.load_conversation_key(promise.thread_id, fc.contact_email, promise.received_at)
            kept = (any(r.triage_category == 'gave_info' for r in later)
                    or any(at > promise.received_at and conv != own_conv
                           for at, conv in counted.get(fc.id, ())))
        else:
            kept = bool(later)
        if not kept:
            reason = 'promised_load_vanished' if kind == 'load' else 'promised_not_delivered'
            add(fc, reason, promise.received_at,
                f'Said on {day(promise.received_at)}: "{_snippet(_strip_quoted(promise.body))}"')

    # 3. A client that has gone quiet for much longer than its own rhythm.
    clients = [fc for fc in contacts if fc.rung == 'client' and fc.id not in found
               and fc.last_reply_at is not None]
    if clients:
        history = _replies_by_contact(uid, clients, only=True)
        for fc in clients:
            days = sorted({_local_date(r.received_at, tz) for r in history.get(fc.id, ())})
            threshold = _ladder.silence_threshold_days([(b - a).days for a, b in zip(days, days[1:])])
            silent = (now - fc.last_reply_at).total_seconds() / 86400
            if silent > threshold:
                add(fc, 'client_silent', fc.last_reply_at,
                    f'No reply for {int(silent)} days (flagged after {threshold:g})')

    ordered = sorted(found.values(), key=lambda v: (v[0], v[1]))
    return [{'id': fc.id, 'contact_email': fc.contact_email, 'contact_name': fc.display_name,
             'rung': fc.rung, 'reason': reason, 'detail': detail}
            for _, _, reason, detail, fc in ordered]


@app.route('/api/followups/needs-you')
@login_required
def api_followups_needs_you():
    """The short list that needs the owner: an unhandled reply, a promise not kept
    (a load, or something else) or a client gone unusually quiet. One row per contact."""
    return jsonify(items=_ladder_needs_you(_current_user_id(), _utcnow()),
                   promise_grace_days=_ladder.PROMISE_GRACE_DAYS,
                   promise_horizon_days=_ladder.PROMISE_HORIZON_DAYS)


@app.route('/api/followups/activity')
@login_required
def api_followups_activity():
    """What the ladder did in the last `hours` (default 24, at most 30 days):
    touches sent and rung steps up (events), contacts quieted and stopped (people)."""
    from app.models import FollowupContact as FC, FollowupEvent as FE
    uid = _current_user_id()
    hours = max(1, min(720, request.args.get('hours', default=24, type=int)))
    cutoff = _utcnow() - timedelta(hours=hours)
    sent = raised = 0
    quieted, stopped = set(), set()
    for cid, etype, frm, to, meta in db.session.query(
            FE.followup_contact_id, FE.event_type, FE.from_state, FE.to_state, FE.metadata_json).join(
            FC, FE.followup_contact_id == FC.id).filter(
            FC.user_id == uid, FE.event_at >= cutoff,
            db.or_(FE.event_type == 'touch_sent', FE.event_type.startswith('ladder_', autoescape=True))):
        if etype == 'touch_sent':
            sent += '"error"' not in (meta or '')           # a failed send is logged under the same type
        elif etype == 'ladder_exhausted':
            quieted.add(cid)
        elif etype in ('ladder_refusal', 'ladder_parked'):
            stopped.add(cid)
        elif _RUNG_RANK.get(to, -2) > _RUNG_RANK.get(frm, 99):
            raised += 1
    return jsonify(hours=hours, sent=sent, raised=raised, quieted=len(quieted), stopped=len(stopped))


@app.route('/api/fu-templates', methods=['GET'])
@login_required
def api_get_fu_templates(): return jsonify(get_fu_templates())

@app.route('/api/fu-templates', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
@csrf_protected
def api_save_fu_templates():
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    data = request.json  # {'FU1': '...', 'FU2': '...', 'FU3': '...'}
    for level, body in data.items():
        normalized_level = _normalize_fu_template_level(level)
        tmpl = Template.query.filter_by(user_id=uid, type='followup', level=normalized_level).order_by(Template.created_at.asc()).first()
        if tmpl:
            tmpl.body = body
            tmpl.is_active = True
            if not tmpl.name:
                tmpl.name = normalized_level
        else:
            db.session.add(Template(
                user_id=uid,
                type='followup',
                level=normalized_level,
                name=normalized_level,
                body=body,
                is_active=True,
            ))
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
@limiter.limit("20 per minute")
@csrf_protected
def api_add_fu_template():
    """Add a new FU template (any name allowed)."""
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    data = request.json or {}
    name = (data.get('name') or '').strip()
    level = _normalize_fu_template_level(data.get('level') or name or 'General')
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'error': 'Template body is required'}), 400
    # Exact duplicates used to pile up via repeated/double-clicked Add while
    # Delete silently did nothing — reject them with a clear message instead.
    dup = Template.query.filter_by(user_id=uid, type='followup', level=level,
                                   name=name or level, body=body).first()
    if dup:
        return jsonify({'error': 'An identical template already exists',
                        'duplicate': True, 'template': dup.to_dict()}), 409
    tmpl = Template(user_id=uid, type='followup', level=level, name=name or level, body=body)
    db.session.add(tmpl)
    db.session.commit()
    return jsonify({'ok': True, 'template': tmpl.to_dict()})

@app.route('/api/fu-templates/<tmpl_id>', methods=['PUT'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
def api_update_fu_template(tmpl_id):
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    tmpl = Template.query.filter_by(id=tmpl_id, user_id=uid, type='followup').first_or_404()
    data = request.json or {}
    if 'name' in data:
        tmpl.name = data['name'].strip()
    if 'level' in data:
        tmpl.level = _normalize_fu_template_level(data['level'])
    elif 'name' in data and tmpl.level not in DEFAULT_FU_TEMPLATES:
        tmpl.level = data['name'].strip() or 'General'
    if 'body' in data:
        tmpl.body = data['body']
    if 'is_active' in data:
        tmpl.is_active = bool(data['is_active'])
    db.session.commit()
    return jsonify({'ok': True, 'template': tmpl.to_dict()})

@app.route('/api/fu-templates/<tmpl_id>', methods=['DELETE'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
def api_delete_fu_template(tmpl_id):
    # Real delete. The old soft-delete (is_active=False) combined with an
    # unfiltered /list left the row visible forever — "Delete does nothing".
    # Nothing references templates.id (no FKs; follow-up sends resolve the
    # template text by stage at send time), so a hard delete cannot orphan
    # anything; the keep-but-disable use case is the ACTIVE toggle.
    uid = current_user_id()
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    from app.models import Template
    tmpl = Template.query.filter_by(id=tmpl_id, user_id=uid, type='followup').first_or_404()
    try:
        db.session.delete(tmpl)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error('template delete failed id=%s uid=%s: %s', tmpl_id, uid, e)
        return jsonify({'error': f'Delete failed: {e}'}), 500
    return jsonify({'ok': True, 'deleted': tmpl_id})

# ── Ladder copy: the rung emails, readable and editable ──────────────────────
# The bodies in DEFAULT_RUNG_TEMPLATES go out under the owner's name, so he reads them here
# before the switch is on. A saved edit becomes the workspace's own Template(level=<RUNG>)
# rows, which `_template_for_rung` already prefers; text equal to the code default is not
# stored, so a workspace that never edits keeps following the defaults.
_LADDER_COPY_RUNGS = ('cold', 'neutral', 'warm', 'hot')       # the rungs that are emailed
_LADDER_COPY_MAX_BODIES = 10
_LADDER_COPY_MAX_CHARS = 5000
_LADDER_COPY_VARIABLES = [
    {'name': '{origin}', 'means': 'the city of our first outreach to them'},
    {'name': '{destination}', 'means': 'where that lane ended'},
    {'name': '{route}', 'means': 'the whole lane, origin to destination'},
    {'name': '{last_rate}', 'means': 'the last rate they quoted us'},
    {'name': '{name} {company} {phone}', 'means': 'yours, from Settings'},
]


def _ladder_copy_norm(body):
    return (body or '').replace('\r\n', '\n').replace('\r', '\n').strip()


def _ladder_copy_rows(uid, rung):
    from app.models import Template
    return Template.query.filter(
        Template.user_id == uid, Template.type == 'followup',
        db.func.lower(Template.level) == rung,
    ).order_by(Template.sort_order, Template.created_at).all()


def _ladder_copy_payload(uid):
    rungs = []
    for rung in _LADDER_COPY_RUNGS:
        defaults = list(DEFAULT_RUNG_TEMPLATES[rung])
        own = [r.body for r in _ladder_copy_rows(uid, rung) if r.is_active and (r.body or '').strip()]
        rungs.append({'rung': rung, 'bodies': own or defaults, 'defaults': defaults, 'custom': bool(own)})
    return {'rungs': rungs, 'variables': _LADDER_COPY_VARIABLES}


@app.route('/api/followups/ladder-copy', methods=['GET'])
@login_required
def api_ladder_copy():
    return jsonify(_ladder_copy_payload(_current_user_id()))


@app.route('/api/followups/ladder-copy', methods=['PUT'])
@login_required
@limiter.limit("30 per minute")
@csrf_protected
def api_ladder_copy_save():
    """Save the bodies for one or more rungs: {rungs: {warm: [body, ...]}}. All or nothing."""
    from app.models import Template, Workspace
    uid = _current_user_id()
    ws = Workspace.query.filter_by(owner_id=uid).first()
    data = request.get_json(silent=True) or {}
    rungs = data.get('rungs')
    if not isinstance(rungs, dict) or not rungs:
        return jsonify(error='Nothing to save'), 400
    clean = {}
    for rung, bodies in rungs.items():
        if rung not in _LADDER_COPY_RUNGS:
            return jsonify(error=f'{rung or "(none)"} has no email copy: only '
                                 + ', '.join(_LADDER_COPY_RUNGS) + ' are emailed'), 400
        if not isinstance(bodies, list) or len(bodies) > _LADDER_COPY_MAX_BODIES \
                or not all(isinstance(b, str) for b in bodies):
            return jsonify(error=f'{rung}: send up to {_LADDER_COPY_MAX_BODIES} email texts'), 400
        texts = [_ladder_copy_norm(b) for b in bodies]
        if any(len(t) > _LADDER_COPY_MAX_CHARS for t in texts):
            return jsonify(error=f'{rung}: an email is longer than {_LADDER_COPY_MAX_CHARS} characters'), 400
        texts = [t for t in texts if t]
        if not texts:
            return jsonify(error=f'{rung} needs at least one email text'), 400
        clean[rung] = texts
    for rung, texts in clean.items():
        for row in _ladder_copy_rows(uid, rung):
            db.session.delete(row)
        if texts == [_ladder_copy_norm(b) for b in DEFAULT_RUNG_TEMPLATES[rung]]:
            continue                       # the code default: store nothing, keep following it
        for i, text in enumerate(texts):
            db.session.add(Template(user_id=uid, workspace_id=ws.id if ws else None, type='followup',
                                    level=rung.upper(), name=rung.upper(), body=text,
                                    sort_order=i, is_active=True))
    db.session.commit()
    return jsonify(ok=True, **_ladder_copy_payload(uid))


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

def upsert_pipeline(email, updates, uid=None):
    uid = uid or current_user_id()
    if not uid: return {}
    from app.models import PipelineContact
    existing = PipelineContact.query.filter_by(user_id=uid, email=email.lower()).first()
    if existing:
        for k, v in updates.items():
            if hasattr(existing, k): setattr(existing, k, v)
        existing.updated_at = _utcnow()
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
@csrf_protected
def api_add_pipeline():
    d = request.json; contact = upsert_pipeline(d['email'], d)
    return jsonify({'ok': True, 'contact': contact})

@app.route('/api/pipeline/update', methods=['POST'])
@login_required
@csrf_protected
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
@csrf_protected
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

    now = _utcnow()

    # born on the ladder (cold): `stage` keeps its column default and means nothing now
    fc = FollowupContact(
        user_id=uid, workspace_id=ws.id, contact_email=email,
        contact_name=getattr(reply_obj, 'from_name', '') or '',
        state='active', stage='fu1_scheduled',
        is_followup_enabled=False, rung='cold',
        last_activity_at=now, last_reply_at=now,
        reply_subject=reply_obj.subject or '',
        reply_msg_id=getattr(reply_obj, 'msg_id', '') or '',
        source_reply_id=reply_obj.id,
        source_thread_id=getattr(reply_obj, 'thread_id', '') or '',
        current_route=getattr(reply_obj, 'route', '') or '',
    )
    db.session.add(fc)
    db.session.flush()
    # The message that puts a broker in follow-up is usually their first load.
    # Its conversation key is stored here, so the reply hook never counts it twice.
    _apply_reply_to_ladder(fc, reply_obj, ws, now)
    _schedule_touch(fc, ws)             # whatever the reply did not date (e.g. a plain reply) gets its rung's rhythm
    _record_event(fc, 'created', actor_type='user', actor_user_id=uid)
    db.session.commit()


def _reply_rows_by_msg_id(uid, replies):
    """Stored Reply rows for freshly fetched reply dicts, keyed by msg_id.

    The warmth ladder needs the row (thread, body, category). A failed lookup is
    rolled back and logged, a missing row is logged as a warning: either way the
    ladder is skipped for that reply, and the log says so.
    """
    from app.models import Reply
    msg_ids = [r['msg_id'] for r in replies]
    try:
        rows = {row.msg_id: row for row in db.session.query(Reply).filter(
            Reply.user_id == uid, Reply.msg_id.in_(msg_ids)).all()}
    except Exception:
        db.session.rollback()
        app.logger.exception('reply row lookup failed; warmth ladder skipped for %d replies',
                             len(msg_ids))
        return {}
    for msg_id in msg_ids:
        if msg_id not in rows:
            app.logger.warning('no stored reply row for %s; warmth ladder skipped', msg_id)
    return rows


_LADDER_LOAD_EVENT = 'ladder_load'


def _ladder_load_counted(fc, conv_key):
    """True if the load conversation `conv_key` already counted for this contact.

    Reader half of the load event; `_ladder_record_load` is the writer. Live
    reply handling and the historical migration both go through the pair, so
    the stored format is defined once.
    """
    from app.models import FollowupEvent
    rows = FollowupEvent.query.filter_by(
        followup_contact_id=fc.id, event_type=_LADDER_LOAD_EVENT).all()
    for evt in rows:
        try:
            if json.loads(evt.metadata_json or '{}').get('conv') == conv_key:
                return True
        except ValueError:
            continue
    return False


def _ladder_record_load(fc, conv_key, from_rung=None, notes=None):
    """Writer half: log one counted load conversation on the contact."""
    return _record_event(fc, _LADDER_LOAD_EVENT, actor_type='system',
                         from_state=from_rung, to_state=fc.rung,
                         metadata_json=json.dumps({'conv': conv_key}), notes=notes)


def _ladder_set_next(fc, when, ws=None):
    """Set (or clear) the next touch. Only an active, unpaused contact on a
    scheduled rung (not client/dormant/excluded) is ever given a date, and the
    date lands at the touch hour the rest of the app uses (`_at_touch_hour`)."""
    if (when is not None and (fc.state != 'active' or fc.auto_paused
                              or fc.rung not in _ladder.RUNGS or fc.rung == 'client')):
        when = None
    if when is not None:
        if ws is None and fc.workspace_id:
            from app.models import Workspace
            ws = db.session.get(Workspace, fc.workspace_id)
        landed = _at_touch_hour(when, ws, fc.user_id)
        when = landed if landed > _utcnow() else when   # never land in the past
    fc.next_followup_at = when
    fc.touch_enabled = when is not None


def _ladder_raise_rung(fc):
    """Rung implied by the loads received and by the fact that they replied.
    Raises the rung (and revives a dormant contact), never lowers it."""
    derived = _ladder.rung_for(fc.load_count or 0, True)
    if fc.rung not in _ladder.RUNGS or _ladder.RUNGS.index(derived) > _ladder.RUNGS.index(fc.rung):
        fc.rung = derived


def _ladder_lift_cold(fc):
    """Any reply lifts a cold contact to neutral. Nothing but a load goes higher, so a
    reply that is not a load never undoes a rung the owner chose by hand."""
    if fc.rung == 'cold':
        fc.rung = 'neutral'


def _subject_opens_with_lane(subject, origin, destination):
    """True when `subject` (minus any Re:/Fwd: prefixes) is "<origin> to <destination>"
    followed by a comma or the end, matching whole names, case-insensitively."""
    words = lambda t: r'\s+'.join(re.escape(w) for w in t.split())
    return bool(re.match(
        r'(?i)\s*(?:(?:re|fwd?)\s*:\s*)*' + words(origin) + r'\s+to\s+' + words(destination)
        + r'\s*(?:,|$)', subject or ''))


def _ladder_refresh_route(fc, reply, now):
    """Point current_route at the lane this reply answers, when that can be told.

    current_route is the lane of our first outreach and nothing else updates it, so a
    contact that has since talked to us about other lanes would keep the first one. The
    answered Send is looked up by the address we wrote to (the matched recipient when a
    colleague replied) among sends made before the reply: if they all share one lane that
    is it, otherwise the newest whose lane appears in the reply's subject. Anything less
    certain leaves the route alone; a lane is never read out of the reply text."""
    from app.models import Send
    recipient = (reply.matched_recipient or fc.contact_email or '').strip().lower()
    if not recipient:
        return
    sends = Send.query.filter(
        Send.user_id == fc.user_id, Send.status == 'sent',
        db.func.lower(Send.recipient_email) == recipient,
        Send.sent_at <= (reply.received_at or now),
    ).order_by(Send.sent_at.desc()).all()
    lanes = {}                                     # newest first
    for s in sends:
        o, d = _lane_part(s.origin), _lane_part(s.destination)
        if o and d:
            lanes.setdefault((o, d), None)
    if len(lanes) == 1:
        chosen = next(iter(lanes))
    else:
        # _build_subject writes "Origin to Destination, date, ..." and a reply only adds
        # a Re:/Fwd: prefix, so the lane must open the subject, in that order and with
        # whole city names. A looser match (both cities somewhere, the reverse lane,
        # "North Houston" for "Houston") cannot tell two lanes apart: then leave it.
        hits = [(o, d) for o, d in lanes if _subject_opens_with_lane(reply.subject, o, d)]
        chosen = hits[0] if len(hits) == 1 else None
    if chosen:
        fc.current_route = f'{chosen[0]} \u2192 {chosen[1]}'


def _ladder_revive(fc, now, ws, cfg):
    """The contact is back in play: the rung its loads earn, a clean slate, a date.

    Used wherever a dormant contact comes back — a load, or simply writing in.

    On the attempt budget, which looks like a contradiction and is not. The spec
    says replies never refill the budget; only a load does. That rule is about a
    contact who is still LIVE: without it a broker could buy himself unlimited
    touches by answering "maybe later" forever, and a live deferral still refills
    nothing. But the budget exists to stop us chasing someone who never answers,
    and a contact we parked for silence has just answered — the premise is gone
    and the rule has done its job. Reviving without a fresh budget would put them
    on a live rung with nothing left to spend, so the next tick would park them
    again: churn that helps nobody. So the reset belongs to the revival, not to
    the reply.
    """
    _ladder_raise_rung(fc)          # dormant is not a rung, so this takes the derived one
    fc.exit_reason = None
    fc.touch_attempt = 0
    _ladder_set_next(fc, _ladder.next_touch_at(fc.rung, 0, now, cfg), ws)


# Why a dormant contact is out of play, in the two cases where it is a DECISION
# rather than silence — somebody chose it, so a reply does not undo it.
_LADDER_DECIDED_EXITS = ('refused', 'manual')
# What the ladder writes when such a contact writes in anyway. Deliberately NOT in
# `_LADDER_HANDLED`: this event means "a human still has to decide", so the
# "Needs you" list must keep showing the contact after it is written.
_LADDER_OPTOUT_EVENT = 'ladder_optout_reply'


def _ladder_back_in_play(fc, category, now, ws, cfg):
    """Apply a non-load reply's effect on where the contact stands.

    Returns 'revived' if it brought a dormant contact back, 'optout' if the
    contact wrote in but stays out of play and now needs the owner, else ''.

    A contact that goes quiet is parked, and writing in brings it back — so any
    reply revives a dormant contact. What does not revive one:

      * an automatic reply — the mailbox is talking, not the broker, and nobody
        wrote in;
      * a contact already carrying `refused` or `manual`. Those are decisions,
        not silence: the broker opted out, or the owner moved them out. Reviving
        them would be an opt-out bypass — a vague line four months after "remove
        me" would put him back on an automated sequence — and it is not the
        machine's call to undo either decision. Note that the refusal branch
        cannot cover this: it protects a reply that IS a refusal, and says
        nothing about a contact that is already carrying one.

        So the reply is not dropped either: `attention_at` goes up and the
        contact lands in "Needs you" with its words visible, and the owner
        decides with `set-rung`, which clears `exit_reason`. A load still
        revives them, because sending freight is unambiguous.

    A contact that is still live only gets the usual lift out of cold.
    """
    if fc.rung != 'dormant':
        _ladder_lift_cold(fc)
        return ''
    if category == 'auto_reply':
        return ''
    if fc.exit_reason in _LADDER_DECIDED_EXITS:
        fc.attention_at = now
        return 'optout'
    _ladder_revive(fc, now, ws, cfg)
    return 'revived'


def _ladder_record_reply_outcome(fc, back, event_type, old_rung, notes):
    """One event for what a non-load reply did. A contact that wrote in but stays
    out of play gets its own type, because the owner — not the ladder — acts next."""
    if back == 'optout':
        event_type = _LADDER_OPTOUT_EVENT
        notes = (f'wrote in after {fc.exit_reason}: needs your decision '
                 '(move them to a rung to reopen)')
    elif back == 'revived':
        notes += ' — back on the ladder'
    return _record_event(fc, event_type, actor_type='system',
                         from_state=old_rung, to_state=fc.rung, notes=notes)


def _ladder_reply_triage(reply, ws):
    """(category, filter_key) for one stored reply, as the ladder must read it.

    Either can be missing: at ingest this hook runs before triage has written a
    category, and rows from before the filter-key column carry none. Whichever is
    absent is recovered from the text with the same classifier the Replies page
    uses; a category already stored is never overridden by the recovery.

    The filter key matters because the shared 'negative' bucket holds
    `mc_request` — see `_ladder.PACKET_REQUEST_FILTERS`. The migration reads
    replies through this same function, so it and the live hook cannot disagree.
    """
    category, filter_key = reply.triage_category, reply.reply_filter_key
    if category is None or not filter_key:
        res = classify_reply_text(reply.subject, reply.body,
                                  ws.get_reply_filters(), ws.get_filter_keywords())
        if res:
            category = category or res['category']
            filter_key = filter_key or res['filter_key']
    return category, filter_key


def _apply_reply_to_ladder(fc, reply, ws, now):
    """Move a contact on the warmth ladder because of an inbound reply.

    A broker sending load information is the only thing that raises the rung
    past neutral (one step per load conversation). Any reply lifts cold to
    neutral. A refusal parks the contact as dormant, a deferral keeps its place
    and comes back on their date, anything else asks for a human.

    A contact goes quiet and is parked; if it writes in, it comes back. An
    automatic reply does not count as writing in, and a contact already out of
    play by someone's DECISION — `refused` or `manual` — is not revived at all:
    it goes to the owner instead. See `_ladder_back_in_play`.

    Returns the kind applied: 'load' | 'refusal' | 'deferral' | 'unknown'.
    Returns None when nothing was applied: an excluded contact, or a load whose
    conversation was already counted.
    """
    if fc.rung == 'excluded':
        return None
    if fc.rung not in _ladder.RUNGS and fc.rung != 'dormant':
        # a rung we do not know (legacy value): leave it alone, ask a human
        fc.attention_at = now
        _record_event(fc, 'ladder_unknown', actor_type='system',
                      from_state=fc.rung, to_state=fc.rung,
                      notes=f'unrecognised rung {fc.rung!r}')
        return 'unknown'
    cfg = _ladder_cfg(ws)
    category, filter_key = _ladder_reply_triage(reply, ws)
    kind, resume_at = _ladder.interpret_reply(category, _strip_quoted(reply.body), now,
                                              filter_key=filter_key)
    old_rung = fc.rung

    if kind == 'load':
        conv_key = _ladder.load_conversation_key(
            reply.thread_id, fc.contact_email, reply.received_at or now)
        if _ladder_load_counted(fc, conv_key):
            return None
        fc.load_count = (fc.load_count or 0) + 1
        fc.last_load_at = now
        _ladder_revive(fc, now, ws, cfg)
        _ladder_record_load(fc, conv_key, old_rung, notes=f'load #{fc.load_count} received')
        try:
            with db.session.begin_nested():     # a failed lookup rolls back to here, not the load
                _ladder_refresh_route(fc, reply, now)
        except Exception:
            app.logger.warning('ladder route refresh failed for %s', fc.contact_email, exc_info=True)
    elif kind == 'refusal':
        fc.rung = 'dormant'
        fc.exit_reason = 'refused'
        _ladder_set_next(fc, None)
        _record_event(fc, 'ladder_refusal', actor_type='system',
                      from_state=old_rung, to_state='dormant', notes='refused')
    elif kind == 'deferral':
        back = _ladder_back_in_play(fc, category, now, ws, cfg)
        # A date they stated wins; otherwise they keep their place in the rhythm.
        # A contact that stayed out of play is on no rung, so this gives it none.
        _ladder_set_next(fc, resume_at or _ladder.next_touch_at(
            fc.rung, fc.touch_attempt or 0, now, cfg), ws)
        _ladder_record_reply_outcome(
            fc, back, 'ladder_deferral', old_rung,
            'asked to come back ' + (resume_at.strftime('%Y-%m-%d')
                                     if resume_at else 'later'))
    else:
        back = _ladder_back_in_play(fc, category, now, ws, cfg)
        fc.attention_at = now
        _ladder_record_reply_outcome(fc, back, 'ladder_unknown', old_rung,
                                     'reply needs a human look')
    return kind


# ── Tier list rows and the owner's manual overrides ──────────────────────────
# The owner can see who is where, stop anyone and move them out by hand. Whatever the
# machine decides he can override; these actions never send, they only move a contact
# and its date. Each writes one `manual_*` event with actor_type 'user' (no `ladder_`
# prefix: the activity and funnel read that prefix as what the ladder itself did).

_LADDER_RUNG_VALUES = _ladder.RUNGS + _ladder.OFF_LADDER
_LADDER_MANUAL_ACTIONS = ('pause-auto', 'resume-auto', 'set-rung', 'exclude')   # single and bulk
_LADDER_SINGLE_ACTIONS = ('unexclude',)        # one contact at a time, never in bulk
_EXCLUDED_MSG = 'Excluded contacts are never contacted again'
_REFUSED_MSG = 'This contact asked us to stop'
# Why "send now" (a touch on a live rung) cannot go to a contact that is out of play.
_OFF_LADDER_SEND_MSG = {'dormant': 'This contact is inactive: move it to a rung first',
                        'excluded': _EXCLUDED_MSG,
                        'client': 'Clients get no scheduled follow-ups'}
_EXCLUDE_STOP_REASON = 'excluded'              # what `exclude` writes on the Stop List; unexclude removes only this
# Events that (re)set a contact's date. A deferral is only "why the date is what it is"
# while none of these has come after it.
_RESCHEDULING_EVENTS = ('touch_sent', 'free_send', 'manual_send', 'touch_snoozed', 'touch_skipped',
                        'ladder_load', 'ladder_parked', 'ladder_exhausted', 'scheduled_once',
                        'recurring_set', 'manual_set_rung', 'manual_resume_auto', 'manual_pause_auto',
                        'manual_unexclude',
                        # these also set or clear the date, so a deferral before them is stale
                        'schedule_cancelled', 'recurring_stopped', 'restarted_fu1',
                        'scheduled_once_sent', 'recurring_sent')


def _ladder_budget(rung, ws):
    """Attempts the contact's rung allows in this workspace; 0 for a rung the ladder does not know."""
    try:
        return _ladder.budget_for(rung, _ladder_cfg(ws))
    except ValueError:
        return 0


def _ladder_rung_counts(uid):
    """Contacts per rung (every known rung present, zero when empty): the numbers behind
    the tier tabs. Unlike `counts.warm`, which is the legacy contact state."""
    from app.models import FollowupContact as FC
    out = {r: 0 for r in _LADDER_RUNG_VALUES}
    for rung, n in db.session.query(FC.rung, db.func.count()).filter(FC.user_id == uid).group_by(FC.rung):
        if rung in out:
            out[rung] = n
    return out


def _ladder_deferred_ids(uid, contacts):
    """Ids, among `contacts`, whose next date is the one a broker asked for: the newest
    `ladder_deferral` event is newer than anything else that sets the date.

    Only contacts whose reason could be a deferral are looked up (active, on a rung that
    is dated, with a plain ladder date), by id, so the cost follows the rows on screen
    and not the size of the events table."""
    from app.models import FollowupContact as FC, FollowupEvent as FE
    from sqlalchemy import func, case
    candidates = [fc.id for fc in contacts
                  if fc.state == 'active' and fc.rung in _ladder.RUNGS and fc.rung != 'client'
                  and not fc.auto_paused and fc.next_followup_at is not None
                  and not (fc.recurring_enabled or fc.scheduled_once or fc.is_followup_enabled
                           or fc.send_fail_count)]
    out = set()
    for i in range(0, len(candidates), 400):
        rows = db.session.query(
            FE.followup_contact_id,
            func.max(case((FE.event_type == 'ladder_deferral', FE.event_at))),
            func.max(case((FE.event_type.in_(_RESCHEDULING_EVENTS), FE.event_at))),
        ).join(FC, FE.followup_contact_id == FC.id).filter(
            FC.user_id == uid, FE.followup_contact_id.in_(candidates[i:i + 400]),
            FE.event_type.in_(('ladder_deferral',) + _RESCHEDULING_EVENTS),
        ).group_by(FE.followup_contact_id)
        out.update(cid for cid, asked, since in rows
                   if asked is not None and (since is None or asked > since))
    return out


def _ladder_next_reason(fc, deferred, ws):
    """One line saying why the contact's next touch is (or is not) what it is."""
    rung = fc.rung or 'cold'
    if rung == 'excluded':
        return 'excluded: never contact again'
    if rung == 'dormant':
        why = {'refused': 'they asked us to stop', 'exhausted': 'attempts used up, waits for a load',
               'manual': 'moved by you',
               'stale': 'silent for months when the ladder started'}.get(fc.exit_reason)
        return 'dormant: ' + why if why else 'dormant'
    if rung == 'client':
        return 'client: no automatic touches'
    if rung not in _ladder.RUNGS:
        return 'unrecognised rung'
    if fc.state != 'active':
        return f'{fc.state}: no automatic touches'
    if fc.auto_paused:
        return ('auto paused: sending failed repeatedly' if fc.exit_reason == 'send_failed'
                else 'auto paused by you')
    if fc.next_followup_at is None:
        return 'nothing scheduled'
    if fc.recurring_enabled:
        return 'recurring schedule you set'
    if fc.scheduled_once:
        return 'one-time send you scheduled'
    if fc.is_followup_enabled:
        return 'not yet placed on the ladder'
    if fc.send_fail_count:
        return 'retrying after a failed send'
    if deferred:
        return 'they asked us to come back later'
    budget = _ladder_budget(rung, ws)
    if (fc.touch_attempt or 0) >= budget:
        return 'attempts used up'
    return f'touch {(fc.touch_attempt or 0) + 1} of {budget}'


def _fu_row(fc, deferred=False, ws=None):
    """A contact as the Follow-up table shows it: its fields plus the ladder's budget
    and the reason for its next touch, both under its workspace's settings."""
    from app.models import Workspace
    if ws is None and fc.workspace_id:
        ws = db.session.get(Workspace, fc.workspace_id)      # the session caches it: one read per list
    row = fc.to_dict()
    row['budget'] = _ladder_budget(fc.rung, ws)
    row['next_touch_reason'] = _ladder_next_reason(fc, deferred, ws)
    return row


def _fu_row_one(fc):
    return _fu_row(fc, fc.id in _ladder_deferred_ids(fc.user_id, [fc]))


def _ladder_stop_all(fc):
    """Switch off every engine that could email this contact and clear its date."""
    fc.is_followup_enabled = False
    fc.scheduled_once = False
    fc.recurring_enabled = False
    fc.recurring_days = None
    fc.recurring_time = None
    _ladder_set_next(fc, None)


def _ladder_redate(fc, ws, now):
    """Give the contact the date its rung implies. A drip, one-time or recurring send the
    owner scheduled keeps its own date; if that date is gone (paused) it is restored.
    A paused contact is never dated: resume-auto does that."""
    if fc.auto_paused:
        return
    if fc.scheduled_once and fc.next_followup_at is None:
        fc.scheduled_once = False         # a paused one-time date cannot be recovered: the rung takes over
    if fc.is_followup_enabled or fc.scheduled_once or fc.recurring_enabled:
        if fc.next_followup_at is None:
            _restore_contact_schedule(fc, now)
        return
    _ladder_set_next(fc, _ladder.next_touch_at(
        fc.rung, fc.touch_attempt or 0, now, _ladder_cfg(ws)), ws)


def _ladder_parse_rung(raw):
    """(rung, error) for a set-rung request: a ladder rung or dormant; excluded has its own action."""
    target = raw.strip() if isinstance(raw, str) else ''
    if target == 'excluded':
        return None, 'Use exclude: it is permanent'
    if target not in _ladder.RUNGS and target != 'dormant':
        return None, f'Unknown rung: {target or raw}'
    return target, None


def _remove_excluded_stop_entry(uid, email):
    """Remove the Stop List entry that `exclude` wrote, and only that one: an entry the
    owner made for another reason (a block) stays."""
    from app.models import StopListEntry
    n = StopListEntry.query.filter_by(user_id=uid, type='email', value=(email or '').strip().lower(),
                                      reason=_EXCLUDE_STOP_REASON).delete()
    if n:
        _cache_del(f'stop_list:{uid}')
    return bool(n)


def _ladder_manual_action(fc, action, data, uid):
    """Apply pause-auto / resume-auto / set-rung / exclude / unexclude to a contact the
    caller has already verified belongs to `uid`. Returns (ok, error, info): nothing is
    changed on an error; `info` holds extra response fields (what was discarded).

    Attempts: set-rung and unexclude start a fresh run on a ladder rung (touch_attempt 0),
    the others leave the count alone. A manual send never spends one (see free-send)."""
    from app.models import Workspace
    now = _utcnow()
    old = fc.rung
    info = {}
    ws = db.session.get(Workspace, fc.workspace_id) if fc.workspace_id else None

    def discard_notes():
        """Tell the owner about a send he scheduled by hand that this action drops."""
        out = []
        if fc.scheduled_once and fc.next_followup_at is not None:
            info['discarded_scheduled_at'] = _z(fc.next_followup_at)
            out.append(f'one-time send for {fc.next_followup_at:%Y-%m-%d %H:%M} UTC discarded')
        return ('; ' + '; '.join(out)) if out else ''

    def stop_everything():
        extra = discard_notes()
        if fc.recurring_enabled:
            info['discarded_recurring'] = True
            extra += '; recurring send switched off'
        _ladder_stop_all(fc)
        return extra

    if action == 'unexclude':
        if old != 'excluded':
            return False, 'Contact is not excluded', {}
        target = _ladder.rung_for(fc.load_count or 0, bool(fc.last_reply_at))
        # a Block made while excluded found the address already listed and left this entry's
        # reason alone: it is the block's entry too, so a blocked contact keeps it
        removed = False if fc.state == 'blocked' else _remove_excluded_stop_entry(uid, fc.contact_email)
        fc.rung = target
        fc.exit_reason = None
        fc.touch_attempt = 0
        _ladder_redate(fc, ws, now)
        info['stop_list_removed'] = removed
        _record_event(fc, 'manual_unexclude', actor_user_id=uid, from_state='excluded', to_state=target,
                      metadata_json=json.dumps({'to': target, 'stop_list_removed': removed}),
                      notes=f'taken off the excluded list by you, back on {target}')

    elif old == 'excluded' and action != 'exclude':
        # the owner's permanent decision: only unexclude undoes it
        return False, _EXCLUDED_MSG, {}

    elif action == 'exclude':
        # the Stop List is what makes it permanent for every sender (send page, drip,
        # one-time, recurring, ladder); it is written even when already excluded to heal a gap
        listed = _add_to_stop_list(uid, fc.contact_email, reason=_EXCLUDE_STOP_REASON)
        if old == 'excluded':
            return True, None, {}
        extra = stop_everything()
        fc.rung = 'excluded'
        fc.exit_reason = 'excluded'
        fc.attention_at = None
        _record_event(fc, 'manual_exclude', actor_user_id=uid, from_state=old, to_state='excluded',
                      metadata_json=json.dumps({'stop_list_added': listed}),
                      notes='excluded by you: never contact again' + extra)

    elif action == 'pause-auto':
        if fc.auto_paused:
            return True, None, {}
        extra = discard_notes()       # the date goes; the flag stays until resume drops it
        fc.auto_paused = True
        _ladder_set_next(fc, None, ws)
        _record_event(fc, 'manual_pause_auto', actor_user_id=uid, from_state=old, to_state=old,
                      notes='automation paused by you' + extra)

    elif action == 'resume-auto':
        if old not in _LADDER_SENDABLE:
            return False, f'A {old} contact is not on the automatic schedule: move it to a rung first', {}
        if fc.state != 'active':
            return False, f'Contact is {fc.state}: resume it first', {}
        if not fc.auto_paused:
            return True, None, {}
        # a contact parked after failed sends carries all three; clear them together or the
        # next failure would back off for 72 hours and give up again at once
        fc.auto_paused = False
        if fc.exit_reason == 'send_failed':
            fc.exit_reason = None
        fc.send_fail_count = 0
        _ladder_redate(fc, ws, now)
        _record_event(fc, 'manual_resume_auto', actor_user_id=uid, from_state=old, to_state=old,
                      notes='automation resumed by you')

    elif action == 'set-rung':
        target, err = _ladder_parse_rung(data.get('rung'))
        if err:
            return False, err, {}
        if target == old:
            return True, None, {}
        spent = fc.touch_attempt or 0
        fc.rung = target
        extra = ''
        if target in _ladder.RUNGS and target != 'client':
            # a fresh run on the new rung: attempts spent on the old one must not park the
            # contact again on the next tick and undo the move
            fc.touch_attempt = 0
            if fc.exit_reason != 'send_failed':      # that one belongs to the pause
                fc.exit_reason = None
            _ladder_redate(fc, ws, now)
        else:
            extra = stop_everything()
            fc.exit_reason = 'manual' if target == 'dormant' else None
        _record_event(fc, 'manual_set_rung', actor_user_id=uid, from_state=old, to_state=target,
                      metadata_json=json.dumps({'from': old, 'to': target, 'attempts_reset_from': spent}),
                      notes=f'moved from {old} to {target} by you' + extra)

    fc.updated_at = now
    return True, None, info


def _check_reply_stops_followup(reply_email, user_id, reply=None):
    """A reply from a pipeline contact: take it off the retired drip flag, flag warm
    contacts for a human answer (🔥), and — iron rule — schedule the next
    ladder touch instead of leaving the contact with no next step.
    With the Reply row, the warmth ladder then reads it (load / refusal /
    deferral) and sets the contact's rung and next touch."""
    from app.models import FollowupContact, Workspace
    ws = Workspace.query.filter_by(owner_id=user_id).first()
    if not ws:
        return
    email = reply_email.strip().lower()
    fc = FollowupContact.query.filter_by(workspace_id=ws.id, contact_email=email).first()
    if not fc:
        return

    now = _utcnow()
    fc.last_reply_at = now
    fc.last_activity_at = now
    if fc.rung == 'excluded':
        return                         # the owner's permanent decision: a reply changes nothing
    if (fc.pipeline_stage or 1) >= 2:
        fc.attention_at = now          # warm contact replied — answer today

    # A reply always takes the contact off the retired drip (the old auto-stop-on-reply
    # setting is gone: with the drip, that switch was the only way a reply did not stop
    # it) and re-bases the ladder's next touch from now.
    was_unplaced = bool(fc.is_followup_enabled)
    if was_unplaced:
        fc.is_followup_enabled = False
        if not _schedule_touch(fc, ws, force=True):
            fc.next_followup_at = None
        _record_event(fc, 'reply_detected', actor_type='system', notes=f'Reply from {email}')
    elif fc.touch_enabled and fc.state == 'active':
        _schedule_touch(fc, ws, force=True)

    if reply is not None:
        _apply_reply_to_ladder(fc, reply, ws, now)   # last: its schedule wins


def _get_fu_templates_for_user(uid):
    """Fetch active FU templates for a specific user — safe in threads."""
    from app.models import Template
    return Template.query.filter_by(user_id=uid, type='followup', is_active=True)\
        .order_by(Template.sort_order, Template.created_at).all()

def _is_rung_level(level):
    """True for a template level that names a ladder rung (COLD/NEUTRAL/WARM/HOT, any case)."""
    return (level or '').strip().lower() in DEFAULT_RUNG_TEMPLATES


def _lane_part(value):
    """One side of a lane, or '' when it is missing. A NULL column reaches us as the
    literal string 'None' wherever a route is built with an f-string."""
    text = (value or '').strip()
    return '' if text.lower() == 'none' else text


def _rung_template_vars(fc, names):
    """Values for the lane/rate variables a ladder body asks for. Unknown values are ''.
    {route} needs both ends of the lane; {origin} and {destination} stand on their own."""
    raw = (fc.current_route or '').strip()
    parts = re.split(r'\s*(?:\u2192|->)\s*', raw, maxsplit=1) if raw else []
    origin = _lane_part(parts[0]) if len(parts) == 2 else ''
    destination = _lane_part(parts[1]) if len(parts) == 2 else ''
    values = {
        'route': raw if origin and destination else '',
        'origin': origin,
        'destination': destination,
    }
    if 'last_rate' in names:                       # only query when a body asks for it
        quote = None
        if fc.contact_email:
            from app.models import RateQuote
            quote = RateQuote.query.filter(
                RateQuote.user_id == fc.user_id,
                db.func.lower(RateQuote.contact_email) == fc.contact_email.lower(),
                RateQuote.hidden == False,
                RateQuote.rate.isnot(None),
            ).order_by(RateQuote.created_at.desc()).first()
        values['last_rate'] = f'${quote.rate:,}' if quote else ''
    return values


def _render_rung_body(body, fc, strict=False):
    """Fill the lane/rate variables of a ladder body, leaving {name} {company}
    {phone} for the sender. A line that needs a value the contact does not have is
    dropped rather than sent with a hole in it. With strict=True (a body the user
    wrote) nothing is dropped: the whole body counts as blank, so the caller falls
    through to the next source instead of silently cutting a line the owner composed.
    Returns '' for a blank result."""
    body = body or ''
    values = _rung_template_vars(fc, set(_TMPL_FIELD_RE.findall(body)))
    kept = []
    for line in body.split('\n'):
        if any(values.get(n) == '' for n in _TMPL_FIELD_RE.findall(line)):
            if strict:
                return ''
            continue
        kept.append(line)
    text = re.sub(r'\n{3,}', '\n\n', '\n'.join(kept))
    return _safe_render(text, values).strip()


def _template_for_rung(uid, rung, fc):
    """The body for this contact's next ladder touch, or None when there is genuinely
    nothing to send (the scheduler then asks a human).

    Order: the user's own Template(level=<RUNG>) -> the code default for the rung ->
    the user's general pool -> None. Where a source holds several bodies the attempt
    number plus the load count picks one: touch N+1 does not repeat touch N, and a
    new load (which resets the attempts) does not restart at the first body. A source
    that renders to nothing, or whose user-written body needs a value the contact
    lacks, falls through to the next, so a send is never blank and never blocked by a
    missing variable."""
    from app.models import Template
    rows = Template.query.filter_by(user_id=uid, type='followup', is_active=True)\
        .order_by(Template.sort_order, Template.created_at).all()
    rows = [r for r in rows if (r.body or '').strip()]
    key = (rung or '').strip().lower()
    # a contact's first touch on a rung opens with that rung's lead body; every further
    # load on the same rung shifts the start, so a refilled budget is not a replay
    step = (fc.touch_attempt or 0) + max(0, (fc.load_count or 0) - _RUNG_FIRST_LOAD.get(key, 0))
    own = [r.body for r in rows if (r.level or '').strip().lower() == key] if key in DEFAULT_RUNG_TEMPLATES else []
    defaults = list(DEFAULT_RUNG_TEMPLATES.get(key, ()))
    general = [r.body for r in rows
               if _normalize_fu_template_level(r.level) not in DEFAULT_FU_TEMPLATES
               and not _is_rung_level(r.level)]
    if own:
        text = _render_rung_body(own[step % len(own)], fc, strict=True)
        if text:
            return text
    if defaults:
        text = _render_rung_body(defaults[step % len(defaults)], fc)
        if text:
            return text
    if general:
        text = _render_rung_body(random.choice(general), fc, strict=True)
        if text:
            return text
    return None


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
    now = _utcnow()
    for offset in range(0, 8):
        candidate = (now + timedelta(days=offset)).replace(
            hour=h, minute=m, second=0, microsecond=0)
        if candidate.weekday() in days and candidate > now:
            return candidate
    raise ValueError(f'No valid day found — unreachable with valid input: days={days}')

def _auto_send_on(workspace_id, cache):
    """Workspace master switch over every automatic send path (default on)."""
    if workspace_id not in cache:
        from app.models import Workspace
        ws = db.session.get(Workspace, workspace_id) if workspace_id else None
        cache[workspace_id] = bool(((ws.pipeline_config or {}) if ws else {}).get('auto_send_enabled', True))
    return cache[workspace_id]


def _would_auto_send(fc, ws):
    """True if the scheduler would email this due contact without a human click."""
    if fc.scheduled_once or fc.recurring_enabled:
        return bool(ws and ws.fu_auto_enabled)         # behind the same kill switch as the ladder
    if fc.is_followup_enabled:
        return False                                   # unplaced: no engine sends it
    if fc.touch_enabled:
        return _ladder_would_send(fc, ws)
    return False


def _auto_send_preview(ws, hours=24):
    """How many contacts the scheduler would email on its own in the next
    `hours` (overdue included), split by path. Scheduled sends are counted as if
    the master switch and the follow-up kill switch were on, so the Settings banner
    can update live while the user flips them; ladder touches are counted only when
    the scheduler really would send them (both ladder gates on, a sendable rung, not
    paused, budget left)."""
    from app.models import FollowupContact
    out = {'touches': 0, 'scheduled': 0}
    if not ws:
        return out
    horizon = _utcnow() + timedelta(hours=hours)
    due = FollowupContact.query.filter(
        FollowupContact.workspace_id == ws.id,
        FollowupContact.state == 'active',
        FollowupContact.next_followup_at.isnot(None),
        FollowupContact.next_followup_at <= horizon,
    ).all()
    for fc in due:
        if fc.scheduled_once or fc.recurring_enabled:
            out['scheduled'] += 1
        elif fc.is_followup_enabled:
            continue                      # unplaced: nothing sends it
        elif fc.touch_enabled and _ladder_would_send(fc, ws):
            out['touches'] += 1
    return out


def _prefetch_replies_before_sending(now):
    """Pull fresh Gmail replies for every user about to get automatic sends in
    this run, so a contact who already answered is stopped before we email
    them. Returns the user ids whose reply check failed — their automatic
    sends are held until the next run rather than risk emailing a replier."""
    from app.models import FollowupContact, Workspace
    due = FollowupContact.query.filter(
        FollowupContact.state == 'active',
        FollowupContact.next_followup_at <= now,
        db.or_(FollowupContact.scheduled_once == True,
               FollowupContact.recurring_enabled == True,
               FollowupContact.touch_enabled == True),
    ).all()
    gate, uids = {}, set()
    for fc in due:
        if fc.user_id in uids or not _auto_send_on(fc.workspace_id, gate):
            continue
        ws = db.session.get(Workspace, fc.workspace_id) if fc.workspace_id else None
        if _would_auto_send(fc, ws):
            uids.add(fc.user_id)
    hold = set()
    for uid in uids:
        try:
            res = fetch_replies_from_gmail(uid=uid, rate_limit=False) or {}
        except Exception:
            db.session.rollback()
            app.logger.exception('pre-send reply check crashed for uid=%s', uid)
            hold.add(uid)
            continue
        err = str(res.get('error') or '')
        # not connected = no Gmail API to check (legacy app-password accounts)
        if err and 'not connected' not in err.lower():
            app.logger.warning('pre-send reply check failed for uid=%s: %s — holding auto-sends', uid, err)
            hold.add(uid)
    return hold


# ── Scheduler send-failure backoff ───────────────────────────────────────────
# A failed scheduler send used to leave next_followup_at untouched: the contact
# stayed due, every tick retried it and wrote another followup_events row. One
# account with a revoked Gmail token produced 368k rows (12k per contact) and
# filled the database volume, which took production down on 2026-10-27.
SEND_FAIL_BACKOFF_HOURS = [6, 24, 72]   # 1st / 2nd / 3rd+ consecutive failure
SEND_FAIL_GIVE_UP_AFTER = 5             # then stop auto-retrying, ask a human

def _record_send_failure(fc, event_type, err, now=None):
    """Back off a failed scheduler send instead of retrying it on every tick.

    Writes an event only on the first failure and on giving up — never once per
    attempt — so a broken account can no longer flood followup_events. Returns
    True once auto-sending for this contact has been given up on.
    """
    now = now or _utcnow()
    n = (fc.send_fail_count or 0) + 1
    fc.send_fail_count = n
    hours = SEND_FAIL_BACKOFF_HOURS[min(n, len(SEND_FAIL_BACKOFF_HOURS)) - 1]
    fc.next_followup_at = now + timedelta(hours=hours)
    gave_up = n >= SEND_FAIL_GIVE_UP_AFTER
    if gave_up:
        fc.attention_at = now           # 🔥 surfaces it for manual handling
    if n == 1 or n == SEND_FAIL_GIVE_UP_AFTER:
        _record_event(fc, event_type, actor_type='scheduler',
                      from_stage=fc.stage, to_stage=fc.stage,
                      metadata_json=json.dumps({'error': str(err), 'attempt': n}),
                      notes=('Send failed - auto-send paused, needs attention'
                             if gave_up else 'Send failed - backing off'))
    app.logger.warning('scheduler send failed (attempt %s) for %s: %s',
                       n, fc.contact_email, err)
    return gave_up


_LADDER_SENDABLE = ('cold', 'neutral', 'warm', 'hot')   # client/dormant/excluded are never emailed


def _ladder_would_send(fc, ws):
    """True if the ladder scheduler would email this contact once it is due, with
    nobody clicking: both gates on, a sendable rung, not paused, budget left."""
    return bool(ws and ws.fu_auto_enabled and ws.ladder_auto_enabled and _ladder_sendable(fc, ws))


def _ladder_sendable(fc, ws):
    """The part of `_ladder_would_send` that belongs to the contact and the owner's
    budget setting rather than to the switches: a sendable rung, not paused, budget left."""
    return bool(fc.rung in _LADDER_SENDABLE and not fc.auto_paused
                and (fc.touch_attempt or 0) < _ladder.budget_for(fc.rung, _ladder_cfg(ws)))


# What a successful automated send writes, by event type: the note prefix is what tells
# it from the failure event that shares the type (a failure's note is 'Send failed ...').
_AUTO_SEND_NOTES = (('touch_sent', 'ladder touch'),
                    ('scheduled_once_sent', 'one-time send'),
                    ('recurring_sent', 'recurring send'))


def _auto_sent_today(ws):
    """Follow-ups the scheduler has emailed for this workspace since its owner's local
    midnight, whichever engine queued them (ladder touch, one-time or recurring send), counted
    from the events it writes, so a restart cannot hand out a second day's worth. The daily
    cap protects the broker's inbox and the owner's sending reputation, and neither cares
    which engine queued the mail. Failed sends write a differently worded note and do not count."""
    from app.models import FollowupEvent
    if not ws:
        return 0
    return FollowupEvent.query.filter(
        FollowupEvent.workspace_id == ws.id,
        FollowupEvent.actor_type == 'scheduler',
        FollowupEvent.event_at >= _local_day_start(_ws_tz(ws)),
        db.or_(*[db.and_(FollowupEvent.event_type == et,
                         FollowupEvent.notes.startswith(prefix, autoescape=True))
                 for et, prefix in _AUTO_SEND_NOTES]),
    ).count()


_ladder_sent_today = _auto_sent_today        # the ladder's own name for it, kept for its callers


def _ladder_due_summary(ws, hours=24):
    """What switching the ladder on would do, under the workspace's daily cap: `due` are the
    contacts that would be emailed in the next `hours` (overdue included) if the switch were
    on, `today` is how many of them the cap lets out today, `days` how many days the whole
    set takes to go. It never sends or changes anything."""
    cap = _ladder_cfg(ws)['daily_cap']
    due = _ladder_due_count(ws, hours)
    room = max(0, cap - _ladder_sent_today(ws))
    today = min(due, room)
    days = (1 if today else 0) + -(-(due - today) // cap)      # days that send; ceil division
    return {'due': due, 'today': today, 'days': days}


def _ladder_preview_fields(ws):
    """The payload keys behind the switch's label: due in 24 h, how many of those go out
    today under the cap, and over how many days the whole set drains."""
    s = _ladder_due_summary(ws)
    return {'ladder_due_total': s['due'], 'ladder_due_24h': s['today'], 'ladder_drain_days': s['days']}


def _ladder_due_count(ws, hours=24):
    """How many contacts the ladder would email in the next `hours` (overdue included)
    if its switch were on, whatever the switch says now, before the daily cap."""
    from app.models import FollowupContact
    if not ws:
        return 0
    horizon = _utcnow() + timedelta(hours=hours)
    due = FollowupContact.query.filter(
        FollowupContact.workspace_id == ws.id,
        FollowupContact.state == 'active',
        FollowupContact.touch_enabled == True,
        FollowupContact.is_followup_enabled == False,
        FollowupContact.scheduled_once == False,
        FollowupContact.recurring_enabled == False,
        FollowupContact.next_followup_at.isnot(None),
        FollowupContact.next_followup_at <= horizon,
    ).all()
    return sum(1 for fc in due if _ladder_sendable(fc, ws))


def _ladder_flag(fc, now, event_type, notes):
    """Ask a human to look at this contact: attention plus one event. Written only
    while attention is empty, so a row that stays due cannot flood the events table."""
    if fc.attention_at is None:
        fc.attention_at = now
        _record_event(fc, event_type, actor_type='scheduler',
                      from_state=fc.rung, to_state=fc.rung, notes=notes)
        return True
    return False


def _ladder_send_failed(fc, err, now, ws=None, event_type='touch_sent'):
    """A scheduled send did not go through: the shared backoff, then park the contact
    once auto-sending has been given up on, so a dead token cannot retry for ever.
    Parked = paused with a reason: rung and attempts are kept for a deliberate resume.
    Used by the ladder and by the one-time and recurring paths alike."""
    if _record_send_failure(fc, event_type, err, now):
        fc.auto_paused = True
        fc.exit_reason = 'send_failed'
        _ladder_set_next(fc, None, ws)
        _record_event(fc, 'ladder_parked', actor_type='scheduler',
                      from_state=fc.rung, to_state=fc.rung,
                      notes=f'auto-send given up after {fc.send_fail_count} failed sends')


def _ladder_exhaust(fc, now, ws=None):
    """The last allowed attempt is spent: park the contact. Only a load revives it."""
    old_rung = fc.rung
    fc.rung = 'dormant'
    fc.exit_reason = 'exhausted'
    _ladder_set_next(fc, None, ws)
    _record_event(fc, 'ladder_exhausted', actor_type='scheduler',
                  from_state=old_rung, to_state='dormant',
                  notes=f'{fc.touch_attempt or 0} attempts spent with no further load')


def _run_ladder_touches(now, hold_uids=(), skip_ids=()):
    """Send the warmth ladder's due touches; returns how many went out.

    Behind the workspace kill switch (fu_auto_enabled), the ladder's own consent
    flag (ladder_auto_enabled, default off) and the auto-send master switch. One attempt is spent per successful send; a failed send goes through
    _record_send_failure's backoff and spends nothing. `hold_uids` are users whose
    pre-send reply check failed; `skip_ids` are contacts another path already sent.
    """
    from app.models import FollowupContact, EmailAccount, Workspace
    gate = {}
    sent_today = {}            # workspace id -> ladder touches sent since its local midnight
    try:
        # One-time and recurring sends own the contacts flagged for them; a contact still
        # carrying the legacy drip flag is unplaced (scripts/migrate_to_ladder.py) and is never sent.
        q = FollowupContact.query.join(
            Workspace, Workspace.id == FollowupContact.workspace_id
        ).filter(
            Workspace.fu_auto_enabled == True,
            Workspace.ladder_auto_enabled == True,
            FollowupContact.state == 'active',
            FollowupContact.auto_paused == False,
            FollowupContact.touch_enabled == True,
            FollowupContact.is_followup_enabled == False,
            FollowupContact.scheduled_once == False,
            FollowupContact.recurring_enabled == False,
            FollowupContact.next_followup_at <= now,
            db.or_(FollowupContact.rung.is_(None),
                   FollowupContact.rung.notin_(_ladder.OFF_LADDER + ('client',))),
            # a refusal is never emailed, whatever its rung (it is dormant today; do not rely on it)
            db.or_(FollowupContact.exit_reason.is_(None),
                   FollowupContact.exit_reason != 'refused'),
        ).order_by(FollowupContact.next_followup_at)
        try:
            contacts = q.with_for_update(skip_locked=True, of=FollowupContact).all()
        except Exception:
            contacts = q.all()
    except Exception as e:
        app.logger.error(f'FU ladder query error: {e}')
        return 0

    sent = 0
    for fc in contacts:
        fc_id, fc_email = fc.id, fc.contact_email      # still readable after a rollback
        if fc_id in skip_ids or fc.user_id in hold_uids or not _auto_send_on(fc.workspace_id, gate):
            continue
        try:
            if fc.rung not in _LADDER_SENDABLE:
                # a legacy or unmigrated rung: never guess, ask a human (once)
                if _ladder_flag(fc, now, 'ladder_unknown', f'unrecognised rung {fc.rung!r}'):
                    db.session.commit()
                continue
            ws = db.session.get(Workspace, fc.workspace_id)
            cfg = _ladder_cfg(ws)         # each contact under its own workspace's settings
            if (fc.touch_attempt or 0) >= _ladder.budget_for(fc.rung, cfg):
                _ladder_exhaust(fc, now, ws)
                db.session.commit()
                continue

            acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
            if not acct:
                if _ladder_flag(fc, now, 'ladder_blocked', 'no email account connected: cannot send'):
                    db.session.commit()
                continue
            template_text = _template_for_rung(fc.user_id, fc.rung, fc)
            if not template_text:
                if _ladder_flag(fc, now, 'ladder_blocked', 'no follow-up template: cannot send'):
                    db.session.commit()
                continue
            # The daily cap comes last: a capped tick spends no attempt and flags nobody; the
            # contact stays due and goes out on a later day, oldest first.
            if ws.id not in sent_today:
                sent_today[ws.id] = _ladder_sent_today(ws)
            if sent_today[ws.id] >= cfg['daily_cap']:
                continue
            fu_dict, send_cfg = _followup_send_args(fc, acct)
            ok, err = send_followup_email(fu_dict, template_text, send_cfg, uid=fc.user_id)
            if ok:
                fc.touch_attempt = (fc.touch_attempt or 0) + 1
                fc.last_followup_sent_at = now
                fc.last_activity_at = now
                fc.attention_at = None
                fc.send_fail_count = 0
                _record_event(fc, 'touch_sent', actor_type='scheduler',
                              from_state=fc.rung, to_state=fc.rung,
                              notes=f'ladder touch {fc.touch_attempt} on {fc.rung}')
                sent_today[ws.id] += 1
                if fc.touch_attempt >= _ladder.budget_for(fc.rung, cfg):
                    _ladder_exhaust(fc, now, ws)
                else:
                    _ladder_set_next(fc, _ladder.next_touch_at(fc.rung, fc.touch_attempt, now, cfg), ws)
                sent += 1
            else:
                _ladder_send_failed(fc, err, now, ws)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'FU ladder error for {fc_email}: {e}')
            # The send may already have gone out, with its bookkeeping now rolled
            # back: the contact would stay due and be emailed again on every tick.
            # Push it out through the shared backoff in a fresh transaction.
            try:
                fresh = db.session.get(FollowupContact, fc_id)
                if fresh is not None:
                    _ladder_send_failed(fresh, f'unexpected error: {e}', now)
                    db.session.commit()
            except Exception:
                db.session.rollback()
                app.logger.exception(f'FU ladder could not back off {fc_email}')
    if sent:
        app.logger.info(f'FU scheduler: sent {sent} ladder touches')
    return sent


def _run_scheduled_followups():
    """Process due follow-up contacts and send emails. Called from daemon thread.
    Uses SELECT FOR UPDATE SKIP LOCKED on PostgreSQL to prevent duplicate sends.

    Three send paths remain, all behind the workspace kill switch (fu_auto_enabled) and
    the auto-send master switch, and all held for a user whose pre-send reply check failed:
      Path 0  a one-time send the owner scheduled for one contact;
      Path 2  a recurring send the owner set for one contact;
      Path 3  the warmth ladder (_run_ladder_touches), which also needs its own consent
              flag.
    One daily cap (ladder.daily_cap, per workspace, from its local midnight) covers all
    three: Paths 0 and 2 spend room first, the ladder gets what is left. A capped contact
    stays due and goes out on a later day. A send that fails five times parks the contact
    (auto_paused, exit_reason 'send_failed') on every path, so a dead token cannot retry for ever.
    The FU1-FU3 stage drip that used to be Path 1 is retired."""
    from app.models import FollowupContact, EmailAccount, Workspace
    now = _utcnow()
    with app.app_context():
        try:
            hold_uids = _prefetch_replies_before_sending(now)
        except Exception:
            db.session.rollback()
            app.logger.exception('pre-send reply check failed — holding all auto-sends this run')
            return 0
        _gate = {}

        def _allowed(c):
            return c.user_id not in hold_uids and _auto_send_on(c.workspace_id, _gate)

        # Workspace kill switch: with fu_auto_enabled off nothing here may email anyone;
        # due contacts stay in Overdue/Today's touches for manual sending. (Incident
        # 2026-07-25: 249 auto-FU2s went out because a path had no gate at all.) A broker
        # who asked us to stop (exit_reason 'refused') is never emailed by a date.
        def _owned(q):
            return q.join(Workspace, Workspace.id == FollowupContact.workspace_id).filter(
                Workspace.fu_auto_enabled == True,
                FollowupContact.state == 'active',
                FollowupContact.auto_paused == False,
                FollowupContact.rung != 'excluded',
                db.or_(FollowupContact.exit_reason.is_(None),
                       FollowupContact.exit_reason != 'refused'),
                FollowupContact.next_followup_at <= now,
            )

        processed_ids = set()
        sent_today = {}              # workspace id -> follow-ups emailed since its local midnight

        def _has_room(c):
            """The workspace's daily cap covers every automated follow-up, not just the ladder:
            this path spends the same room the ladder is left with afterwards."""
            ws_ = db.session.get(Workspace, c.workspace_id)
            if c.workspace_id not in sent_today:
                sent_today[c.workspace_id] = _auto_sent_today(ws_)
            return sent_today[c.workspace_id] < _ladder_cfg(ws_)['daily_cap']

        # ── Path 0: One-time scheduled sends ────────────────────────────────
        try:
            sq = _owned(FollowupContact.query).filter(FollowupContact.scheduled_once == True)
            try:
                sched_contacts = sq.with_for_update(skip_locked=True, of=FollowupContact).all()
            except Exception:
                sched_contacts = sq.all()
        except Exception as e:
            app.logger.error(f'FU scheduled-once query error: {e}')
            sched_contacts = []

        sched_total = 0
        for fc in sched_contacts:
            if fc.id in processed_ids or not _allowed(fc):
                continue
            try:
                if fc.state != 'active':
                    continue
                template_text = _followup_copy(fc.user_id, fc)
                if not template_text:
                    continue
                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue
                if not _has_room(fc):
                    continue             # capped: stays due and goes out on a later day
                fu_dict, cfg = _followup_send_args(fc, acct)
                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)
                if ok:
                    sent_today[fc.workspace_id] += 1
                    fc.scheduled_once = False
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now
                    _restore_contact_schedule(fc, now=now)
                    fc.send_fail_count = 0
                    _record_event(fc, 'scheduled_once_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage, notes='one-time send')
                    processed_ids.add(fc.id)
                    sched_total += 1
                else:
                    _ladder_send_failed(fc, err, now, event_type='scheduled_once_sent')
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU scheduled-once error for {fc.contact_email}: {e}')

        if sched_total:
            app.logger.info(f'FU scheduler: sent {sched_total} one-time scheduled follow-ups')

        # ── Path 2: Recurring sends ──────────────────────────────────────────
        # processed_ids already includes Path 0
        try:
            rq = _owned(FollowupContact.query).filter(FollowupContact.recurring_enabled == True)
            try:
                recurring = rq.with_for_update(skip_locked=True, of=FollowupContact).all()
            except Exception:
                recurring = rq.all()
        except Exception as e:
            app.logger.error(f'FU recurring scheduler query error: {e}')
            return sched_total

        rec_total = 0
        for fc in recurring:
            if fc.id in processed_ids or not _allowed(fc):
                continue  # already sent in Path 0 this run, or auto-send held/off
            try:
                if fc.state != 'active' or not fc.recurring_enabled:
                    continue
                if not fc.recurring_days or not fc.recurring_time:
                    continue

                template_text = _followup_copy(fc.user_id, fc)
                if not template_text:
                    continue

                acct = EmailAccount.query.filter_by(user_id=fc.user_id).first()
                if not acct:
                    continue

                if not _has_room(fc):
                    continue             # capped: stays due and goes out on a later day
                fu_dict, cfg = _followup_send_args(fc, acct)
                ok, err = send_followup_email(fu_dict, template_text, cfg, uid=fc.user_id)

                if ok:
                    sent_today[fc.workspace_id] += 1
                    fc.last_followup_sent_at = now
                    fc.last_activity_at = now
                    try:
                        fc.next_followup_at = _next_recurring_datetime(fc.recurring_days, fc.recurring_time)
                    except ValueError as ve:
                        app.logger.error(f'FU recurring next-date error for {fc.contact_email}: {ve}')
                        fc.next_followup_at = None

                    fc.send_fail_count = 0
                    _record_event(fc, 'recurring_sent', actor_type='scheduler',
                                  from_stage=fc.stage, to_stage=fc.stage, notes='recurring send')
                    processed_ids.add(fc.id)
                    rec_total += 1
                else:
                    _ladder_send_failed(fc, err, now, event_type='recurring_sent')

                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'FU recurring scheduler error for {fc.contact_email}: {e}')

        if rec_total:
            app.logger.info(f'FU scheduler: sent {rec_total} recurring follow-ups')

        # ── Path 3: Warmth-ladder touches ────────────────────────────────────
        # The ladder decides who is due and how often; fu_auto_enabled, its own
        # ladder_auto_enabled consent flag, the auto-send master switch and the
        # workspace's daily cap gate it.
        touch_total = _run_ladder_touches(now, hold_uids, processed_ids)

        # ── Path 4: Weekly digest emails (Mondays, after 06:00 user time) ────
        try:
            _maybe_send_digests(now)
        except Exception as e:
            app.logger.error(f'digest error: {e}')

        return sched_total + rec_total + touch_total

def _compose_digest(uid):
    """Weekly digest text from the same aggregates the dashboard shows."""
    d = _dashboard_data(uid)
    f7, h, t = d['funnel']['7'], d['health'], d['touches']
    lines = [
        'Your DAT Mailer week:',
        '',
        f"  Sent {f7['sent']} · Replied {f7['replied']} · Got info {f7['got_info']} · Booked {f7['booked']}",
        f"  Reply rate (30d): {h['reply_rate'] if h['reply_rate'] is not None else '-'}%",
        '',
        'Right now:',
        f"  Touches due today: {t['due_today']}",
        f"  Warm replies waiting for an answer: {d['attention']}",
        f"  Replies pending triage: {d['replies_pending']['total']}",
        f"  Pipeline contacts stalled 14d+ (Kanban stage 2 or higher): {h['rotting']}",
    ]
    if d['top_lanes']:
        top = d['top_lanes'][0]
        lines += ['', f"Top lane: {top['lane']} — {top['replies']} replies, {top['gave_info']} gave info"]
    lines += ['', 'Open the dashboard to act on it.']
    return '\n'.join(lines)


def _send_self_email(uid, subject, body):
    """Send a plain email to the user's own connected Gmail address."""
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=uid).first()
    if not acct or not acct.gmail_address:
        return False, 'no email account'
    try:
        try:
            service = _get_gmail_service(uid)
            mime_msg = MIMEText(body, 'plain')
            mime_msg['to'] = acct.gmail_address
            mime_msg['from'] = acct.gmail_address
            mime_msg['subject'] = subject
            import base64 as _b64
            raw = _b64.urlsafe_b64encode(mime_msg.as_bytes()).decode('utf-8')
            _gmail_send_with_retry(service, raw)
            return True, None
        except RuntimeError as _e:
            if 'not connected' not in str(_e).lower():
                raise
        msg = MIMEMultipart()
        msg['From'] = acct.gmail_address; msg['To'] = acct.gmail_address
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        _smtp_send_with_retry(msg, acct.gmail_address, acct.gmail_address, acct.gmail_password or '')
        return True, None
    except Exception as e:
        return False, str(e)


def _maybe_send_digests(now):
    """Mondays after 06:00 in each owner's time zone: one digest per workspace
    owner, deduped by that local date."""
    from app.models import Workspace
    sent = 0
    for ws in Workspace.query.all():
        cfg = dict(ws.pipeline_config or {})
        if not cfg.get('digest_enabled', True):
            continue
        local = now.replace(tzinfo=UTC).astimezone(_ws_tz(ws))
        if local.weekday() != 0 or local.hour < 6:
            continue
        today = local.strftime('%Y-%m-%d')
        if cfg.get('last_digest_at') == today:
            continue
        ok, _err = _send_self_email(ws.owner_id, 'Your weekly DAT Mailer digest',
                                    _compose_digest(ws.owner_id))
        if ok:
            cfg['last_digest_at'] = today
            ws.pipeline_config = cfg
            db.session.commit()
            sent += 1
    if sent:
        app.logger.info(f'digest: sent {sent} weekly digests')
    return sent


def scheduled_followup_worker():
    """Daemon thread: checks for due follow-ups every 15 minutes."""
    time.sleep(60)   # initial delay so server finishes starting up
    while True:
        try:
            with app.app_context():
                if _acquire_system_lease('followup_scheduler', lease_seconds=840):
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

def _migrate_reply_msg_id_per_user():
    """replies.msg_id used to be unique across ALL users, so an email that
    reached two users made the second one's fetch update the first one's reply.
    Swap the global unique constraint/index for UNIQUE (user_id, msg_id).
    PostgreSQL only (prod); idempotent. SQLite dev DBs get it from create_all."""
    if db.engine.dialect.name != 'postgresql':
        return
    with db.engine.connect() as conn:
        msg_col = """(SELECT attnum FROM pg_attribute
                      WHERE attrelid = 'replies'::regclass AND attname = 'msg_id')"""
        old_constraints = [r[0] for r in conn.execute(db.text(f"""
            SELECT conname FROM pg_constraint
            WHERE conrelid = 'replies'::regclass AND contype = 'u'
              AND conkey = ARRAY[{msg_col}]::smallint[]""")).fetchall()]
        old_indexes = [r[0] for r in conn.execute(db.text(f"""
            SELECT i.relname FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
            WHERE x.indrelid = 'replies'::regclass AND x.indisunique AND NOT x.indisprimary
              AND x.indnatts = 1 AND x.indkey[0] = {msg_col}
              AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = x.indexrelid)""")).fetchall()]
        conn.execute(db.text(
            'CREATE UNIQUE INDEX IF NOT EXISTS uq_replies_user_msg ON replies (user_id, msg_id)'))
        for name in old_constraints:
            conn.execute(db.text(f'ALTER TABLE replies DROP CONSTRAINT "{name}"'))
        for name in old_indexes:
            conn.execute(db.text(f'DROP INDEX IF EXISTS "{name}"'))
        conn.commit()
        if old_constraints or old_indexes:
            print(f'✓ Migration: replies.msg_id now unique per user (dropped {old_constraints + old_indexes})')


def _apply_add_column_migrations(conn, migrations):
    """ADD COLUMN for every (table, column, type) that is not there yet.

    Production schema changes ship through this list, not Alembic (an
    Alembic-only column took the app down on 2026-10-20), and a column that is
    already there raises — which is the normal case on every later start. So
    each failure is swallowed, which also hides a genuinely broken entry:
    tests/test_ladder_migration.py checks the entries against a legacy-shaped
    table for that reason. Returns the "table.column" names actually added.
    """
    added = []
    for tbl, col, typ in migrations:
        try:
            conn.execute(db.text(f'ALTER TABLE {tbl} ADD COLUMN {col} {typ}'))
            conn.commit()
            added.append(f'{tbl}.{col}')
            print(f'✓ Migration: added {tbl}.{col}')
        except Exception:
            conn.rollback()  # column already exists — ignore
    return added


with app.app_context():
    db.create_all()   # Creates all tables if they don't exist (safe to run repeatedly)
    # Inline migrations — safe to run on every startup (idempotent ADD COLUMN IF NOT EXISTS)
    _migrations = [
        ('email_accounts', 'google_refresh_token', 'TEXT'),
        ('email_accounts', 'google_access_token',  'TEXT'),
        ('email_accounts', 'token_expiry',         'TIMESTAMP'),
        ('email_accounts', 'daily_target',         'INTEGER DEFAULT 100'),
        ('follow_ups',     'auto_enabled',          'BOOLEAN DEFAULT TRUE'),
        ('follow_ups',     'scheduled_at',          'TIMESTAMP'),
        ('follow_ups',     'last_error',            'TEXT'),
        ('workspaces',     'fu_auto_enabled',       'BOOLEAN DEFAULT TRUE'),
        ('followup_contacts', 'recurring_enabled',  'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('followup_contacts', 'recurring_days',     'VARCHAR(20)'),
        ('followup_contacts', 'recurring_time',     'VARCHAR(5)'),
        ('followup_contacts', 'scheduled_once',     'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('replies',           'thread_id',           'VARCHAR(255)'),
        # Pipeline / Kanban (Follow-up v2) — delivered inline for reliable startup creation
        ('workspaces',        'pipeline_config',     'JSON'),
        ('users',             'followup_view_mode',  "VARCHAR(20) DEFAULT 'table'"),
        ('followup_contacts', 'pipeline_stage',      'INTEGER NOT NULL DEFAULT 1'),
        ('replies',           'reply_filter_key',    'VARCHAR(50)'),
        ('replies',           'auto_advanced',       'BOOLEAN NOT NULL DEFAULT FALSE'),
        # Semi-automatic reply triage
        ('replies',           'triage_category',     'VARCHAR(20)'),
        ('replies',           'triage_confidence',   'FLOAT'),
        ('replies',           'auto_processed',      'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('replies',           'auto_action',         'VARCHAR(20)'),
        # Follow-up cadence engine (Today's touches)
        ('followup_contacts', 'touch_enabled',       'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('followup_contacts', 'attention_at',        'TIMESTAMP'),
        ('followup_contacts', 'send_fail_count',     'INTEGER NOT NULL DEFAULT 0'),
        # Warmth ladder position. Inline delivery is REQUIRED (Alembic does not
        # migrate the live DB); server defaults keep existing rows valid at once.
        ('followup_contacts', 'rung',                "VARCHAR(20) NOT NULL DEFAULT 'cold'"),
        ('followup_contacts', 'load_count',          'INTEGER NOT NULL DEFAULT 0'),
        ('followup_contacts', 'touch_attempt',       'INTEGER NOT NULL DEFAULT 0'),
        ('followup_contacts', 'auto_paused',         'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('followup_contacts', 'last_load_at',        'TIMESTAMP'),
        ('followup_contacts', 'exit_reason',         'VARCHAR(40)'),
        # Ladder consent flag: default OFF so a deploy cannot start auto-sending.
        ('workspaces',        'ladder_auto_enabled', 'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('users',             'session_version',     'INTEGER NOT NULL DEFAULT 0'),
        ('replies',           'matched_recipient',   'VARCHAR(255)'),
        ('replies',           'date_checked',        'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('replies',           'rates_parsed',        'BOOLEAN NOT NULL DEFAULT FALSE'),
        # Bulk follow-up send jobs (SendJob kind discriminator + per-contact log).
        # Inline delivery is REQUIRED: prod schema changes only apply here — the
        # Alembic releaseCommand does not run against the live DB (a3b4c5d6e7f8
        # exists for fresh installs only).
        ('send_jobs',         'kind',                "VARCHAR(20) NOT NULL DEFAULT 'outreach'"),
        ('send_jobs',         'log_json',            'TEXT'),
    ]
    try:
        with db.engine.connect() as _conn:
            _apply_add_column_migrations(_conn, _migrations)
    except Exception as _e:
        print(f'Migration check skipped: {_e}')
    # Recover send jobs stranded by a restart — no worker thread survives a process
    # restart, so any job still 'queued'/'running' at boot is dead. Mark them 'error'
    # so users aren't blocked by the "Already running" guard after a deploy/restart.
    try:
        from app.models import SendJob
        _stranded = SendJob.query.filter(SendJob.status.in_(['queued', 'running'])).all()
        for _j in _stranded:
            _j.status      = 'error'
            _j.error_msg   = 'Auto-recovered: server restarted while job was in progress'
            _j.finished_at = _utcnow()
        if _stranded:
            db.session.commit()
            print(f'✓ Recovered {len(_stranded)} stranded send job(s) after restart')
    except Exception as _e:
        db.session.rollback()
        print(f'Send-job recovery skipped: {_e}')
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
            _conn.execute(db.text(
                'CREATE INDEX IF NOT EXISTS ix_sends_user_status_sent_at ON sends (user_id, status, sent_at)'
            ))
            _conn.execute(db.text(
                'CREATE INDEX IF NOT EXISTS ix_sends_user_recipient_email ON sends (user_id, recipient_email)'
            ))
            _conn.commit()
    except Exception:
        pass
    try:
        _migrate_reply_msg_id_per_user()
    except Exception as _e:
        print(f'replies msg_id migration skipped: {_e}')
    # Mark any DB jobs still "running" as "interrupted" (handles deploy mid-send)
    try:
        from app.models import SendJob
        stale = SendJob.query.filter(SendJob.status.in_(['queued', 'running'])).all()
        if stale:
            for _j in stale:
                _j.status = 'interrupted'
                _j.finished_at = _utcnow()
            db.session.commit()
            print(f'✓ Marked {len(stale)} stale send job(s) as interrupted')
    except Exception as _e:
        print(f'Stale job cleanup skipped: {_e}')
    try:
        auto_create_admin()
    except Exception as _e:
        print(f'auto_create_admin skipped: {_e}')
    try:
        _recover_followup_data()
    except Exception as _e:
        db.session.rollback()
        print(f'follow-up recovery skipped: {_e}')

# ── Start background follow-up scheduler ──────────────────────────────────────
if _scheduler_enabled:
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
