"""
DAT Mailer v2 — Database Models
All tables include workspace_id for future multi-tenant isolation.
"""
import uuid
from datetime import datetime, UTC
from app.extensions import db


def _uuid():
    return str(uuid.uuid4())


def _utcnow():
    """Naive UTC now (_utcnow is deprecated in py3.12)."""
    return datetime.now(UTC).replace(tzinfo=None)


# ── USERS & WORKSPACES ──────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    email        = db.Column(db.String(255), unique=True, nullable=False)
    name         = db.Column(db.String(255))
    password     = db.Column(db.String(255), nullable=False)   # bcrypt hash
    role         = db.Column(db.String(20), default='user')    # 'admin' | 'user'
    invited_by   = db.Column(db.String(255))
    followup_view_mode = db.Column(db.String(20), default='table', server_default='table')  # 'table' | 'kanban'
    created_at   = db.Column(db.DateTime, default=_utcnow)
    last_login   = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email, 'name': self.name,
            'role': self.role, 'invited_by': self.invited_by,
            'followup_view_mode': self.followup_view_mode or 'table',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M') if self.last_login else None,
        }


# ── PIPELINE / KANBAN CONFIG DEFAULTS ────────────────────────────────────────
# Customizable per-workspace (editing UI is phase 2); these are the fallbacks.
PIPELINE_DEFAULT_STAGES = [
    {"id": 1, "name": "Follow Pending",       "color": "#ff6b6b"},
    {"id": 2, "name": "Got info (1st)",       "color": "#ffd93d"},
    {"id": 3, "name": "Got info 2 (Repeat)",  "color": "#6bcf7f"},
    {"id": 4, "name": "Regular info",         "color": "#4c6ef5"},
    {"id": 5, "name": "Booked",               "color": "#9c36b5"},
]

PIPELINE_DEFAULT_REPLY_FILTERS = [
    {"key": "can_use",       "label": "we can use you",                 "auto_advance_to": 2},
    {"key": "no_landstar",   "label": "can not use Landstar",           "auto_advance_to": None},
    {"key": "no_landstar_v2", "label": "no Landstar",                   "auto_advance_to": None},
    {"key": "dnu",           "label": "DNU",                            "auto_advance_to": None},
    {"key": "no_contact",    "label": "Please don't contact me anymore.", "auto_advance_to": None},
    {"key": "cannot_use_ls", "label": "We cannot use landstar",         "auto_advance_to": None},
]


class Workspace(db.Model):
    __tablename__ = 'workspaces'

    id               = db.Column(db.String(36), primary_key=True, default=_uuid)
    name             = db.Column(db.String(255), nullable=False)
    owner_id         = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    plan             = db.Column(db.String(20), default='free')  # 'free' | 'starter' | 'pro'
    fu_auto_enabled  = db.Column(db.Boolean, default=True, nullable=False, server_default='1')
    pipeline_config  = db.Column(db.JSON, nullable=True)   # {stages: [...], reply_filters: [...]}
    created_at       = db.Column(db.DateTime, default=_utcnow)

    owner = db.relationship('User', backref='owned_workspaces')

    def get_stages(self):
        """Pipeline stages for this workspace, falling back to defaults."""
        config = self.pipeline_config or {}
        stages = config.get('stages')
        return stages if stages else [dict(s) for s in PIPELINE_DEFAULT_STAGES]

    def get_reply_filters(self):
        """Reply filters for this workspace, falling back to defaults."""
        config = self.pipeline_config or {}
        filters = config.get('reply_filters')
        return filters if filters else [dict(f) for f in PIPELINE_DEFAULT_REPLY_FILTERS]


class Invitation(db.Model):
    __tablename__ = 'invitations'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    invited_by   = db.Column(db.String(36), db.ForeignKey('users.id'))
    email        = db.Column(db.String(255), nullable=False)
    token        = db.Column(db.String(255), unique=True, nullable=False)
    status       = db.Column(db.String(20), default='pending')  # 'pending' | 'accepted' | 'expired'
    created_at   = db.Column(db.DateTime, default=_utcnow)
    expires_at   = db.Column(db.DateTime)   # NULL = no expiry (legacy); new invites set 7-day expiry
    used_at      = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email, 'status': self.status,
            'invited_by': self.invited_by,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'used_at': self.used_at.strftime('%Y-%m-%d %H:%M') if self.used_at else None,
            'expires_at': self.expires_at.strftime('%Y-%m-%d %H:%M') if self.expires_at else None,
            'used': self.status == 'accepted',
            'token': self.token if self.status == 'pending' else None,  # only for pending
        }


# ── EMAIL ACCOUNT (per user/workspace) ─────────────────────────────────────

class EmailAccount(db.Model):
    __tablename__ = 'email_accounts'

    id             = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id   = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    gmail_address        = db.Column(db.String(255), default='')
    gmail_password       = db.Column(db.Text, default='')   # legacy App Password, Fernet-encrypted
    google_refresh_token = db.Column(db.Text, nullable=True)  # OAuth2 refresh token, Fernet-encrypted
    google_access_token  = db.Column(db.Text, nullable=True)  # OAuth2 access token, Fernet-encrypted
    token_expiry         = db.Column(db.DateTime, nullable=True)  # UTC expiry of access token
    your_name      = db.Column(db.String(255), default='')
    your_company   = db.Column(db.String(255), default='')
    your_phone     = db.Column(db.String(100), default='')
    delay_min      = db.Column(db.Integer, default=20)
    delay_max      = db.Column(db.Integer, default=45)
    daily_target   = db.Column(db.Integer, default=100)
    created_at     = db.Column(db.DateTime, default=_utcnow)
    updated_at     = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    user = db.relationship('User', backref='email_accounts')

    def to_config_dict(self):
        return {
            'gmail_address':      self.gmail_address,
            'gmail_app_password': self.gmail_password,
            'gmail_connected':    bool(self.google_refresh_token),
            'your_name':          self.your_name,
            'your_company':       self.your_company,
            'your_phone':         self.your_phone,
            'delay_min':          self.delay_min,
            'delay_max':          self.delay_max,
            'daily_target':       self.daily_target or 100,
        }


# ── SENDS ───────────────────────────────────────────────────────────────────

class Send(db.Model):
    __tablename__ = 'sends'

    id               = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id          = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id     = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    recipient_email  = db.Column(db.String(255), nullable=False)
    origin           = db.Column(db.String(255), default='')
    destination      = db.Column(db.String(255), default='')
    load_date        = db.Column(db.String(50), default='')
    equipment        = db.Column(db.String(100), default='')
    weight           = db.Column(db.String(100), default='')
    company          = db.Column(db.String(255), default='')
    template_variant = db.Column(db.Integer, default=1)
    status           = db.Column(db.String(20), default='sent')  # 'sent' | 'error' | 'skipped'
    error_msg        = db.Column(db.Text)
    sent_at          = db.Column(db.DateTime, default=_utcnow)

    user = db.relationship('User', backref='sends')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.recipient_email,
            'origin': self.origin, 'destination': self.destination,
            'date': self.load_date, 'equip': self.equipment,
            'weight': self.weight, 'company': self.company,
            'variant': self.template_variant, 'status': self.status,
            'error': self.error_msg or '',
            'timestamp': self.sent_at.strftime('%Y-%m-%d %H:%M:%S') if self.sent_at else '',
        }


# ── REPLIES ─────────────────────────────────────────────────────────────────

class Reply(db.Model):
    __tablename__ = 'replies'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    msg_id       = db.Column(db.String(512), unique=True, nullable=False)
    thread_id    = db.Column(db.String(255), nullable=True)   # Gmail threadId
    from_email   = db.Column(db.String(255), default='')
    from_name    = db.Column(db.String(255), default='')
    subject      = db.Column(db.String(512), default='')
    body         = db.Column(db.Text, default='')
    route        = db.Column(db.String(512), default='')
    status       = db.Column(db.String(30), default='new')  # 'new' | 'interested' | 'not_interested'
    received_at  = db.Column(db.DateTime, default=_utcnow)
    classified_at = db.Column(db.DateTime)

    user = db.relationship('User', backref='replies')

    __table_args__ = (
        db.Index('ix_reply_user_received', 'user_id', 'received_at'),
        db.Index('ix_reply_user_status', 'user_id', 'status'),
        db.Index('ix_reply_user_email', 'user_id', 'from_email'),
    )

    def to_dict(self):
        return {
            'id': self.id, 'msg_id': self.msg_id,
            'email': self.from_email, 'from': self.from_name,
            'subject': self.subject, 'body': self.body,
            'route': self.route, 'status': self.status,
            'received_at': self.received_at.strftime('%Y-%m-%d %H:%M') if self.received_at else '',
        }


# ── FOLLOW-UPS ───────────────────────────────────────────────────────────────

class FollowUp(db.Model):
    __tablename__ = 'follow_ups'

    id              = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id         = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id    = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    contact_email   = db.Column(db.String(255), nullable=False)
    contact_name    = db.Column(db.String(255), default='')
    route           = db.Column(db.String(512), default='')
    reply_subject   = db.Column(db.String(512), default='')
    reply_msg_id    = db.Column(db.String(512), default='')
    level           = db.Column(db.String(10), default='FU1')   # 'FU1'|'FU2'|'FU3'|'closed'
    status          = db.Column(db.String(20), default='pending')  # 'pending'|'sent'|'paused'|'failed'|'closed'
    added_at        = db.Column(db.DateTime, default=_utcnow)
    last_contact    = db.Column(db.DateTime)
    last_fu_sent    = db.Column(db.DateTime)
    notes           = db.Column(db.Text, default='')
    auto_enabled    = db.Column(db.Boolean, default=True, nullable=False, server_default='1')
    scheduled_at    = db.Column(db.DateTime, nullable=True)   # manual reschedule override
    last_error      = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref='follow_ups')

    def next_send_at(self):
        """Compute expected next send datetime (UTC). Returns None if closed/paused."""
        from datetime import timedelta
        _delays = {'FU1': 3, 'FU2': 5, 'FU3': 7}
        if self.status in ('closed', 'paused') or self.level == 'closed':
            return None
        if self.scheduled_at:
            return self.scheduled_at
        delay = _delays.get(self.level)
        if not delay:
            return None
        ref = self.last_fu_sent if self.level != 'FU1' else (self.last_contact or self.added_at)
        return (ref + timedelta(days=delay)) if ref else None

    def to_dict(self):
        nsa = self.next_send_at()
        return {
            'id': self.id,
            'email': self.contact_email, 'from': self.contact_name,
            'route': self.route, 'reply_subject': self.reply_subject,
            'reply_msg_id': self.reply_msg_id,
            'level': self.level, 'status': self.status,
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M') if self.added_at else '',
            'last_contact': self.last_contact.strftime('%Y-%m-%d %H:%M') if self.last_contact else '',
            'last_fu_sent': self.last_fu_sent.strftime('%Y-%m-%d %H:%M') if self.last_fu_sent else None,
            'next_send_at': nsa.strftime('%Y-%m-%d') if nsa else None,
            'auto_enabled': bool(self.auto_enabled),
            'last_error': self.last_error or None,
            'notes': self.notes or '',
        }


# ── FOLLOW-UP v2 (new models) ────────────────────────────────────────────────

class FollowupContact(db.Model):
    __tablename__ = 'followup_contacts'
    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), nullable=False)
    contact_email = db.Column(db.String(255), nullable=False)
    contact_name = db.Column(db.String(255))
    company_name = db.Column(db.String(255))
    state = db.Column(db.String(20), default='active', nullable=False)
    stage = db.Column(db.String(30), default='fu1_scheduled', nullable=False)
    pipeline_stage = db.Column(db.Integer, default=1, nullable=False, server_default='1')  # Kanban stage 1-5
    is_followup_enabled = db.Column(db.Boolean, default=True, nullable=False)
    next_followup_at = db.Column(db.DateTime)
    last_followup_sent_at = db.Column(db.DateTime)
    last_reply_at = db.Column(db.DateTime)
    last_activity_at = db.Column(db.DateTime)
    initial_email_sent_at = db.Column(db.DateTime)
    fu1_sent_at = db.Column(db.DateTime)
    fu2_sent_at = db.Column(db.DateTime)
    fu3_sent_at = db.Column(db.DateTime)
    completed_fu3_at = db.Column(db.DateTime)
    loads_at = db.Column(db.DateTime)
    warm_at = db.Column(db.DateTime)
    blocked_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    paused_at = db.Column(db.DateTime)
    resumed_at = db.Column(db.DateTime)
    block_reason = db.Column(db.String(512))
    pause_reason = db.Column(db.String(512))
    close_reason = db.Column(db.String(512))
    source_thread_id = db.Column(db.String(512))
    source_reply_id = db.Column(db.String(512))
    reply_subject = db.Column(db.String(512))
    reply_msg_id = db.Column(db.String(512))
    current_route = db.Column(db.String(512))
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)
    recurring_enabled = db.Column(db.Boolean, default=False, nullable=False, server_default='false')
    recurring_days    = db.Column(db.String(20))   # "0,2,4" = Mon/Wed/Fri (0=Mon...6=Sun)
    recurring_time    = db.Column(db.String(5))    # "HH:MM" stored as UTC
    scheduled_once    = db.Column(db.Boolean, default=False, nullable=False, server_default='false')

    user = db.relationship('User', backref='followup_contacts')

    __table_args__ = (
        db.Index('ix_fc_ws_state', 'workspace_id', 'state'),
        db.Index('ix_fc_ws_stage', 'workspace_id', 'stage'),
        db.Index('ix_fc_ws_next', 'workspace_id', 'next_followup_at'),
        db.UniqueConstraint('workspace_id', 'contact_email', name='uq_fc_ws_email'),
        db.Index('ix_fc_user_state', 'user_id', 'state'),
    )

    def to_dict(self):
        fmt = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None
        return {
            'id': self.id,
            'contact_email': self.contact_email,
            'contact_name': self.contact_name or '',
            'company_name': self.company_name or '',
            'state': self.state,
            'stage': self.stage,
            'pipeline_stage': self.pipeline_stage or 1,
            'is_followup_enabled': self.is_followup_enabled,
            'next_followup_at': fmt(self.next_followup_at),
            'last_followup_sent_at': fmt(self.last_followup_sent_at),
            'last_reply_at': fmt(self.last_reply_at),
            'last_activity_at': fmt(self.last_activity_at),
            'current_route': self.current_route or '',
            'notes': self.notes or '',
            'reply_subject': self.reply_subject or '',
            'recurring_enabled': self.recurring_enabled,
            'recurring_days':    self.recurring_days or '',
            'recurring_time':    self.recurring_time or '',
            'scheduled_once':    self.scheduled_once,
        }


class FollowupEvent(db.Model):
    __tablename__ = 'followup_events'
    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    followup_contact_id = db.Column(db.String(36), db.ForeignKey('followup_contacts.id', ondelete='CASCADE'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    event_type = db.Column(db.String(30), nullable=False)
    from_state = db.Column(db.String(20))
    to_state = db.Column(db.String(20))
    from_stage = db.Column(db.String(30))
    to_stage = db.Column(db.String(30))
    event_at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    actor_type = db.Column(db.String(20), nullable=False)
    actor_user_id = db.Column(db.String(36))
    metadata_json = db.Column(db.Text)
    notes = db.Column(db.String(512))

    contact = db.relationship('FollowupContact', backref=db.backref('events', cascade='all, delete-orphan'))

    __table_args__ = (
        db.Index('ix_fe_contact_at', 'followup_contact_id', 'event_at'),
        db.Index('ix_fe_workspace_type_at', 'workspace_id', 'event_type', 'event_at'),
        db.Index('ix_fe_actor_type_at', 'actor_user_id', 'event_type', 'event_at'),
    )


class FollowupSettings(db.Model):
    __tablename__ = 'followup_settings'
    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), unique=True, nullable=False)
    fu1_delay_days = db.Column(db.Integer, default=3, nullable=False)
    fu2_delay_days = db.Column(db.Integer, default=5, nullable=False)
    fu3_delay_days = db.Column(db.Integer, default=7, nullable=False)
    auto_stop_on_reply = db.Column(db.Boolean, default=True, nullable=False)
    default_followup_enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)


# ── PIPELINE ─────────────────────────────────────────────────────────────────

class PipelineContact(db.Model):
    __tablename__ = 'pipeline_contacts'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    email        = db.Column(db.String(255), nullable=False)
    company      = db.Column(db.String(255), default='')
    route        = db.Column(db.String(512), default='')
    stage        = db.Column(db.String(30), default='new_lead')
    # 'new_lead'|'contacted'|'replied'|'interested'|'deal'|'lost'
    deal_value   = db.Column(db.Numeric(10, 2))
    notes        = db.Column(db.Text, default='')
    added_at     = db.Column(db.DateTime, default=_utcnow)
    updated_at   = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    user = db.relationship('User', backref='pipeline_contacts')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'email', name='uq_pipeline_user_email'),
    )

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email,
            'company': self.company, 'route': self.route,
            'stage': self.stage,
            'deal_value': str(self.deal_value) if self.deal_value else '',
            'notes': self.notes or '',
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M') if self.added_at else '',
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M') if self.updated_at else '',
        }


# ── STOP LIST ────────────────────────────────────────────────────────────────

class StopListEntry(db.Model):
    __tablename__ = 'stop_list'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    type         = db.Column(db.String(10), nullable=False)   # 'email' | 'domain'
    value        = db.Column(db.String(255), nullable=False)
    reason       = db.Column(db.String(255), default='')
    added_at     = db.Column(db.DateTime, default=_utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'type', 'value', name='uq_stop_user_type_value'),
    )

    def to_dict(self):
        return {'id': self.id, 'type': self.type, 'value': self.value, 'reason': self.reason}


# ── TEMPLATES ────────────────────────────────────────────────────────────────

class Template(db.Model):
    __tablename__ = 'templates'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    type         = db.Column(db.String(20), nullable=False)  # 'outreach' | 'followup'
    level        = db.Column(db.String(50))                   # NULL for outreach; any name for followup templates
    name         = db.Column(db.String(255), default='')
    body         = db.Column(db.Text, nullable=False)
    sort_order   = db.Column(db.Integer, default=0)
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=_utcnow)

    __table_args__ = (
        db.Index('ix_template_user_type_active', 'user_id', 'type', 'is_active'),
    )

    def to_dict(self):
        return {
            'id': self.id, 'type': self.type, 'level': self.level,
            'name': self.name, 'body': self.body,
            'sort_order': self.sort_order, 'is_active': self.is_active,
        }


# ── USAGE TRACKING ───────────────────────────────────────────────────────────

class UsageEvent(db.Model):
    __tablename__ = 'usage_events'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id      = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    event_type   = db.Column(db.String(50), nullable=False)
    # 'email_sent' | 'reply_fetched' | 'followup_sent'
    count        = db.Column(db.Integer, default=1)
    period_date  = db.Column(db.Date, default=_utcnow)
    created_at   = db.Column(db.DateTime, default=_utcnow)


# ── AUDIT LOG ────────────────────────────────────────────────────────────────

class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id            = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id       = db.Column(db.String(36), db.ForeignKey('users.id'))
    workspace_id  = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    action        = db.Column(db.String(100), nullable=False)
    # e.g. 'login', 'send_batch', 'mark_interested', 'config_save', 'followup_sent'
    resource_type = db.Column(db.String(50))   # 'reply', 'send', 'followup', etc.
    resource_id   = db.Column(db.String(36))
    detail        = db.Column(db.Text)          # JSON string for extra context
    ip_address    = db.Column(db.String(45))    # IPv4 or IPv6
    created_at    = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'action': self.action,
            'resource_type': self.resource_type, 'resource_id': self.resource_id,
            'detail': self.detail, 'ip_address': self.ip_address,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else '',
        }


# ── PASSWORD RESET TOKENS ────────────────────────────────────────────────────

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'

    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(255), nullable=False, index=True)
    token      = db.Column(db.String(86), unique=True, nullable=False)  # urlsafe base64, 64 chars
    created_at = db.Column(db.DateTime, default=_utcnow)
    used_at    = db.Column(db.DateTime, nullable=True)   # NULL = not yet used


# ── SEND JOBS ─────────────────────────────────────────────────────────────────

class SendJob(db.Model):
    __tablename__ = 'send_jobs'

    id          = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id     = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    status      = db.Column(db.String(20), default='queued')  # queued|running|done|interrupted
    total       = db.Column(db.Integer, default=0)
    sent        = db.Column(db.Integer, default=0)
    errors      = db.Column(db.Integer, default=0)
    skipped     = db.Column(db.Integer, default=0)
    started_at  = db.Column(db.DateTime, default=_utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)
    error_msg   = db.Column(db.Text, nullable=True)


class SystemLease(db.Model):
    __tablename__ = 'system_leases'

    name        = db.Column(db.String(100), primary_key=True)
    owner       = db.Column(db.String(255), nullable=False)
    lease_until = db.Column(db.DateTime, nullable=False)
    updated_at  = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)


# ── PERFORMANCE INDEXES ───────────────────────────────────────────────────────
# Applied via db.create_all() on first run; for existing DBs run flask db migrate.

db.Index('ix_usage_user_date',    UsageEvent.user_id,  UsageEvent.period_date)
db.Index('ix_sends_user_sent',    Send.user_id,        Send.sent_at)
db.Index('ix_followups_status',   FollowUp.status,     FollowUp.level)
db.Index('ix_replies_user_id',    Reply.user_id)
db.Index('ix_audit_user_id',      AuditLog.user_id)
