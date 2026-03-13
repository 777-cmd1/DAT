"""
DAT Mailer v2 — Database Models
All tables include workspace_id for future multi-tenant isolation.
"""
import uuid
from datetime import datetime
from app.extensions import db


def _uuid():
    return str(uuid.uuid4())


# ── USERS & WORKSPACES ──────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    email        = db.Column(db.String(255), unique=True, nullable=False)
    name         = db.Column(db.String(255))
    password     = db.Column(db.String(255), nullable=False)   # bcrypt hash
    role         = db.Column(db.String(20), default='user')    # 'admin' | 'user'
    invited_by   = db.Column(db.String(255))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    last_login   = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email, 'name': self.name,
            'role': self.role, 'invited_by': self.invited_by,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M') if self.last_login else None,
        }


class Workspace(db.Model):
    __tablename__ = 'workspaces'

    id         = db.Column(db.String(36), primary_key=True, default=_uuid)
    name       = db.Column(db.String(255), nullable=False)
    owner_id   = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    plan       = db.Column(db.String(20), default='free')  # 'free' | 'starter' | 'pro'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref='owned_workspaces')


class Invitation(db.Model):
    __tablename__ = 'invitations'

    id           = db.Column(db.String(36), primary_key=True, default=_uuid)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    invited_by   = db.Column(db.String(36), db.ForeignKey('users.id'))
    email        = db.Column(db.String(255), nullable=False)
    token        = db.Column(db.String(255), unique=True, nullable=False)
    status       = db.Column(db.String(20), default='pending')  # 'pending' | 'accepted' | 'expired'
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at   = db.Column(db.DateTime)   # NULL = no expiry (legacy); new invites set 7-day expiry
    used_at      = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id, 'email': self.email, 'status': self.status,
            'invited_by': self.invited_by,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M') if self.created_at else None,
            'used_at': self.used_at.strftime('%Y-%m-%d %H:%M') if self.used_at else None,
            'used': self.status == 'accepted',
        }


# ── EMAIL ACCOUNT (per user/workspace) ─────────────────────────────────────

class EmailAccount(db.Model):
    __tablename__ = 'email_accounts'

    id             = db.Column(db.String(36), primary_key=True, default=_uuid)
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    workspace_id   = db.Column(db.String(36), db.ForeignKey('workspaces.id'))
    gmail_address  = db.Column(db.String(255), default='')
    gmail_password = db.Column(db.Text, default='')   # stored Fernet-encrypted; decrypt via decrypt_field() in app.py
    your_name      = db.Column(db.String(255), default='')
    your_company   = db.Column(db.String(255), default='')
    your_phone     = db.Column(db.String(100), default='')
    delay_min      = db.Column(db.Integer, default=20)
    delay_max      = db.Column(db.Integer, default=45)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref='email_accounts')

    def to_config_dict(self):
        return {
            'gmail_address':      self.gmail_address,
            'gmail_app_password': self.gmail_password,
            'your_name':          self.your_name,
            'your_company':       self.your_company,
            'your_phone':         self.your_phone,
            'delay_min':          self.delay_min,
            'delay_max':          self.delay_max,
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
    sent_at          = db.Column(db.DateTime, default=datetime.utcnow)

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
    from_email   = db.Column(db.String(255), default='')
    from_name    = db.Column(db.String(255), default='')
    subject      = db.Column(db.String(512), default='')
    body         = db.Column(db.Text, default='')
    route        = db.Column(db.String(512), default='')
    status       = db.Column(db.String(30), default='new')  # 'new' | 'interested' | 'not_interested'
    received_at  = db.Column(db.DateTime, default=datetime.utcnow)
    classified_at = db.Column(db.DateTime)

    user = db.relationship('User', backref='replies')

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
    status          = db.Column(db.String(20), default='pending')  # 'pending'|'sent'|'closed'
    added_at        = db.Column(db.DateTime, default=datetime.utcnow)
    last_contact    = db.Column(db.DateTime)
    last_fu_sent    = db.Column(db.DateTime)
    notes           = db.Column(db.Text, default='')

    user = db.relationship('User', backref='follow_ups')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.contact_email, 'from': self.contact_name,
            'route': self.route, 'reply_subject': self.reply_subject,
            'reply_msg_id': self.reply_msg_id,
            'level': self.level, 'status': self.status,
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M') if self.added_at else '',
            'last_contact': self.last_contact.strftime('%Y-%m-%d %H:%M') if self.last_contact else '',
            'last_fu_sent': self.last_fu_sent.strftime('%Y-%m-%d %H:%M') if self.last_fu_sent else None,
            'notes': self.notes or '',
        }


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
    added_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    added_at     = db.Column(db.DateTime, default=datetime.utcnow)

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
    level        = db.Column(db.String(10))                   # NULL for outreach, 'FU1/FU2/FU3' for fu
    name         = db.Column(db.String(255), default='')
    body         = db.Column(db.Text, nullable=False)
    sort_order   = db.Column(db.Integer, default=0)
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

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
    period_date  = db.Column(db.Date, default=datetime.utcnow)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)


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
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at    = db.Column(db.DateTime, nullable=True)   # NULL = not yet used


# ── PERFORMANCE INDEXES ───────────────────────────────────────────────────────
# Applied via db.create_all() on first run; for existing DBs run flask db migrate.

db.Index('ix_usage_user_date',    UsageEvent.user_id,  UsageEvent.period_date)
db.Index('ix_sends_user_sent',    Send.user_id,        Send.sent_at)
db.Index('ix_followups_status',   FollowUp.status,     FollowUp.level)
db.Index('ix_replies_user_id',    Reply.user_id)
db.Index('ix_audit_user_id',      AuditLog.user_id)
