# Follow-up System Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Security note:** Frontend uses `innerHTML` for dynamic rendering. All user data MUST be escaped via the existing `esc()` function before insertion. The follow-up page is behind `@login_required` authentication.

**Goal:** Replace the simple FU1→FU2→FU3 follow-up system with a proper contact lifecycle system featuring separated stages/states, event history, manual actions, configurable settings, and conversion analytics.

**Architecture:** Three new SQLAlchemy models (`FollowupContact`, `FollowupEvent`, `FollowupSettings`) replace the existing `FollowUp` model. State machine logic is centralized in a helper function. Scheduler is rewritten to use new models. Frontend is fully rewritten with card-based layout, filters, and analytics tab.

**Tech Stack:** Flask, SQLAlchemy, PostgreSQL (prod) / SQLite (dev), Flask-Migrate (Alembic), vanilla JS frontend

**Spec:** `docs/superpowers/specs/2026-03-25-followup-system-upgrade-design.md`

**Branch:** `feature/followup-v2` (create before starting)

---

### Task 1: Create feature branch and new models

**Files:**
- Modify: `app/models.py` (lines 178–230 — existing FollowUp model area)

- [ ] **Step 1: Create feature branch**

```bash
git checkout -b feature/followup-v2
```

- [ ] **Step 2: Add FollowupContact model to app/models.py**

Add AFTER the existing FollowUp model (do NOT remove it yet). Include all fields from spec Section 2.1:

```python
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
            'is_followup_enabled': self.is_followup_enabled,
            'next_followup_at': fmt(self.next_followup_at),
            'last_followup_sent_at': fmt(self.last_followup_sent_at),
            'last_reply_at': fmt(self.last_reply_at),
            'last_activity_at': fmt(self.last_activity_at),
            'current_route': self.current_route or '',
            'notes': self.notes or '',
            'reply_subject': self.reply_subject or '',
        }
```

- [ ] **Step 3: Add FollowupEvent model**

```python
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
    event_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    actor_type = db.Column(db.String(20), nullable=False)
    actor_user_id = db.Column(db.String(36))
    metadata_json = db.Column(db.Text)
    notes = db.Column(db.String(512))

    contact = db.relationship('FollowupContact', backref=db.backref('events', cascade='all, delete-orphan'))

    __table_args__ = (
        db.Index('ix_fe_contact_at', 'followup_contact_id', 'event_at'),
    )
```

- [ ] **Step 4: Add FollowupSettings model**

```python
class FollowupSettings(db.Model):
    __tablename__ = 'followup_settings'
    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    workspace_id = db.Column(db.String(36), db.ForeignKey('workspaces.id'), unique=True, nullable=False)
    fu1_delay_days = db.Column(db.Integer, default=3, nullable=False)
    fu2_delay_days = db.Column(db.Integer, default=5, nullable=False)
    fu3_delay_days = db.Column(db.Integer, default=7, nullable=False)
    auto_stop_on_reply = db.Column(db.Boolean, default=True, nullable=False)
    default_followup_enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

- [ ] **Step 5: Generate and run migration**

```bash
flask db migrate -m "Add followup_contacts, followup_events, followup_settings tables"
flask db upgrade
```

- [ ] **Step 6: Verify tables created**

```bash
python3 -c "from app import create_app; app=create_app(); ctx=app.app_context(); ctx.push(); from app.models import FollowupContact, FollowupEvent, FollowupSettings; print('Models OK')"
```

- [ ] **Step 7: Commit**

```bash
git add app/models.py migrations/
git commit -m "feat: add FollowupContact, FollowupEvent, FollowupSettings models"
```

---

### Task 2: Data migration script

**Files:**
- Create: `scripts/migrate_followups.py`

- [ ] **Step 1: Write migration script**

The script must:
1. Query all existing `FollowUp` records
2. For each record, create a `FollowupContact` using the mapping from spec Section 2.4:
   - `level=FU1, status=pending` -> `stage=fu1_scheduled, state=active`
   - `level=FU1, status=sent` -> `stage=fu1_sent, state=active`
   - `level=FU2, status=pending` -> `stage=fu2_scheduled, state=active`
   - `level=FU2, status=sent` -> `stage=fu2_sent, state=active`
   - `level=FU3, status=pending` -> `stage=fu3_scheduled, state=active`
   - `level=FU3, status=sent` -> `stage=fu3_sent, state=active`
   - `level=closed, status=closed` -> `stage=completed_fu3, state=closed`
   - `status=paused` (any level) -> `state=paused, is_followup_enabled=False`
   - `status=failed` -> `state=active, is_followup_enabled=True`, append last_error to notes
3. Map fields: `route->current_route`, `last_contact->last_activity_at`, `last_fu_sent->last_followup_sent_at`, `added_at->created_at`, `auto_enabled->is_followup_enabled`, `scheduled_at->next_followup_at`, `reply_msg_id->reply_msg_id`, `reply_subject->reply_subject`
4. For each workspace with `fu_auto_enabled`, create a `FollowupSettings` record
5. Create a `FollowupEvent` with `event_type=created, actor_type=system` for each migrated contact
6. Print summary: total migrated, per-state counts

```python
#!/usr/bin/env python3
"""Migrate follow_ups -> followup_contacts. Run once."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import FollowUp, FollowupContact, FollowupEvent, FollowupSettings, Workspace
from datetime import datetime

STAGE_MAP = {
    ('FU1', 'pending'): ('fu1_scheduled', 'active', True),
    ('FU1', 'sent'):    ('fu1_sent', 'active', True),
    ('FU2', 'pending'): ('fu2_scheduled', 'active', True),
    ('FU2', 'sent'):    ('fu2_sent', 'active', True),
    ('FU3', 'pending'): ('fu3_scheduled', 'active', True),
    ('FU3', 'sent'):    ('fu3_sent', 'active', True),
    ('closed', 'closed'): ('completed_fu3', 'closed', False),
}

app = create_app()
with app.app_context():
    old_records = FollowUp.query.all()
    print(f"Found {len(old_records)} old follow-up records")
    migrated = 0
    skipped = 0
    for fu in old_records:
        exists = FollowupContact.query.filter_by(
            workspace_id=fu.workspace_id, contact_email=fu.contact_email
        ).first()
        if exists:
            skipped += 1
            continue

        if fu.status == 'paused':
            stage = f"fu{fu.level[-1]}_scheduled" if fu.level in ('FU1','FU2','FU3') else 'completed_fu3'
            state = 'paused'
            enabled = False
        elif (fu.level, fu.status) in STAGE_MAP:
            stage, state, enabled = STAGE_MAP[(fu.level, fu.status)]
        elif fu.status == 'failed':
            stage = f"fu{fu.level[-1]}_scheduled" if fu.level in ('FU1','FU2','FU3') else 'completed_fu3'
            state = 'active'
            enabled = True
        else:
            stage = 'fu1_scheduled'
            state = 'active'
            enabled = True

        notes = fu.notes or ''
        if fu.status == 'failed' and fu.last_error:
            notes = f"[Migration: last error: {fu.last_error}]\n{notes}".strip()

        fc = FollowupContact(
            user_id=fu.user_id,
            workspace_id=fu.workspace_id,
            contact_email=fu.contact_email,
            contact_name=fu.contact_name or '',
            state=state,
            stage=stage,
            is_followup_enabled=enabled if fu.auto_enabled else False,
            next_followup_at=fu.scheduled_at,
            last_followup_sent_at=fu.last_fu_sent,
            last_activity_at=fu.last_contact,
            reply_subject=fu.reply_subject or '',
            reply_msg_id=fu.reply_msg_id or '',
            current_route=fu.route or '',
            notes=notes,
            created_at=fu.added_at or datetime.utcnow(),
        )
        db.session.add(fc)
        db.session.flush()

        evt = FollowupEvent(
            followup_contact_id=fc.id,
            workspace_id=fc.workspace_id,
            event_type='created',
            to_state=state,
            to_stage=stage,
            actor_type='system',
            notes='Migrated from follow_ups table',
        )
        db.session.add(evt)
        migrated += 1

    settings_created = 0
    for ws in Workspace.query.all():
        if not FollowupSettings.query.filter_by(workspace_id=ws.id).first():
            s = FollowupSettings(
                workspace_id=ws.id,
                default_followup_enabled=ws.fu_auto_enabled,
            )
            db.session.add(s)
            settings_created += 1

    db.session.commit()
    print(f"Migrated: {migrated}, Skipped (duplicate): {skipped}, Settings created: {settings_created}")
```

- [ ] **Step 2: Test migration locally**

```bash
python3 scripts/migrate_followups.py
```

Verify output shows correct counts.

- [ ] **Step 3: Commit**

```bash
git add scripts/migrate_followups.py
git commit -m "feat: add data migration script follow_ups -> followup_contacts"
```

---

### Task 3: State machine helper and action handler

**Files:**
- Modify: `app.py` — add helper functions near the follow-up section (around line 2670)

- [ ] **Step 1: Add state machine constants and helper**

Add near the existing `FU_AUTO_DELAYS` constant (line 267 area) or near the follow-up functions (line 2670 area):

```python
# ---------- Follow-up v2: state machine ----------

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
        if reason: contact.pause_reason = reason
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
        if reason: contact.block_reason = reason
    elif new_state == 'closed':
        contact.is_followup_enabled = False
        contact.next_followup_at = None
        contact.closed_at = now
        if reason: contact.close_reason = reason

    _record_event(contact, 'state_change', actor_type='user', actor_user_id=actor_user_id,
                  from_state=old_state, to_state=new_state)
    return True, None
```

- [ ] **Step 2: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('SYNTAX OK')"
```

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat: add follow-up v2 state machine helpers and transition logic"
```

---

### Task 4: New API routes — CRUD and actions

**Files:**
- Modify: `app.py` — replace old follow-up routes (lines 2751–2918) with new ones

- [ ] **Step 1: Replace GET /api/followups**

Remove the old route at line 2751-2753. Write new route that:
- Queries `FollowupContact` filtered by `user_id`
- Accepts `?state=`, `?stage=`, `?filter=` (needs_action/overdue/due_today), `?q=` params
- Returns `{contacts: [...], counts: {...}}` per spec Section 7.3
- Computes counts via SQL GROUP BY, not Python loops

```python
@app.route('/api/followups')
@login_required
def api_followups_list():
    uid = session['user_id']
    q = FollowupContact.query.filter_by(user_id=uid)

    state_f = request.args.get('state')
    stage_f = request.args.get('stage')
    special = request.args.get('filter')

    if state_f and state_f in VALID_STATES:
        q = q.filter_by(state=state_f)
    if stage_f:
        stage_map = {'FU1': ['fu1_scheduled','fu1_sent'], 'FU2': ['fu2_scheduled','fu2_sent'],
                     'FU3': ['fu3_scheduled','fu3_sent'], 'Done': ['completed_fu3']}
        stages = stage_map.get(stage_f, [])
        if stages:
            q = q.filter(FollowupContact.stage.in_(stages))

    now = datetime.utcnow()
    if special == 'needs_action':
        q = q.filter_by(stage='completed_fu3', state='active')
    elif special == 'overdue':
        q = q.filter(FollowupContact.next_followup_at < now, FollowupContact.state == 'active',
                     FollowupContact.is_followup_enabled == True)
    elif special == 'due_today':
        end_of_day = now.replace(hour=23, minute=59, second=59)
        q = q.filter(FollowupContact.next_followup_at <= end_of_day,
                     FollowupContact.next_followup_at >= now,
                     FollowupContact.state == 'active', FollowupContact.is_followup_enabled == True)

    contacts = q.order_by(FollowupContact.created_at.desc()).all()

    from sqlalchemy import func, case
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
    ).filter_by(user_id=uid).first()

    counts = {
        'total': count_q.total, 'active': count_q.active, 'paused': count_q.paused,
        'warm': count_q.warm, 'loads': count_q.loads, 'blocked': count_q.blocked,
        'closed': count_q.closed, 'needs_action': count_q.needs_action, 'overdue': count_q.overdue,
    }
    return jsonify(contacts=[c.to_dict() for c in contacts], counts=counts)
```

- [ ] **Step 2: Add POST /api/followups/add**

```python
@app.route('/api/followups/add', methods=['POST'])
@login_required
def api_followups_add():
    uid = session['user_id']
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
```

- [ ] **Step 3: Add POST /api/followups/action**

This is the core action handler. Implements: pause, resume, warm, loads, block, close, send-now.

```python
@app.route('/api/followups/action', methods=['POST'])
@login_required
def api_followups_action():
    uid = session['user_id']
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

        template_key = STAGE_TO_TEMPLATE[fc.stage]
        templates = _get_fu_templates_for_user(uid)
        template_text = templates.get(template_key, DEFAULT_FU_TEMPLATES.get(template_key, ''))
        acct = EmailAccount.query.filter_by(user_id=uid).first()
        if not acct:
            return jsonify(error='No email account configured'), 400

        cfg = {'name': acct.sender_name or '', 'company': acct.company_name or '',
               'phone': acct.phone or '', 'route': fc.current_route or ''}
        fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                   'reply_msg_id': fc.reply_msg_id or ''}
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
```

- [ ] **Step 4: Add POST /api/followups/bulk-action**

```python
@app.route('/api/followups/bulk-action', methods=['POST'])
@login_required
def api_followups_bulk_action():
    uid = session['user_id']
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
        else:
            results.append({'id': cid, 'ok': False, 'error': f'Unknown action: {action}'})
    db.session.commit()
    return jsonify(results=results)
```

- [ ] **Step 5: Add POST /api/followups/delete and /api/followups/notes**

```python
@app.route('/api/followups/delete', methods=['POST'])
@login_required
def api_followups_delete():
    uid = session['user_id']
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
    uid = session['user_id']
    data = request.get_json()
    fc = FollowupContact.query.get(data.get('id'))
    if not fc or fc.user_id != uid:
        return jsonify(error='Not found'), 404
    fc.notes = data.get('notes', '')
    fc.updated_at = datetime.utcnow()
    _record_event(fc, 'note_added', actor_user_id=uid, notes=fc.notes[:100])
    db.session.commit()
    return jsonify(ok=True)
```

- [ ] **Step 6: Add GET /api/followups/candidates**

```python
@app.route('/api/followups/candidates')
@login_required
def api_followups_candidates():
    uid = session['user_id']
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
```

- [ ] **Step 7: Add GET/POST /api/settings/followup**

```python
@app.route('/api/settings/followup', methods=['GET', 'POST'])
@login_required
def api_settings_followup():
    uid = session['user_id']
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
```

- [ ] **Step 8: Remove old follow-up routes**

Delete the old routes at lines 2751-2918:
- `/api/followups` (old GET), `/api/followups/send`, `/api/followups/update`, `/api/followups/delete` (old), `/api/followups/toggle-auto`, `/api/followups/reschedule`, `/api/followups/bulk-action` (old), `/api/settings/fu-auto`

Also remove old helper functions no longer used:
- `load_followups()` (lines 2639-2644)
- `save_followups()` (lines 2646-2674)
- `add_to_followups()` (lines 2676-2694) — will be rewritten in Task 5

- [ ] **Step 9: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('SYNTAX OK')"
```

- [ ] **Step 10: Commit**

```bash
git add app.py
git commit -m "feat: replace old follow-up routes with v2 API (CRUD, actions, candidates, settings)"
```

---

### Task 5: Rewrite scheduler and reply detection

**Files:**
- Modify: `app.py` — rewrite `_run_scheduled_followups()` (lines 3015-3081) and `add_to_followups()` (line 2676), update reply handler (line 2574)

- [ ] **Step 1: Rewrite add_to_followups()**

Replace the old function with one that creates `FollowupContact`:

```python
def add_to_followups(reply_obj):
    """Create FollowupContact from a Reply marked as 'follow_up'."""
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
        current_route=getattr(reply_obj, 'route', '') or '',
    )
    db.session.add(fc)
    db.session.flush()
    _record_event(fc, 'created', actor_type='user', actor_user_id=uid)
    db.session.commit()
```

- [ ] **Step 2: Add reply detection auto-stop**

Add this function and call `_check_reply_stops_followup(from_email, user_id)` inside `fetch_replies_from_gmail()` after each new Reply is saved:

```python
def _check_reply_stops_followup(reply_email, user_id):
    """If a reply comes from a contact in followup_contacts, stop their FU."""
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
```

- [ ] **Step 3: Rewrite _run_scheduled_followups()**

Replace the entire function (lines 3015-3081) with new scheduler that queries `FollowupContact` instead of `FollowUp`:

```python
def _run_scheduled_followups():
    """Process due follow-up contacts and send emails."""
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
            return

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

                template_key = STAGE_TO_TEMPLATE[fc.stage]
                templates = _get_fu_templates_for_user(fc.user_id)
                template_text = templates.get(template_key, DEFAULT_FU_TEMPLATES.get(template_key, ''))

                cfg = {'name': acct.sender_name or '', 'company': acct.company_name or '',
                       'phone': acct.phone or '', 'route': fc.current_route or ''}
                fu_dict = {'contact_email': fc.contact_email, 'reply_subject': fc.reply_subject or '',
                           'reply_msg_id': fc.reply_msg_id or ''}

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
```

- [ ] **Step 4: Verify send_followup_email() compatibility**

Read `send_followup_email()` (line 2696). It should accept a dict with keys `contact_email`, `reply_subject`, `reply_msg_id`. Our new code passes exactly these keys. No changes needed if the function uses dict access (`fu['key']`).

- [ ] **Step 5: Remove old constants and functions**

Delete if still present:
- `LEVEL_PROGRESSION` constant (line 2735)
- `load_followups()`, `save_followups()` functions
- Keep `FU_AUTO_DELAYS` as fallback reference or remove if `_get_fu_settings()` handles defaults

- [ ] **Step 6: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('SYNTAX OK')"
```

- [ ] **Step 7: Commit**

```bash
git add app.py
git commit -m "feat: rewrite scheduler, reply detection, and add_to_followups for v2"
```

---

### Task 6: Analytics endpoint

**Files:**
- Modify: `app.py` — add `/api/followups/analytics` route

- [ ] **Step 1: Add analytics endpoint**

```python
@app.route('/api/followups/analytics')
@login_required
def api_followups_analytics():
    uid = session['user_id']
    from sqlalchemy import func

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
```

- [ ] **Step 2: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('SYNTAX OK')"
```

- [ ] **Step 3: Commit**

```bash
git add app.py
git commit -m "feat: add follow-up analytics endpoint (funnel, outcomes, conversion)"
```

---

### Task 7: Frontend — CSS and HTML structure

**Files:**
- Modify: `templates/index.html` — replace follow-up page HTML (lines 1982-2069) and add CSS

- [ ] **Step 1: Add new CSS styles**

Find the existing follow-up CSS section (around lines 1153-1207). Replace/extend with new styles for: `.fu-page-header`, `.fu-tabs`, `.fu-tab`, `.fu-filters`, `.fu-filter-btn`, `.fu-stats-bar`, `.fu-card` (with `.overdue`, `.needs-action`, `.muted`, `.terminal` variants), `.fu-card-left/badges/dates/actions`, `.fu-stage-badge` (fu1/fu2/fu3/done), `.fu-state-badge` (active/paused/warm/loads/blocked/closed), `.fu-btn-primary`, `.fu-btn-secondary`, `.fu-dropdown`, `.fu-modal-overlay`, `.fu-modal`, `.fu-candidate`, `.fu-analytics`, `.fu-funnel-*`, `.fu-outcomes-grid`, `.fu-outcome-card`.

See the spec mockups for exact colors. Use existing CSS vars (`--accent`, `--bg`, `--surface`, `--border`, `--text`, `--muted`).

- [ ] **Step 2: Replace follow-up page HTML**

Replace `page-followup` div (lines 1982-2069) with new structure containing:
- Header with title + "Add Contact" button
- Tabs: Contacts / Analytics
- Contacts tab: filters (stage group + state group + special group separated by dividers), stats bar, contacts list container
- Analytics tab: analytics content container
- Add Contact Modal (hidden by default): manual email input + name/company fields, divider, search + candidates list
- Dropdown menu div (hidden, positioned dynamically by JS)

- [ ] **Step 3: Verify no unclosed tags**

Manually check that all divs are properly closed.

- [ ] **Step 4: Commit**

```bash
git add templates/index.html
git commit -m "feat(fu): add new CSS styles and HTML structure for follow-up v2 page"
```

---

### Task 8: Frontend — JavaScript (contacts tab)

**Files:**
- Modify: `templates/index.html` — replace all follow-up JS functions (lines 3647-4031)

- [ ] **Step 1: Add core state and data loading**

Replace ALL existing follow-up JS with new code. Global state: `fuContacts`, `fuCounts`, `fuStageFilter`, `fuStateFilter`, `fuSpecialFilter`, `fuTab`. Functions: `switchFuTab()`, `loadFollowups()`.

- [ ] **Step 2: Add filter rendering and handlers**

Functions: `renderFuFilters()`, `setFuStageFilter()`, `setFuStateFilter()`, `setFuSpecialFilter()`, `filterFuContacts()`.

- [ ] **Step 3: Add contact card rendering**

Function: `renderFuContacts()` — renders card rows with company/email, stage+state badges, next FU date, last activity, primary button + dropdown button. All user data escaped via `esc()`.

- [ ] **Step 4: Add helper functions**

Functions: `getFuStageInfo()`, `getFuStateInfo()`, `getFuPrimaryBtn()`, `formatFuDate()`, `formatFuRelative()`, `updateFuBadge()`.

- [ ] **Step 5: Add action handlers**

Functions: `fuAction()` (POST to /api/followups/action), `toggleFuDropdown()` (show/hide context menu), `fuDropdownAction()` (dispatch from menu).

- [ ] **Step 6: Add modal handlers**

Functions: `openAddContactModal()`, `closeAddContactModal()`, `addContactManual()`, `addCandidate()`, `loadCandidates()`.

- [ ] **Step 7: Update page loading**

Ensure `loadFollowups()` is called when follow-up page is shown (in `switchPage()` or equivalent).

- [ ] **Step 8: Commit**

```bash
git add templates/index.html
git commit -m "feat(fu): complete JS rewrite - contacts tab with cards, filters, actions, add modal"
```

---

### Task 9: Frontend — Analytics tab

**Files:**
- Modify: `templates/index.html` — add analytics rendering JS

- [ ] **Step 1: Add analytics loading and rendering**

Functions: `loadFuAnalytics()` (fetch from /api/followups/analytics), `renderFuAnalytics()` (render funnel bars, outcomes grid, conversion bars). All numbers are computed server-side, frontend only renders. Use `esc()` for any text content.

- [ ] **Step 2: Commit**

```bash
git add templates/index.html
git commit -m "feat(fu): add analytics tab - funnel, outcomes, conversion charts"
```

---

### Task 10: Update reply handler and clean up old code

**Files:**
- Modify: `app.py` — update reply status handler, clean up old functions/constants

- [ ] **Step 1: Verify reply status handler uses new add_to_followups()**

The call at line 2574-2575 should remain the same since we rewrote the function in Task 5.

- [ ] **Step 2: Integrate _check_reply_stops_followup into reply fetch**

Find `fetch_replies_from_gmail()` (around line 1356). After each new Reply record is saved, add call to `_check_reply_stops_followup(from_email, user_id)`.

- [ ] **Step 3: Clean up remaining old code**

Remove from `app.py`:
- `LEVEL_PROGRESSION` constant if still present
- `FU_AUTO_DELAYS` constant if still present (only if `_get_fu_settings()` fully replaces it)
- Any remaining old helper functions

Do NOT remove old `FollowUp` model from `app/models.py` yet — keep until migration verified in production.

- [ ] **Step 4: Verify syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('SYNTAX OK')"
```

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "feat: integrate reply auto-stop, clean up old follow-up code"
```

---

### Task 11: Verify and test

**Files:** None created — verification only

- [ ] **Step 1: Verify Python syntax**

```bash
python3 -c "import ast; ast.parse(open('app.py').read()); print('OK')"
```

- [ ] **Step 2: Verify models importable**

```bash
python3 -c "from app.models import FollowupContact, FollowupEvent, FollowupSettings; print('Models OK')"
```

- [ ] **Step 3: Check all new routes exist**

```bash
python3 -c "
from app import create_app
app = create_app()
rules = [r.rule for r in app.url_map.iter_rules() if 'followup' in r.rule.lower()]
expected = ['/api/followups', '/api/followups/add', '/api/followups/action',
            '/api/followups/bulk-action', '/api/followups/delete', '/api/followups/notes',
            '/api/followups/analytics', '/api/followups/candidates', '/api/settings/followup']
for e in expected:
    status = 'OK' if e in rules else 'MISSING'
    print(f'{status}: {e}')
"
```

- [ ] **Step 4: Manual checklist in browser**

1. Follow-up page loads with new card layout
2. Stage filters work (All/FU1/FU2/FU3/Done)
3. State filters work (Active/Paused/Warm/Loads/Blocked/Closed)
4. Special filters work (Needs Action/Overdue/Due Today)
5. Search filters contacts client-side
6. "Add Contact" modal opens, search works, manual entry works
7. Send Now button sends and advances stage
8. Pause/Resume works
9. Mark as Loads/Warm/Block/Close works
10. Dropdown menu shows correct actions per state
11. Analytics tab shows funnel and outcomes
12. Badge count updates

- [ ] **Step 5: Commit verification**

```bash
git add -A
git commit -m "chore: verification complete - all routes, models, and UI confirmed working"
```

---

## Summary of files changed

| File | Action | What |
|------|--------|------|
| `app/models.py` | Modified | Added FollowupContact, FollowupEvent, FollowupSettings models |
| `app.py` | Modified | New state machine, new routes, rewritten scheduler, reply detection |
| `templates/index.html` | Modified | Full follow-up page rewrite (HTML, CSS, JS) |
| `scripts/migrate_followups.py` | Created | One-time data migration script |
| `migrations/versions/` | Created | Alembic migration for new tables |
