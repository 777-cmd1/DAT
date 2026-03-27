#!/usr/bin/env python3
"""Migrate follow_ups -> followup_contacts. Run once."""
import sys, os, importlib.util

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)

# Load app.py explicitly (app/ package would shadow it otherwise)
_spec = importlib.util.spec_from_file_location('_dat_app', os.path.join(_root, 'app.py'))
_mod = importlib.util.module_from_spec(_spec)
sys.modules['_dat_app'] = _mod
_spec.loader.exec_module(_mod)
app = _mod.app
db  = _mod.db

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

with app.app_context():
    old_records = FollowUp.query.all()
    print(f"Found {len(old_records)} old follow-up records")
    migrated = 0
    skipped = 0
    for fu in old_records:
        # Resolve workspace_id — fall back to user's first workspace
        ws_id = fu.workspace_id
        if not ws_id:
            ws = Workspace.query.filter_by(owner_id=fu.user_id).first()
            if not ws:
                print(f"  SKIP (no workspace): {fu.contact_email}")
                skipped += 1
                continue
            ws_id = ws.id

        exists = FollowupContact.query.filter_by(
            workspace_id=ws_id, contact_email=fu.contact_email
        ).first()
        if exists:
            skipped += 1
            continue

        if fu.status == 'paused':
            stage = f"fu{fu.level[-1]}_scheduled" if fu.level in ('FU1', 'FU2', 'FU3') else 'completed_fu3'
            state = 'paused'
            enabled = False
        elif (fu.level, fu.status) in STAGE_MAP:
            stage, state, enabled = STAGE_MAP[(fu.level, fu.status)]
        elif fu.status == 'failed':
            stage = f"fu{fu.level[-1]}_scheduled" if fu.level in ('FU1', 'FU2', 'FU3') else 'completed_fu3'
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
            workspace_id=ws_id,
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

    # Summary
    from sqlalchemy import func
    state_counts = dict(
        db.session.query(FollowupContact.state, func.count(FollowupContact.id))
        .group_by(FollowupContact.state).all()
    )
    print(f"Migrated: {migrated}, Skipped (duplicate): {skipped}, Settings created: {settings_created}")
    print(f"State counts: {state_counts}")
