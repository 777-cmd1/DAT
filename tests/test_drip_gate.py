"""Workspace kill switch for the FU1–FU3 drip scheduler (fu_auto_enabled).

Incident 2026-07-25: the scheduler's drip path had no auto-send gate — 249
FU2 emails went out automatically on a Saturday even though the user believed
auto follow-up was off (the TOUCH CADENCE Off/Manual settings only gate the
cadence-touch path). The gate: Workspace.fu_auto_enabled, toggled from the
pipeline-config UI.
"""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _mk(db, client=None, fu_auto=True):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount
    email = f'gate_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='T', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto)
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
            sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _due_drip_contact(db, user, ws, stage='fu2_scheduled'):
    from app.models import FollowupContact
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         state='active', stage=stage, is_followup_enabled=True,
                         next_followup_at=_app._utcnow() - timedelta(hours=2))
    db.session.add(fc); db.session.commit()
    return fc


def test_drip_scheduler_respects_kill_switch_off(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=False)
    fc = _due_drip_contact(db, user, ws)
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert sent == []                                  # nothing emailed
    assert fc.stage == 'fu2_scheduled'                 # no progression
    assert fc.next_followup_at is not None             # stays visible in Overdue/Today


def test_drip_scheduler_sends_when_enabled(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    fc = _due_drip_contact(db, user, ws)
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert sent == [fc.contact_email]
    assert fc.stage == 'fu3_scheduled'                 # advanced FU2 → FU3


def test_scheduled_once_unaffected_by_kill_switch(app, db, monkeypatch):
    """Explicit one-time schedules are user-initiated — they still send."""
    from app.models import Template
    user, ws = _mk(db, fu_auto=False)
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='hello', is_active=True))
    fc = _due_drip_contact(db, user, ws, stage='completed_fu3')
    fc.scheduled_once = True
    db.session.commit()
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    _app._run_scheduled_followups()
    assert sent == [fc.contact_email]


def test_pipeline_config_toggles_drip_auto(app, db, client):
    from app.models import Workspace
    user, ws = _mk(db, client, fu_auto=True)

    g = client.get('/api/followups/pipeline-config').get_json()
    assert g['drip_auto_enabled'] is True

    r = client.put('/api/followups/pipeline-config', json={'drip_auto_enabled': False})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['drip_auto_enabled'] is False
    db.session.expire_all()
    assert db.session.get(Workspace, ws.id).fu_auto_enabled is False

    # and back on
    r2 = client.put('/api/followups/pipeline-config', json={'drip_auto_enabled': True})
    assert r2.get_json()['drip_auto_enabled'] is True
    db.session.expire_all()
    assert db.session.get(Workspace, ws.id).fu_auto_enabled is True
