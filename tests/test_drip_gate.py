"""Workspace kill switch (fu_auto_enabled) over every scheduled send; the FU1–FU3 drip it
once guarded is retired.

History: the switch was added for the drip path.

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


def _capture_sends(monkeypatch):
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    return sent


def test_the_stage_drip_is_retired_and_sends_nothing(app, db, monkeypatch):
    """A due FU2 contact used to be emailed and moved to FU3. Nothing owns it now:
    it is unplaced (no migration has put it on a rung), so no path sends it."""
    user, ws = _mk(db, fu_auto=True)
    fc = _due_drip_contact(db, user, ws)
    sent = _capture_sends(monkeypatch)
    assert _app._run_scheduled_followups() == 0
    db.session.expire_all()
    assert sent == []
    assert fc.stage == 'fu2_scheduled'                 # the history is not advanced
    assert fc.fu2_sent_at is None and fc.fu3_sent_at is None
    assert fc.is_followup_enabled is True              # and the flag still marks it unplaced


def test_scheduled_once_respects_the_kill_switch(app, db, monkeypatch):
    """A one-time date used to ignore the owner's switch (it was 'user-initiated'). It no
    longer does: with follow-up automation off it waits, still due, for a click."""
    user, ws = _mk(db, fu_auto=False)
    fc = _due_drip_contact(db, user, ws, stage='completed_fu3')
    fc.is_followup_enabled = False
    fc.scheduled_once = True
    db.session.commit()
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert sent == []
    assert fc.scheduled_once is True and fc.next_followup_at is not None   # still waiting, still visible


def test_recurring_respects_the_kill_switch(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=False)
    fc = _due_drip_contact(db, user, ws, stage='completed_fu3')
    fc.is_followup_enabled = False
    fc.recurring_enabled, fc.recurring_days, fc.recurring_time = True, '0,1,2,3,4,5,6', '09:00'
    db.session.commit()
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert sent == []


def test_scheduled_once_and_recurring_send_when_the_switch_is_on(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    once = _due_drip_contact(db, user, ws, stage='completed_fu3')
    once.is_followup_enabled, once.scheduled_once = False, True
    rec = _due_drip_contact(db, user, ws, stage='completed_fu3')
    rec.is_followup_enabled = False
    rec.recurring_enabled, rec.recurring_days, rec.recurring_time = True, '0,1,2,3,4,5,6', '09:00'
    db.session.commit()
    sent = _capture_sends(monkeypatch)
    assert _app._run_scheduled_followups() == 2
    assert sorted(sent) == sorted([once.contact_email, rec.contact_email])
    db.session.expire_all()
    assert once.scheduled_once is False


def test_scheduled_sends_obey_the_master_switch(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    ws.pipeline_config = {'auto_send_enabled': False}
    fc = _due_drip_contact(db, user, ws, stage='completed_fu3')
    fc.is_followup_enabled, fc.scheduled_once = False, True
    db.session.commit()
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert sent == []


def test_a_date_never_emails_someone_who_asked_us_to_stop(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    refused = _due_drip_contact(db, user, ws, stage='completed_fu3')
    refused.is_followup_enabled, refused.scheduled_once = False, True
    refused.rung, refused.exit_reason = 'dormant', 'refused'
    excluded = _due_drip_contact(db, user, ws, stage='completed_fu3')
    excluded.is_followup_enabled, excluded.recurring_enabled = False, True
    excluded.recurring_days, excluded.recurring_time, excluded.rung = '0,1,2,3,4,5,6', '09:00', 'excluded'
    db.session.commit()
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert sent == []


def test_scheduled_sends_use_the_rung_copy_not_a_stage_template(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    fc = _due_drip_contact(db, user, ws, stage='completed_fu3')
    fc.is_followup_enabled, fc.scheduled_once, fc.rung = False, True, 'warm'
    db.session.commit()
    bodies = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (bodies.append(tpl), (True, None))[1])
    expected = _app._template_for_rung(user.id, 'warm', fc)
    _app._run_scheduled_followups()
    assert bodies == [expected] and expected
    assert expected != _app.DEFAULT_FU_TEMPLATES['FU1']


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
