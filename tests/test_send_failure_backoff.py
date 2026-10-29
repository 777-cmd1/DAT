"""Scheduler send-failure backoff.

Incident 2026-10-27: an account whose Gmail OAuth token was revoked made the
scheduler retry the same contacts on every tick. Each attempt left
next_followup_at untouched and wrote a followup_events row, producing 368k
rows (12k for a single contact), 236MB of table bloat, a full database volume
and a production outage. These tests pin the behaviour that prevents it.
"""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _mk(db, fu_auto=True):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount, Template
    email = f'bo_{uuid.uuid4().hex[:8]}@test.com'
    user = User(email=email, name='T', role='user',
                password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto)
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='hi', is_active=True))
    db.session.commit()
    return user, ws


def _due(db, user, ws, stage='fu1_scheduled'):
    from app.models import FollowupContact
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         state='active', stage=stage, is_followup_enabled=True,
                         next_followup_at=_app._utcnow() - timedelta(hours=2))
    db.session.add(fc); db.session.commit()
    return fc


def _events(db, fc):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id).count()


def test_failure_backs_off_instead_of_staying_due(app, db, monkeypatch):
    """The core bug: a failed send left the contact due forever."""
    user, ws = _mk(db)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda *a, **k: (False, 'invalid_grant: Bad Request'))
    before = fc.next_followup_at
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert fc.send_fail_count == 1
    assert fc.next_followup_at > before            # pushed into the future
    assert fc.next_followup_at > _app._utcnow()    # no longer due


def test_repeated_failures_do_not_spam_events(app, db, monkeypatch):
    """12k rows for one contact must be impossible: 2 events, ever."""
    user, ws = _mk(db)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda *a, **k: (False, 'invalid_grant: revoked'))
    for _ in range(12):
        fc.next_followup_at = _app._utcnow() - timedelta(minutes=1)  # force due
        fc.attention_at = None
        db.session.commit()
        _app._run_scheduled_followups()
        db.session.expire_all()
    assert fc.send_fail_count == 12
    assert _events(db, fc) == 2     # first failure + the give-up one


def test_gives_up_and_flags_for_human(app, db, monkeypatch):
    user, ws = _mk(db)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'boom'))
    for _ in range(_app.SEND_FAIL_GIVE_UP_AFTER):
        fc.next_followup_at = _app._utcnow() - timedelta(minutes=1)
        db.session.commit()
        _app._run_scheduled_followups()
        db.session.expire_all()
    assert fc.send_fail_count >= _app.SEND_FAIL_GIVE_UP_AFTER
    assert fc.attention_at is not None            # 🔥 raised for manual handling


def test_backoff_grows_with_each_failure(app, db, monkeypatch):
    user, ws = _mk(db)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'x'))
    gaps = []
    for _ in range(3):
        fc.next_followup_at = _app._utcnow() - timedelta(minutes=1)
        db.session.commit()
        now = _app._utcnow()
        _app._run_scheduled_followups()
        db.session.expire_all()
        gaps.append((fc.next_followup_at - now).total_seconds() / 3600)
    assert gaps[0] < gaps[1] < gaps[2]            # 6h → 24h → 72h
    assert gaps[2] >= 71


def test_success_resets_the_counter(app, db, monkeypatch):
    user, ws = _mk(db)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'x'))
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert fc.send_fail_count == 1

    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))
    fc.next_followup_at = _app._utcnow() - timedelta(minutes=1)
    db.session.commit()
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert fc.send_fail_count == 0
    assert fc.stage == 'fu2_scheduled'            # normal progression resumed
