"""Package 4: data integrity — replies.msg_id unique per user."""
import sys
import uuid

import pytest

_app = sys.modules['_dat_mailer_app']


def _user(db, client=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'di_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user', password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    db.session.add(Workspace(owner_id=u.id, name='WS')); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
    return u


def _reply(db, user, msg_id, status='new'):
    from app.models import Reply
    r = Reply(user_id=user.id, msg_id=msg_id, from_email='dispatch@carrier.com',
              subject='Re: Laredo, TX to Doral, FL', body='we can cover', status=status)
    db.session.add(r); db.session.commit()
    return r


def test_same_message_can_reach_two_users(app, db):
    from sqlalchemy.exc import IntegrityError
    a, b = _user(db), _user(db)
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid)
    _reply(db, b, mid)                     # used to violate the global unique
    with pytest.raises(IntegrityError):
        _reply(db, a, mid)                 # still unique within one mailbox
    db.session.rollback()


def test_save_replies_only_touches_own_row(app, db):
    from app.models import Reply
    a, b = _user(db), _user(db)
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid, status='follow_up')
    _app.save_replies([{'msg_id': mid, 'email': 'dispatch@carrier.com', 'status': 'new'}], uid=b.id)
    rows = {r.user_id: r.status for r in Reply.query.filter_by(msg_id=mid).all()}
    assert rows == {a.id: 'follow_up', b.id: 'new'}


def test_marking_reply_does_not_change_other_users_copy(app, db, client):
    from app.models import Reply
    a = _user(db)
    b = _user(db, client)                  # logged in as B
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid, status='new')
    _reply(db, b, mid, status='new')
    res = client.post('/api/replies/status', json={'msg_id': mid, 'status': 'not_interested'})
    assert res.status_code == 200
    db.session.expire_all()
    assert Reply.query.filter_by(user_id=a.id, msg_id=mid).first().status == 'new'
    assert Reply.query.filter_by(user_id=b.id, msg_id=mid).first().status == 'not_interested'


# ── One reply-rate definition ─────────────────────────────────────────────────

def _send(db, u, to, when):
    from app.models import Send
    db.session.add(Send(user_id=u.id, recipient_email=to, status='sent', sent_at=when,
                        origin='Laredo, TX', destination='Doral, FL'))
    db.session.commit()


def _got(db, u, frm, when, status='new', body='ok'):
    from app.models import Reply
    db.session.add(Reply(user_id=u.id, msg_id=f'<{uuid.uuid4().hex}@m>', from_email=frm,
                         subject='Re: load', body=body, status=status, received_at=when))
    db.session.commit()


def test_reply_rate_is_share_of_contacts_emailed_in_window(app, db):
    from datetime import timedelta
    u = _user(db)
    now = _app._utcnow()
    since = now - timedelta(days=7)
    for i in range(3):
        _send(db, u, f'c{i}@acme.com', now - timedelta(days=2))
    _send(db, u, 'c0@acme.com', now - timedelta(days=1))          # emailed twice → still 1 contact
    _got(db, u, 'C0@acme.com', now - timedelta(hours=5))          # counted (case-insensitive)
    _got(db, u, 'c0@acme.com', now - timedelta(hours=4))          # same contact again
    _got(db, u, 'c1@acme.com', now - timedelta(days=30))          # replied before the window
    _got(db, u, 'stranger@else.com', now - timedelta(hours=1))    # never emailed
    assert _app._reply_cohort(u.id, since) == (3, 1)
    assert _app._reply_rate(3, 1) == 33.3
    assert _app._reply_rate(0, 0) is None


def test_analytics_today_reply_rate_cannot_exceed_100(app, db, client):
    from datetime import timedelta
    u = _user(db, client)
    now = _app._utcnow()
    for i in range(4):                                             # emailed last week
        _send(db, u, f'old{i}@acme.com', now - timedelta(days=5))
        _got(db, u, f'old{i}@acme.com', now - timedelta(minutes=30))   # all reply today
    _send(db, u, 'new@acme.com', now - timedelta(seconds=5))      # one email today
    rr = client.get('/api/stats?period=today').get_json()['response_rate']
    assert rr['contacted'] == 1 and rr['replied'] == 0 and rr['pct'] == 0   # used to be 400%
    life = client.get('/api/stats?period=lifetime').get_json()['response_rate']
    assert life['contacted'] == 5 and life['replied'] == 4 and life['pct'] == 80.0


def test_dashboard_and_intelligence_use_the_same_rate(app, db, client):
    from datetime import timedelta
    u = _user(db, client)
    now = _app._utcnow()
    dom = f'{uuid.uuid4().hex[:6]}.com'
    _send(db, u, f'a@{dom}', now - timedelta(days=3))
    _send(db, u, f'b@{dom}', now - timedelta(days=3))
    for _ in range(5):                                            # a chatty thread
        _got(db, u, f'a@{dom}', now - timedelta(days=1))
    h = _app._dashboard_data(u.id)['health']
    assert (h['contacted_30d'], h['replied_30d'], h['reply_rate']) == (2, 1, 50.0)
    b = next(x for x in client.get('/api/intelligence').get_json()['brokers'] if x['domain'] == dom)
    assert b['replies'] == 1 and b['reply_rate'] == 50.0          # used to be 5 replies / 250%


# ── Auto FU3 hands the contact to the cadence immediately ─────────────────────

def test_auto_fu3_schedules_next_touch(app, db, monkeypatch):
    from datetime import timedelta
    from app.models import Workspace, EmailAccount, FollowupContact
    u = _user(db)
    ws = Workspace.query.filter_by(owner_id=u.id).first()
    ws.fu_auto_enabled = True
    ws.pipeline_config = {'cadence': {'1': {'days': 3, 'mode': 'manual'}}, 'touch_hour': 'auto'}
    db.session.add(EmailAccount(user_id=u.id, workspace_id=ws.id, gmail_address='me@test.com', your_name='Me'))
    fc = FollowupContact(user_id=u.id, workspace_id=ws.id, contact_email=f'{uuid.uuid4().hex[:8]}@c.com',
                         state='active', stage='fu3_scheduled', is_followup_enabled=True, pipeline_stage=1,
                         next_followup_at=_app._utcnow() - timedelta(hours=1))
    db.session.add(fc); db.session.commit()
    monkeypatch.setattr(_app, 'send_followup_email', lambda fu, tpl, cfg, uid=None: (True, None))
    monkeypatch.setattr(_app, '_prefetch_replies_before_sending', lambda now: set())
    _app._run_scheduled_followups()
    db.session.expire_all()
    fc = db.session.get(FollowupContact, fc.id)
    assert fc.stage == 'completed_fu3' and not fc.is_followup_enabled
    assert fc.touch_enabled and fc.next_followup_at is not None        # used to be None until a sweep
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=2)
