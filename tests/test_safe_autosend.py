"""Package 3: safe automatic sending — pre-send reply check, master switch,
auto-drip default off, hard-bounce handling, consistent Block."""
import base64
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _mk(db, client=None, fu_auto=True, auto_send=None, oauth=False):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount
    email = f'safe_{uuid.uuid4().hex[:8]}@test.com'
    user = User(email=email, name='T', role='user',
                password=_bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode())
    db.session.add(user); db.session.flush()
    cfg = {} if auto_send is None else {'auto_send_enabled': auto_send}
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto, pipeline_config=cfg)
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id, gmail_address='me@test.com',
                                your_name='Me', google_refresh_token='tok' if oauth else None))
    db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
    return user, ws


def _due(db, user, ws, **kw):
    from app.models import FollowupContact
    fields = dict(user_id=user.id, workspace_id=ws.id,
                  contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', state='active',
                  stage='fu2_scheduled', is_followup_enabled=True,
                  next_followup_at=_app._utcnow() - timedelta(hours=1))
    fields.update(kw)
    fc = FollowupContact(**fields)
    db.session.add(fc); db.session.commit()
    return fc


def _capture_sends(monkeypatch):
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    return sent


# ── Master switch ─────────────────────────────────────────────────────────────

def test_master_switch_off_blocks_every_auto_path(app, db, monkeypatch):
    from app.models import Template
    user, ws = _mk(db, fu_auto=True, auto_send=False)
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='hi', is_active=True))
    db.session.commit()
    drip = _due(db, user, ws)
    once = _due(db, user, ws, stage='completed_fu3', is_followup_enabled=False, scheduled_once=True)
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert drip.contact_email not in sent and once.contact_email not in sent
    assert drip.stage == 'fu2_scheduled' and once.scheduled_once is True


def test_master_switch_default_on_keeps_existing_behavior(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)          # no auto_send_enabled key stored
    fc = _due(db, user, ws)
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert fc.contact_email in sent


def test_master_switch_roundtrips_through_pipeline_config(app, db, client):
    user, ws = _mk(db, client)
    assert client.get('/api/followups/pipeline-config').get_json()['auto_send_enabled'] is True
    res = client.put('/api/followups/pipeline-config', json={'auto_send_enabled': False})
    assert res.get_json()['auto_send_enabled'] is False
    db.session.refresh(ws)
    assert ws.pipeline_config.get('auto_send_enabled') is False


# ── Pre-send reply check ──────────────────────────────────────────────────────

def test_replier_is_stopped_before_the_drip_emails_them(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True, oauth=True)
    replier = _due(db, user, ws)
    quiet = _due(db, user, ws)
    checked = []

    def fake_fetch(uid=None, rate_limit=True):
        checked.append((uid, rate_limit))
        _app._check_reply_stops_followup(replier.contact_email, uid)   # their reply lands
        db.session.commit()
        return {'new': 1}
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail', fake_fetch)
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert (user.id, False) in checked            # checked without the manual 60s limit
    assert quiet.contact_email in sent
    assert replier.contact_email not in sent      # the replier got nothing
    db.session.expire_all()
    assert replier.is_followup_enabled is False


def test_failed_reply_check_holds_that_users_auto_sends(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True, oauth=True)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail',
                        lambda uid=None, rate_limit=True: {'error': 'HttpError 503 backend error'})
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert fc.contact_email not in sent
    # held, not dropped: still due for the next run
    db.session.expire_all()
    assert fc.stage == 'fu2_scheduled' and fc.next_followup_at is not None


def test_not_connected_gmail_does_not_hold_sends(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=True)
    fc = _due(db, user, ws)
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail',
                        lambda uid=None, rate_limit=True: {'error': 'Gmail OAuth not connected — please connect in Settings'})
    sent = _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert fc.contact_email in sent


def test_no_reply_check_when_nothing_would_auto_send(app, db, monkeypatch):
    user, ws = _mk(db, fu_auto=False)             # drip off → due drip contacts wait for a click
    _due(db, user, ws)
    calls = []
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail',
                        lambda uid=None, rate_limit=True: (calls.append(uid), {})[1])
    _capture_sends(monkeypatch)
    _app._run_scheduled_followups()
    assert user.id not in calls


def test_reply_rebases_touch_mode_contact(app, db):
    user, ws = _mk(db)
    fc = _due(db, user, ws, stage='completed_fu3', is_followup_enabled=False,
              touch_enabled=True, pipeline_stage=2,
              next_followup_at=_app._utcnow() + timedelta(minutes=5))
    _app._check_reply_stops_followup(fc.contact_email, user.id)
    db.session.commit(); db.session.refresh(fc)
    # stage 2 default cadence is 3 days — the touch moved out, not minutes away
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=1)


# ── Auto-drip default ─────────────────────────────────────────────────────────

def test_new_workspaces_start_with_auto_drip_off(app, db):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    u = User(email=f'fresh_{uuid.uuid4().hex[:6]}@t.com', name='F', role='user',
             password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS')
    db.session.add(ws); db.session.commit()
    assert ws.fu_auto_enabled is False


# ── Hard bounces ──────────────────────────────────────────────────────────────

KNOWN = {'dispatch@broker.com', 'ops@carrier.com'}


def test_bounce_detection_rules():
    br = _app._bounced_recipient
    daemon = 'Mail Delivery Subsystem <mailer-daemon@googlemail.com>'
    body = "Your message wasn't delivered to dispatch@broker.com because the address couldn't be found. 550 5.1.1"
    assert br(daemon, {'Subject': 'Delivery Status Notification (Failure)'}, body, KNOWN) == 'dispatch@broker.com'
    assert br(daemon, {'Subject': 'Delivery Status Notification (Delay)'}, body, KNOWN) is None
    assert br(daemon, {'Subject': 'Failure'}, 'temporary problem delivering to dispatch@broker.com', KNOWN) is None
    assert br(daemon, {'Subject': 'Failure'}, body.replace('dispatch@broker.com', 'stranger@x.com'), KNOWN) is None
    assert br('someone@corp.com', {'X-Failed-Recipients': 'ops@carrier.com'}, '', KNOWN) == 'ops@carrier.com'
    assert br('dispatch@broker.com', {'Subject': 'Re: load'}, 'we have loads', KNOWN) is None


class _FakeGmail:
    def __init__(self, messages):
        self._msgs = messages

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, **kw):
        self._next = {'messages': [{'id': k} for k in self._msgs]}
        return self

    def get(self, userId=None, id=None, format=None):
        self._next = self._msgs[id]
        return self

    def execute(self):
        return self._next


def _gmail_msg(from_addr, subject, body, extra_headers=()):
    headers = [{'name': 'From', 'value': from_addr}, {'name': 'Subject', 'value': subject},
               {'name': 'Message-ID', 'value': f'<{uuid.uuid4().hex}@mail>'}] + list(extra_headers)
    data = base64.urlsafe_b64encode(body.encode()).decode()
    return {'threadId': 't1', 'payload': {'mimeType': 'text/plain', 'headers': headers, 'body': {'data': data}}}


def test_fetch_stop_lists_hard_bounce_and_blocks_contact(app, db, monkeypatch):
    from app.models import Send, StopListEntry, Reply
    user, ws = _mk(db, oauth=True)
    dead = f'dead_{uuid.uuid4().hex[:6]}@broker.com'
    db.session.add(Send(user_id=user.id, workspace_id=ws.id, recipient_email=dead, status='sent'))
    db.session.commit()
    fc = _due(db, user, ws, contact_email=dead)
    bounce = _gmail_msg('Mail Delivery Subsystem <mailer-daemon@googlemail.com>',
                        'Delivery Status Notification (Failure)',
                        f"Address not found. Your message wasn't delivered to {dead}. 550 5.1.1",
                        [{'name': 'X-Failed-Recipients', 'value': dead}])
    monkeypatch.setattr(_app, '_get_gmail_service', lambda uid: _FakeGmail({'m1': bounce}))
    res = _app.fetch_replies_from_gmail(uid=user.id, rate_limit=False)
    assert res['bounced'] == 1 and res['new'] == 0
    entry = StopListEntry.query.filter_by(user_id=user.id, value=dead).first()
    assert entry is not None and entry.reason == 'bounced'
    db.session.refresh(fc)
    assert fc.state == 'blocked' and fc.next_followup_at is None
    assert Reply.query.filter_by(user_id=user.id).count() == 0     # bounces aren't replies
    # a second fetch doesn't double-count
    assert _app.fetch_replies_from_gmail(uid=user.id, rate_limit=False)['bounced'] == 0


# ── Block consistency ─────────────────────────────────────────────────────────

def test_block_from_replies_also_blocks_pipeline_contact(app, db, client):
    from app.models import Reply, StopListEntry
    user, ws = _mk(db, client)
    fc = _due(db, user, ws)
    db.session.add(Reply(user_id=user.id, msg_id=f'<{uuid.uuid4().hex}@t>', from_email=fc.contact_email,
                         from_name='C', subject='Re: load', body='no', status='new'))
    db.session.commit()
    msg_id = Reply.query.filter_by(from_email=fc.contact_email).first().msg_id
    res = client.post('/api/replies/status', json={'msg_id': msg_id, 'status': 'not_interested', 'add_to_stop': True})
    assert res.status_code == 200
    db.session.expire_all()
    assert StopListEntry.query.filter_by(user_id=user.id, value=fc.contact_email).count() == 1
    assert fc.state == 'blocked'


def test_block_from_followup_adds_stop_list_and_restart_removes_it(app, db, client):
    from app.models import StopListEntry
    user, ws = _mk(db, client)
    fc = _due(db, user, ws)
    assert client.post('/api/followups/action', json={'id': fc.id, 'action': 'block'}).status_code == 200
    assert StopListEntry.query.filter_by(user_id=user.id, value=fc.contact_email).count() == 1
    assert client.post('/api/followups/action', json={'id': fc.id, 'action': 'restart-fu1'}).status_code == 200
    assert StopListEntry.query.filter_by(user_id=user.id, value=fc.contact_email).count() == 0


def test_bulk_block_adds_stop_list(app, db, client):
    from app.models import StopListEntry
    user, ws = _mk(db, client)
    a, b = _due(db, user, ws), _due(db, user, ws)
    res = client.post('/api/followups/bulk-action', json={'ids': [a.id, b.id], 'action': 'block'})
    assert res.status_code == 200
    vals = {e.value for e in StopListEntry.query.filter_by(user_id=user.id).all()}
    assert {a.contact_email, b.contact_email} <= vals
