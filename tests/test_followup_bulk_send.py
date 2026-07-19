"""Bulk follow-up send as a background job (SendJob kind='followup_bulk').

Covers: job creation + inline worker run, per-contact bookkeeping via the
shared _followup_send_now_core, dedupe guard, failure logging with reasons,
concurrent-job protection, ownership isolation, and kind-isolation from the
outreach send machinery.
"""
import json
import sys
import uuid

_app = sys.modules['_dat_mailer_app']


class _InlineThread:
    """threading.Thread stand-in that runs the target synchronously on start()."""
    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        self._target, self._args, self._kwargs = target, args, (kwargs or {})
    def start(self):
        self._target(*self._args, **self._kwargs)


def _mk_user(db, client):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount, Template
    email = f'fubulk_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='T', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='Hi {name}', is_active=True))
    db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
        sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _contact(db, user, ws, stage='fu1_scheduled', state='active'):
    from app.models import FollowupContact
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         state=state, stage=stage,
                         is_followup_enabled=(stage.endswith('_scheduled')))
    db.session.add(fc); db.session.commit()
    return fc


def _inline_worker(monkeypatch):
    monkeypatch.setattr(_app.threading, 'Thread', _InlineThread)


def test_bulk_send_job_processes_contacts(app, db, client, monkeypatch):
    from app.models import SendJob, FollowupContact
    user, ws = _mk_user(db, client)
    ok1 = _contact(db, user, ws)
    ok2 = _contact(db, user, ws)
    done = _contact(db, user, ws, stage='completed_fu3')   # not eligible → skip

    sent_to = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent_to.append(fu['contact_email']), (True, None))[1])
    _inline_worker(monkeypatch)

    res = client.post('/api/followups/bulk-send',
                      json={'ids': [ok1.id, ok2.id, done.id]})
    body = res.get_json()
    assert res.status_code == 200, body
    assert body['ok'] and body['total'] == 3

    job = db.session.get(SendJob, body['job_id'])
    assert job.kind == 'followup_bulk'
    assert job.status == 'done'
    assert (job.sent, job.skipped, job.errors) == (2, 1, 0)
    assert len(sent_to) == 2

    db.session.expire_all()
    assert db.session.get(FollowupContact, ok1.id).stage == 'fu2_scheduled'
    assert db.session.get(FollowupContact, ok2.id).stage == 'fu2_scheduled'

    s = client.get('/api/followups/bulk-send/status').get_json()
    assert s['done'] is True and s['running'] is False
    assert (s['sent'], s['skipped'], s['failed']) == (2, 1, 0)
    assert len(s['failures']) == 1 and s['failures'][0]['kind'] == 'skipped'


def test_bulk_send_records_failures_with_reason(app, db, client, monkeypatch):
    from app.models import SendJob
    user, ws = _mk_user(db, client)
    c1 = _contact(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda *a, **k: (False, 'SMTP 535 bad credentials'))
    _inline_worker(monkeypatch)

    res = client.post('/api/followups/bulk-send', json={'ids': [c1.id]})
    job = db.session.get(SendJob, res.get_json()['job_id'])
    assert job.status == 'done' and job.errors == 1

    failures = json.loads(job.log_json)
    assert failures[0]['email'] == c1.contact_email
    assert 'SMTP 535 bad credentials' in failures[0]['reason']
    assert failures[0]['kind'] == 'failed'

    s = client.get('/api/followups/bulk-send/status').get_json()
    assert s['failed'] == 1 and 'SMTP 535' in s['failures'][0]['reason']


def test_bulk_send_respects_dedupe_guard(app, db, client, monkeypatch):
    user, ws = _mk_user(db, client)
    c1 = _contact(db, user, ws)
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))
    _inline_worker(monkeypatch)

    r1 = client.post('/api/followups/bulk-send', json={'ids': [c1.id]})
    assert r1.status_code == 200

    # Same contact again within 24h → skipped by the duplicate guard, not re-sent
    r2 = client.post('/api/followups/bulk-send', json={'ids': [c1.id]})
    assert r2.status_code == 200
    s = client.get('/api/followups/bulk-send/status').get_json()
    assert s['sent'] == 0 and s['skipped'] == 1
    assert s['failures'][0]['kind'] == 'skipped'


def test_bulk_send_blocks_concurrent_job(app, db, client, monkeypatch):
    from app.models import SendJob
    user, ws = _mk_user(db, client)
    c1 = _contact(db, user, ws)
    running = SendJob(user_id=user.id, kind='followup_bulk', status='running', total=5)
    db.session.add(running); db.session.commit()
    _inline_worker(monkeypatch)

    res = client.post('/api/followups/bulk-send', json={'ids': [c1.id]})
    assert res.status_code == 409
    assert res.get_json()['job_id'] == running.id


def test_bulk_send_skips_foreign_contacts(app, db, client, monkeypatch):
    from app.models import SendJob
    user, ws = _mk_user(db, client)
    other_client_sessions = None  # second user owns the contact
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    other = User(email=f'other_{uuid.uuid4().hex[:6]}@test.com', name='O',
                 password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode(), role='user')
    db.session.add(other); db.session.flush()
    ows = Workspace(owner_id=other.id, name='O WS')
    db.session.add(ows); db.session.commit()
    foreign = _contact(db, other, ows)

    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))
    _inline_worker(monkeypatch)

    res = client.post('/api/followups/bulk-send', json={'ids': [foreign.id]})
    job = db.session.get(SendJob, res.get_json()['job_id'])
    assert job.sent == 0 and job.skipped == 1
    db.session.expire_all()
    from app.models import FollowupContact
    assert db.session.get(FollowupContact, foreign.id).stage == 'fu1_scheduled'  # untouched


def test_followup_job_invisible_to_outreach_status(app, db, client, monkeypatch):
    """kind isolation: a follow-up bulk job must not surface in /api/send-status."""
    from app.models import SendJob
    user, ws = _mk_user(db, client)
    db.session.add(SendJob(user_id=user.id, kind='followup_bulk',
                           status='running', total=100))
    db.session.commit()
    s = client.get('/api/send-status').get_json()
    assert not s.get('running')   # outreach machinery unaffected
