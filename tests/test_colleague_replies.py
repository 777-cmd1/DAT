"""A colleague answering for the address we emailed (dispatch@abc.com →
john@abc.com replies) is a real reply: it is ingested, stops the emailed
contact's drip and counts in the reply rate."""
import base64
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


class _Gmail:
    """Minimal Gmail API fake: inbox messages (full) + our sent messages (metadata)."""

    def __init__(self, inbox, sent=()):
        self.inbox = inbox            # {id: full message}
        self.sent = dict(sent)        # {id: (thread_id, to)}
        self.calls = []

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId=None, q='', maxResults=None, pageToken=None):
        self.calls.append(('list', q))
        if 'in:sent' in q:
            self._next = {'messages': [{'id': k, 'threadId': t} for k, (t, _) in self.sent.items()]}
        else:
            self._next = {'messages': [{'id': k, 'threadId': m['threadId']} for k, m in self.inbox.items()]}
        return self

    def get(self, userId=None, id=None, format=None, metadataHeaders=None):
        self.calls.append(('get', id))
        if id in self.sent:
            t, to = self.sent[id]
            self._next = {'id': id, 'threadId': t, 'payload': {'headers': [{'name': 'To', 'value': to}]}}
        else:
            self._next = self.inbox[id]
        return self

    def execute(self):
        return self._next


def _msg(frm, subject, thread, body='we can cover it, $1500', in_reply_to=True):
    headers = [{'name': 'From', 'value': frm}, {'name': 'Subject', 'value': subject},
               {'name': 'Message-ID', 'value': f'<{uuid.uuid4().hex}@mail>'}]
    if in_reply_to:
        headers.append({'name': 'In-Reply-To', 'value': '<ours@mail.gmail.com>'})
    data = base64.urlsafe_b64encode(body.encode()).decode()
    return {'threadId': thread, 'payload': {'mimeType': 'text/plain', 'headers': headers, 'body': {'data': data}}}


def _setup(db, recipients):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount, Send
    u = User(email=f'col_{uuid.uuid4().hex[:8]}@test.com', name='T', role='user',
             password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS'); db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=u.id, workspace_id=ws.id, gmail_address='bogdan@ofcagent.com',
                                your_name='Me', google_refresh_token='tok'))
    for r in recipients:
        db.session.add(Send(user_id=u.id, workspace_id=ws.id, recipient_email=r, status='sent',
                            origin='Laredo, TX', destination='Doral, FL',
                            sent_at=_app._utcnow() - timedelta(days=2)))
    db.session.commit()
    return u, ws


def _fetch(monkeypatch, u, gmail):
    monkeypatch.setattr(_app, '_get_gmail_service', lambda uid: gmail)
    return _app.fetch_replies_from_gmail(uid=u.id, rate_limit=False)


def test_colleague_reply_in_our_thread_is_ingested_and_attributed(app, db, monkeypatch):
    from app.models import Reply, FollowupContact
    dom = f'{uuid.uuid4().hex[:6]}-freight.com'
    u, ws = _setup(db, [f'dispatch@{dom}'])
    fc = FollowupContact(user_id=u.id, workspace_id=ws.id, contact_email=f'dispatch@{dom}', state='active',
                         stage='fu2_scheduled', is_followup_enabled=True,
                         next_followup_at=_app._utcnow() + timedelta(hours=3))
    db.session.add(fc); db.session.commit()
    gmail = _Gmail({'m1': _msg(f'John Smith <john@{dom}>', 'Re: Laredo, TX to Doral, FL, 10/02, Van', 'T1')},
                   sent={'s1': ('T1', f'dispatch@{dom}')})
    assert _fetch(monkeypatch, u, gmail)['new'] == 1
    r = Reply.query.filter_by(user_id=u.id).one()
    assert r.from_email == f'john@{dom}' and r.matched_recipient == f'dispatch@{dom}'
    assert r.route == 'Laredo, TX → Doral, FL'
    db.session.refresh(fc)
    assert fc.is_followup_enabled is False          # the drip to dispatch@ stops
    assert _app._reply_cohort(u.id, _app._utcnow() - timedelta(days=7)) == (1, 1)


def test_reply_to_forwarded_email_matches_by_domain_and_lane(app, db, monkeypatch):
    from app.models import Reply
    dom = f'{uuid.uuid4().hex[:6]}-logistics.com'
    u, ws = _setup(db, [f'loads@{dom}'])
    gmail = _Gmail({'m1': _msg(f'mary@{dom}', 'RE: FW: Laredo, TX to Doral, FL, 10/02, Van, 53 ft', 'T9')})
    assert _fetch(monkeypatch, u, gmail)['new'] == 1
    assert Reply.query.filter_by(user_id=u.id).one().matched_recipient == f'loads@{dom}'


def test_public_mail_and_own_domain_need_a_thread_match(app, db, monkeypatch):
    from app.models import Reply
    u, ws = _setup(db, ['joe.trucking@gmail.com', 'agent2@ofcagent.com'])
    gmail = _Gmail({
        'm1': _msg('bob.carrier@gmail.com', 'Re: Laredo, TX to Doral, FL', 'T8'),     # another gmail user
        'm2': _msg('boss@ofcagent.com', 'Re: Laredo, TX to Doral, FL', 'T7'),        # my own company
    })
    assert _fetch(monkeypatch, u, gmail)['new'] == 0
    assert Reply.query.filter_by(user_id=u.id).count() == 0


def test_unrelated_mail_from_a_contacted_company_is_skipped_once(app, db, monkeypatch):
    from app.models import Reply
    dom = f'{uuid.uuid4().hex[:6]}-broker.com'
    u, ws = _setup(db, [f'dispatch@{dom}'])
    news = _msg(f'news@{dom}', 'October carrier newsletter', 'T5', in_reply_to=False)
    gmail = _Gmail({'m1': news})
    assert _fetch(monkeypatch, u, gmail)['new'] == 0
    assert Reply.query.filter_by(user_id=u.id).count() == 0
    # a reply-looking miss is remembered, so later fetches don't re-query Gmail threads
    gmail2 = _Gmail({'m2': _msg(f'other@{dom}', 'Re: something else', 'T6')})
    _fetch(monkeypatch, u, gmail2)
    sent_lists = sum(1 for c in gmail2.calls if c == ('list', 'in:sent newer_than:30d'))
    _fetch(monkeypatch, u, gmail2)
    assert sum(1 for c in gmail2.calls if c == ('list', 'in:sent newer_than:30d')) == sent_lists
