"""Lane rate memory: rates quoted in replies, tied to the lane + equipment of
the load we emailed about, dated by when the reply really arrived."""
import base64
import sys
import uuid
from datetime import datetime, timedelta

import pytest

_app = sys.modules['_dat_mailer_app']


# ── Extraction ────────────────────────────────────────────────────────────────

def _rates(text):
    return [(r['rate'], r['rate_per_mile']) for r in _app.extract_rates(text)]


@pytest.mark.parametrize('text, expected', [
    ('Still available PU FCFS 0800 DEL 07/01 15,000 LBS RATE $5400 let me know', [(5400, None)]),
    ('We can do it for $1,500 all in', [(1500, None)]),
    ('rate is $1,850.00', [(1850, None)]),
    ('can do $2.5k', [(2500, None)]),
    ('paying $2.10/mi loaded', [(None, 2.1)]),
    ('2.45 rpm on this one', [(None, 2.45)]),
    ('$2.30 per mile', [(None, 2.3)]),
    ('$1500, detention $50/hr after 2 hrs', [(1500, None)]),
    ('$350 TONU if cancelled', []),
    ('layover $300 per day', []),
    ('lumper $250 reimbursed', []),
    ('only $150 extra', []),
    ("What's your rate on this lane?", []),
    ('$1700 or $2.40/mi', [(1700, None), (None, 2.4)]),
])
def test_extract_rates(text, expected):
    assert _rates(text) == expected


def test_quoted_original_mail_is_ignored():
    body = ("Sorry, covered.\n\nOn Mon, Sep 28, 2026 at 9:00 AM Bogdan <b@x.com> wrote:\n"
            "> Laredo, TX to Doral, FL, Van — target $1,500?")
    assert _app.extract_rates(body) == []


def test_snippet_shows_where_the_rate_came_from():
    r = _app.extract_rates('Hi Bogdan, we can cover it for $1,650 picking up Friday.')[0]
    assert '$1,650' in r['snippet'] and len(r['snippet']) <= 300


# ── Lane + equipment from the outreach email ─────────────────────────────────

def _user(db, client=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    u = User(email=f'rm_{uuid.uuid4().hex[:8]}@test.com', name='T', role='user',
             password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS'); db.session.add(ws); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = u.email
    return u, ws


def _send(db, u, to, origin, dest, equip, when):
    from app.models import Send
    db.session.add(Send(user_id=u.id, recipient_email=to, status='sent', origin=origin,
                        destination=dest, equipment=equip, sent_at=when))
    db.session.commit()


def _reply(db, u, frm, body, when, subject='Re: load', matched=None, route=''):
    from app.models import Reply
    r = Reply(user_id=u.id, msg_id=f'<{uuid.uuid4().hex}@m>', from_email=frm, from_name=frm,
              subject=subject, body=body, received_at=when, matched_recipient=matched, route=route)
    db.session.add(r); db.session.commit()
    return r


def test_quote_takes_lane_and_equipment_of_the_load_it_answers(app, db):
    from app.models import RateQuote
    u, ws = _user(db)
    now = _app._utcnow()
    to = f'd_{uuid.uuid4().hex[:5]}@broker.com'
    _send(db, u, to, 'Laredo, TX', 'Doral, FL', 'V', now - timedelta(days=3))
    _send(db, u, to, 'Phoenix, AZ', 'Santa Teresa, NM', 'F', now - timedelta(days=2))   # later, other lane
    r = _reply(db, u, to, 'We can do $1,500', now - timedelta(days=1),
               subject='RE: Laredo, TX to Doral, FL, 10/02, Van, 53 ft')
    assert _app._extract_rate_quotes(u.id) == 1
    q = RateQuote.query.filter_by(reply_id=r.id).one()
    assert (q.origin, q.destination, q.equipment, q.rate) == ('Laredo, TX', 'Doral, FL', 'V', 1500)
    assert _app._extract_rate_quotes(u.id) == 0                 # parsed once


def test_colleague_quote_uses_the_emailed_address(app, db):
    from app.models import RateQuote
    u, ws = _user(db)
    now = _app._utcnow()
    dom = f'{uuid.uuid4().hex[:6]}.com'
    _send(db, u, f'dispatch@{dom}', 'Omaha, NE', 'Des Moines, IA', 'R', now - timedelta(days=2))
    r = _reply(db, u, f'john@{dom}', 'Roman is out — $900 works', now - timedelta(hours=3),
               matched=f'dispatch@{dom}')
    _app._extract_rate_quotes(u.id)
    q = RateQuote.query.filter_by(reply_id=r.id).one()
    assert (q.origin, q.equipment, q.contact_email) == ('Omaha, NE', 'R', f'dispatch@{dom}')


def test_equipment_from_reply_subject_when_no_outreach_found(app, db):
    from app.models import RateQuote
    u, ws = _user(db)
    r = _reply(db, u, 'x@carrier.com', '$1800 works', _app._utcnow(),
               subject='Re: Miami, FL to Mississauga, ON, 10/04, Reefer, 53 ft', route='Miami, FL → Mississauga, ON')
    _app._extract_rate_quotes(u.id)
    q = RateQuote.query.filter_by(reply_id=r.id).one()
    assert (q.origin, q.equipment) == ('Miami, FL', 'R')
    assert _app._equip_from_subject('Re: Vancouver, WA to Boise, ID, 10/04') == ''   # not "Van"


def test_rate_without_any_lane_is_skipped(app, db):
    from app.models import RateQuote, Reply
    u, ws = _user(db)
    r = _reply(db, u, 'stranger@x.com', 'our rate $2000', _app._utcnow())
    _app._extract_rate_quotes(u.id)
    assert RateQuote.query.filter_by(reply_id=r.id).count() == 0
    assert db.session.get(Reply, r.id).rates_parsed is True


# ── Report API ────────────────────────────────────────────────────────────────

def _seed_report(db, u):
    now = _app._utcnow()
    for i, (rate, days_ago, equip) in enumerate([(1500, 2, 'V'), (1700, 10, 'V'), (2100, 5, 'F'), (1400, 200, 'V')]):
        to = f'r{i}_{uuid.uuid4().hex[:4]}@broker.com'
        _send(db, u, to, 'Laredo, TX', 'Doral, FL', equip, now - timedelta(days=days_ago + 1))
        _reply(db, u, to, f'can do ${rate}', now - timedelta(days=days_ago),
               subject='Re: Laredo, TX to Doral, FL, 10/02')


def test_report_groups_by_lane_and_equipment_with_dates(app, db, client):
    u, ws = _user(db, client)
    _seed_report(db, u)
    d = client.get('/api/intelligence/rates').get_json()            # default 90 days
    assert d['total'] == 3
    by_equip = {g['equipment']: g for g in d['groups']}
    van = by_equip['V']
    assert van['equipment_label'] == 'Van' and van['lane'] == 'Laredo, TX → Doral, FL'
    assert [q['rate'] for q in van['quotes']] == [1500, 1700]         # newest first
    assert van['flat'] == {'avg': 1600, 'min': 1500, 'max': 1700, 'count': 2}
    assert van['quotes'][0]['quoted_at'].endswith('Z')
    assert d['groups'][0]['equipment'] == 'V'                         # most recent quote first
    assert {e['code'] for e in d['equipment']} == {'V', 'F'}
    assert client.get('/api/intelligence/rates?days=0').get_json()['total'] == 4
    assert client.get('/api/intelligence/rates?equip=F').get_json()['total'] == 1
    assert client.get('/api/intelligence/rates?q=phoenix').get_json()['total'] == 0


def test_hide_and_restore_a_wrong_rate(app, db, client):
    u, ws = _user(db, client)
    _seed_report(db, u)
    qid = client.get('/api/intelligence/rates').get_json()['groups'][0]['quotes'][0]['id']
    assert client.post('/api/intelligence/rates/hide', json={'id': qid}).get_json()['hidden'] is True
    assert client.get('/api/intelligence/rates').get_json()['total'] == 2
    client.post('/api/intelligence/rates/hide', json={'id': qid, 'hidden': False})
    assert client.get('/api/intelligence/rates').get_json()['total'] == 3
    # someone else's quote
    other, _ = _user(db, client)
    assert client.post('/api/intelligence/rates/hide', json={'id': qid}).status_code == 404


# ── Real reply dates ──────────────────────────────────────────────────────────

class _Gmail:
    def __init__(self, inbox=None, threads=None, fail=None):
        self.inbox, self.threads_, self.fail = inbox or {}, threads or {}, fail or {}

    def users(self):
        return self

    def messages(self):
        self._kind = 'm'
        return self

    def threads(self):
        self._kind = 't'
        return self

    def list(self, **kw):
        self._next = {'messages': [{'id': k, 'threadId': v['threadId']} for k, v in self.inbox.items()]}
        return self

    def get(self, userId=None, id=None, **kw):
        if self._kind == 't':
            if id in self.fail:
                raise self.fail[id]
            self._next = self.threads_[id]
        else:
            self._next = self.inbox[id]
        return self

    def execute(self):
        return self._next


def _ms(dt):
    return str(int(dt.replace(tzinfo=_app.UTC).timestamp() * 1000))


def test_new_reply_is_dated_by_gmail_not_by_fetch_time(app, db, monkeypatch):
    from app.models import Reply, Send, EmailAccount
    u, ws = _user(db)
    to = f'd_{uuid.uuid4().hex[:5]}@broker.com'
    db.session.add(Send(user_id=u.id, recipient_email=to, status='sent'))
    db.session.add(EmailAccount(user_id=u.id, workspace_id=ws.id, gmail_address='me@ofc.com', google_refresh_token='t'))
    db.session.commit()
    arrived = datetime(2026, 9, 20, 15, 30)
    body = base64.urlsafe_b64encode(b'$1500').decode()
    msg = {'threadId': 'T1', 'internalDate': _ms(arrived),
           'payload': {'mimeType': 'text/plain', 'body': {'data': body},
                       'headers': [{'name': 'From', 'value': to}, {'name': 'Subject', 'value': 'Re: x'},
                                   {'name': 'Message-ID', 'value': '<a1@m>'}]}}
    monkeypatch.setattr(_app, '_get_gmail_service', lambda uid: _Gmail(inbox={'g1': msg}))
    _app.fetch_replies_from_gmail(uid=u.id, rate_limit=False)
    r = Reply.query.filter_by(user_id=u.id).one()
    assert r.received_at == arrived and r.date_checked is True


def test_backfill_corrects_dates_of_stored_replies(app, db):
    from googleapiclient.errors import HttpError
    from app.models import Reply
    u, ws = _user(db)
    fetched = datetime(2026, 10, 1, 12, 0)                           # day of the deploy
    a = _reply(db, u, 'a@x.com', 'hi', fetched)
    a.thread_id, a.msg_id = 'TA', '<a@m>'
    b = _reply(db, u, 'b@x.com', 'hi', fetched)
    b.thread_id = 'TB'                                               # thread deleted in Gmail
    c = _reply(db, u, 'c@x.com', 'hi', fetched)                      # legacy row, no thread
    db.session.commit()
    real = datetime(2026, 9, 14, 9, 5)
    gm = _Gmail(threads={'TA': {'messages': [{'id': 'x', 'internalDate': _ms(real),
                                               'payload': {'headers': [{'name': 'Message-Id', 'value': '<a@m>'}]}}]}},
                fail={'TB': HttpError(type('R', (), {'status': 404, 'reason': 'nf'})(), b'')})
    assert _app._backfill_reply_dates(gm, u.id) == 1
    db.session.expire_all()
    assert db.session.get(Reply, a.id).received_at == real
    assert db.session.get(Reply, b.id).received_at == fetched
    assert all(db.session.get(Reply, x.id).date_checked for x in (a, b, c))


def test_backfill_stops_on_transient_error_and_retries_later(app, db):
    from app.models import Reply
    u, ws = _user(db)
    r = _reply(db, u, 'a@x.com', 'hi', datetime(2026, 10, 1, 12))
    r.thread_id = 'T1'; db.session.commit()
    _app._backfill_reply_dates(_Gmail(fail={'T1': RuntimeError('quota')}), u.id)
    assert db.session.get(Reply, r.id).date_checked is False
