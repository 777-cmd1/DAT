"""Package 5: one contact label everywhere (FollowupContact.display_name)."""
import sys
import uuid

_app = sys.modules['_dat_mailer_app']


def _fc(**kw):
    from app.models import FollowupContact
    kw.setdefault('contact_email', 'laura@hartstonelogistics.com')
    return FollowupContact(**kw)


def test_display_name_prefers_person_name_from_raw_from_header():
    assert _fc(contact_name='Laura Neal <laura@hartstonelogistics.com>').display_name == 'Laura Neal'
    assert _fc(contact_name='"Neal, Laura" <laura@x.com>').display_name == 'Neal, Laura'
    assert _fc(contact_name='Laura Neal', company_name='Hartstone').display_name == 'Laura Neal'


def test_display_name_falls_back_to_company_then_email():
    assert _fc(contact_name='laura@hartstonelogistics.com', company_name='Hartstone').display_name == 'Hartstone'
    assert _fc(contact_name='<laura@hartstonelogistics.com>').display_name == 'laura@hartstonelogistics.com'
    assert _fc(contact_name='', company_name='').display_name == 'laura@hartstonelogistics.com'
    assert _fc(contact_name=None, company_name='  Hartstone ').display_name == 'Hartstone'


def test_api_followups_returns_display_name(app, db, client):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, FollowupContact
    email = f'fux_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user', password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS'); db.session.add(ws); db.session.flush()
    db.session.add(FollowupContact(user_id=u.id, workspace_id=ws.id, contact_email='roman@ljtsi.com',
                                   contact_name='Roman Diaz <roman@ljtsi.com>', state='active',
                                   stage='fu1_scheduled'))
    db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
    rows = client.get('/api/followups').get_json()['contacts']
    assert [r['display_name'] for r in rows] == ['Roman Diaz']


def test_intelligence_counts_follow_up_replies(app, db, client):
    """'Follow-up' in Intelligence means the same as in Analytics: replies the
    user moved to Follow-up (status follow_up, or legacy 'interested')."""
    import bcrypt as _bcrypt
    from app.models import User, Workspace, Send, Reply
    email = f'intel_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user', password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS'); db.session.add(ws); db.session.flush()
    dom = f'{uuid.uuid4().hex[:6]}-freight.com'
    for i in range(3):
        db.session.add(Send(user_id=u.id, workspace_id=ws.id, recipient_email=f'd{i}@{dom}',
                            origin='Laredo, TX', destination='Doral, FL', status='sent'))
    db.session.add(Reply(user_id=u.id, from_email=f'd0@{dom}', subject='Re: load', body='we can do it',
                         status='follow_up', msg_id=f'm-{uuid.uuid4().hex}'))
    db.session.add(Reply(user_id=u.id, from_email=f'd1@{dom}', subject='Re: load', body='old one',
                         status='interested', msg_id=f'm-{uuid.uuid4().hex}'))
    db.session.add(Reply(user_id=u.id, from_email=f'd2@{dom}', subject='Re: load', body='no thanks',
                         status='ignored', msg_id=f'm-{uuid.uuid4().hex}'))
    db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
    brokers = client.get('/api/intelligence').get_json()['brokers']
    row = next(b for b in brokers if b['domain'] == dom)
    assert row['interested'] == 2 and row['replies'] == 3
