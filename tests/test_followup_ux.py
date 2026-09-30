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
