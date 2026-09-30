"""Package 2 fixes: admin re-invite for existing users, append-mode notes."""
import sys
import uuid

_app = sys.modules['_dat_mailer_app']


def _user(db, role='user'):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'p2_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role=role,
             password=_bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    ws = Workspace(owner_id=u.id, name='WS')
    db.session.add(ws); db.session.commit()
    return u, ws


def _login(client, user):
    with client.session_transaction() as sess:
        sess['user_email'] = user.email
        sess['csrf_token'] = 'test-csrf-token'


# ── Admin invite ──────────────────────────────────────────────────────────────

def test_invite_existing_user_without_gmail_does_not_crash(app, db, client):
    admin, _ = _user(db, role='admin')
    target, _ = _user(db)
    _login(client, admin)
    res = client.post('/api/admin/invite', json={'email': target.email})
    assert res.status_code == 200
    data = res.get_json()
    assert data['user_exists'] is True and 'invite_url' not in data


def test_invite_existing_user_with_gmail_is_rejected(app, db, client):
    from app.models import EmailAccount
    admin, _ = _user(db, role='admin')
    target, ws = _user(db)
    db.session.add(EmailAccount(user_id=target.id, workspace_id=ws.id,
                                gmail_address=target.email, google_refresh_token='enc'))
    db.session.commit()
    _login(client, admin)
    res = client.post('/api/admin/invite', json={'email': target.email})
    assert res.status_code == 400
    assert 'Gmail connected' in res.get_json()['error']


def test_invite_new_email_returns_link(app, db, client):
    admin, _ = _user(db, role='admin')
    _login(client, admin)
    res = client.post('/api/admin/invite', json={'email': f'new_{uuid.uuid4().hex[:6]}@x.com'})
    assert res.status_code == 200
    assert '/register/' in res.get_json()['invite_url']


# ── Notes ─────────────────────────────────────────────────────────────────────

def _contact(db, user, ws, notes=''):
    from app.models import FollowupContact
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         state='active', stage='fu1_scheduled', notes=notes)
    db.session.add(fc); db.session.commit()
    return fc


def test_note_append_keeps_existing_text(app, db, client):
    user, ws = _user(db)
    fc = _contact(db, user, ws, notes='has reefers')
    _login(client, user)
    res = client.post('/api/followups/notes', json={'id': fc.id, 'notes': 'call Monday', 'append': True})
    assert res.status_code == 200
    db.session.refresh(fc)
    lines = fc.notes.split('\n')
    assert lines[0] == 'has reefers'
    assert lines[1].startswith('[') and lines[1].endswith('] call Monday')
    assert res.get_json()['notes'] == fc.notes


def test_note_append_on_empty_notes_has_no_leading_newline(app, db, client):
    user, ws = _user(db)
    fc = _contact(db, user, ws)
    _login(client, user)
    client.post('/api/followups/notes', json={'id': fc.id, 'notes': 'first', 'append': True})
    db.session.refresh(fc)
    assert not fc.notes.startswith('\n') and fc.notes.endswith('] first')


def test_note_append_rejects_empty(app, db, client):
    user, ws = _user(db)
    fc = _contact(db, user, ws, notes='keep me')
    _login(client, user)
    res = client.post('/api/followups/notes', json={'id': fc.id, 'notes': '   ', 'append': True})
    assert res.status_code == 400
    db.session.refresh(fc)
    assert fc.notes == 'keep me'


def test_note_replace_mode_unchanged(app, db, client):
    user, ws = _user(db)
    fc = _contact(db, user, ws, notes='old')
    _login(client, user)
    client.post('/api/followups/notes', json={'id': fc.id, 'notes': 'new'})
    db.session.refresh(fc)
    assert fc.notes == 'new'


def test_note_other_users_contact_404(app, db, client):
    owner, ws = _user(db)
    fc = _contact(db, owner, ws, notes='private')
    intruder, _ = _user(db)
    _login(client, intruder)
    res = client.post('/api/followups/notes', json={'id': fc.id, 'notes': 'x', 'append': True})
    assert res.status_code == 404
