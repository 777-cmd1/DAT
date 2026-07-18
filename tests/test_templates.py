"""Follow-up template management: real delete, duplicate-add guard, isolation.

Bug history: DELETE /api/fu-templates/<id> used to soft-delete
(is_active=False) while /api/fu-templates/list returned every row regardless
of is_active — so "deleted" templates never left the list, and users re-adding
them piled up identical 'General / All Services' duplicates (the Add endpoint
had no dedupe and the Add button no double-click guard).
"""
import sys
import uuid

_app = sys.modules['_dat_mailer_app']


def _mk_user(db, client):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'tmpl_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='T', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
        sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _tmpl(db, user, name='General / All Services', body='Hi, any loads this week?',
          level='General', active=True):
    from app.models import Template
    t = Template(user_id=user.id, type='followup', level=level, name=name,
                 body=body, is_active=active)
    db.session.add(t); db.session.commit()
    return t


def test_delete_removes_template_from_db_and_list(app, db, client):
    from app.models import Template
    user, _ = _mk_user(db, client)
    t = _tmpl(db, user)

    res = client.delete(f'/api/fu-templates/{t.id}')
    assert res.status_code == 200, res.get_json()
    assert res.get_json()['deleted'] == t.id

    assert db.session.get(Template, t.id) is None          # gone from the DB
    listed = client.get('/api/fu-templates/list').get_json()['templates']
    assert all(row['id'] != t.id for row in listed)        # gone from the list


def test_delete_inactive_template_also_works(app, db, client):
    """Rows stranded by the old soft-delete (is_active=False) must be removable."""
    from app.models import Template
    user, _ = _mk_user(db, client)
    t = _tmpl(db, user, active=False)
    res = client.delete(f'/api/fu-templates/{t.id}')
    assert res.status_code == 200
    assert db.session.get(Template, t.id) is None


def test_delete_foreign_template_is_404(app, db, client):
    from app.models import Template
    owner, _ = _mk_user(db, client)
    t = _tmpl(db, owner)
    # switch session to a different user
    _mk_user(db, client)
    res = client.delete(f'/api/fu-templates/{t.id}')
    assert res.status_code == 404
    assert db.session.get(Template, t.id) is not None      # untouched


def test_delete_missing_template_is_404(app, db, client):
    _mk_user(db, client)
    assert client.delete(f'/api/fu-templates/{uuid.uuid4()}').status_code == 404


def test_add_rejects_exact_duplicate(app, db, client):
    from app.models import Template
    user, _ = _mk_user(db, client)
    payload = {'name': 'General / All Services', 'level': 'General',
               'body': 'Hi, Just wanted to follow up - are you working on any loads this week? FTL, LTL...'}

    r1 = client.post('/api/fu-templates/add', json=payload)
    assert r1.status_code == 200, r1.get_json()

    r2 = client.post('/api/fu-templates/add', json=payload)   # double-click / re-add
    assert r2.status_code == 409
    assert r2.get_json()['duplicate'] is True

    rows = Template.query.filter_by(user_id=user.id, type='followup').all()
    assert len(rows) == 1                                     # no pile-up


def test_add_allows_same_name_different_body(app, db, client):
    from app.models import Template
    user, _ = _mk_user(db, client)
    r1 = client.post('/api/fu-templates/add',
                     json={'name': 'General', 'level': 'General', 'body': 'Variant A'})
    r2 = client.post('/api/fu-templates/add',
                     json={'name': 'General', 'level': 'General', 'body': 'Variant B'})
    assert r1.status_code == 200 and r2.status_code == 200
    assert Template.query.filter_by(user_id=user.id, type='followup').count() == 2


def test_deleted_template_not_used_for_sends(app, db, client, monkeypatch):
    """After deleting the only custom FU1 template, sends fall back to defaults
    (no crash, no stale text)."""
    from app.models import EmailAccount, FollowupContact
    user, ws = _mk_user(db, client)
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    custom = _tmpl(db, user, name='FU1', level='FU1', body='CUSTOM FU1 TEXT')
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email='b@x.com', state='active',
                         stage='fu1_scheduled', is_followup_enabled=True)
    db.session.add(fc); db.session.commit()

    assert client.delete(f'/api/fu-templates/{custom.id}').status_code == 200

    used = {}
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (used.setdefault('tpl', tpl), (True, None))[1])
    res = client.post('/api/followups/action', json={'id': fc.id, 'action': 'send-now'})
    assert res.status_code == 200, res.get_json()
    assert used['tpl'] == _app.DEFAULT_FU_TEMPLATES['FU1']   # default, not the deleted text
