"""24h duplicate guard for manual follow-up sends (Bug #4).

A contact must not receive a second manual follow-up within
FU_DUPLICATE_GUARD_HOURS of the previous send (prevents rapid
double-clicks / double-selection from firing 2-3 identical sends).
"""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _make_user_and_login(db, client, plan='free'):
    """Create a user+workspace with a unique email, log in via session."""
    import bcrypt as _bcrypt
    from app.models import User, Workspace

    email = f'fudedup_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Tester', password=pw, role='user')
    db.session.add(user)
    db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', plan=plan)
    db.session.add(ws)
    db.session.commit()

    with client.session_transaction() as sess:
        sess['user_email'] = email
        sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _seed_contact(db, user, ws, monkeypatch):
    """Email account + active FU template + one active FU1 contact.
    Mocks SMTP so send-now reaches the post-send bookkeeping."""
    from app.models import EmailAccount, Template, FollowupContact

    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='Hi {name}', is_active=True))
    fc = FollowupContact(
        user_id=user.id, workspace_id=ws.id, contact_email='broker@acme.com',
        contact_name='Broker', company_name='Acme',
        state='active', stage='fu1_scheduled', is_followup_enabled=True,
    )
    db.session.add(fc)
    db.session.commit()
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))
    return fc.id


def test_send_now_blocks_duplicate_within_24h(app, db, client, monkeypatch):
    from app.models import FollowupContact
    user, ws = _make_user_and_login(db, client)
    cid = _seed_contact(db, user, ws, monkeypatch)

    # 1) First manual send succeeds and stamps last_followup_sent_at.
    r1 = client.post('/api/followups/action',
                     json={'id': cid, 'action': 'send-now', '_csrf': 'test-csrf-token'})
    assert r1.status_code == 200, r1.get_json()

    db.session.expire_all()
    fc = db.session.get(FollowupContact, cid)
    assert fc.last_followup_sent_at is not None
    assert fc.stage == 'fu2_scheduled'   # advanced past FU1

    # 2) Second send within 24h is rejected as a duplicate.
    r2 = client.post('/api/followups/action',
                     json={'id': cid, 'action': 'send-now', '_csrf': 'test-csrf-token'})
    assert r2.status_code == 409, r2.get_json()
    assert r2.get_json().get('duplicate') is True

    # 3) Simulate >24h since the last send → allowed again.
    db.session.expire_all()
    fc = db.session.get(FollowupContact, cid)
    fc.last_followup_sent_at = _app._utcnow() - timedelta(hours=25)
    db.session.commit()

    r3 = client.post('/api/followups/action',
                     json={'id': cid, 'action': 'send-now', '_csrf': 'test-csrf-token'})
    assert r3.status_code == 200, r3.get_json()


def test_bulk_send_now_skips_duplicate(app, db, client, monkeypatch):
    user, ws = _make_user_and_login(db, client)
    cid = _seed_contact(db, user, ws, monkeypatch)

    # Prime: one successful send so the contact is inside the 24h window.
    r1 = client.post('/api/followups/action',
                     json={'id': cid, 'action': 'send-now', '_csrf': 'test-csrf-token'})
    assert r1.status_code == 200, r1.get_json()

    # Bulk send-now on the same contact must skip it (not double-send).
    r2 = client.post('/api/followups/bulk-action',
                     json={'ids': [cid], 'action': 'send-now', '_csrf': 'test-csrf-token'})
    body = r2.get_json()
    assert r2.status_code == 200, body
    assert body['sent'] == 0
    assert body['skipped'] == 1
    assert body['results'][0].get('duplicate') is True
