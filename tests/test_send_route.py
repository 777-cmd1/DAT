"""
Tests for POST /api/send — quota enforcement, Gmail config check, already-running guard.
All external calls (Gmail API, SMTP) are mocked.
"""
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

_m = sys.modules['_dat_mailer_app']
flask_app = _m.app
_db       = _m.db


# ── Sample payload ────────────────────────────────────────────────────────────

SAMPLE_LOADS = [
    {
        'email': 'broker@test.com',
        'origin': 'Chicago, IL',
        'destination': 'Dallas, TX',
        'date': '3/15',
        'equip': 'V',
        'weight': '44,000 lbs',
        'company': 'Test Co',
    }
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user_and_login(db, client, plan='free', role='user'):
    """Create a user+workspace, log in via session, return user."""
    import bcrypt as _bcrypt
    import uuid
    from app.models import User, Workspace, EmailAccount

    email = f'send_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Tester', password=pw, role=role)
    db.session.add(user)
    db.session.flush()

    ws = Workspace(owner_id=user.id, name='WS', plan=plan)
    db.session.add(ws)
    db.session.flush()

    with client.session_transaction() as sess:
        sess['user_email'] = email
        sess['csrf_token'] = 'test-csrf-token'

    db.session.commit()
    return user


def _post_send(client, loads=None, csrf='test-csrf-token'):
    payload_loads = SAMPLE_LOADS if loads is None else loads
    return client.post(
        '/api/send',
        data=json.dumps({'loads': payload_loads, '_csrf': csrf}),
        content_type='application/json',
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_returns_401_when_not_logged_in(app, db):
    with app.app_context():
        client = app.test_client()
        resp = _post_send(client)
        assert resp.status_code == 401


def test_returns_400_when_gmail_not_configured(app, db):
    """No EmailAccount row = Gmail not configured → 400."""
    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client)

        resp = _post_send(client)
        data = resp.get_json()
        assert resp.status_code == 400
        assert 'gmail' in data['error'].lower() or 'configured' in data['error'].lower()


def test_returns_400_when_email_account_has_no_credentials(app, db):
    """EmailAccount exists but gmail_address is empty → 400."""
    from app.models import EmailAccount

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client)

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='',
            gmail_password='',
        )
        db.session.add(acct)
        db.session.commit()

        resp = _post_send(client)
        assert resp.status_code == 400


def test_returns_400_when_loads_empty(app, db):
    """Empty loads list → 400."""
    from app.models import EmailAccount

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client)

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='test@gmail.com',
            gmail_password='apppass',
        )
        db.session.add(acct)
        db.session.commit()

        resp = _post_send(client, loads=[])
        data = resp.get_json()
        assert resp.status_code == 400
        assert 'no loads' in data['error'].lower()


def test_returns_429_when_quota_exceeded(app, db):
    """Free user with 50/50 used → 429 quota exceeded."""
    from app.models import EmailAccount, UsageEvent
    from datetime import date

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client, plan='free')

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='test@gmail.com',
            gmail_password='apppass',
        )
        db.session.add(acct)

        # Fill the quota
        ev = UsageEvent(
            user_id=user.id,
            event_type='email_sent',
            count=50,
            period_date=date.today(),
        )
        db.session.add(ev)
        db.session.commit()

        resp = _post_send(client)
        data = resp.get_json()
        assert resp.status_code == 429
        assert 'quota' in data['error'].lower() or 'quota' in data


def test_returns_400_when_already_running(app, db):
    """If send state is running=True → 400 Already running."""
    from app.models import EmailAccount

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client)

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='test@gmail.com',
            gmail_password='apppass',
        )
        db.session.add(acct)
        db.session.commit()

        # Mark as already running
        state = _m._user_send_state(user.id)
        state['running'] = True

        resp = _post_send(client)
        data = resp.get_json()
        assert resp.status_code == 400
        assert 'running' in data['error'].lower()

        # Cleanup
        state['running'] = False


def test_returns_200_with_valid_config_mocked_thread(app, db):
    """Valid config + quota available → 200, thread is started (mocked)."""
    from app.models import EmailAccount

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client, plan='free')

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='test@gmail.com',
            gmail_password='apppass',
        )
        db.session.add(acct)
        db.session.commit()

        # Mock run_send_job so the spawned thread does nothing (no real SMTP)
        with patch.object(_m, 'run_send_job', return_value=None):
            resp = _post_send(client)

        data = resp.get_json()
        assert resp.status_code == 200
        assert data.get('ok') is True
        assert 'quota' in data


def test_pro_user_ignores_quota(app, db):
    """Pro user with many emails used → still gets 200 (not 429)."""
    from app.models import EmailAccount, UsageEvent
    from datetime import date

    with app.app_context():
        client = app.test_client()
        user = _make_user_and_login(db, client, plan='pro')

        acct = EmailAccount(
            user_id=user.id,
            gmail_address='pro@gmail.com',
            gmail_password='apppass',
        )
        db.session.add(acct)

        # Simulate heavy usage (over free limit)
        ev = UsageEvent(
            user_id=user.id,
            event_type='email_sent',
            count=999,
            period_date=date.today(),
        )
        db.session.add(ev)
        db.session.commit()

        with patch.object(_m, 'run_send_job', return_value=None):
            resp = _post_send(client)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('ok') is True
