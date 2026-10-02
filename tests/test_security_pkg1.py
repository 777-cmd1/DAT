"""Package 1 security fixes: OAuth state, /health redaction, proxy trust,
password-reset rate limits, session revocation on logout / password reset."""
import sys
import uuid
import secrets as _secrets

from flask import Flask, request

_app = sys.modules['_dat_mailer_app']


def _user(db, password=b'correct-horse-9'):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'p1_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user',
             password=_bcrypt.hashpw(password, _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    db.session.add(Workspace(owner_id=u.id, name='WS')); db.session.commit()
    return u


def _rejected(res):
    """Unauthenticated: 401 for JSON calls, redirect to /login otherwise."""
    return res.status_code == 401 or (res.status_code == 302 and '/login' in res.headers.get('Location', ''))


def _stolen_session(app, user, sv=0):
    """A second browser holding a copy of the user's session cookie."""
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_email'] = user.email
        sess['sv'] = sv
    return c


# ── OAuth callback state ──────────────────────────────────────────────────────

def test_oauth_missing_state_on_both_sides_is_rejected(app, db, client):
    u = _user(db)
    with client.session_transaction() as sess:
        sess['user_email'] = u.email          # logged in, never started Connect Gmail
    res = client.get('/api/gmail/callback?code=attacker-code')
    assert res.status_code == 302
    assert 'state_mismatch' in res.headers['Location']


def test_oauth_wrong_state_is_rejected_and_state_is_single_use(app, db, client):
    u = _user(db)
    with client.session_transaction() as sess:
        sess['user_email'] = u.email
        sess['oauth_state'] = 'expected-state'
    res = client.get('/api/gmail/callback?code=x&state=other')
    assert 'state_mismatch' in res.headers['Location']
    with client.session_transaction() as sess:
        assert 'oauth_state' not in sess     # consumed even on failure


def test_oauth_matching_state_requires_login(app, db, client):
    with client.session_transaction() as sess:
        sess['oauth_state'] = 'st'
    res = client.get('/api/gmail/callback?code=x&state=st')
    assert res.status_code == 302
    assert 'state_mismatch' not in res.headers['Location']
    assert '/login' in res.headers['Location']


def test_oauth_matching_state_proceeds_to_token_exchange(app, db, client, monkeypatch):
    u = _user(db)
    with client.session_transaction() as sess:
        sess['user_email'] = u.email
        sess['oauth_state'] = 'st'

    def _boom(*a, **kw):
        raise RuntimeError('exchange reached')
    monkeypatch.setattr(_app.urllib.request, 'urlopen', _boom)
    res = client.get('/api/gmail/callback?code=x&state=st')
    loc = res.headers['Location']
    assert 'state_mismatch' not in loc and 'exchange' in loc


# ── /health ───────────────────────────────────────────────────────────────────

def test_health_never_exposes_limiter_storage(app, client, monkeypatch):
    monkeypatch.setattr(_app, '_limiter_storage', 'redis://default:s3cr3t@redis.internal:6379')
    res = client.get('/health')
    body = res.get_data(as_text=True)
    assert 'rate_limit_store' not in res.get_json()
    assert 's3cr3t' not in body and 'redis://' not in body


# ── Proxy trust ───────────────────────────────────────────────────────────────

def test_proxy_hops_detection():
    assert _app._proxy_hops({}) == 0
    assert _app._proxy_hops({'RAILWAY_PROJECT_ID': 'p'}) == 1
    assert _app._proxy_hops({'RAILWAY_ENVIRONMENT_NAME': 'production'}) == 1
    assert _app._proxy_hops({'PROXY_HOPS': '2', 'RAILWAY_PROJECT_ID': 'p'}) == 2
    assert _app._proxy_hops({'PROXY_HOPS': 'junk', 'RAILWAY_SERVICE_ID': 's'}) == 1
    assert _app._proxy_hops({'PROXY_HOPS': '0', 'RAILWAY_PROJECT_ID': 'p'}) == 0


def _probe_app(hops):
    mini = Flask('probe')

    @mini.route('/probe')
    def probe():
        return {'ip': request.remote_addr, 'scheme': request.scheme}
    _app._apply_proxy_fix(mini, hops)
    return mini.test_client()


def test_proxy_fix_uses_client_ip_and_https_behind_one_proxy():
    c = _probe_app(1)
    # client tried to spoof 6.6.6.6; the edge proxy appended the real client IP
    r = c.get('/probe', headers={'X-Forwarded-For': '6.6.6.6, 203.0.113.9',
                                 'X-Forwarded-Proto': 'https'},
              environ_base={'REMOTE_ADDR': '10.0.0.1'}).get_json()
    assert r == {'ip': '203.0.113.9', 'scheme': 'https'}


def test_no_proxy_trust_ignores_forwarded_headers():
    c = _probe_app(0)
    r = c.get('/probe', headers={'X-Forwarded-For': '6.6.6.6'},
              environ_base={'REMOTE_ADDR': '10.0.0.1'}).get_json()
    assert r['ip'] == '10.0.0.1'


# ── Password reset rate limits ────────────────────────────────────────────────

def _with_limiter(fn):
    _app.limiter.enabled = True
    _app.limiter.reset()
    try:
        fn()
    finally:
        _app.limiter.reset()
        _app.limiter.enabled = False


def test_reset_request_limited_per_email(app, client):
    def run():
        target = f'victim_{uuid.uuid4().hex[:6]}@x.com'
        codes = [client.post('/api/auth/reset-request', json={'email': target}).status_code
                 for _ in range(4)]
        assert codes[:3] == [200, 200, 200] and codes[3] == 429
    _with_limiter(run)


def test_reset_request_limited_per_ip(app, client):
    def run():
        codes = [client.post('/api/auth/reset-request',
                             json={'email': f'u{i}_{uuid.uuid4().hex[:4]}@x.com'}).status_code
                 for i in range(6)]
        assert codes[:5] == [200] * 5 and codes[5] == 429
    _with_limiter(run)


# ── Session revocation ────────────────────────────────────────────────────────

def test_logout_kills_copied_session_cookie(app, db, client):
    u = _user(db)
    assert client.post('/api/auth/login', json={'email': u.email, 'password': 'correct-horse-9'}).status_code == 200
    stolen = _stolen_session(app, u, sv=0)
    assert stolen.get('/api/followups').status_code == 200
    client.post('/api/auth/logout')
    assert _rejected(stolen.get('/api/followups'))
    assert stolen.get('/api/auth/me').status_code == 401


def test_password_reset_kills_existing_sessions(app, db, client):
    from app.models import PasswordResetToken
    u = _user(db)
    stolen = _stolen_session(app, u, sv=0)
    assert stolen.get('/api/followups').status_code == 200
    tok = _secrets.token_urlsafe(48)
    db.session.add(PasswordResetToken(email=u.email, token=tok)); db.session.commit()
    res = client.post('/api/auth/reset-confirm', json={'token': tok, 'password': 'brand-new-pass-1'})
    assert res.status_code == 200
    assert _rejected(stolen.get('/api/followups'))
    # the new password works and yields a valid session
    fresh = app.test_client()
    assert fresh.post('/api/auth/login', json={'email': u.email, 'password': 'brand-new-pass-1'}).status_code == 200
    assert fresh.get('/api/followups').status_code == 200


def test_existing_session_without_version_key_still_valid(app, db):
    u = _user(db)
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_email'] = u.email       # cookie issued before this release
    assert c.get('/api/followups').status_code == 200


def test_deleted_user_session_rejected(app, db):
    from app.models import User, Workspace
    u = _user(db)
    c = _stolen_session(app, u)
    Workspace.query.filter_by(owner_id=u.id).delete()
    db.session.delete(db.session.get(User, u.id)); db.session.commit()
    assert _rejected(c.get('/api/followups'))


# ── DB URL driver pin (deploy 2026-10-01 healthcheck failure) ──────────────────

def test_postgres_url_is_pinned_to_psycopg2():
    f = _app._sqlalchemy_db_url
    assert f('postgresql://u:p@h:5432/db') == 'postgresql+psycopg2://u:p@h:5432/db'
    assert f('postgres://u:p@h/db') == 'postgresql+psycopg2://u:p@h/db'
    assert f('postgresql+psycopg2://u@h/db') == 'postgresql+psycopg2://u@h/db'
    assert f('sqlite:///x.db') == 'sqlite:///x.db'
