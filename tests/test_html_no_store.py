"""HTML pages must never be cached.

Every HTML page embeds a session-bound CSRF token. A browser that re-serves a
cached page sends a token from an older session, and the next POST is rejected
with "Invalid CSRF token" — which locked a user out of /login on 2026-10-30.
JSON API responses are unaffected.
"""
import uuid


def _login_page(client):
    return client.get('/login')


def test_login_page_is_not_cacheable(client):
    res = _login_page(client)
    assert res.status_code == 200
    assert 'no-store' in res.headers.get('Cache-Control', '')


def test_every_csrf_bearing_page_is_not_cacheable(client):
    for path in ['/login', '/register', '/reset-password']:
        res = client.get(path)
        if res.status_code in (301, 302, 404):
            continue                      # route may require a token/param
        assert 'no-store' in res.headers.get('Cache-Control', ''), path


def test_app_page_is_not_cacheable(app, db, client):
    """The main app page embeds CSRF_TOKEN for every mutating fetch."""
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'nostore_{uuid.uuid4().hex[:8]}@test.com'
    user = User(email=email, name='T', role='user',
                password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(user); db.session.flush()
    db.session.add(Workspace(owner_id=user.id, name='WS'))
    db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
    res = client.get('/')
    assert res.status_code == 200
    assert 'no-store' in res.headers.get('Cache-Control', '')


def test_json_api_is_left_alone(app, db, client):
    """Only HTML gets the no-store treatment — JSON responses are untouched."""
    res = client.get('/api/auth/me')
    assert res.mimetype == 'application/json'
    assert 'no-store' not in res.headers.get('Cache-Control', '')
