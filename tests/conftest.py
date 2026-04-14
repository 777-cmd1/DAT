"""
Test configuration for DAT Mailer v2.
Sets up in-memory SQLite DB, Flask test client, and helper fixtures.
"""
import os
import sys
import importlib.util
import pytest

# ── Set env vars BEFORE loading the app ──────────────────────────────────────
os.environ.setdefault('SECRET_KEY', 'test-secret-key-32chars-padding!!')
os.environ.setdefault('TESTING', '1')

# Force in-memory SQLite (never use prod PostgreSQL in tests)
# Must be set BEFORE app.py is loaded, as it reads this at module level.
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

# Generate a fresh Fernet key for each test session
from cryptography.fernet import Fernet
_test_fernet_key = Fernet.generate_key().decode()
os.environ['ENCRYPTION_KEY'] = _test_fernet_key

# Suppress Sentry during tests
os.environ['SENTRY_DSN'] = ''

# Disable Flask-Limiter rate limiting during tests
os.environ['RATELIMIT_ENABLED'] = '0'

# Disable the background scheduler thread during tests
os.environ['DISABLE_SCHEDULER'] = '1'

# ── Load app.py via the same pattern as wsgi.py ───────────────────────────────
_APP_PY = os.path.join(os.path.dirname(__file__), '..', 'app.py')
_spec = importlib.util.spec_from_file_location('_dat_mailer_app', _APP_PY)
_module = importlib.util.module_from_spec(_spec)
sys.modules['_dat_mailer_app'] = _module
_spec.loader.exec_module(_module)

flask_app = _module.app
_db       = _module.db

# Disable rate limiting for all tests (limiter is already initialized at this point)
_module.limiter.enabled = False


@pytest.fixture(scope='session')
def app():
    """Session-scoped Flask app configured for testing."""
    flask_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'SESSION_COOKIE_SECURE': False,
        'RATELIMIT_ENABLED': False,
    })
    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.drop_all()


@pytest.fixture(scope='function')
def db(app):
    """Function-scoped DB — rolls back after each test to keep isolation."""
    with app.app_context():
        yield _db
        _db.session.rollback()


@pytest.fixture(scope='function')
def client(app):
    """Flask test client with session support."""
    return app.test_client()


@pytest.fixture(scope='function')
def auth_client(app, db):
    """Authenticated test client: creates a user and logs in via session."""
    import bcrypt as _bcrypt
    from app.models import User, Workspace

    with app.app_context():
        pw_hash = _bcrypt.hashpw(b'testpass123', _bcrypt.gensalt()).decode()
        user = User(
            email='testuser@example.com',
            name='Test User',
            password=pw_hash,
            role='user',
        )
        db.session.add(user)
        db.session.flush()

        ws = Workspace(owner_id=user.id, name='Test Workspace', plan='free')
        db.session.add(ws)
        db.session.commit()

        uid = user.id

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user_email'] = 'testuser@example.com'

    client._test_user_id = uid
    return client


def make_user(db_session, app_ctx, email='user@test.com', role='user', plan='free'):
    """Helper: create a User + Workspace and return (user, workspace)."""
    import bcrypt as _bcrypt
    from app.models import User, Workspace

    pw_hash = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Test', password=pw_hash, role=role)
    db_session.session.add(user)
    db_session.session.flush()

    ws = Workspace(owner_id=user.id, name='WS', plan=plan)
    db_session.session.add(ws)
    db_session.session.commit()
    return user, ws
