"""
Tests for get_daily_quota() — plan-based daily send limits.
"""
import sys
import pytest
from datetime import date

_m = sys.modules['_dat_mailer_app']
get_daily_quota = _m.get_daily_quota
_db_module      = _m.db


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _create_user_with_plan(db, plan='free', role='user', email=None):
    from app.models import User, Workspace
    import bcrypt as _bcrypt
    import uuid
    email = email or f'quota_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Test', password=pw, role=role)
    db.session.add(user)
    db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', plan=plan)
    db.session.add(ws)
    db.session.commit()
    return user, ws


def _add_usage(db, uid, count):
    from app.models import UsageEvent
    ev = UsageEvent(user_id=uid, event_type='email_sent', count=count, period_date=date.today())
    db.session.add(ev)
    db.session.commit()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_free_plan_limit_is_50(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free')
        quota = get_daily_quota(user.id)
        assert quota['plan'] == 'free'
        assert quota['limit'] == 50
        assert quota['unlimited'] is False


def test_starter_plan_limit(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='starter')
        quota = get_daily_quota(user.id)
        assert quota['plan'] == 'starter'
        assert quota['limit'] == 300
        assert quota['unlimited'] is False


def test_pro_plan_is_unlimited(app, db):
    with app.app_context():
        user, ws = _create_user_with_plan(db, plan='pro')
        quota = get_daily_quota(user.id)
        assert quota['plan'] == 'pro'
        assert quota['limit'] is None
        assert quota['unlimited'] is True
        assert quota['remaining'] is None


def test_admin_user_is_unlimited(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free', role='admin',
                                         email='admin_quota@test.com')
        quota = get_daily_quota(user.id)
        assert quota['unlimited'] is True
        assert quota['limit'] is None


def test_used_count_reflected(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free')
        _add_usage(db, user.id, 30)
        quota = get_daily_quota(user.id)
        assert quota['used'] == 30
        assert quota['remaining'] == 20


def test_remaining_capped_at_zero(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free')
        _add_usage(db, user.id, 60)   # over limit
        quota = get_daily_quota(user.id)
        assert quota['remaining'] == 0


def test_no_uid_returns_zero_quota(app, db):
    with app.app_context():
        quota = get_daily_quota(uid=None)
        assert quota['limit'] == 0
        assert quota['used'] == 0
        assert quota['unlimited'] is False


def test_fresh_user_has_zero_used(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free')
        quota = get_daily_quota(user.id)
        assert quota['used'] == 0
        assert quota['remaining'] == 50


def test_pct_calculated_correctly(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='free')
        _add_usage(db, user.id, 25)   # 50% of 50
        quota = get_daily_quota(user.id)
        assert quota['pct'] == 50


def test_pct_zero_for_unlimited(app, db):
    with app.app_context():
        user, _ = _create_user_with_plan(db, plan='pro')
        _add_usage(db, user.id, 100)
        quota = get_daily_quota(user.id)
        assert quota['pct'] == 0
        assert quota['unlimited'] is True
