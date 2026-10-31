"""Warmth-ladder columns on FollowupContact: defaults and to_dict exposure."""
import uuid

import bcrypt as _bcrypt


def _make_contact(db):
    from app.models import FollowupContact, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'ladder_{uuid.uuid4().hex[:8]}@test.com', name='L',
                password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.flush()
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com')
    db.session.add(fc); db.session.commit()
    return fc


def test_new_contact_starts_cold_with_empty_counters(app, db):
    fc = _make_contact(db)
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('cold', 0, 0)
    assert fc.auto_paused is False
    assert fc.last_load_at is None and fc.exit_reason is None


def test_to_dict_exposes_ladder_fields(app, db):
    d = _make_contact(db).to_dict()
    for key in ('rung', 'load_count', 'touch_attempt', 'auto_paused', 'exit_reason'):
        assert key in d
