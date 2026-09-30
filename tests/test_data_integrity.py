"""Package 4: data integrity — replies.msg_id unique per user."""
import sys
import uuid

import pytest

_app = sys.modules['_dat_mailer_app']


def _user(db, client=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'di_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user', password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    db.session.add(Workspace(owner_id=u.id, name='WS')); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
    return u


def _reply(db, user, msg_id, status='new'):
    from app.models import Reply
    r = Reply(user_id=user.id, msg_id=msg_id, from_email='dispatch@carrier.com',
              subject='Re: Laredo, TX to Doral, FL', body='we can cover', status=status)
    db.session.add(r); db.session.commit()
    return r


def test_same_message_can_reach_two_users(app, db):
    from sqlalchemy.exc import IntegrityError
    a, b = _user(db), _user(db)
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid)
    _reply(db, b, mid)                     # used to violate the global unique
    with pytest.raises(IntegrityError):
        _reply(db, a, mid)                 # still unique within one mailbox
    db.session.rollback()


def test_save_replies_only_touches_own_row(app, db):
    from app.models import Reply
    a, b = _user(db), _user(db)
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid, status='follow_up')
    _app.save_replies([{'msg_id': mid, 'email': 'dispatch@carrier.com', 'status': 'new'}], uid=b.id)
    rows = {r.user_id: r.status for r in Reply.query.filter_by(msg_id=mid).all()}
    assert rows == {a.id: 'follow_up', b.id: 'new'}


def test_marking_reply_does_not_change_other_users_copy(app, db, client):
    from app.models import Reply
    a = _user(db)
    b = _user(db, client)                  # logged in as B
    mid = f'<{uuid.uuid4().hex}@mail.gmail.com>'
    _reply(db, a, mid, status='new')
    _reply(db, b, mid, status='new')
    res = client.post('/api/replies/status', json={'msg_id': mid, 'status': 'not_interested'})
    assert res.status_code == 200
    db.session.expire_all()
    assert Reply.query.filter_by(user_id=a.id, msg_id=mid).first().status == 'new'
    assert Reply.query.filter_by(user_id=b.id, msg_id=mid).first().status == 'not_interested'
