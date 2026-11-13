"""scripts/backfill_conversations.py — point each contact at its newest stored reply.

The live hook keeps the conversation current from the moment it shipped; a base that
has been running for months still carries the thread its contacts were created with.
"""
import sys
import uuid
from datetime import timedelta

import pytest

_app = sys.modules['_dat_mailer_app']

import scripts.backfill_conversations as bf_mod                                # noqa: E402

bf_mod._APP = _app                      # the suite's already-loaded app module


@pytest.fixture
def bf():
    return bf_mod


def _ws(db, name='WS'):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'bf_{uuid.uuid4().hex[:8]}@test.com', name='B', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name=name)
    db.session.add(ws); db.session.commit()
    return user, ws


def _contact(db, user, ws, **kw):
    from app.models import FollowupContact
    kw.setdefault('contact_email', f'{uuid.uuid4().hex[:8]}@x.com')
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id, state='active',
                         stage='completed_fu3', is_followup_enabled=False, rung='warm', **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _reply(db, user, from_email, *, thread, msg_id, subject, days_ago=0, matched=None):
    from app.models import Reply
    r = Reply(user_id=user.id, msg_id=msg_id, thread_id=thread, from_email=from_email,
              matched_recipient=matched, subject=subject, body='text',
              received_at=_app._utcnow() - timedelta(days=days_ago))
    db.session.add(r); db.session.commit()
    return r


def test_a_contact_moves_onto_its_newest_reply(app, db, bf):
    user, ws = _ws(db)
    fc = _contact(db, user, ws, source_thread_id='t-aug', reply_msg_id='<aug@m>',
                  reply_subject='Re: Laredo to El Paso')
    _reply(db, user, fc.contact_email, thread='t-aug', msg_id='<aug@m>',
           subject='Re: Laredo to El Paso', days_ago=90)
    _reply(db, user, fc.contact_email, thread='t-oct', msg_id='<oct@m>',
           subject='Re: Newark to Atlanta', days_ago=10)
    out = bf.backfill(ws.id, dry_run=False)
    db.session.refresh(fc)
    assert out['moved'] == 1 and out['already_current'] == 0
    assert fc.source_thread_id == 't-oct' and fc.reply_msg_id == '<oct@m>'
    assert fc.reply_subject == 'Re: Newark to Atlanta'


def test_a_dry_run_reports_the_move_and_writes_nothing(app, db, bf):
    user, ws = _ws(db)
    fc = _contact(db, user, ws, source_thread_id='t-old', reply_subject='Re: Old lane')
    _reply(db, user, fc.contact_email, thread='t-new', msg_id='<new@m>',
           subject='Re: New lane')
    out = bf.backfill(ws.id, dry_run=True)
    assert out['moved'] == 1 and out['rows'][0]['to_subject'] == 'Re: New lane'
    db.session.expire_all()
    from app.models import FollowupContact
    assert db.session.get(FollowupContact, fc.id).source_thread_id == 't-old'


def test_a_colleagues_reply_counts_for_the_contact_we_wrote_to(app, db, bf):
    # dispatch@abc.com was written to, john@abc.com answered: the engine already
    # treats that as this contact's reply, so the backfill must too
    user, ws = _ws(db)
    fc = _contact(db, user, ws, contact_email='dispatch@abc.com', source_thread_id='t-old')
    _reply(db, user, 'john@abc.com', thread='t-colleague', msg_id='<john@m>',
           subject='Re: Dallas to Memphis', matched='dispatch@abc.com')
    out = bf.backfill(ws.id, dry_run=False)
    db.session.refresh(fc)
    assert out['moved'] == 1 and fc.source_thread_id == 't-colleague'


def test_a_contact_with_no_stored_reply_is_left_alone(app, db, bf):
    user, ws = _ws(db)
    fc = _contact(db, user, ws, source_thread_id='t-old', reply_msg_id='<old@m>')
    out = bf.backfill(ws.id, dry_run=False)
    db.session.refresh(fc)
    assert out['no_reply_stored'] == 1 and out['moved'] == 0
    assert fc.source_thread_id == 't-old'


def test_a_contact_already_on_its_newest_conversation_is_not_counted_as_moved(app, db, bf):
    user, ws = _ws(db)
    fc = _contact(db, user, ws, source_thread_id='t-new', reply_msg_id='<new@m>',
                  reply_subject='Re: New lane')
    _reply(db, user, fc.contact_email, thread='t-new', msg_id='<new@m>', subject='Re: New lane')
    out = bf.backfill(ws.id, dry_run=False)
    assert out['moved'] == 0 and out['already_current'] == 1


def test_the_backfill_never_reaches_another_workspace(app, db, bf):
    # the one bug this must never have
    mine_user, mine = _ws(db, 'Mine')
    other_user, other = _ws(db, 'Theirs')
    ours = _contact(db, mine_user, mine, source_thread_id='t-old')
    theirs = _contact(db, other_user, other, source_thread_id='t-theirs')
    _reply(db, mine_user, ours.contact_email, thread='t-mine-new', msg_id='<m1@m>', subject='Re: a')
    _reply(db, other_user, theirs.contact_email, thread='t-their-new', msg_id='<m2@m>', subject='Re: b')
    bf.backfill(mine.id, dry_run=False)
    db.session.refresh(ours); db.session.refresh(theirs)
    assert ours.source_thread_id == 't-mine-new'
    assert theirs.source_thread_id == 't-theirs'


def test_an_unknown_workspace_is_refused(app, db, bf):
    with pytest.raises(ValueError):
        bf.backfill(str(uuid.uuid4()), dry_run=True)
