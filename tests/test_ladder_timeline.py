"""The contact history: human titles for the ladder's and the owner's events, and an order that reads
correctly for a contact created from a load-bearing reply."""
import sys
import uuid
from datetime import timedelta

import pytest

_app = sys.modules['_dat_mailer_app']


@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    from app.models import FollowupContact, FollowupEvent
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    db.session.commit()


@pytest.fixture
def me(app, db, client):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'tl_{uuid.uuid4().hex[:8]}@test.com', name='T', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = user.email
    return user, ws


def _contact(db, me):
    from app.models import FollowupContact
    user, ws = me
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id, rung='warm', load_count=1, state='active',
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com')
    db.session.add(fc); db.session.commit()
    return fc


def _event(db, fc, etype, at, **kw):
    from app.models import FollowupEvent
    db.session.add(FollowupEvent(followup_contact_id=fc.id, workspace_id=fc.workspace_id, event_type=etype,
                                 event_at=at, actor_type=kw.pop('actor_type', 'system'), **kw))


def _history(client, fc):
    return client.get(f'/api/followups/timeline?id={fc.id}').get_json()['items']


def test_ladder_and_manual_events_get_human_titles_and_their_type(app, db, client, me):
    fc = _contact(db, me)
    now = _app._utcnow()
    kinds = ['ladder_load', 'ladder_refusal', 'ladder_deferral', 'ladder_unknown', 'ladder_exhausted',
             'ladder_parked', 'ladder_blocked', 'manual_pause_auto', 'manual_resume_auto', 'manual_set_rung',
             'manual_exclude', 'manual_unexclude']
    for i, k in enumerate(kinds):
        _event(db, fc, k, now - timedelta(minutes=i), notes='x')
    db.session.commit()
    items = _history(client, fc)
    assert [i['type'] for i in items] == kinds
    for i in items:
        assert i['title'] != i['type'] and '_' not in i['title']       # never the raw event name
    titles = {i['type']: i['title'] for i in items}
    assert titles['manual_set_rung'] == 'Moved by you'
    assert titles['manual_pause_auto'] == 'Automation paused by you'
    assert titles['ladder_load'] == 'Sent load information'


def test_a_ladder_step_shows_which_rung_it_moved_from_and_to(app, db, client, me):
    fc = _contact(db, me)
    _event(db, fc, 'ladder_load', _app._utcnow(), from_state='neutral', to_state='warm', notes='load #1 received')
    _event(db, fc, 'ladder_load', _app._utcnow() - timedelta(hours=1), from_state='hot', to_state='hot',
           notes='load #3 received')
    db.session.commit()
    first, second = _history(client, fc)
    assert first['detail'] == 'NEUTRAL → WARM · load #1 received'
    assert second['detail'] == 'load #3 received'                       # no arrow when the rung stayed


def test_added_comes_before_the_ladder_step_recorded_a_moment_earlier(app, db, client, me):
    """The create path writes the ladder event first (same transaction): the history must still
    read 'added', then 'sent load information'."""
    fc = _contact(db, me)
    t = _app._utcnow() - timedelta(days=1)
    _event(db, fc, 'ladder_load', t, from_state='neutral', to_state='warm', notes='load #1 received')
    _event(db, fc, 'created', t + timedelta(microseconds=900), actor_type='user')
    _event(db, fc, 'touch_sent', t + timedelta(days=1), actor_type='scheduler', notes='ladder touch 1 on warm')
    db.session.commit()
    types = [i['type'] for i in _history(client, fc)]
    # newest first: the touch, then the ladder step, then 'created' last (oldest)
    assert types == ['touch_sent', 'ladder_load', 'created']


def test_a_ladder_step_long_after_creation_is_not_pulled_back(app, db, client, me):
    fc = _contact(db, me)
    t = _app._utcnow() - timedelta(days=3)
    _event(db, fc, 'created', t, actor_type='user')
    _event(db, fc, 'ladder_load', t + timedelta(hours=2), from_state='neutral', to_state='warm')
    db.session.commit()
    assert [i['type'] for i in _history(client, fc)] == ['ladder_load', 'created']


def test_a_failed_send_is_titled_as_failed_not_as_the_send_it_was_meant_to_be(app, db, client, me):
    import json
    fc = _contact(db, me)
    now = _app._utcnow()
    _event(db, fc, 'touch_sent', now, actor_type='scheduler', notes='Send failed - backing off',
           metadata_json=json.dumps({'error': 'token revoked', 'attempt': 1}))
    _event(db, fc, 'free_send', now - timedelta(minutes=1), notes='Send failed',
           metadata_json=json.dumps({'error': 'smtp down'}))
    _event(db, fc, 'touch_sent', now - timedelta(minutes=2), actor_type='scheduler', notes='ladder touch 1 on warm')
    db.session.commit()
    items = _history(client, fc)
    assert [i['title'] for i in items] == ['Send failed', 'Send failed', 'Auto touch sent']
    assert [i['failed'] for i in items] == [True, True, False]


def test_event_types_that_were_raw_snake_case_now_have_titles(app, db, client, me):
    fc = _contact(db, me)
    now = _app._utcnow()
    kinds = ['auto_send', 'state_change', 'scheduled_once', 'schedule_cancelled', 'recurring_set',
             'recurring_stopped']
    for i, k in enumerate(kinds):
        _event(db, fc, k, now - timedelta(minutes=i), from_state='active' if k == 'state_change' else None,
               to_state='paused' if k == 'state_change' else None)
    db.session.commit()
    items = _history(client, fc)
    assert [i['title'] for i in items] == ['Drip follow-up sent', 'Status changed', 'One-time send scheduled',
                                           'Schedule cancelled', 'Recurring send set', 'Recurring send stopped']
    assert items[1]['detail'] == 'active → paused'


def test_a_reply_shows_its_own_words_and_a_human_label(app, db, client, me):
    from app.models import Reply
    fc = _contact(db, me)
    user, _ = me
    db.session.add(Reply(user_id=user.id, msg_id=f'<tl-{uuid.uuid4().hex}@t>', from_email=fc.contact_email,
                         body='Yes, load Monday.\n\nOn Mon, Oct 5, 2026 at 9:00 AM Me <me@x.com> wrote:\n> Any loads?',
                         status='follow_up', triage_category='gave_info', received_at=_app._utcnow()))
    db.session.commit()
    item = _history(client, fc)[0]
    assert item['title'] == 'Reply · gave information'
    assert item['detail'] == 'Yes, load Monday.'


def test_the_history_says_when_it_was_cut_short(app, db, client, me):
    fc = _contact(db, me)
    now = _app._utcnow()
    for i in range(101):
        _event(db, fc, 'note_added', now - timedelta(minutes=i), notes='n')
    db.session.commit()
    data = client.get(f'/api/followups/timeline?id={fc.id}').get_json()
    assert data['truncated'] is True and len(data['items']) == 100
    fresh = _contact(db, me)
    _event(db, fresh, 'note_added', now, notes='n')
    db.session.commit()
    assert client.get(f'/api/followups/timeline?id={fresh.id}').get_json()['truncated'] is False
