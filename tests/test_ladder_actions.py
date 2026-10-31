"""Warmth ladder: the tier list and the owner's manual overrides.

The owner can see who is where, stop anyone, and move them out by hand; whatever
the machine decides, he can override, and the machine must not override him back.
"""
import json
import sys
import uuid
from datetime import timedelta

import pytest

from app import ladder

_app = sys.modules['_dat_mailer_app']


# ── helpers ──────────────────────────────────────────────────────────────────

def _user(db):
    import bcrypt as _bcrypt
    from app.models import EmailAccount, Template, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'act_{uuid.uuid4().hex[:8]}@test.com', name='A', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', pipeline_config={'touch_hour': 15})
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                gmail_address='me@test.com', your_name='Me'))
    db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup',
                            level='FU1', name='FU1', body='Hi', is_active=True))
    db.session.commit()
    return user, ws


def _sign_in(client, user):
    with client.session_transaction() as sess:
        sess['user_email'] = user.email


@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    """The scheduler scans every workspace and committed rows outlive a test."""
    from app.models import FollowupContact, FollowupEvent
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    db.session.commit()


@pytest.fixture
def me(app, db, client):
    user, ws = _user(db)
    _sign_in(client, user)
    return user, ws


def _fc(db, me, rung='warm', **kw):
    from app.models import FollowupContact
    user, ws = me
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'completed_fu3')
    kw.setdefault('is_followup_enabled', False)
    kw.setdefault('load_count', {'warm': 1, 'hot': 2}.get(rung, 0))
    if 'next_followup_at' not in kw and rung in ladder.RUNGS and rung != 'client':
        kw['next_followup_at'] = _app._utcnow() + timedelta(days=2)
        kw.setdefault('touch_enabled', True)
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id, rung=rung,
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _act(client, fc, action, **extra):
    return client.post('/api/followups/action', json={'id': fc.id, 'action': action, **extra})


def _bulk(client, ids, action, **extra):
    return client.post('/api/followups/bulk-action', json={'ids': ids, 'action': action, **extra})


def _events(fc, event_type=None):
    from app.models import FollowupEvent
    q = FollowupEvent.query.filter_by(followup_contact_id=fc.id)
    if event_type:
        q = q.filter_by(event_type=event_type)
    return q.order_by(FollowupEvent.event_at).all()


def _reload(db, fc):
    db.session.expire_all()
    return db.session.get(type(fc), fc.id)


def _row(client, fc):
    resp = client.get('/api/followups')
    assert resp.status_code == 200
    return next(c for c in resp.get_json()['contacts'] if c['id'] == fc.id)


# ── the tier list ────────────────────────────────────────────────────────────

def test_list_filters_by_rung(app, db, client, me):
    warm = _fc(db, me, 'warm')
    hot = _fc(db, me, 'hot')
    dormant = _fc(db, me, 'dormant')
    got = client.get('/api/followups?rung=warm').get_json()
    assert [c['id'] for c in got['contacts']] == [warm.id]
    off = client.get('/api/followups?rung=dormant').get_json()
    assert [c['id'] for c in off['contacts']] == [dormant.id]
    everyone = client.get('/api/followups').get_json()
    assert {c['id'] for c in everyone['contacts']} == {warm.id, hot.id, dormant.id}


def test_select_all_filtered_uses_the_same_rung_filter(app, db, client, me):
    warm = _fc(db, me, 'warm')
    _fc(db, me, 'hot')
    assert client.get('/api/followups/ids?rung=warm').get_json()['ids'] == [warm.id]


def test_an_unknown_rung_is_rejected_not_ignored(app, db, client, me):
    _fc(db, me, 'warm')
    assert client.get('/api/followups?rung=lukewarm').status_code == 400
    assert client.get('/api/followups/ids?rung=lukewarm').status_code == 400


def test_the_rung_filter_never_shows_another_users_contacts(app, db, client, me):
    mine = _fc(db, me, 'warm')
    other = _user(db)
    _fc(db, other, 'warm')
    got = client.get('/api/followups?rung=warm').get_json()
    assert [c['id'] for c in got['contacts']] == [mine.id]


def test_row_carries_the_ladder_fields(app, db, client, me):
    fc = _fc(db, me, 'warm', touch_attempt=2)
    row = _row(client, fc)
    assert row['rung'] == 'warm' and row['load_count'] == 1 and row['touch_attempt'] == 2
    assert row['budget'] == ladder.budget_for('warm', ladder.LADDER_DEFAULTS) == 5
    assert row['auto_paused'] is False
    assert row['next_followup_at'] is not None
    assert row['next_touch_reason']


def test_row_explains_why_the_next_touch_is_when_it_is(app, db, client, me):
    # the next touch in the budget
    fc = _fc(db, me, 'warm', touch_attempt=2)
    assert _row(client, fc)['next_touch_reason'] == 'touch 3 of 5'

    # a date a broker asked for: the deferral is the latest thing that set the date
    asked = _fc(db, me, 'neutral')
    _app._record_event(asked, 'ladder_deferral', actor_type='system',
                       notes='asked to come back 2026-11-13')
    db.session.commit()
    assert _row(client, asked)['next_touch_reason'] == 'they asked us to come back later'

    # ...until a later touch moves the date on
    _app._record_event(asked, 'touch_sent', actor_type='scheduler')
    db.session.commit()
    assert _row(client, asked)['next_touch_reason'] == 'touch 1 of 3'

    # stopped by hand
    paused = _fc(db, me, 'warm', auto_paused=True, next_followup_at=None)
    assert _row(client, paused)['next_touch_reason'] == 'auto paused by you'
    parked = _fc(db, me, 'warm', auto_paused=True, exit_reason='send_failed', next_followup_at=None)
    assert 'sending failed' in _row(client, parked)['next_touch_reason']


def test_row_reasons_for_contacts_with_no_date(app, db, client, me):
    cases = {
        'excluded': ('excluded', 'never'),
        'client': (None, 'client'),
    }
    for rung, (exit_reason, word) in cases.items():
        fc = _fc(db, me, rung, exit_reason=exit_reason)
        assert word in _row(client, fc)['next_touch_reason']
    refused = _fc(db, me, 'dormant', exit_reason='refused')
    assert 'asked us to stop' in _row(client, refused)['next_touch_reason']
    spent = _fc(db, me, 'dormant', exit_reason='exhausted')
    assert 'attempts used up' in _row(client, spent)['next_touch_reason']
    moved = _fc(db, me, 'dormant', exit_reason='manual')
    assert 'moved by you' in _row(client, moved)['next_touch_reason']
    idle = _fc(db, me, 'warm', next_followup_at=None)
    assert _row(client, idle)['next_touch_reason'] == 'nothing scheduled'


def test_a_legacy_rung_does_not_break_the_list(app, db, client, me):
    fc = _fc(db, me, 'legacy-rung', next_followup_at=None)
    row = _row(client, fc)
    assert row['budget'] == 0 and 'unrecognised' in row['next_touch_reason']


# ── pause-auto / resume-auto ─────────────────────────────────────────────────

def test_pause_auto_keeps_the_contact_but_stops_sending(app, db, client, me):
    fc = _fc(db, me, 'warm', touch_attempt=2)
    resp = _act(client, fc, 'pause-auto')
    assert resp.status_code == 200
    body = resp.get_json()['contact']
    assert body['auto_paused'] is True and body['next_followup_at'] is None
    assert body['budget'] == 5 and body['next_touch_reason'] == 'auto paused by you'
    fc = _reload(db, fc)
    assert fc.auto_paused and fc.rung == 'warm' and fc.touch_attempt == 2
    assert fc.next_followup_at is None and not fc.touch_enabled and fc.state == 'active'
    evt, = _events(fc, 'manual_pause_auto')
    assert evt.actor_type == 'user' and evt.actor_user_id == me[0].id


def test_a_pause_survives_the_stage_cadence_too(app, db, client, me):
    # a fresh cold contact is dated by the stage cadence, which every reply, stage move
    # and sweep re-bases: the pause must hold against it
    fc = _fc(db, me, 'cold', next_followup_at=None, pipeline_stage=2)   # stage 2 is dated every 3 days
    _act(client, fc, 'pause-auto')
    fc = _reload(db, fc)
    _app._schedule_touch(fc, force=True)
    db.session.commit()
    assert _reload(db, fc).next_followup_at is None


def test_pausing_twice_writes_one_event(app, db, client, me):
    fc = _fc(db, me, 'warm')
    assert _act(client, fc, 'pause-auto').status_code == 200
    assert _act(client, fc, 'pause-auto').status_code == 200
    assert len(_events(fc, 'manual_pause_auto')) == 1


def test_pause_stops_a_running_drip_too(app, db, client, me):
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True,
             next_followup_at=_app._utcnow() + timedelta(days=1))
    _act(client, fc, 'pause-auto')
    assert _reload(db, fc).next_followup_at is None
    _act(client, fc, 'resume-auto')
    fc = _reload(db, fc)
    assert fc.is_followup_enabled and fc.next_followup_at is not None   # the drip is back


def test_resume_auto_reschedules_from_the_current_rung(app, db, client, me):
    fc = _fc(db, me, 'warm', touch_attempt=2, auto_paused=True, next_followup_at=None)
    before = _app._utcnow()
    resp = _act(client, fc, 'resume-auto')
    assert resp.status_code == 200
    fc = _reload(db, fc)
    assert fc.auto_paused is False and fc.touch_attempt == 2 and fc.rung == 'warm'
    # attempt 3 on warm is weekly; the date lands on the configured touch hour (15:00 local)
    assert before + timedelta(days=6) < fc.next_followup_at < before + timedelta(days=8, hours=2)
    assert fc.touch_enabled
    assert len(_events(fc, 'manual_resume_auto')) == 1
    assert resp.get_json()['contact']['next_touch_reason'] == 'touch 3 of 5'


def test_resuming_a_parked_contact_clears_all_three_so_it_is_not_parked_again(app, db, client, me):
    fc = _fc(db, me, 'warm', auto_paused=True, exit_reason='send_failed',
             send_fail_count=5, next_followup_at=None, attention_at=_app._utcnow())
    assert _act(client, fc, 'resume-auto').status_code == 200
    fc = _reload(db, fc)
    assert (fc.auto_paused, fc.exit_reason, fc.send_fail_count) == (False, None, 0)
    assert fc.next_followup_at is not None
    # the next failure is a first failure: a 6 hour backoff, not an instant give-up
    gave_up = _app._record_send_failure(fc, 'touch_sent', 'smtp down', _app._utcnow())
    assert gave_up is False and fc.send_fail_count == 1


def test_resume_does_not_erase_why_a_dormant_contact_left(app, db, client, me):
    fc = _fc(db, me, 'dormant', exit_reason='refused', auto_paused=True)
    resp = _act(client, fc, 'resume-auto')
    assert resp.status_code == 400
    fc = _reload(db, fc)
    assert fc.exit_reason == 'refused' and fc.auto_paused is True and not _events(fc, 'manual_resume_auto')


@pytest.mark.parametrize('rung', ['dormant', 'client', 'excluded'])
def test_resume_is_refused_off_the_automatic_schedule(app, db, client, me, rung):
    fc = _fc(db, me, rung)
    resp = _act(client, fc, 'resume-auto')
    assert resp.status_code == 400
    assert _reload(db, fc).next_followup_at is None


def test_resume_is_refused_for_a_contact_that_is_not_active(app, db, client, me):
    fc = _fc(db, me, 'warm', state='blocked', auto_paused=True, next_followup_at=None)
    assert _act(client, fc, 'resume-auto').status_code == 400
    fc = _reload(db, fc)
    assert fc.auto_paused is True and fc.next_followup_at is None


def test_resume_on_a_contact_that_is_not_paused_changes_nothing(app, db, client, me):
    due = _app._utcnow() + timedelta(days=4)
    fc = _fc(db, me, 'warm', next_followup_at=due)
    assert _act(client, fc, 'resume-auto').status_code == 200
    fc = _reload(db, fc)
    assert fc.next_followup_at == due and not _events(fc, 'manual_resume_auto')


def test_resume_hands_a_lost_one_time_date_back_to_the_ladder(app, db, client, me):
    fc = _fc(db, me, 'warm', scheduled_once=True, auto_paused=True, next_followup_at=None)
    assert _act(client, fc, 'resume-auto').status_code == 200
    fc = _reload(db, fc)
    assert fc.scheduled_once is False and fc.next_followup_at is not None


# ── set-rung ─────────────────────────────────────────────────────────────────

def test_set_rung_is_recorded_as_a_manual_event(app, db, client, me):
    fc = _fc(db, me, 'neutral', touch_attempt=2)
    resp = _act(client, fc, 'set-rung', rung='hot')
    assert resp.status_code == 200
    assert resp.get_json()['contact']['rung'] == 'hot'
    fc = _reload(db, fc)
    assert fc.rung == 'hot'
    evt, = _events(fc, 'manual_set_rung')
    assert evt.actor_type == 'user' and evt.actor_user_id == me[0].id
    assert (evt.from_state, evt.to_state) == ('neutral', 'hot')
    assert json.loads(evt.metadata_json) == {'from': 'neutral', 'to': 'hot', 'attempts_reset_from': 2}


def test_set_rung_starts_a_fresh_run_on_the_new_rung(app, db, client, me):
    # the budget of the old rung must not leak: 5 spent attempts on a rung with a budget of 5
    # would be parked by the very next scheduler tick, undoing the owner's move
    fc = _fc(db, me, 'dormant', exit_reason='exhausted', touch_attempt=5, load_count=1,
             next_followup_at=None)
    before = _app._utcnow()
    assert _act(client, fc, 'set-rung', rung='warm').status_code == 200
    fc = _reload(db, fc)
    assert (fc.rung, fc.touch_attempt, fc.exit_reason) == ('warm', 0, None)
    assert fc.next_followup_at is not None and fc.next_followup_at > before   # touch 1, tomorrow
    assert fc.next_followup_at < before + timedelta(days=3)


def test_a_scheduler_tick_does_not_undo_a_set_rung(app, db, client, me, monkeypatch):
    user, ws = me
    ws.fu_auto_enabled = True
    ws.ladder_auto_enabled = True
    sent = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (sent.append(fu['contact_email']), (True, None))[1])
    fc = _fc(db, me, 'dormant', exit_reason='exhausted', touch_attempt=5, load_count=1,
             next_followup_at=None)
    db.session.commit()
    _act(client, fc, 'set-rung', rung='warm')
    fc = _reload(db, fc)
    fc.next_followup_at = _app._utcnow() - timedelta(hours=1)    # it is now due
    db.session.commit()

    assert _app._run_ladder_touches(_app._utcnow()) == 1
    fc = _reload(db, fc)
    assert sent == [fc.contact_email]
    assert fc.rung == 'warm' and fc.touch_attempt == 1 and fc.exit_reason is None


def test_set_rung_to_dormant_stops_everything(app, db, client, me):
    fc = _fc(db, me, 'warm', is_followup_enabled=True, stage='fu1_scheduled',
             recurring_enabled=True, recurring_days='0', recurring_time='10:00', scheduled_once=True)
    assert _act(client, fc, 'set-rung', rung='dormant').status_code == 200
    fc = _reload(db, fc)
    assert fc.rung == 'dormant' and fc.exit_reason == 'manual'
    assert fc.next_followup_at is None and not fc.touch_enabled
    assert not (fc.is_followup_enabled or fc.recurring_enabled or fc.scheduled_once)


def test_set_rung_to_client_takes_the_contact_out_of_automation(app, db, client, me):
    fc = _fc(db, me, 'hot', is_followup_enabled=True, stage='fu1_scheduled')
    assert _act(client, fc, 'set-rung', rung='client').status_code == 200
    fc = _reload(db, fc)
    assert fc.rung == 'client' and fc.next_followup_at is None and not fc.is_followup_enabled


def test_set_rung_leaves_a_running_drip_alone(app, db, client, me):
    due = _app._utcnow() + timedelta(days=1)
    fc = _fc(db, me, 'cold', is_followup_enabled=True, stage='fu1_scheduled', next_followup_at=due)
    assert _act(client, fc, 'set-rung', rung='warm').status_code == 200
    fc = _reload(db, fc)
    assert fc.rung == 'warm' and fc.is_followup_enabled and fc.next_followup_at == due


def test_set_rung_keeps_a_pause(app, db, client, me):
    fc = _fc(db, me, 'warm', auto_paused=True, next_followup_at=None)
    _act(client, fc, 'set-rung', rung='hot')
    fc = _reload(db, fc)
    assert fc.rung == 'hot' and fc.auto_paused and fc.next_followup_at is None


def test_set_rung_to_the_same_rung_is_a_no_op(app, db, client, me):
    due = _app._utcnow() + timedelta(days=4)
    fc = _fc(db, me, 'warm', touch_attempt=3, next_followup_at=due)
    assert _act(client, fc, 'set-rung', rung='warm').status_code == 200
    fc = _reload(db, fc)
    assert fc.touch_attempt == 3 and fc.next_followup_at == due and not _events(fc, 'manual_set_rung')


@pytest.mark.parametrize('rung', [None, '', 'lukewarm', 'excluded'])
def test_set_rung_rejects_what_it_cannot_set(app, db, client, me, rung):
    fc = _fc(db, me, 'warm')
    resp = _act(client, fc, 'set-rung', rung=rung)
    assert resp.status_code == 400
    assert _reload(db, fc).rung == 'warm' and not _events(fc, 'manual_set_rung')


def test_set_rung_cannot_undo_an_exclusion(app, db, client, me):
    fc = _fc(db, me, 'excluded', exit_reason='excluded')
    assert _act(client, fc, 'set-rung', rung='warm').status_code == 400
    assert _reload(db, fc).rung == 'excluded'


# ── set-rung against the machine: replies ────────────────────────────────────

def _reply(db, fc, category, body, thread=None):
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=f'<{uuid.uuid4().hex}@mail>', thread_id=thread,
              from_email=fc.contact_email, subject='Re: Laredo to Dallas', body=body,
              triage_category=category)
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit()
    return _reload(db, fc)


@pytest.mark.parametrize('category, body', [
    ('rate_request', 'what is your rate?'),            # unknown: asks for a human
    (None, 'maybe next week, call me then'),           # deferral
])
def test_a_reply_that_is_not_a_load_does_not_raise_a_rung_the_owner_lowered(
        app, db, client, me, category, body):
    # 2 loads on record (derived rung: hot) but the owner put the contact on neutral
    fc = _fc(db, me, 'hot', load_count=2)
    _act(client, fc, 'set-rung', rung='neutral')
    fc = _reply(db, fc, category, body)
    assert fc.rung == 'neutral'


def test_a_cold_contact_that_replies_still_becomes_neutral(app, db, client, me):
    fc = _fc(db, me, 'cold')
    fc = _reply(db, fc, 'rate_request', 'what is your rate?')
    assert fc.rung == 'neutral'


def test_a_load_reply_does_not_pull_a_manual_rung_down(app, db, client, me):
    fc = _fc(db, me, 'cold')
    _act(client, fc, 'set-rung', rung='hot')
    fc = _reply(db, fc, 'gave_info', 'load Laredo to Dallas', thread='t1')
    assert fc.rung == 'hot' and fc.load_count == 1 and fc.touch_attempt == 0


def test_a_client_stays_a_client_when_it_sends_a_load(app, db, client, me):
    fc = _fc(db, me, 'warm')
    _act(client, fc, 'set-rung', rung='client')
    fc = _reply(db, fc, 'gave_info', 'load Laredo to Dallas', thread='t1')
    assert fc.rung == 'client' and fc.next_followup_at is None


def test_a_deferral_does_not_date_a_manually_dormant_contact(app, db, client, me):
    fc = _fc(db, me, 'warm')
    _act(client, fc, 'set-rung', rung='dormant')
    fc = _reply(db, fc, 'negative', 'nothing right now, check back next week')
    assert fc.rung == 'dormant' and fc.next_followup_at is None


# ── exclude ──────────────────────────────────────────────────────────────────

def test_exclude_is_permanent_and_clears_the_schedule(app, db, client, me):
    fc = _fc(db, me, 'hot', is_followup_enabled=True, stage='fu1_scheduled', scheduled_once=True,
             recurring_enabled=True, recurring_days='0', recurring_time='10:00',
             attention_at=_app._utcnow())
    resp = _act(client, fc, 'exclude')
    assert resp.status_code == 200
    fc = _reload(db, fc)
    assert (fc.rung, fc.exit_reason) == ('excluded', 'excluded')
    assert fc.next_followup_at is None and not fc.touch_enabled and fc.attention_at is None
    # every engine that could email them is off
    assert not (fc.is_followup_enabled or fc.scheduled_once or fc.recurring_enabled)
    evt, = _events(fc, 'manual_exclude')
    assert evt.actor_type == 'user' and evt.actor_user_id == me[0].id
    assert (evt.from_state, evt.to_state) == ('hot', 'excluded')


def test_nothing_automatic_undoes_an_exclusion(app, db, client, me):
    fc = _fc(db, me, 'warm')
    _act(client, fc, 'exclude')
    fc = _reply(db, fc, 'gave_info', 'here is a load', thread='t9')
    assert fc.rung == 'excluded' and fc.next_followup_at is None
    _app._schedule_touch(fc, force=True)
    assert _reload(db, fc).rung == 'excluded' and fc.next_followup_at is None
    for action, extra in (('pause-auto', {}), ('resume-auto', {}), ('set-rung', {'rung': 'warm'})):
        assert _act(client, fc, action, **extra).status_code == 400
    assert _reload(db, fc).rung == 'excluded'


def test_excluding_twice_writes_one_event(app, db, client, me):
    fc = _fc(db, me, 'warm')
    assert _act(client, fc, 'exclude').status_code == 200
    assert _act(client, fc, 'exclude').status_code == 200
    assert len(_events(fc, 'manual_exclude')) == 1


# ── bulk ─────────────────────────────────────────────────────────────────────

def test_bulk_actions_apply_to_every_selected_contact(app, db, client, me):
    a, b = _fc(db, me, 'warm'), _fc(db, me, 'hot')
    resp = _bulk(client, [a.id, b.id], 'pause-auto')
    assert resp.status_code == 200
    assert [r['ok'] for r in resp.get_json()['results']] == [True, True]
    assert _reload(db, a).auto_paused and _reload(db, b).auto_paused
    resp = _bulk(client, [a.id, b.id], 'resume-auto')
    assert [r['ok'] for r in resp.get_json()['results']] == [True, True]
    a, b = _reload(db, a), _reload(db, b)
    assert not a.auto_paused and not b.auto_paused
    assert a.next_followup_at is not None and b.next_followup_at is not None


def test_bulk_set_rung_and_exclude(app, db, client, me):
    a, b = _fc(db, me, 'cold'), _fc(db, me, 'cold')
    assert _bulk(client, [a.id, b.id], 'set-rung', rung='warm').get_json()['sent'] == 2
    assert _reload(db, a).rung == 'warm' and _reload(db, b).rung == 'warm'
    assert _bulk(client, [a.id, b.id], 'exclude').get_json()['sent'] == 2
    assert _reload(db, a).rung == 'excluded' and _reload(db, b).rung == 'excluded'


def test_bulk_reports_each_contact_and_never_touches_the_excluded_or_foreign(app, db, client, me):
    mine = _fc(db, me, 'cold')
    gone = _fc(db, me, 'excluded', exit_reason='excluded')
    stranger = _fc(db, _user(db), 'cold')
    results = _bulk(client, [mine.id, gone.id, stranger.id, 'no-such-id'],
                    'set-rung', rung='warm').get_json()['results']
    assert [r['ok'] for r in results] == [True, False, False, False]
    assert results[2]['error'] == 'Not found' and results[3]['error'] == 'Not found'
    assert _reload(db, mine).rung == 'warm'
    assert _reload(db, gone).rung == 'excluded'
    assert _reload(db, stranger).rung == 'cold'


# ── ownership ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('action, extra', [
    ('pause-auto', {}), ('resume-auto', {}), ('set-rung', {'rung': 'hot'}), ('exclude', {}),
])
def test_another_users_contact_cannot_be_changed(app, db, client, me, action, extra):
    stranger = _fc(db, _user(db), 'warm', auto_paused=True, next_followup_at=None)
    resp = _act(client, stranger, action, **extra)
    assert resp.status_code == 404
    stranger = _reload(db, stranger)
    assert stranger.rung == 'warm' and stranger.auto_paused is True
    assert stranger.exit_reason is None and not _events(stranger)
    results = _bulk(client, [stranger.id], action, **extra).get_json()['results']
    assert results == [{'id': stranger.id, 'ok': False, 'error': 'Not found'}]
    assert not _events(_reload(db, stranger))


# ── manual sends are history, and do not spend the budget ────────────────────

def _send_ok(monkeypatch):
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))


def test_a_manual_send_is_recorded_as_a_touch_and_spends_no_attempt(app, db, client, me, monkeypatch):
    _send_ok(monkeypatch)
    fc = _fc(db, me, 'warm', touch_attempt=2)
    resp = _act(client, fc, 'free-send')
    assert resp.status_code == 200
    fc = _reload(db, fc)
    assert fc.touch_attempt == 2                       # the owner's send is not the machine's
    assert fc.last_followup_sent_at is not None
    evt, = _events(fc, 'free_send')
    assert evt.actor_type == 'user' and evt.actor_user_id == me[0].id
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=5)   # re-based: touch 3 is a week out


def test_a_bulk_manual_send_is_recorded_and_re_based_like_a_single_one(app, db, client, me, monkeypatch):
    _send_ok(monkeypatch)
    fc = _fc(db, me, 'warm', touch_attempt=2, next_followup_at=_app._utcnow() - timedelta(hours=1))
    resp = _bulk(client, [fc.id], 'free-send')
    assert resp.get_json()['results'][0]['ok'] is True
    fc = _reload(db, fc)
    assert fc.touch_attempt == 2 and len(_events(fc, 'free_send')) == 1
    # without a re-base it would still be overdue and the scheduler would send again at once
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=5)


def test_send_now_is_recorded_as_a_manual_touch(app, db, client, me, monkeypatch):
    _send_ok(monkeypatch)
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True, touch_attempt=0)
    assert _act(client, fc, 'send-now').status_code == 200
    fc = _reload(db, fc)
    assert fc.touch_attempt == 0
    evt, = _events(fc, 'manual_send')
    assert evt.actor_type == 'user'
