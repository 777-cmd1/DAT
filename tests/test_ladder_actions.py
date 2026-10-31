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


def test_set_rung_cannot_re_arm_a_paused_drip(app, db, client, me):
    # the pause clears the drip's date; moving the rung must not hand it a new one
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True,
             next_followup_at=_app._utcnow() + timedelta(days=1))
    _act(client, fc, 'pause-auto')
    assert _act(client, fc, 'set-rung', rung='warm').status_code == 200
    fc = _reload(db, fc)
    assert fc.rung == 'warm' and fc.auto_paused and fc.next_followup_at is None
    assert _row(client, fc)['next_touch_reason'] == 'auto paused by you'


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


# ══ fix round 1 ══════════════════════════════════════════════════════════════
# excluded must stop every sender, a pause must hold against every engine

@pytest.fixture
def sent_log(monkeypatch):
    """Capture every follow-up send; each one succeeds."""
    out = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, *a, **k: (out.append(fu['contact_email']), (True, None))[1])
    return out


def _stop_entries(uid):
    from app.models import StopListEntry
    return StopListEntry.query.filter_by(user_id=uid).all()


def _soon_iso():
    return (_app._utcnow() + timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')


def test_exclude_puts_the_address_on_the_stop_list(app, db, client, me):
    fc = _fc(db, me, 'warm')
    resp = _act(client, fc, 'exclude')
    assert resp.status_code == 200
    entry, = _stop_entries(me[0].id)
    assert (entry.type, entry.value, entry.reason) == ('email', fc.contact_email, 'excluded')
    # the real sender refuses it: this is what stops the Send page, the drip, one-time,
    # recurring and the ladder, none of which look at the rung
    blocked, domains = _app.load_stop_list(uid=me[0].id)
    assert _app.is_blocked(fc.contact_email, blocked, domains)
    ok, err = _app.send_followup_email({'contact_email': fc.contact_email}, 'Hi', {}, uid=me[0].id)
    assert (ok, err) == (False, 'blocked by stop list')


def test_exclude_does_not_rewrite_a_block_the_owner_made(app, db, client, me):
    from app.models import StopListEntry
    fc = _fc(db, me, 'warm')
    db.session.add(StopListEntry(user_id=me[0].id, type='email', value=fc.contact_email,
                                 reason='blocked from Follow-up'))
    db.session.commit()
    assert _act(client, fc, 'exclude').status_code == 200
    entry, = _stop_entries(me[0].id)
    assert entry.reason == 'blocked from Follow-up'


@pytest.mark.parametrize('action, extra', [
    ('free-send', {}), ('send-now', {}), ('restart-fu1', {}),
    ('schedule-once', {'scheduled_at': '__soon__'}),
    ('set-recurring', {'recurring_days': '1,3', 'recurring_time': '10:00'}),
])
def test_an_excluded_contact_is_refused_by_every_send_and_schedule_action(
        app, db, client, me, sent_log, action, extra):
    # the exact contact the old code let through: excluded, but still on its drip stage
    fc = _fc(db, me, 'warm', stage='fu1_scheduled', next_followup_at=None)
    _act(client, fc, 'exclude')
    extra = {k: (_soon_iso() if v == '__soon__' else v) for k, v in extra.items()}

    resp = _act(client, fc, action, **extra)
    assert resp.status_code in (400, 409) and 'never contacted' in resp.get_json()['error']
    bulk = _bulk(client, [fc.id], action, **extra).get_json()['results'][0]
    assert bulk['ok'] is False and 'never contacted' in bulk['error']

    fc = _reload(db, fc)
    assert sent_log == []
    assert fc.rung == 'excluded' and fc.next_followup_at is None
    assert not (fc.is_followup_enabled or fc.scheduled_once or fc.recurring_enabled)


def test_the_background_bulk_job_core_refuses_an_excluded_contact(app, db, client, me, sent_log):
    fc = _fc(db, me, 'warm', stage='fu1_scheduled', next_followup_at=None)
    _act(client, fc, 'exclude')
    fc = _reload(db, fc)
    assert _app._followup_send_now_core(fc, me[0].id) == ('skip', _app._EXCLUDED_MSG)
    assert sent_log == []


def _run_drip():
    n = _app._run_scheduled_followups()
    _app.db.session.expire_all()
    return n


def _arm_scheduler(db, me):
    me[1].fu_auto_enabled = True
    db.session.commit()


def _due(): return _app._utcnow() - timedelta(hours=2)


def test_the_scheduler_never_sends_to_a_paused_contact_on_any_engine(app, db, client, me, sent_log):
    _arm_scheduler(db, me)
    drip = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True, next_followup_at=_due())
    once = _fc(db, me, 'cold', scheduled_once=True, next_followup_at=_due())
    rec = _fc(db, me, 'cold', recurring_enabled=True, recurring_days='0,1,2,3,4,5,6',
              recurring_time='10:00', next_followup_at=_due())
    # control: unpaused, every engine does send
    assert _run_drip() >= 1
    assert drip.contact_email in sent_log and once.contact_email in sent_log \
        and rec.contact_email in sent_log

    sent_log.clear()
    db.session.expire_all()
    for fc in (drip, once, rec):                   # make them all due again, then pause by data
        fc.auto_paused = True
        fc.next_followup_at = _due()
        fc.stage = 'fu1_scheduled'
        fc.state = 'active'
    drip.is_followup_enabled = True       # the control run spent each engine's state: re-arm it
    once.scheduled_once = True
    rec.recurring_enabled = True
    db.session.commit()
    _run_drip()
    assert sent_log == []


def test_the_scheduler_never_sends_to_an_excluded_contact_on_any_engine(app, db, client, me, sent_log):
    _arm_scheduler(db, me)
    drip = _fc(db, me, 'excluded', stage='fu1_scheduled', is_followup_enabled=True, next_followup_at=_due())
    once = _fc(db, me, 'excluded', scheduled_once=True, next_followup_at=_due())
    rec = _fc(db, me, 'excluded', recurring_enabled=True, recurring_days='0,1,2,3,4,5,6',
              recurring_time='10:00', next_followup_at=_due())
    _run_drip()
    assert sent_log == []


# ── unexclude ────────────────────────────────────────────────────────────────

def test_unexclude_restores_the_rung_from_the_loads_and_lifts_the_stop_list_entry(app, db, client, me):
    fc = _fc(db, me, 'hot', load_count=2, last_reply_at=_app._utcnow())
    _act(client, fc, 'exclude')
    assert _stop_entries(me[0].id)
    resp = _act(client, fc, 'unexclude')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['contact']['rung'] == 'hot' and body['stop_list_removed'] is True
    fc = _reload(db, fc)
    assert (fc.rung, fc.exit_reason, fc.touch_attempt) == ('hot', None, 0)
    assert fc.next_followup_at is not None and fc.touch_enabled
    assert not _stop_entries(me[0].id)
    evt, = _events(fc, 'manual_unexclude')
    assert evt.actor_type == 'user' and (evt.from_state, evt.to_state) == ('excluded', 'hot')
    # and the contact can be sent to again
    assert _app.is_blocked(fc.contact_email, *_app.load_stop_list(uid=me[0].id)) is False


@pytest.mark.parametrize('loads, replied, rung', [(0, False, 'cold'), (0, True, 'neutral'),
                                                  (1, True, 'warm'), (3, True, 'hot')])
def test_unexclude_derives_the_rung_from_load_count(app, db, client, me, loads, replied, rung):
    fc = _fc(db, me, 'warm', load_count=loads, last_reply_at=_app._utcnow() if replied else None)
    _act(client, fc, 'exclude')
    _act(client, fc, 'unexclude')
    assert _reload(db, fc).rung == rung


def test_unexclude_leaves_a_block_the_owner_made_for_another_reason(app, db, client, me):
    from app.models import StopListEntry
    fc = _fc(db, me, 'warm')
    db.session.add(StopListEntry(user_id=me[0].id, type='email', value=fc.contact_email,
                                 reason='blocked from Follow-up'))
    db.session.commit()
    _act(client, fc, 'exclude')
    body = _act(client, fc, 'unexclude').get_json()
    assert body['stop_list_removed'] is False
    entry, = _stop_entries(me[0].id)
    assert entry.reason == 'blocked from Follow-up'


def test_unexclude_is_refused_for_a_contact_that_is_not_excluded(app, db, client, me):
    fc = _fc(db, me, 'warm')
    resp = _act(client, fc, 'unexclude')
    assert resp.status_code == 400
    assert _reload(db, fc).rung == 'warm' and not _events(fc, 'manual_unexclude')


def test_unexclude_is_never_available_in_bulk(app, db, client, me):
    fc = _fc(db, me, 'warm')
    _act(client, fc, 'exclude')
    resp = _bulk(client, [fc.id], 'unexclude')
    assert resp.status_code == 400
    assert _reload(db, fc).rung == 'excluded'


def test_unexclude_checks_ownership(app, db, client, me):
    other = _user(db)
    stranger = _fc(db, other, 'excluded', exit_reason='excluded')
    assert _act(client, stranger, 'unexclude').status_code == 404
    assert _reload(db, stranger).rung == 'excluded'


# ── a pause holds against every engine that dates a contact ──────────────────

def test_a_paused_contact_is_not_re_dated_by_cancel_stop_or_resume(app, db, client, me):
    sched = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True, scheduled_once=True,
                next_followup_at=_app._utcnow() + timedelta(days=2))
    rec = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True, recurring_enabled=True,
              recurring_days='1', recurring_time='10:00',
              next_followup_at=_app._utcnow() + timedelta(days=2))
    state = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True, state='paused',
                next_followup_at=None)
    for fc in (sched, rec, state):
        fc.auto_paused = True
        fc.next_followup_at = None
    db.session.commit()
    assert _act(client, sched, 'cancel-schedule').status_code == 200
    assert _act(client, rec, 'stop-recurring').status_code == 200
    assert _act(client, state, 'resume').status_code == 200
    for name, fc in (('cancel-schedule', sched), ('stop-recurring', rec), ('resume', state)):
        assert _reload(db, fc).next_followup_at is None, name


def test_restoring_a_schedule_gives_no_date_to_a_dormant_contact(app, db, client, me):
    fc = _fc(db, me, 'dormant', stage='fu1_scheduled', is_followup_enabled=True, next_followup_at=None)
    _app._restore_contact_schedule(fc)
    assert fc.next_followup_at is None


# ── counts, bulk validation, discarded sends ─────────────────────────────────

def test_counts_tell_the_state_warm_from_the_rung_warm(app, db, client, me):
    _fc(db, me, 'warm')
    _fc(db, me, 'warm')
    _fc(db, me, 'hot')
    _fc(db, me, 'cold', state='warm', next_followup_at=None)      # the legacy contact state
    got = client.get('/api/followups?rung=hot').get_json()
    assert got['counts']['state_warm'] == got['counts']['warm'] == 1
    assert got['rung_counts'] == {'cold': 1, 'neutral': 0, 'warm': 2, 'hot': 1, 'client': 0,
                                  'dormant': 0, 'excluded': 0}      # the whole base, not the filter
    assert [c['rung'] for c in got['contacts']] == ['hot']


def test_bulk_set_rung_with_a_bad_rung_is_one_400_and_changes_nothing(app, db, client, me):
    a, b = _fc(db, me, 'cold'), _fc(db, me, 'cold')
    for bad in ('lukewarm', 'excluded', None):
        resp = _bulk(client, [a.id, b.id], 'set-rung', rung=bad)
        assert resp.status_code == 400 and resp.get_json()['error']
    assert _reload(db, a).rung == 'cold' and _reload(db, b).rung == 'cold'
    assert not _events(a) and not _events(b)


def test_pause_says_when_it_discards_a_one_time_send_the_owner_scheduled(app, db, client, me):
    when = _app._utcnow() + timedelta(days=2)
    fc = _fc(db, me, 'warm', scheduled_once=True, next_followup_at=when)
    body = _act(client, fc, 'pause-auto').get_json()
    assert body['discarded_scheduled_at'] == when.strftime('%Y-%m-%dT%H:%M:%SZ')
    evt, = _events(fc, 'manual_pause_auto')
    assert 'one-time send' in evt.notes and 'discarded' in evt.notes
    # nothing to report when nothing was discarded
    plain = _fc(db, me, 'warm')
    assert 'discarded_scheduled_at' not in _act(client, plain, 'pause-auto').get_json()


def test_bulk_results_carry_what_was_discarded(app, db, client, me):
    when = _app._utcnow() + timedelta(days=2)
    fc = _fc(db, me, 'warm', scheduled_once=True, next_followup_at=when)
    rec = _fc(db, me, 'warm', recurring_enabled=True, recurring_days='1', recurring_time='10:00')
    res = _bulk(client, [fc.id, rec.id], 'set-rung', rung='dormant').get_json()['results']
    assert res[0]['discarded_scheduled_at'] == when.strftime('%Y-%m-%dT%H:%M:%SZ')
    assert res[1]['discarded_recurring'] is True


# ── the deferral lookup follows the rows on screen ───────────────────────────

def test_the_deferral_lookup_is_limited_to_the_rows_returned(app, db, client, me, monkeypatch):
    asked = []
    real = _app._ladder_deferred_ids
    monkeypatch.setattr(_app, '_ladder_deferred_ids',
                        lambda uid, contacts: (asked.append([c.id for c in contacts]), real(uid, contacts))[1])
    warm = _fc(db, me, 'warm')
    _fc(db, me, 'hot')
    client.get('/api/followups?rung=warm')
    assert asked == [[warm.id]]


def test_the_deferral_lookup_skips_contacts_whose_reason_cannot_be_one(app, db, client, me):
    from sqlalchemy import event
    statements = []
    listener = lambda conn, cur, stmt, *a: statements.append(stmt)
    event.listen(db.engine, 'before_cursor_execute', listener)
    try:
        _fc(db, me, 'dormant')
        _fc(db, me, 'excluded')
        _fc(db, me, 'warm', auto_paused=True, next_followup_at=None)
        client.get('/api/followups')
    finally:
        event.remove(db.engine, 'before_cursor_execute', listener)
    assert not [s for s in statements if 'followup_events' in s and 'GROUP BY' in s]
