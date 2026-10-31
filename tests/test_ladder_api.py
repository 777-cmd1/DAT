"""Warmth ladder scoreboard data: funnel, "Needs you" and the day's activity."""
import json
import sys
import uuid
from datetime import datetime, timedelta

import pytest

from app import ladder

_app = sys.modules['_dat_mailer_app']


# ── helpers ──────────────────────────────────────────────────────────────────

def _user(db, tz=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'api_{uuid.uuid4().hex[:8]}@test.com', name='A', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    if tz:
        ws.pipeline_config = {'timezone': tz}
    db.session.add(ws); db.session.commit()
    return user, ws


def _sign_in(client, user):
    with client.session_transaction() as sess:
        sess['user_email'] = user.email


@pytest.fixture
def me(app, db, client):
    """A signed-in user with a workspace."""
    user, ws = _user(db)
    _sign_in(client, user)
    return user, ws


def _get(client, url):
    resp = client.get(url)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


def _fc(db, me, rung='cold', created_days_ago=1, name='', **kw):
    from app.models import FollowupContact
    user, ws = me
    kw.setdefault('state', 'active')
    fc = FollowupContact(
        user_id=user.id, workspace_id=ws.id, contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
        contact_name=name, stage='completed_fu3', is_followup_enabled=False, rung=rung,
        created_at=_app._utcnow() - timedelta(days=created_days_ago), **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _event(db, fc, event_type, ago=timedelta(hours=1), from_state=None, to_state=None,
           notes=None, metadata=None):
    from app.models import FollowupEvent
    evt = FollowupEvent(
        followup_contact_id=fc.id, workspace_id=fc.workspace_id, event_type=event_type,
        from_state=from_state, to_state=to_state, actor_type='system',
        event_at=_app._utcnow() - ago, notes=notes,
        metadata_json=json.dumps(metadata) if metadata is not None else None)
    db.session.add(evt); db.session.commit()
    return evt


def _reply(db, fc, body, days_ago=0.0, category=None, **kw):
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=f'<{uuid.uuid4().hex}@mail>', thread_id=kw.pop('thread', None),
              from_email=kw.pop('from_email', fc.contact_email), subject='Re: Laredo to Dallas',
              body=body, triage_category=category,
              received_at=_app._utcnow() - timedelta(days=days_ago), **kw)
    db.session.add(r); db.session.commit()
    return r


def _row(data, rung):
    return next(r for r in data['conversion'] if r['rung'] == rung)


def _ids(people):
    """Ids of a list of {id, email, name} people."""
    return [p['id'] for p in people]


# ── ladder.py: promise phrases and the silence threshold ─────────────────────

@pytest.mark.parametrize('text', [
    "I'll send you a load next week",
    'We will send you some loads once the season picks up',
    'Have a load for you Thursday, will confirm',
    'I’ll send you something soon',          # curly apostrophe
    "Not now, thanks. I'll send you a load next week",   # the 'not' belongs to another sentence
    "No loads this week, but I'll send you a load next week",   # ...or to an earlier clause
    "No problem I'll send you a load",                          # "no problem" is a yes
    "Sorry, no loads right now - will send you a load when we do",   # a dash ends the clause
    "Sorry, no loads right now \u2013 will send you a load when we do",
    "I can send you a load tomorrow",         # "I can" / "we can" is how a broker says yes
    "We can send you a load on Friday",
    "Sure, I can send you a load",
    "yes I can get you a load",
])
def test_a_load_promise_is_recognised(text):
    assert ladder.promise_kind(text) == 'load'


@pytest.mark.parametrize('text', [
    "I'll send you the rates tomorrow",
    'Will send you the details this afternoon',
])
def test_a_non_load_promise_is_recognised(text):
    assert ladder.promise_kind(text) == 'other'


@pytest.mark.parametrize('text', [
    "We can't send you a load right now",
    'We will not send you loads, please remove us',
    'Do you want me to send you the rates?',
    'Thanks for reaching out, nothing at this time',
    '',
    None,
])
def test_a_refusal_or_offer_is_not_a_promise(text):
    assert ladder.promise_kind(text) is None


@pytest.mark.parametrize('text', [
    "I'll let you know if I have a load for you",
    'We will keep you in mind if we have something for you',
    'I wish I could send you a load',
    "I'd love to send you a load",
    'Hopefully we can send you a load soon',
    'I can send you a load if you need one',      # the condition comes after the phrase
    'I have a load for you if you want it',
])
def test_a_hedge_or_a_condition_is_not_a_promise(text):
    assert ladder.promise_kind(text) is None


def test_a_load_promise_wins_over_a_rate_promise():
    assert ladder.promise_kind("I'll send you a load and the rates") == 'load'


def test_silence_threshold_is_twice_the_median_gap_with_a_floor():
    assert ladder.silence_threshold_days([]) == 14           # no history: the floor
    assert ladder.silence_threshold_days([3, 5, 7]) == 14    # 2 x 5 = 10, below the floor
    assert ladder.silence_threshold_days([10, 10, 12]) == 20
    assert ladder.silence_threshold_days([4, 30]) == 34      # even count: median is the mean


# ── funnel: the rung strip ───────────────────────────────────────────────────

def test_funnel_counts_each_rung(app, db, client, me):
    for rung, n in (('warm', 2), ('hot', 1), ('dormant', 3)):
        for _ in range(n):
            _fc(db, me, rung=rung)
    data = _get(client, '/api/followups/funnel')
    assert data['rungs'] == {'cold': 0, 'neutral': 0, 'warm': 2, 'hot': 1,
                             'client': 0, 'dormant': 3, 'excluded': 0}


# ── funnel: conversion in whole contacts ─────────────────────────────────────

def test_conversion_reports_absolute_numbers_not_only_percentages(app, db, client, me):
    _fc(db, me, rung='neutral')
    row = _get(client, '/api/followups/funnel')['conversion'][1]
    assert row['rung'] == 'neutral'
    assert 'reached' in row and 'lost' in row and isinstance(row['reached'], int)
    assert row['reached'] == 1 and row['lost'] == 0


def test_conversion_rows_follow_the_climb_cold_to_client(app, db, client, me):
    data = _get(client, '/api/followups/funnel')
    assert [r['rung'] for r in data['conversion']] == ['cold', 'neutral', 'warm', 'hot', 'client']


def test_conversion_counts_a_contact_at_every_rung_it_reached(app, db, client, me):
    # neutral -> warm -> hot inside the window: counted once at neutral, warm AND hot
    mover = _fc(db, me, rung='hot', load_count=2)
    _event(db, mover, 'ladder_load', from_state='neutral', to_state='warm')
    _event(db, mover, 'ladder_load', from_state='warm', to_state='hot')
    stayed = _fc(db, me, rung='cold')
    data = _get(client, '/api/followups/funnel')
    assert [(r['rung'], r['reached']) for r in data['conversion']] == [
        ('cold', 2), ('neutral', 1), ('warm', 1), ('hot', 1), ('client', 0)]
    assert _ids(_row(data, 'hot')['reached_contacts']) == [mover.id]
    assert _ids(_row(data, 'cold')['reached_contacts']) == sorted([mover.id, stayed.id])


def test_conversion_percentages_are_of_the_previous_step(app, db, client, me):
    for _ in range(4):
        _fc(db, me, rung='cold')
    for _ in range(2):
        _fc(db, me, rung='neutral')
    _fc(db, me, rung='warm', load_count=1)
    data = _get(client, '/api/followups/funnel')
    assert _row(data, 'cold')['pct_of_previous'] is None
    assert [(_row(data, r)['reached'], _row(data, r)['pct_of_previous'])
            for r in ('neutral', 'warm', 'hot')] == [(3, 42.9), (1, 33.3), (0, 0.0)]
    assert _row(data, 'client')['pct_of_previous'] is None     # nobody reached hot: nothing to divide


def test_a_contact_that_left_is_lost_at_the_rung_it_reached(app, db, client, me):
    gone = _fc(db, me, rung='dormant', exit_reason='refused')
    _event(db, gone, 'ladder_load', ago=timedelta(days=5), from_state='neutral', to_state='warm')
    _event(db, gone, 'ladder_refusal', from_state='warm', to_state='dormant')
    tired = _fc(db, me, rung='dormant', exit_reason='exhausted')
    _event(db, tired, 'ladder_exhausted', from_state='neutral', to_state='dormant')
    data = _get(client, '/api/followups/funnel')
    warm = _row(data, 'warm')
    assert (warm['reached'], warm['lost'], warm['still_here']) == (1, 1, 0)
    assert [(r['reason'], r['count'], _ids(r['contacts'])) for r in warm['lost_reasons']] == [
        ('refused', 1, [gone.id])]
    neutral = _row(data, 'neutral')
    assert (neutral['reached'], neutral['lost']) == (2, 1)
    assert [(r['reason'], r['count'], _ids(r['contacts'])) for r in neutral['lost_reasons']] == [
        ('exhausted', 1, [tired.id])]
    # the cold row counts everyone who entered, and nobody left from cold
    assert (_row(data, 'cold')['reached'], _row(data, 'cold')['lost']) == (2, 0)
    assert data['totals']['lost'] == 2


def test_every_row_adds_up_reached_equals_advanced_plus_lost_plus_still_here(app, db, client, me):
    _fc(db, me, rung='cold')
    _fc(db, me, rung='neutral')
    _fc(db, me, rung='warm', load_count=1)
    _fc(db, me, rung='dormant', exit_reason='exhausted')
    _fc(db, me, rung='excluded')
    data = _get(client, '/api/followups/funnel')
    rows = data['conversion']
    for i, row in enumerate(rows):
        advanced = rows[i + 1]['reached'] if i + 1 < len(rows) else 0
        assert row['reached'] == advanced + row['lost'] + row['still_here'], row
    assert sum(r['lost'] for r in rows) == data['totals']['lost'] == 2


def test_a_lost_contact_without_a_recorded_reason_is_still_listed(app, db, client, me):
    owner_cut = _fc(db, me, rung='excluded')
    parked = _fc(db, me, rung='dormant')
    data = _get(client, '/api/followups/funnel')
    reasons = {r['reason']: r for r in _row(data, 'cold')['lost_reasons']}
    assert _ids(reasons['excluded']['contacts']) == [owner_cut.id]
    assert _ids(reasons['unspecified']['contacts']) == [parked.id]


def test_loads_alone_place_a_contact_when_there_are_no_events(app, db, client, me):
    # e.g. a migrated contact: load_count says hot, the history says nothing
    fc = _fc(db, me, rung='dormant', load_count=2, exit_reason='exhausted')
    data = _get(client, '/api/followups/funnel')
    assert (_row(data, 'hot')['reached'], _row(data, 'hot')['lost']) == (1, 1)
    assert _ids(_row(data, 'hot')['lost_reasons'][0]['contacts']) == [fc.id]


def test_only_ladder_events_place_a_contact(app, db, client, me):
    # followup_events.to_state also holds 'warm' as a *state*, not a rung
    fc = _fc(db, me, rung='cold')
    _event(db, fc, 'state_change', from_state='active', to_state='warm')
    assert _row(_get(client, '/api/followups/funnel'), 'warm')['reached'] == 0


def test_conversion_covers_contacts_in_play_during_the_last_30_local_days(app, db, client, me):
    _fc(db, me, rung='cold', created_days_ago=5)
    _fc(db, me, rung='cold', created_days_ago=60)          # old and silent: not in play
    data = _get(client, '/api/followups/funnel')
    assert _row(data, 'cold')['reached'] == 1
    assert data['totals']['entered'] == 1
    assert data['window']['days'] == 30
    assert 'in play' in data['window']['cohort']
    # the rung strip is the whole base today, not the cohort
    assert data['rungs']['cold'] == 2


def test_an_old_contact_with_ladder_activity_in_the_window_is_in_play(app, db, client, me):
    # a base migrated months ago: created long before the window, but it did something in it
    active = _fc(db, me, rung='hot', load_count=2, created_days_ago=200)
    _event(db, active, 'ladder_load', ago=timedelta(days=50), from_state='neutral', to_state='warm')
    _event(db, active, 'ladder_load', ago=timedelta(days=3), from_state='warm', to_state='hot')
    quiet = _fc(db, me, rung='warm', load_count=1, created_days_ago=200)
    _event(db, quiet, 'ladder_load', ago=timedelta(days=50), from_state='neutral', to_state='warm')
    data = _get(client, '/api/followups/funnel')
    assert data['totals']['entered'] == 1
    assert _ids(_row(data, 'cold')['reached_contacts']) == [active.id]
    # the peak is still read from its whole history, not only the window
    assert _ids(_row(data, 'warm')['reached_contacts']) == [active.id]
    assert _ids(_row(data, 'hot')['reached_contacts']) == [active.id]


def test_a_contact_that_left_inside_the_window_counts_as_lost(app, db, client, me):
    gone = _fc(db, me, rung='dormant', exit_reason='exhausted', created_days_ago=120)
    _event(db, gone, 'ladder_exhausted', ago=timedelta(days=4), from_state='neutral', to_state='dormant')
    data = _get(client, '/api/followups/funnel')
    assert (data['totals']['entered'], data['totals']['lost']) == (1, 1)
    assert _row(data, 'neutral')['lost'] == 1


def test_who_is_in_every_count(app, db, client, me):
    fc = _fc(db, me, rung='dormant', exit_reason='refused', name='Sam Ray')
    data = _get(client, '/api/followups/funnel')
    person = {'id': fc.id, 'email': fc.contact_email, 'name': 'Sam Ray'}
    assert _row(data, 'cold')['reached_contacts'] == [person]
    assert _row(data, 'cold')['lost_reasons'] == [{'reason': 'refused', 'count': 1, 'contacts': [person]}]


def test_the_30_day_window_is_30_local_days_not_720_hours(app, db, client, monkeypatch):
    # Auckland is UTC+13. At 2026-10-31 12:00 UTC it is already 1 Nov there, so the
    # window opens at local midnight on 3 Oct = 2026-10-02 11:00 UTC.
    user, ws = _user(db, tz='Pacific/Auckland')
    _sign_in(client, user)
    monkeypatch.setattr(_app, '_utcnow', lambda: datetime(2026, 10, 31, 12, 0))
    from app.models import FollowupContact
    def at(created):
        fc = FollowupContact(user_id=user.id, workspace_id=ws.id, state='active', rung='cold',
                             contact_email=f'{uuid.uuid4().hex[:8]}@x.com', created_at=created)
        db.session.add(fc); db.session.commit()
        return fc
    too_early = at(datetime(2026, 10, 2, 5, 0))     # 29d 7h ago, but local 2 Oct: day 31
    inside = at(datetime(2026, 10, 2, 12, 0))       # local 3 Oct 01:00: day 30
    data = _get(client, '/api/followups/funnel')
    assert _ids(_row(data, 'cold')['reached_contacts']) == [inside.id]
    assert too_early.id not in _ids(_row(data, 'cold')['reached_contacts'])
    assert data['window']['since'] == '2026-10-02T11:00:00Z'


# ── funnel: totals ───────────────────────────────────────────────────────────

def test_totals_entered_lost_and_end_to_end(app, db, client, me):
    _fc(db, me, rung='client', load_count=3)
    _fc(db, me, rung='hot', load_count=2)
    _fc(db, me, rung='cold')
    _fc(db, me, rung='dormant', exit_reason='refused')
    totals = _get(client, '/api/followups/funnel')['totals']
    assert (totals['entered'], totals['lost']) == (4, 1)
    assert totals['end_to_end_pct'] == 25.0           # 1 of 4 reached client
    assert (totals['warm_or_better'], totals['warm_or_better_pct']) == (2, 50.0)   # client + hot
    assert totals['avg_days_between_loads'] is None
    assert totals['loads_this_month'] == 0


def test_totals_with_nobody_entered_have_no_percentage(app, db, client, me):
    totals = _get(client, '/api/followups/funnel')['totals']
    assert totals == {'entered': 0, 'lost': 0, 'end_to_end_pct': None,
                      'warm_or_better': 0, 'warm_or_better_pct': None,
                      'avg_days_between_loads': None, 'loads_this_month': 0}


def test_average_gap_between_loads_is_per_contact(app, db, client, me):
    a = _fc(db, me, rung='hot')
    _event(db, a, 'ladder_load', ago=timedelta(days=20))
    _event(db, a, 'ladder_load', ago=timedelta(days=10))      # 10 days after the first
    _event(db, a, 'ladder_load', ago=timedelta(days=4))       # 6 days after that
    b = _fc(db, me, rung='warm')
    _event(db, b, 'ladder_load', ago=timedelta(days=1))       # a single load: no gap
    assert _get(client, '/api/followups/funnel')['totals']['avg_days_between_loads'] == 8.0


def test_loads_this_month_is_the_local_calendar_month(app, db, client, monkeypatch):
    user, ws = _user(db, tz='America/Los_Angeles')      # 1 Nov 03:00 UTC is still 31 Oct there (UTC-7)
    _sign_in(client, user)
    monkeypatch.setattr(_app, '_utcnow', lambda: datetime(2026, 11, 1, 3, 0))
    fc = _fc(db, (user, ws), rung='warm')
    from app.models import FollowupEvent
    for when in (datetime(2026, 10, 1, 8, 0),       # 1 Oct 01:00 local: this (local) month
                 datetime(2026, 10, 1, 6, 0),       # 30 Sep 23:00 local: last month
                 datetime(2026, 10, 20, 9, 0)):
        db.session.add(FollowupEvent(followup_contact_id=fc.id, workspace_id=ws.id,
                                     event_type='ladder_load', actor_type='system', event_at=when))
    db.session.commit()
    assert _get(client, '/api/followups/funnel')['totals']['loads_this_month'] == 2


# ── needs-you ────────────────────────────────────────────────────────────────

def test_needs_you_is_empty_on_a_quiet_day(app, db, client, me):
    _fc(db, me, rung='warm', load_count=1)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_needs_you_states_the_promise_window_it_applies(app, db, client, me):
    data = _get(client, '/api/followups/needs-you')
    assert (data['promise_grace_days'], data['promise_horizon_days']) == (2, 30)


def test_needs_you_lists_an_unparsed_reply(app, db, client, me):
    fc = _fc(db, me, rung='neutral', name='Pat Broker', attention_at=_app._utcnow())
    _event(db, fc, 'ladder_unknown', notes='reply needs a human look')
    _reply(db, fc, 'Call me about the thing', days_ago=0.1)
    items = _get(client, '/api/followups/needs-you')['items']
    assert len(items) == 1
    item = items[0]
    assert item['id'] == fc.id and item['contact_email'] == fc.contact_email
    assert (item['contact_name'], item['rung'], item['reason']) == ('Pat Broker', 'neutral', 'unparsed_reply')
    assert 'Call me about the thing' in item['detail']


def test_a_rate_request_goes_to_needs_you_through_the_real_reply_hook(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    r = _reply(db, fc, 'What is your rate on Laredo to Dallas?', category='rate_request')
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit()
    items = _get(client, '/api/followups/needs-you')['items']
    assert [(i['id'], i['reason']) for i in items] == [(fc.id, 'unparsed_reply')]
    assert items[0]['detail'].lower().startswith('asked for a rate')


def test_a_reply_the_ladder_handled_is_not_listed(app, db, client, me):
    # attention was raised (warm contact replied), then the ladder counted a load: no human needed
    fc = _fc(db, me, rung='warm', load_count=1, attention_at=_app._utcnow() - timedelta(minutes=5))
    _event(db, fc, 'ladder_load', ago=timedelta(minutes=4), from_state='neutral', to_state='warm')
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_flag_from_the_scheduler_is_not_a_broker_reply(app, db, client, me):
    # "no email account connected" is a setup problem, not one of the four reasons
    fc = _fc(db, me, rung='warm', load_count=1, attention_at=_app._utcnow() - timedelta(minutes=5))
    _event(db, fc, 'ladder_blocked', ago=timedelta(minutes=4), notes='no email account connected')
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_attention_on_an_excluded_or_closed_contact_is_not_listed(app, db, client, me):
    _fc(db, me, rung='excluded', attention_at=_app._utcnow())
    _fc(db, me, rung='neutral', state='closed', attention_at=_app._utcnow())
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_needs_you_lists_a_vanished_load_promise(app, db, client, me):
    fc = _fc(db, me, rung='neutral', name='Dana')
    _reply(db, fc, "Nothing today but I'll send you a load next week.", days_ago=5)
    items = _get(client, '/api/followups/needs-you')['items']
    assert [(i['id'], i['reason']) for i in items] == [(fc.id, 'promised_load_vanished')]
    assert 'send you a load' in items[0]['detail']


def test_a_promise_is_given_two_days_before_it_counts_as_vanished(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    _reply(db, fc, "I'll send you a load tomorrow", days_ago=1.5)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_promise_kept_is_not_listed(app, db, client, me):
    fc = _fc(db, me, rung='warm', load_count=1)
    _reply(db, fc, "I'll send you a load next week", days_ago=6, thread='t1')
    _reply(db, fc, 'Here is the load, Laredo to Dallas', days_ago=3, category='gave_info', thread='t2')
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_load_counted_after_the_promise_clears_it(app, db, client, me):
    fc = _fc(db, me, rung='warm', load_count=1)
    _reply(db, fc, "I'll send you a load next week", days_ago=6, thread='t1')
    _event(db, fc, 'ladder_load', ago=timedelta(days=2), metadata={'conv': 'thread:t9'})
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_the_promise_message_being_counted_as_a_load_does_not_clear_it(app, db, client, me):
    # the classifier read the promise itself as load info; that one load is not "since"
    fc = _fc(db, me, rung='warm', load_count=1)
    _reply(db, fc, "I'll send you a load next week", days_ago=5, thread='t1')
    _event(db, fc, 'ladder_load', ago=timedelta(days=5) - timedelta(minutes=2),
           metadata={'conv': 'thread:t1'})
    items = _get(client, '/api/followups/needs-you')['items']
    assert [i['reason'] for i in items] == ['promised_load_vanished']


def test_an_old_promise_stops_being_listed_after_30_days(app, db, client, me):
    fc = _fc(db, me, rung='dormant', exit_reason='exhausted')
    _reply(db, fc, "I'll send you a load next week", days_ago=45)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_dormant_contact_that_went_quiet_after_promising_is_still_listed(app, db, client, me):
    fc = _fc(db, me, rung='dormant', exit_reason='exhausted')
    _reply(db, fc, "I'll send you a load next week", days_ago=12)
    assert [i['reason'] for i in _get(client, '/api/followups/needs-you')['items']] == ['promised_load_vanished']


def test_a_promise_from_a_contact_who_then_refused_is_not_listed(app, db, client, me):
    fc = _fc(db, me, rung='dormant', exit_reason='refused')
    _reply(db, fc, "I'll send you a load next week", days_ago=9)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_colleagues_promise_counts_for_the_contact_we_wrote_to(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    _reply(db, fc, "I'll send you a load next week", days_ago=5,
           from_email='john@sameco.com', matched_recipient=fc.contact_email)
    assert [i['id'] for i in _get(client, '/api/followups/needs-you')['items']] == [fc.id]


def test_a_quoted_promise_in_our_own_text_is_ignored(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    _reply(db, fc, 'Not now, thanks.\n\nOn Mon, Oct 5, 2026 at 9:00 AM you wrote:\n> I\'ll send you a load',
           days_ago=5)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_needs_you_lists_a_promise_of_something_else_that_never_came(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    _reply(db, fc, "Will send you the rates tomorrow", days_ago=4)
    items = _get(client, '/api/followups/needs-you')['items']
    assert [(i['id'], i['reason']) for i in items] == [(fc.id, 'promised_not_delivered')]


def test_a_later_reply_delivers_the_other_promise(app, db, client, me):
    fc = _fc(db, me, rung='neutral')
    _reply(db, fc, "Will send you the rates tomorrow", days_ago=4)
    _reply(db, fc, 'Rates attached', days_ago=3)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_needs_you_lists_a_client_silent_unusually_long(app, db, client, me):
    fc = _fc(db, me, rung='client', name='Big Shipper', last_reply_at=_app._utcnow() - timedelta(days=20))
    for days in (20, 25, 30, 35, 40):                     # replies every 5 days -> threshold 14
        _reply(db, fc, 'ok', days_ago=days)
    items = _get(client, '/api/followups/needs-you')['items']
    assert [(i['id'], i['reason']) for i in items] == [(fc.id, 'client_silent')]
    assert '20' in items[0]['detail']


def test_a_client_inside_its_own_rhythm_is_not_listed(app, db, client, me):
    fc = _fc(db, me, rung='client', last_reply_at=_app._utcnow() - timedelta(days=20))
    for days in (20, 40, 60, 80):                         # replies every 20 days -> threshold 40
        _reply(db, fc, 'ok', days_ago=days)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_client_is_never_flagged_before_14_days(app, db, client, me):
    fc = _fc(db, me, rung='client', last_reply_at=_app._utcnow() - timedelta(days=10))
    for days in (10, 11, 12):                             # median gap 1 day -> 2 x 1 < the 14 floor
        _reply(db, fc, 'ok', days_ago=days)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_only_clients_are_checked_for_silence(app, db, client, me):
    fc = _fc(db, me, rung='hot', load_count=2, last_reply_at=_app._utcnow() - timedelta(days=60))
    _reply(db, fc, 'ok', days_ago=60)
    assert _get(client, '/api/followups/needs-you')['items'] == []


def test_a_contact_appears_once_with_its_most_urgent_reason(app, db, client, me):
    fc = _fc(db, me, rung='neutral', attention_at=_app._utcnow())
    _event(db, fc, 'ladder_unknown')
    _reply(db, fc, "I'll send you a load next week", days_ago=5)
    items = _get(client, '/api/followups/needs-you')['items']
    assert [(i['id'], i['reason']) for i in items] == [(fc.id, 'unparsed_reply')]


# ── activity ─────────────────────────────────────────────────────────────────

def test_activity_counts_the_last_day(app, db, client, me):
    fc = _fc(db, me, rung='warm')
    _event(db, fc, 'touch_sent', ago=timedelta(hours=1), notes='ladder touch 1 on warm')
    _event(db, fc, 'touch_sent', ago=timedelta(hours=48), notes='ladder touch 0 on warm')
    data = _get(client, '/api/followups/activity?hours=24')
    assert data == {'hours': 24, 'sent': 1, 'raised': 0, 'quieted': 0, 'stopped': 0}


def test_activity_defaults_to_24_hours(app, db, client, me):
    fc = _fc(db, me)
    _event(db, fc, 'touch_sent', ago=timedelta(hours=30))
    assert _get(client, '/api/followups/activity')['sent'] == 0
    assert _get(client, '/api/followups/activity?hours=48')['sent'] == 1
    assert _get(client, '/api/followups/activity?hours=junk')['hours'] == 24


def test_a_failed_send_is_not_a_touch_sent(app, db, client, me):
    fc = _fc(db, me)
    _event(db, fc, 'touch_sent', notes='Send failed - backing off', metadata={'error': 'smtp', 'attempt': 1})
    assert _get(client, '/api/followups/activity')['sent'] == 0


def test_activity_splits_raised_quieted_and_stopped(app, db, client, me):
    a = _fc(db, me); b = _fc(db, me); c = _fc(db, me); d = _fc(db, me)
    _event(db, a, 'ladder_load', from_state='cold', to_state='warm')        # raised
    _event(db, a, 'ladder_load', from_state='warm', to_state='hot')         # raised again
    _event(db, a, 'ladder_load', from_state='hot', to_state='hot')          # a load, no rung change
    _event(db, b, 'ladder_deferral', from_state='cold', to_state='neutral') # a reply lifts cold: raised
    _event(db, b, 'ladder_deferral', from_state='neutral', to_state='neutral')
    _event(db, c, 'ladder_exhausted', from_state='neutral', to_state='dormant')
    _event(db, c, 'ladder_exhausted', from_state='neutral', to_state='dormant')
    _event(db, c, 'ladder_load', from_state='dormant', to_state='warm')     # a load wakes a dormant contact
    _event(db, d, 'ladder_refusal', from_state='warm', to_state='dormant')
    _event(db, d, 'ladder_parked', from_state='warm', to_state='warm')
    data = _get(client, '/api/followups/activity')
    assert (data['raised'], data['quieted'], data['stopped']) == (4, 1, 1)   # quieted/stopped: contacts


def test_a_state_event_named_like_a_rung_is_not_a_raise(app, db, client, me):
    fc = _fc(db, me)
    _event(db, fc, 'state_change', from_state='active', to_state='warm')
    assert _get(client, '/api/followups/activity')['raised'] == 0


# ── scoping and auth ─────────────────────────────────────────────────────────

def test_endpoints_are_scoped_to_the_signed_in_user(app, db, client, me):
    other = _user(db)
    stranger = _fc(db, other, rung='client', load_count=3, attention_at=_app._utcnow(),
                   last_reply_at=_app._utcnow() - timedelta(days=90))
    _event(db, stranger, 'ladder_unknown')
    _event(db, stranger, 'touch_sent')
    _event(db, stranger, 'ladder_load', from_state='cold', to_state='warm')
    _reply(db, stranger, "I'll send you a load next week", days_ago=5)
    _fc(db, me, rung='warm', load_count=1)

    funnel = _get(client, '/api/followups/funnel')
    assert funnel['rungs']['client'] == 0 and funnel['rungs']['warm'] == 1
    assert funnel['totals']['entered'] == 1
    assert funnel['totals']['loads_this_month'] == 0
    assert all(stranger.id not in _ids(r['reached_contacts']) for r in funnel['conversion'])
    assert _get(client, '/api/followups/needs-you')['items'] == []
    assert _get(client, '/api/followups/activity') == {
        'hours': 24, 'sent': 0, 'raised': 0, 'quieted': 0, 'stopped': 0}


@pytest.mark.parametrize('path', ['funnel', 'needs-you', 'activity'])
def test_endpoints_require_a_signed_in_user(app, db, client, path):
    resp = client.get(f'/api/followups/{path}')
    assert resp.status_code == 302 and '/login' in resp.headers['Location']     # the app's own sign-in redirect
    assert client.get(f'/api/followups/{path}', headers={'Content-Type': 'application/json'}).status_code == 401
