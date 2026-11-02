"""The FU1 -> FU2 -> FU3 stage drip is retired; the warmth ladder carries the work.

What this pins: nothing sends on a stage any more; a contact is born on the ladder; the
send paths that remain share one payload and one voice (the rung copy); the one-time and
recurring paths are behind the owner's switches and refuse an opt-out; a manual send sends
the rung's copy and spends no attempt; and the old stage data is kept, not rewritten.
"""
import sys
import uuid
from datetime import timedelta

import pytest

from app import ladder

_app = sys.modules['_dat_mailer_app']


# ── helpers ──────────────────────────────────────────────────────────────────

def _user(db, fu_auto=True, ladder_on=True, cfg=None):
    import bcrypt as _bcrypt
    from app.models import EmailAccount, Template, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'ret_{uuid.uuid4().hex[:8]}@test.com', name='R', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto,
                   ladder_auto_enabled=ladder_on, pipeline_config=cfg or {'touch_hour': 15})
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id, gmail_address='me@test.com',
                                your_name='Me', your_company='Acme', your_phone='555'))
    db.session.commit()
    return user, ws


@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    from app.models import FollowupContact, FollowupEvent, Template
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    Template.query.delete()
    db.session.commit()


@pytest.fixture
def me(app, db, client):
    user, ws = _user(db)
    with client.session_transaction() as sess:
        sess['user_email'] = user.email
        sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _fc(db, me, rung='warm', **kw):
    from app.models import FollowupContact
    user, ws = me
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'completed_fu3')
    kw.setdefault('is_followup_enabled', False)
    kw.setdefault('load_count', {'warm': 1, 'hot': 2}.get(rung, 0))
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id, rung=rung,
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _due(): return _app._utcnow() - timedelta(hours=2)


def _reload(db, fc):
    db.session.expire_all()
    return db.session.get(type(fc), fc.id)


def _act(client, fc, action, **extra):
    return client.post('/api/followups/action', json={'id': fc.id, 'action': action, **extra})


def _bulk(client, ids, action, **extra):
    return client.post('/api/followups/bulk-action', json={'ids': ids, 'action': action, **extra})


@pytest.fixture
def sent(monkeypatch):
    log = []

    def fake(fu, tpl, cfg, uid=None):
        log.append({'fu': dict(fu), 'tpl': tpl, 'cfg': dict(cfg), 'uid': uid})
        return True, None
    monkeypatch.setattr(_app, 'send_followup_email', fake)
    return log


FUTURE = lambda: (_app._utcnow() + timedelta(days=3)).isoformat() + 'Z'


# ── the engine is gone ───────────────────────────────────────────────────────

def test_the_stage_drip_machinery_is_removed():
    for name in ('STAGE_PROGRESSION', 'STAGE_TO_TEMPLATE', 'STAGE_SENT_FIELD', '_get_stage_delay',
                 '_get_fu_settings', '_get_fu_template_for_stage', '_get_random_fu_template',
                 '_cadence_for_stage', '_ladder_owns_schedule'):
        assert not hasattr(_app, name), name


def test_a_due_stage_drip_contact_sends_nothing_and_its_stage_is_not_advanced(app, db, me, sent):
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True,
             next_followup_at=_due(), touch_enabled=False)
    assert _app._run_scheduled_followups() == 0
    fc = _reload(db, fc)
    assert sent == []
    assert (fc.stage, fc.fu1_sent_at, fc.completed_fu3_at) == ('fu1_scheduled', None, None)


# ── born on the ladder ───────────────────────────────────────────────────────

def test_a_contact_added_by_hand_starts_on_the_ladder(app, db, client, me):
    resp = client.post('/api/followups/add', json={'email': 'New@Broker.com', '_csrf': 'test-csrf-token'},
                       headers={'X-CSRF-Token': 'test-csrf-token'})
    assert resp.status_code == 201, resp.get_json()
    from app.models import FollowupContact
    fc = FollowupContact.query.filter_by(contact_email='new@broker.com').one()
    assert fc.is_followup_enabled is False and fc.rung == 'cold'
    assert fc.touch_enabled is True
    assert _app._utcnow() < fc.next_followup_at < _app._utcnow() + timedelta(days=3)   # touch 1: next day


def test_a_contact_added_from_a_reply_starts_on_the_ladder(app, db, me):
    from app.models import FollowupContact, Reply
    user, ws = me
    reply = Reply(user_id=user.id, from_email='boss@broker.com', from_name='Boss', subject='Re: lane',
                  body='thanks', msg_id=f'm{uuid.uuid4().hex}', thread_id='t1',
                  received_at=_app._utcnow(), status='new')
    db.session.add(reply); db.session.commit()
    _app.add_to_followups(reply)
    fc = FollowupContact.query.filter_by(contact_email='boss@broker.com').one()
    assert fc.is_followup_enabled is False
    assert fc.rung in ('cold', 'neutral', 'warm', 'hot')
    assert fc.touch_enabled and fc.next_followup_at is not None


def test_resuming_a_paused_contact_returns_it_to_the_ladder_not_the_drip(app, db, client, me):
    fc = _fc(db, me, 'neutral', next_followup_at=None, touch_enabled=False, state='paused')
    assert _act(client, fc, 'resume').status_code == 200
    fc = _reload(db, fc)
    assert fc.state == 'active' and fc.is_followup_enabled is False
    assert fc.touch_enabled and fc.next_followup_at is not None


def test_a_reply_takes_a_contact_off_the_drip_even_with_auto_stop_off(app, db, me):
    # the old auto_stop_on_reply setting is gone: a reply always ends the retired drip flag
    from app.models import FollowupSettings
    user, ws = me
    db.session.add(FollowupSettings(workspace_id=ws.id, auto_stop_on_reply=False))
    db.session.commit()
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', is_followup_enabled=True,
             next_followup_at=_app._utcnow() + timedelta(days=1))
    _app._check_reply_stops_followup(fc.contact_email, user.id)
    db.session.commit()
    fc = _reload(db, fc)
    assert fc.is_followup_enabled is False
    assert fc.touch_enabled and fc.next_followup_at is not None


# ── restart no longer re-arms the drip ───────────────────────────────────────

def test_restart_puts_a_live_contact_back_on_its_rung_with_a_fresh_budget(app, db, client, me):
    fc = _fc(db, me, 'warm', touch_attempt=3, next_followup_at=None, touch_enabled=False)
    assert _act(client, fc, 'restart-fu1').status_code == 200
    fc = _reload(db, fc)
    assert (fc.rung, fc.touch_attempt, fc.is_followup_enabled) == ('warm', 0, False)
    assert fc.touch_enabled and fc.next_followup_at is not None
    assert fc.stage == 'completed_fu3'


def test_restart_never_lifts_an_exclusion_or_a_pause(app, db, client, me):
    excluded = _fc(db, me, 'excluded', next_followup_at=None)
    assert _act(client, excluded, 'restart-fu1').status_code == 400
    paused = _fc(db, me, 'warm', auto_paused=True, next_followup_at=None, touch_enabled=False)
    assert _act(client, paused, 'restart-fu1').status_code == 200
    paused = _reload(db, paused)
    assert paused.auto_paused is True and paused.next_followup_at is None   # his pause stands


# ── one payload for every sender (inherited item 1) ──────────────────────────

def test_every_remaining_sender_builds_the_same_payload(app, db, client, me, sent):
    user, ws = me
    from app.models import EmailAccount
    acct = EmailAccount.query.filter_by(user_id=user.id).first()
    shapes = {}

    ladder_fc = _fc(db, me, 'neutral', next_followup_at=_due(), touch_enabled=True,
                    reply_subject='Lane', reply_msg_id='<m1>', source_thread_id='th1', current_route='A, TX → B, TX')
    once = _fc(db, me, 'neutral', scheduled_once=True, next_followup_at=_due(),
               reply_subject='Lane', reply_msg_id='<m1>', source_thread_id='th1', current_route='A, TX → B, TX')
    rec = _fc(db, me, 'neutral', recurring_enabled=True, recurring_days='0,1,2,3,4,5,6', recurring_time='09:00',
              next_followup_at=_due(), reply_subject='Lane', reply_msg_id='<m1>', source_thread_id='th1',
              current_route='A, TX → B, TX')
    _app._run_scheduled_followups()
    for entry in sent:
        shapes[entry['fu']['contact_email']] = (tuple(sorted(entry['fu'])), tuple(sorted(entry['cfg'])))
    manual = _fc(db, me, 'neutral', reply_subject='Lane', reply_msg_id='<m1>', source_thread_id='th1',
                 current_route='A, TX → B, TX')
    assert _act(client, manual, 'send-now').status_code == 200
    shapes[manual.contact_email] = (tuple(sorted(sent[-1]['fu'])), tuple(sorted(sent[-1]['cfg'])))

    assert len(shapes) == 4
    assert len(set(shapes.values())) == 1
    fu, cfg = _app._followup_send_args(ladder_fc, acct)
    assert set(fu) == {'contact_email', 'reply_subject', 'reply_msg_id', 'current_route', 'source_thread_id'}
    assert set(cfg) == {'name', 'company', 'phone', 'route', 'gmail_address', 'gmail_app_password'}
    assert cfg['name'] == 'Me' and cfg['company'] == 'Acme' and fu['source_thread_id'] == 'th1'


# ── the one-time and recurring paths: switches and opt-outs ──────────────────

@pytest.mark.parametrize('action, extra', [
    ('schedule-once', lambda: {'scheduled_at': FUTURE()}),
    ('set-recurring', lambda: {'recurring_days': '1,3', 'recurring_time': '10:00'}),
])
def test_a_date_cannot_be_handed_to_someone_who_asked_us_to_stop(app, db, client, me, action, extra):
    fc = _fc(db, me, 'dormant', exit_reason='refused', next_followup_at=None)
    resp = _act(client, fc, action, **extra())
    assert resp.status_code == 400 and 'asked us to stop' in resp.get_json()['error']
    bulk = _bulk(client, [fc.id], action, **extra()).get_json()['results'][0]
    assert bulk['ok'] is False and 'asked us to stop' in bulk['error']
    fc = _reload(db, fc)
    assert not fc.scheduled_once and not fc.recurring_enabled and fc.next_followup_at is None


def test_a_date_set_before_the_refusal_still_sends_nothing(app, db, me, sent):
    fc = _fc(db, me, 'dormant', exit_reason='refused', scheduled_once=True, next_followup_at=_due())
    _app._run_scheduled_followups()
    assert sent == []


def test_a_dormant_contact_keeps_the_owners_one_time_date(app, db, client, me, sent):
    # the owner can deliberately date a parked (not refused) contact, as he can one-off it
    fc = _fc(db, me, 'dormant', exit_reason='exhausted', next_followup_at=None)
    assert _act(client, fc, 'schedule-once', scheduled_at=FUTURE()).status_code == 200


# ── a manual send sends the rung copy (inherited item 4) ─────────────────────

def test_a_manual_send_uses_the_rung_copy_never_the_general_pool_or_a_stage_template(
        app, db, client, me, sent):
    from app.models import Template
    user, ws = me
    for level, body in (('General', 'GENERAL POOL'), ('FU1', 'STAGE ONE')):
        db.session.add(Template(user_id=user.id, workspace_id=ws.id, type='followup', level=level,
                                name=level, body=body, is_active=True))
    db.session.commit()
    fc = _fc(db, me, 'warm', stage='fu1_scheduled')
    assert _act(client, fc, 'free-send').status_code == 200
    assert sent[-1]['tpl'] == _app._template_for_rung(user.id, 'warm', fc)
    assert 'GENERAL POOL' not in sent[-1]['tpl'] and 'STAGE ONE' not in sent[-1]['tpl']


def test_a_one_off_to_a_dormant_or_client_contact_uses_the_rung_its_loads_earn(
        app, db, client, me, sent):
    user, ws = me
    dormant = _fc(db, me, 'dormant', exit_reason='exhausted', load_count=1, last_reply_at=_app._utcnow())
    assert _act(client, dormant, 'free-send').status_code == 200
    assert sent[-1]['tpl'] == _app._template_for_rung(user.id, 'warm', dormant)
    client_fc = _fc(db, me, 'client', load_count=3)
    assert _act(client, client_fc, 'free-send').status_code == 200
    assert sent[-1]['tpl'] == _app._template_for_rung(user.id, 'hot', client_fc)


def test_a_manual_send_spends_no_attempt_and_redates_from_the_rung(app, db, client, me, sent):
    fc = _fc(db, me, 'neutral', touch_attempt=1, next_followup_at=_due(), touch_enabled=True,
             attention_at=_app._utcnow())
    assert _act(client, fc, 'send-now').status_code == 200
    fc = _reload(db, fc)
    assert fc.touch_attempt == 1                      # the budget is the scheduler's to spend
    assert fc.attention_at is None and fc.last_followup_sent_at is not None
    assert fc.next_followup_at > _app._utcnow()
    assert fc.stage == 'completed_fu3'


def test_send_now_still_refuses_a_parked_contact_but_free_send_does_not(app, db, client, me, sent):
    fc = _fc(db, me, 'dormant', exit_reason='exhausted', next_followup_at=None)
    assert _act(client, fc, 'send-now').status_code == 400
    assert sent == []
    assert _act(client, fc, 'free-send').status_code == 200


@pytest.mark.parametrize('action', ['send-now', 'free-send'])
def test_no_manual_send_reaches_an_excluded_or_refused_contact(app, db, client, me, sent, action):
    excluded = _fc(db, me, 'excluded', next_followup_at=None)
    refused = _fc(db, me, 'dormant', exit_reason='refused', next_followup_at=None)
    for fc in (excluded, refused):
        assert _act(client, fc, action).status_code == 400
        res = _bulk(client, [fc.id], action).get_json()['results'][0]
        assert res['ok'] is False
    assert sent == []


# ── stale deferrals (inherited item 5) ───────────────────────────────────────

@pytest.mark.parametrize('event', ['schedule_cancelled', 'recurring_stopped', 'restarted_fu1',
                                   'scheduled_once_sent', 'recurring_sent'])
def test_an_event_that_resets_the_date_ends_a_deferral(app, db, me, event):
    from app.models import FollowupEvent
    assert event in _app._RESCHEDULING_EVENTS
    fc = _fc(db, me, 'neutral', next_followup_at=_app._utcnow() + timedelta(days=5))
    base = _app._utcnow() - timedelta(hours=3)
    for kind, when in (('ladder_deferral', base), (event, base + timedelta(hours=1))):
        e = _app._record_event(fc, kind, actor_type='system')
        e.event_at = when
    db.session.commit()
    assert fc.id not in _app._ladder_deferred_ids(me[0].id, [fc])
    # control: the deferral alone does explain the date
    FollowupEvent.query.filter_by(followup_contact_id=fc.id, event_type=event).delete()
    db.session.commit()
    assert fc.id in _app._ladder_deferred_ids(me[0].id, [fc])


# ── the gates all stand ──────────────────────────────────────────────────────

def test_the_ladder_is_still_behind_all_three_switches_and_the_cap(app, db, me, sent):
    user, ws = me
    for _ in range(3):
        _fc(db, me, 'neutral', next_followup_at=_due(), touch_enabled=True)
    ws.pipeline_config = {**(ws.pipeline_config or {}), 'ladder': {'daily_cap': 2}}
    db.session.commit()
    assert _app._run_scheduled_followups() == 2          # the cap holds
    for flip in ('fu_auto_enabled', 'ladder_auto_enabled'):
        sent.clear()
        setattr(ws, flip, False)
        db.session.commit()
        assert _app._run_scheduled_followups() == 0 and sent == []
        setattr(ws, flip, True)
        db.session.commit()
    ws.pipeline_config = {**ws.pipeline_config, 'auto_send_enabled': False}
    db.session.commit()
    assert _app._run_scheduled_followups() == 0 and sent == []


# ══ fix round 1 ══════════════════════════════════════════════════════════════

def test_a_manual_send_does_not_invent_drip_history_for_the_sequence_funnel(
        app, db, client, me, sent):
    # /api/followups/analytics buckets manual_send events by from_stage: a new contact is
    # born stage 'fu1_scheduled', and sending to it must not read as an "FU1 sent"
    from app.models import FollowupEvent
    fc = _fc(db, me, 'cold', stage='fu1_scheduled', load_count=0)
    assert _act(client, fc, 'send-now').status_code == 200
    assert _act(client, _fc(db, me, 'cold', stage='fu1_scheduled'), 'free-send').status_code == 200
    evs = FollowupEvent.query.filter(FollowupEvent.event_type.in_(('manual_send', 'free_send'))).all()
    assert len(evs) == 2 and all(e.from_stage is None and e.to_stage is None for e in evs)
    funnel = client.get('/api/followups/analytics').get_json()['funnel']
    assert (funnel['fu1_sent'], funnel['fu2_sent'], funnel['fu3_sent']) == (0, 0, 0)


def test_the_conversion_screen_still_finds_a_real_drip_send_behind_a_newer_manual_one(
        app, db, client, me, sent):
    fc = _fc(db, me, 'warm', stage='fu1_sent', state='loads', next_followup_at=None)
    old = _app._record_event(fc, 'auto_send', actor_type='scheduler', from_stage='fu1_scheduled', to_stage='fu2_scheduled')
    old.event_at = _app._utcnow() - timedelta(days=9)
    _app._record_event(fc, 'manual_send')            # a modern manual send: no stage
    db.session.commit()
    conv = client.get('/api/followups/analytics').get_json()['conversion_by_stage']
    assert conv['fu1_to_loads'] == 1


@pytest.mark.parametrize('how', ['single', 'bulk'])
@pytest.mark.parametrize('action, extra', [
    ('schedule-once', lambda: {'scheduled_at': FUTURE()}),
    ('set-recurring', lambda: {'recurring_days': '0,1,2,3,4,5,6', 'recurring_time': '10:00'}),
])
def test_dating_an_unplaced_contact_takes_it_off_the_drip_flag(app, db, client, me, how, action, extra):
    fc = _fc(db, me, 'cold', stage='fu2_scheduled', is_followup_enabled=True, next_followup_at=None,
             touch_enabled=False)
    if how == 'single':
        assert _act(client, fc, action, **extra()).status_code == 200
    else:
        assert _bulk(client, [fc.id], action, **extra()).get_json()['results'][0]['ok'] is True
    fc = _reload(db, fc)
    assert fc.is_followup_enabled is False
    assert fc.scheduled_once or fc.recurring_enabled


def test_a_row_dated_by_the_owner_before_this_change_loses_the_flag_at_startup(app, db, me):
    once = _fc(db, me, 'cold', is_followup_enabled=True, scheduled_once=True, next_followup_at=_due())
    rec = _fc(db, me, 'cold', is_followup_enabled=True, recurring_enabled=True, recurring_days='1',
              recurring_time='10:00', next_followup_at=_due())
    plain = _fc(db, me, 'cold', is_followup_enabled=True, next_followup_at=_due())
    for fc in (once, rec, plain):
        _app._normalize_followup_contact(fc)
    db.session.commit()
    assert (once.is_followup_enabled, rec.is_followup_enabled, plain.is_followup_enabled) == (False, False, True)


def test_no_scheduler_path_sends_a_contact_that_still_carries_the_flag(app, db, me, sent):
    # a flagged contact with every engine due is sent by none of them (the date-carrying
    # rows are normalised first, as at startup and on every listing, and lose the flag)
    _fc(db, me, 'neutral', is_followup_enabled=True, next_followup_at=_due(), touch_enabled=True)
    _fc(db, me, 'neutral', is_followup_enabled=True, scheduled_once=True, next_followup_at=_due())
    _fc(db, me, 'neutral', is_followup_enabled=True, recurring_enabled=True, recurring_days='0,1,2,3,4,5,6',
        recurring_time='10:00', next_followup_at=_due())
    from app.models import FollowupContact
    for fc in FollowupContact.query.all():
        _app._normalize_followup_contact(fc)
    db.session.commit()
    flagged = {fc.contact_email for fc in FollowupContact.query.filter_by(is_followup_enabled=True)}
    _app._run_scheduled_followups()
    assert len(flagged) == 1 and not (flagged & {e['fu']['contact_email'] for e in sent})


def test_the_backlog_sweep_spreads_undated_contacts_but_a_fresh_entry_is_not_delayed(app, db, me):
    user, ws = me
    ws.pipeline_config = {'touch_hour': 15}
    db.session.commit()
    undated = [_fc(db, me, 'cold', next_followup_at=None, touch_enabled=False) for _ in range(40)]
    for fc in undated:
        _app._normalize_followup_contact(fc)
    db.session.commit()
    days = {fc.next_followup_at.date() for fc in undated}
    weekly = _app._ladder_cfg(ws)['weekly_days']
    assert len(days) > 3                                   # not one wall on one day
    assert (max(days) - min(days)).days < weekly           # and not beyond the weekly window
    # deterministic: the same ids land on the same offsets
    again = {fc.id: fc.next_followup_at for fc in undated}
    for fc in undated:
        fc.next_followup_at, fc.touch_enabled = None, False
        _app._schedule_touch(fc, ws, stagger=True)
    assert {fc.id: fc.next_followup_at for fc in undated} == again
    # a fresh entry (and a forced re-base) is never pushed out by the spread
    fresh = _fc(db, me, 'cold', next_followup_at=None, touch_enabled=False)
    _app._schedule_touch(fresh, ws)
    assert fresh.next_followup_at < _app._utcnow() + timedelta(days=2)


def _cap(db, ws, n):
    ws.pipeline_config = {**(ws.pipeline_config or {}), 'ladder': {'daily_cap': n}}
    db.session.commit()


def test_the_daily_cap_covers_one_time_recurring_and_ladder_sends_together(app, db, me, sent):
    user, ws = me
    _cap(db, ws, 3)
    for _ in range(2):
        _fc(db, me, 'neutral', scheduled_once=True, next_followup_at=_due())
    for _ in range(2):
        _fc(db, me, 'neutral', recurring_enabled=True, recurring_days='0,1,2,3,4,5,6',
            recurring_time='10:00', next_followup_at=_due())
    for _ in range(2):
        _fc(db, me, 'neutral', next_followup_at=_due(), touch_enabled=True)
    assert _app._run_scheduled_followups() == 3             # not 6
    assert len(sent) == 3
    assert _app._auto_sent_today(_reload(db, ws)) == 3
    sent.clear()
    assert _app._run_scheduled_followups() == 0             # and not three more on the next tick
    assert sent == []


def test_a_capped_one_time_send_stays_due_and_the_ladder_gets_only_what_is_left(app, db, me, sent):
    user, ws = me
    _cap(db, ws, 2)
    once = _fc(db, me, 'neutral', scheduled_once=True, next_followup_at=_due())
    touch = [_fc(db, me, 'neutral', next_followup_at=_due(), touch_enabled=True) for _ in range(3)]
    assert _app._run_scheduled_followups() == 2             # the one-time first, one ladder touch
    assert once.contact_email in {e['fu']['contact_email'] for e in sent}
    once = _reload(db, once)
    assert once.scheduled_once is False
    assert sum(1 for t in touch if _reload(db, t).touch_attempt == 1) == 1
    # with the room spent, the next one-time send waits (still due, not lost)
    later = _fc(db, me, 'neutral', scheduled_once=True, next_followup_at=_due())
    sent.clear()
    assert _app._run_scheduled_followups() == 0
    later = _reload(db, later)
    assert later.scheduled_once is True and later.next_followup_at <= _app._utcnow()


def test_a_failed_send_does_not_spend_cap_room(app, db, me, monkeypatch):
    user, ws = me
    _cap(db, ws, 1)
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'boom'))
    _fc(db, me, 'neutral', scheduled_once=True, next_followup_at=_due())
    _app._run_scheduled_followups()
    assert _app._auto_sent_today(_reload(db, ws)) == 0


@pytest.mark.parametrize('kind', ['once', 'recurring'])
def test_a_dead_token_parks_a_dated_contact_like_a_ladder_touch(app, db, me, monkeypatch, kind):
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'invalid_grant: revoked'))
    extra = ({'scheduled_once': True} if kind == 'once' else
             {'recurring_enabled': True, 'recurring_days': '0,1,2,3,4,5,6', 'recurring_time': '10:00'})
    fc = _fc(db, me, 'neutral', next_followup_at=_due(), **extra)
    for _ in range(12):
        fc = _reload(db, fc)
        if not fc.auto_paused:               # force it due again, as a backoff elapsing would
            fc.next_followup_at = _due()
            db.session.commit()
        _app._run_scheduled_followups()
    fc = _reload(db, fc)
    assert fc.send_fail_count == _app.SEND_FAIL_GIVE_UP_AFTER      # it stopped trying at the fifth
    assert fc.auto_paused is True and fc.exit_reason == 'send_failed' and fc.next_followup_at is None
    from app.models import FollowupEvent
    assert FollowupEvent.query.filter_by(followup_contact_id=fc.id).count() == 3
    assert fc.attention_at is not None


def test_the_ladder_query_itself_skips_a_refused_contact_whatever_its_rung(app, db, me, sent):
    _fc(db, me, 'neutral', exit_reason='refused', next_followup_at=_due(), touch_enabled=True)
    assert _app._run_ladder_touches(_app._utcnow()) == 0 and sent == []
