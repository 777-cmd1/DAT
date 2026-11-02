"""Warmth ladder: the scheduler sends the due touches and spends the attempt budget."""
import sys
import uuid
from datetime import timedelta

import pytest

_app = sys.modules['_dat_mailer_app']


def past(hours=2):
    return _app._utcnow() - timedelta(hours=hours)


def _workspace(db, fu_auto=True, cfg=None, oauth=False, ladder=True):
    import bcrypt as _bcrypt
    from app.models import EmailAccount, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'ls_{uuid.uuid4().hex[:8]}@test.com', name='L', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto,
                   ladder_auto_enabled=ladder, pipeline_config=cfg or {})
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id, gmail_address='me@test.com',
                                your_name='Me', google_refresh_token='tok' if oauth else None))
    db.session.commit()
    return user, ws


def _contact(db, user=None, ws=None, rung='neutral', **kw):
    """An active, unpaused contact due for a ladder touch unless `kw` says otherwise."""
    from app.models import FollowupContact
    if user is None:
        user, ws = _workspace(db)
    kw.setdefault('load_count', {'warm': 1, 'hot': 2}.get(rung, 0))
    kw.setdefault('next_followup_at', past())
    kw.setdefault('touch_enabled', kw['next_followup_at'] is not None)
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'completed_fu3')
    kw.setdefault('is_followup_enabled', False)
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', rung=rung, **kw)
    db.session.add(fc); db.session.commit()
    return fc


@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    """The scheduler scans every workspace, and committed rows outlive a test:
    start each test with no contacts so the counts below are exact."""
    from app.models import FollowupContact, FollowupEvent
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    db.session.commit()


@pytest.fixture
def sent(monkeypatch):
    """Capture outgoing follow-ups; every send succeeds."""
    out = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (out.append(fu['contact_email']), (True, None))[1])
    return out


def _run():
    n = _app._run_ladder_touches(_app._utcnow())
    _app.db.session.expire_all()
    return n


def _events(fc, event_type):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id, event_type=event_type).all()


# ── Sending and the budget ───────────────────────────────────────────────────

def test_due_contact_is_sent_and_the_attempt_is_spent(app, db, sent):
    fc = _contact(db, rung='neutral', touch_attempt=0)
    assert _run() == 1
    assert sent == [fc.contact_email]
    assert fc.touch_attempt == 1 and fc.rung == 'neutral'
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=1)   # touch 2: three days out
    assert fc.last_followup_sent_at is not None
    assert len(_events(fc, 'touch_sent')) == 1


def _days_out(fc):
    """Whole calendar days between today and the contact's next touch."""
    return (fc.next_followup_at.date() - _app._utcnow().date()).days


def test_the_rhythm_after_each_touch_is_three_days_then_weekly(app, db, sent):
    user, ws = _workspace(db, cfg={'touch_hour': 15})
    fc = _contact(db, user, ws, rung='warm', touch_attempt=0)
    assert _run() == 1                       # warm gets a budget of 5
    assert fc.touch_attempt == 1 and _days_out(fc) == 3 and fc.next_followup_at.hour == 15
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1
    assert fc.touch_attempt == 2 and _days_out(fc) == 7
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1
    assert fc.touch_attempt == 3 and _days_out(fc) == 7      # weekly from the third touch on


def test_hot_is_weekly_from_the_first_touch(app, db, sent):
    user, ws = _workspace(db, cfg={'touch_hour': 15})
    fc = _contact(db, user, ws, rung='hot', touch_attempt=0)
    assert _run() == 1
    assert fc.touch_attempt == 1 and _days_out(fc) == 7


def test_the_first_touch_is_due_the_day_after_a_load(app, db):
    from app.models import Reply
    user, ws = _workspace(db, cfg={'touch_hour': 15})
    fc = _contact(db, user, ws, rung='neutral', next_followup_at=None)
    r = Reply(user_id=user.id, msg_id='<f1@m>', thread_id='tf1', from_email=fc.contact_email,
              subject='Re: lane', body='load Laredo to Dallas', triage_category='gave_info')
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, user.id, r)
    db.session.commit(); db.session.refresh(fc)
    assert fc.touch_attempt == 0 and _days_out(fc) == 1 and fc.next_followup_at.hour == 15


def test_budget_exhaustion_goes_dormant_with_a_reason(app, db, sent):
    fc = _contact(db, rung='neutral', touch_attempt=2)        # the 3rd of 3
    assert _run() == 1                                        # the last attempt still goes out
    assert fc.touch_attempt == 3
    assert fc.rung == 'dormant' and fc.exit_reason == 'exhausted'
    assert fc.next_followup_at is None and fc.touch_enabled is False
    assert len(_events(fc, 'ladder_exhausted')) == 1


def test_a_contact_already_over_budget_is_parked_without_a_send(app, db, sent):
    fc = _contact(db, rung='neutral', touch_attempt=3)
    assert _run() == 0 and sent == []
    assert (fc.rung, fc.exit_reason, fc.next_followup_at) == ('dormant', 'exhausted', None)


def _reply_to(db, fc, category, body, thread=None):
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=f'<{uuid.uuid4().hex}@m>', thread_id=thread,
              from_email=fc.contact_email, subject='Re: lane', body=body,
              triage_category=category)
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit(); db.session.refresh(fc)


def test_a_live_contacts_reply_does_not_refill_its_budget(app, db, sent):
    """The rule's own case: a contact still on the ladder cannot buy touches by
    answering. Two touches left, a "maybe later", still two touches left."""
    fc = _contact(db, rung='neutral', touch_attempt=1)
    _reply_to(db, fc, 'negative', 'nothing this week, try next week', 't1')
    assert (fc.rung, fc.touch_attempt) == ('neutral', 1)
    fc.next_followup_at = past(); fc.touch_enabled = True; db.session.commit()
    assert _run() == 1 and fc.touch_attempt == 2
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1 and fc.touch_attempt == 3
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 0 and fc.rung == 'dormant'      # spent, and the reply bought nothing


def test_a_parked_contact_that_writes_in_is_sent_to_again(app, db, sent):
    """And the other half: once it is parked, writing in brings it back with a
    fresh budget — the premise of the budget is that they never answer."""
    fc = _contact(db, rung='neutral', touch_attempt=3)
    assert _run() == 0 and fc.rung == 'dormant' and sent == []

    _reply_to(db, fc, 'negative', 'nothing this week, try next week', 't1')
    assert (fc.rung, fc.touch_attempt, fc.exit_reason) == ('neutral', 0, None)
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1 and fc.touch_attempt == 1


def test_an_out_of_office_does_not_bring_a_parked_contact_back(app, db, sent):
    fc = _contact(db, rung='neutral', touch_attempt=3)
    assert _run() == 0 and fc.rung == 'dormant'
    _reply_to(db, fc, 'auto_reply', 'I am out of office until Monday', 't1')
    assert fc.rung == 'dormant'
    fc.next_followup_at = past(); fc.touch_enabled = True; db.session.commit()
    assert _run() == 0 and sent == []


def test_a_load_revives_a_parked_contact_too(app, db, sent):
    fc = _contact(db, rung='neutral', touch_attempt=3)
    assert _run() == 0 and fc.rung == 'dormant'
    _reply_to(db, fc, 'gave_info', 'we have a load Laredo to Dallas', 't2')
    assert (fc.rung, fc.touch_attempt) == ('warm', 0)
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1 and fc.touch_attempt == 1


def test_warm_contacts_get_the_longer_budget(app, db, sent):
    fc = _contact(db, rung='warm', touch_attempt=3)           # a neutral contact would be done
    assert _run() == 1
    assert fc.rung == 'warm' and fc.touch_attempt == 4 and fc.next_followup_at is not None


# ── Who is never sent to ─────────────────────────────────────────────────────

def test_client_is_never_sent_to(app, db, sent):
    # Review Focus: CLIENT leaves automation entirely, even after a load
    fc = _contact(db, rung='client', load_count=3)
    assert _run() == 0 and sent == []
    assert fc.touch_attempt == 0 and fc.rung == 'client'


def test_a_load_from_a_client_schedules_nothing(app, db, sent):
    from app.models import Reply
    fc = _contact(db, rung='client', load_count=3, next_followup_at=None)
    r = Reply(user_id=fc.user_id, msg_id='<c1@m>', thread_id='tc1', from_email=fc.contact_email,
              subject='Re: lane', body='another load for you', triage_category='gave_info')
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit(); db.session.refresh(fc)
    assert fc.rung == 'client' and fc.next_followup_at is None and not fc.touch_enabled
    assert _run() == 0 and sent == []


def test_paused_contact_is_skipped_but_kept(app, db, sent):
    fc = _contact(db, rung='warm', auto_paused=True)
    assert _run() == 0 and sent == []
    assert fc.rung == 'warm' and fc.touch_attempt == 0


@pytest.mark.parametrize('rung', ['excluded', 'dormant'])
def test_excluded_and_dormant_are_never_sent_to(app, db, sent, rung):
    fc = _contact(db, rung=rung)
    assert _run() == 0 and sent == []
    assert fc.rung == rung and fc.touch_attempt == 0


def test_a_blocked_or_paused_state_is_never_sent_to(app, db, sent):
    for state in ('paused', 'blocked'):
        _contact(db, rung='warm', state=state)
    assert _run() == 0 and sent == []


def test_contacts_in_the_drip_or_on_a_one_time_schedule_are_left_to_their_own_path(app, db, sent):
    user, ws = _workspace(db)
    _contact(db, user, ws, rung='cold', is_followup_enabled=True, stage='fu1_scheduled')
    _contact(db, user, ws, rung='cold', scheduled_once=True)
    _contact(db, user, ws, rung='cold', recurring_enabled=True)
    assert _run() == 0 and sent == []


def test_a_contact_not_due_yet_is_not_sent(app, db, sent):
    _contact(db, rung='warm', next_followup_at=_app._utcnow() + timedelta(hours=3))
    assert _run() == 0 and sent == []


# ── The kill switch and the master switch ────────────────────────────────────

def test_kill_switch_still_stops_everything(app, db, sent):
    user, ws = _workspace(db, fu_auto=False)
    fc = _contact(db, user, ws, rung='warm', touch_attempt=4)   # would otherwise send and exhaust
    before = fc.next_followup_at
    assert _run() == 0 and sent == []
    assert (fc.rung, fc.touch_attempt, fc.next_followup_at) == ('warm', 4, before)
    assert fc.exit_reason is None and _events(fc, 'touch_sent') == []


def test_auto_send_master_switch_blocks_the_ladder(app, db, sent):
    user, ws = _workspace(db, cfg={'auto_send_enabled': False})
    fc = _contact(db, user, ws, rung='warm')
    assert _run() == 0 and sent == []
    assert fc.touch_attempt == 0


def test_the_ladder_needs_its_own_consent_flag_which_defaults_off(app, db, sent):
    from app.models import Workspace
    user, ws = _workspace(db, fu_auto=True, ladder=False)
    fc = _contact(db, user, ws, rung='warm', touch_attempt=4)    # would send and exhaust
    before = fc.next_followup_at
    assert _run() == 0 and sent == []
    assert (fc.rung, fc.touch_attempt, fc.next_followup_at) == ('warm', 4, before)
    assert fc.exit_reason is None and _events(fc, 'touch_sent') == []
    # a workspace created without saying anything about the ladder is off
    bare = Workspace(owner_id=user.id, name='bare')
    db.session.add(bare); db.session.commit()
    assert bare.ladder_auto_enabled is False


def test_every_stage_on_manual_does_not_make_the_ladder_mail_the_book(app, db, sent, monkeypatch):
    # the situation a default workspace is in: manual stages, dated contacts, drip toggle on
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail', lambda uid=None, rate_limit=True: {})
    user, ws = _workspace(db, fu_auto=True, ladder=False,
                          cfg={'cadence': {str(i): {'days': 3, 'mode': 'manual'} for i in range(1, 6)}})
    for _ in range(5):
        _contact(db, user, ws, rung='cold', pipeline_stage=2)
    _app._run_scheduled_followups()
    assert sent == []


def test_the_consent_flag_alone_is_not_enough_without_the_kill_switch(app, db, sent):
    user, ws = _workspace(db, fu_auto=False, ladder=True)
    _contact(db, user, ws, rung='warm')
    assert _run() == 0 and sent == []


def test_the_scheduler_entry_point_sends_ladder_touches_only_when_the_switch_is_on(app, db, sent, monkeypatch):
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail', lambda uid=None, rate_limit=True: {})
    on_user, on_ws = _workspace(db, fu_auto=True)
    off_user, off_ws = _workspace(db, fu_auto=False)
    on = _contact(db, on_user, on_ws, rung='warm')
    off = _contact(db, off_user, off_ws, rung='warm')
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert sent == [on.contact_email]
    assert on.touch_attempt == 1 and off.touch_attempt == 0


def test_the_scheduler_checks_replies_before_a_ladder_touch(app, db, sent, monkeypatch):
    user, ws = _workspace(db, oauth=True)
    replier = _contact(db, user, ws, rung='warm')
    quiet = _contact(db, user, ws, rung='warm')
    checked = []

    def fake_fetch(uid=None, rate_limit=True):
        checked.append(uid)
        from app.models import FollowupContact
        fc = db.session.get(FollowupContact, replier.id)
        fc.touch_enabled = False; fc.next_followup_at = None    # their reply lands first
        db.session.commit()
        return {'new': 1}
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail', fake_fetch)
    _app._run_scheduled_followups()
    assert user.id in checked
    assert sent == [quiet.contact_email]


def test_a_failed_reply_check_holds_the_ladder(app, db, sent, monkeypatch):
    user, ws = _workspace(db, oauth=True)
    fc = _contact(db, user, ws, rung='warm')
    monkeypatch.setattr(_app, 'fetch_replies_from_gmail',
                        lambda uid=None, rate_limit=True: {'error': 'HttpError 503'})
    _app._run_scheduled_followups()
    db.session.expire_all()
    assert sent == [] and fc.touch_attempt == 0 and fc.next_followup_at is not None


# ── Failures go through the existing backoff ─────────────────────────────────

def test_send_failure_uses_the_existing_backoff(app, db, monkeypatch):
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'invalid_grant'))
    fc = _contact(db, rung='neutral', touch_attempt=1)
    start = _app._utcnow()
    assert _run() == 0
    assert fc.send_fail_count == 1
    assert fc.next_followup_at >= start + timedelta(hours=_app.SEND_FAIL_BACKOFF_HOURS[0] - 1)
    assert fc.touch_attempt == 1 and fc.rung == 'neutral'      # a failed send spends nothing


def test_repeated_failures_back_off_further_then_park_the_contact(app, db, monkeypatch):
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'invalid_grant'))
    fc = _contact(db, rung='warm', touch_attempt=0)
    gaps = []
    for _ in range(_app.SEND_FAIL_GIVE_UP_AFTER):
        fc.next_followup_at = past(); db.session.commit()
        before = _app._utcnow()
        _run()
        gaps.append((fc.next_followup_at - before).total_seconds() / 3600 if fc.next_followup_at else None)
    assert gaps[0] < gaps[1] < gaps[2] and gaps[2] >= 71
    assert fc.send_fail_count == _app.SEND_FAIL_GIVE_UP_AFTER and fc.touch_attempt == 0
    assert fc.attention_at is not None                         # given up: a human is asked
    # parked with a reason instead of retrying a dead token for ever
    assert fc.auto_paused is True and fc.exit_reason == 'send_failed'
    assert fc.next_followup_at is None and fc.touch_enabled is False and fc.rung == 'warm'
    assert len(_events(fc, 'touch_sent')) == 2                 # first failure + give-up
    assert len(_events(fc, 'ladder_parked')) == 1
    fc.next_followup_at = past(); fc.touch_enabled = True; db.session.commit()
    assert _run() == 0 and fc.send_fail_count == _app.SEND_FAIL_GIVE_UP_AFTER   # not even tried


def test_a_success_after_failures_resets_the_counter(app, db, monkeypatch):
    fc = _contact(db, rung='warm')
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (False, 'x'))
    _run()
    assert fc.send_fail_count == 1
    monkeypatch.setattr(_app, 'send_followup_email', lambda *a, **k: (True, None))
    fc.next_followup_at = past(); db.session.commit()
    assert _run() == 1 and fc.send_fail_count == 0 and fc.touch_attempt == 1


# ── One bad row never aborts the tick ────────────────────────────────────────

def test_an_unrecognised_rung_raises_attention_and_the_rest_still_send(app, db, sent):
    user, ws = _workspace(db)
    bad = _contact(db, user, ws, rung='legacy-value')
    good = _contact(db, user, ws, rung='warm')
    assert _run() == 1
    assert sent == [good.contact_email]
    assert bad.attention_at is not None and bad.touch_attempt == 0 and bad.rung == 'legacy-value'
    assert _run() == 0                                          # still unrecognised: no second event
    assert len(_events(bad, 'ladder_unknown')) == 1


def test_an_exception_on_one_contact_does_not_stop_the_others(app, db, monkeypatch):
    user, ws = _workspace(db)
    first = _contact(db, user, ws, rung='warm', next_followup_at=past(5))
    second = _contact(db, user, ws, rung='warm', next_followup_at=past(1))
    out = []

    def flaky(fu, tpl, cfg, uid=None):
        if fu['contact_email'] == first.contact_email:
            raise RuntimeError('boom')
        out.append(fu['contact_email'])
        return True, None
    monkeypatch.setattr(_app, 'send_followup_email', flaky)
    assert _run() == 1
    assert out == [second.contact_email]
    assert first.touch_attempt == 0 and second.touch_attempt == 1
    # the failed contact is backed off, not left due to blow up on every tick
    assert first.next_followup_at > _app._utcnow() and first.send_fail_count == 1


def test_bookkeeping_that_fails_after_a_send_backs_the_contact_off(app, db, monkeypatch):
    # the email went out but recording it raised: without a backoff the contact
    # stays due and the same email goes out on every tick, for ever
    fc = _contact(db, rung='warm')
    out = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (out.append(fu['contact_email']), (True, None))[1])
    real = _app._ladder_set_next

    def broken(*a, **k):
        raise RuntimeError('db went away')
    monkeypatch.setattr(_app, '_ladder_set_next', broken)
    assert _run() == 0
    monkeypatch.setattr(_app, '_ladder_set_next', real)
    assert out == [fc.contact_email]
    assert fc.send_fail_count == 1 and fc.next_followup_at > _app._utcnow() + timedelta(hours=5)
    assert _run() == 0 and out == [fc.contact_email]            # nothing is sent again now


def test_a_failure_while_backing_off_cannot_escape(app, db, monkeypatch):
    user, ws = _workspace(db)
    first = _contact(db, user, ws, rung='warm', next_followup_at=past(5))
    second = _contact(db, user, ws, rung='warm', next_followup_at=past(1))
    out = []

    def send(fu, tpl, cfg, uid=None):
        if fu['contact_email'] == first.contact_email:
            raise RuntimeError('boom')
        out.append(fu['contact_email'])
        return True, None
    monkeypatch.setattr(_app, 'send_followup_email', send)
    monkeypatch.setattr(_app, '_record_send_failure',
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('still down')))
    assert _run() == 1 and out == [second.contact_email]


def test_a_missing_account_asks_for_attention_once(app, db, sent):
    from app.models import EmailAccount
    user, ws = _workspace(db)
    EmailAccount.query.filter_by(user_id=user.id).delete(); db.session.commit()
    fc = _contact(db, user, ws, rung='warm')
    assert _run() == 0 and sent == []
    assert fc.attention_at is not None and fc.touch_attempt == 0
    assert _run() == 0
    assert len(_events(fc, 'ladder_blocked')) == 1


def test_a_missing_template_asks_for_attention_once(app, db, sent, monkeypatch):
    monkeypatch.setattr(_app, '_template_for_rung', lambda uid, rung, fc: None)
    fc = _contact(db, rung='warm')
    assert _run() == 0 and sent == []
    assert fc.attention_at is not None
    _run()
    assert len(_events(fc, 'ladder_blocked')) == 1


# ── The hour of day ──────────────────────────────────────────────────────────

def test_the_next_touch_lands_at_the_configured_hour(app, db, sent):
    user, ws = _workspace(db, cfg={'touch_hour': 15})            # 15:00 in the workspace zone (UTC)
    fc = _contact(db, user, ws, rung='warm')
    _run()
    assert fc.next_followup_at.hour == 15 and fc.next_followup_at.minute == 0
    assert fc.next_followup_at > _app._utcnow()


def test_the_next_touch_follows_the_workspace_time_zone(app, db, sent):
    user, ws = _workspace(db, cfg={'touch_hour': 9, 'timezone': 'America/Chicago'})
    fc = _contact(db, user, ws, rung='warm')
    _run()
    local = fc.next_followup_at.replace(tzinfo=_app.UTC).astimezone(_app._tz_named('America/Chicago'))
    assert local.hour == 9


def test_a_load_reply_dates_the_touch_at_the_same_hour(app, db):
    from app.models import Reply
    user, ws = _workspace(db, cfg={'touch_hour': 15})
    fc = _contact(db, user, ws, rung='neutral', next_followup_at=None)
    r = Reply(user_id=user.id, msg_id='<h1@m>', thread_id='th1', from_email=fc.contact_email,
              subject='Re: lane', body='load Laredo to Dallas', triage_category='gave_info')
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, user.id, r)
    db.session.commit(); db.session.refresh(fc)
    assert fc.rung == 'warm' and fc.next_followup_at.hour == 15


# ── The stage-cadence sweep cannot undo the ladder ───────────────────────────

def test_the_sweep_does_not_wipe_a_ladder_date_in_a_stage_that_is_off(app, db):
    user, ws = _workspace(db)                    # stage 1 cadence is "off" by default
    fc = _contact(db, user, ws, rung='neutral', pipeline_stage=1,
                  next_followup_at=_app._utcnow() + timedelta(days=2))
    when = fc.next_followup_at
    assert _app._schedule_touch(fc, ws) is False
    _app._normalize_followup_contact(fc)
    assert fc.next_followup_at == when and fc.touch_enabled is True
    assert _app._schedule_touch(fc, ws, force=True) is True      # an explicit re-base stays on the ladder
    assert fc.touch_enabled and fc.next_followup_at is not None


@pytest.mark.parametrize('rung', ['dormant', 'client', 'excluded'])
def test_the_sweep_gives_no_date_to_a_contact_the_ladder_has_parked(app, db, rung):
    user, ws = _workspace(db, cfg={'cadence': {'2': {'days': 3, 'mode': 'auto'}}})
    fc = _contact(db, user, ws, rung=rung, pipeline_stage=2, next_followup_at=None)
    assert _app._schedule_touch(fc, ws) is False
    assert _app._schedule_touch(fc, ws, force=True) is False
    _app._normalize_followup_contact(fc)
    assert fc.next_followup_at is None and fc.touch_enabled is False


def test_a_stage_move_rebases_a_warm_contact_on_the_ladder_not_the_stage(app, db):
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung='warm', next_followup_at=_app._utcnow() + timedelta(days=5))
    ok, _ = _app._apply_pipeline_stage(fc, 3, actor_user_id=user.id)   # stage 3's cadence is 7 days
    assert ok and fc.touch_enabled
    assert _app._utcnow() < fc.next_followup_at < _app._utcnow() + timedelta(days=3)   # touch 1: next day


def test_skipping_a_ladder_touch_pushes_it_one_rung_interval_and_spends_nothing(app, db):
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung='neutral', touch_attempt=1)
    assert _app._schedule_touch(fc, ws, force=True) is True            # what "skip" does
    gap = fc.next_followup_at - _app._utcnow()
    assert timedelta(days=2) < gap < timedelta(days=4) and fc.touch_attempt == 1   # touch 2: three days


def test_the_sweep_fills_a_missing_date_on_a_live_rung(app, db):
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung='warm', pipeline_stage=1, next_followup_at=None)
    assert _app._schedule_touch(fc, ws) is True
    assert fc.touch_enabled and fc.next_followup_at > _app._utcnow()


def test_the_sweep_leaves_a_paused_ladder_contact_undated(app, db):
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung='warm', auto_paused=True, next_followup_at=None)
    assert _app._schedule_touch(fc, ws, force=True) is False
    assert fc.next_followup_at is None and not fc.touch_enabled


def test_the_old_stage_cadence_is_still_used_for_a_fresh_cold_contact(app, db):
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung='cold', pipeline_stage=2, next_followup_at=None)
    assert _app._schedule_touch(fc, ws, force=True) is True
    assert fc.touch_enabled and fc.next_followup_at is not None


def test_saving_the_cadence_config_leaves_ladder_dates_alone(app, db, client):
    user, ws = _workspace(db)
    with client.session_transaction() as sess:
        sess['user_email'] = user.email
        sess['csrf_token'] = 'x'
    warm = _contact(db, user, ws, rung='warm', next_followup_at=_app._utcnow() + timedelta(days=2))
    parked = _contact(db, user, ws, rung='client', next_followup_at=None)
    when = warm.next_followup_at
    res = client.put('/api/followups/pipeline-config',
                     json={'cadence': {'2': {'days': 2, 'mode': 'auto'}}})
    assert res.status_code == 200
    db.session.expire_all()
    assert warm.next_followup_at == when
    assert parked.next_followup_at is None and not parked.touch_enabled


@pytest.mark.parametrize('rung', ['client', 'dormant', 'excluded'])
def test_an_out_of_office_never_schedules_a_parked_contact(app, db, rung):
    from app.models import Reply
    user, ws = _workspace(db)
    fc = _contact(db, user, ws, rung=rung, next_followup_at=None)
    reply = Reply(user_id=user.id, msg_id='<o1@m>', from_email=fc.contact_email,
                  subject='Automatic reply: out of office', body='I am away')
    assert _app._ooo_pause_contact(ws, reply) is False
    assert fc.next_followup_at is None and fc.touch_enabled is False


def test_an_out_of_office_pushes_a_live_contact_a_week_at_the_touch_hour(app, db):
    from app.models import Reply
    user, ws = _workspace(db, cfg={'touch_hour': 15})
    fc = _contact(db, user, ws, rung='warm', next_followup_at=_app._utcnow() + timedelta(days=1))
    reply = Reply(user_id=user.id, msg_id='<o2@m>', from_email=fc.contact_email,
                  subject='Automatic reply', body='I am away')
    assert _app._ooo_pause_contact(ws, reply) is True
    assert _days_out(fc) == 7 and fc.next_followup_at.hour == 15 and fc.touch_enabled


# ── The pre-send reply check knows about the ladder ──────────────────────────

def test_would_auto_send_follows_the_ladder_rules(app, db):
    user, ws = _workspace(db)
    assert _app._would_auto_send(_contact(db, user, ws, rung='warm'), ws) is True
    assert _app._would_auto_send(_contact(db, user, ws, rung='warm', auto_paused=True), ws) is False
    assert _app._would_auto_send(_contact(db, user, ws, rung='client'), ws) is False
    ws.fu_auto_enabled = False
    assert _app._would_auto_send(_contact(db, user, ws, rung='warm'), ws) is False


def test_would_auto_send_needs_the_consent_flag_and_budget(app, db):
    user, ws = _workspace(db)
    assert _app._would_auto_send(_contact(db, user, ws, rung='neutral', touch_attempt=3), ws) is False
    ws.ladder_auto_enabled = False
    assert _app._would_auto_send(_contact(db, user, ws, rung='warm'), ws) is False


def test_the_consent_flag_ships_through_the_inline_migrations_default_off():
    # prod schema changes only apply from the _migrations list in app.py
    import re
    src = open(_app.__file__).read()
    assert re.search(r"\('workspaces',\s+'ladder_auto_enabled',\s+'BOOLEAN NOT NULL DEFAULT FALSE'\)", src)
