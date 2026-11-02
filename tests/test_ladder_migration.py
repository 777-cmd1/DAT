"""Placing the owner's existing contacts on the warmth ladder, once.

Two things are covered here:
  * `place_contacts_on_ladder` — reads each contact's reply history, derives a
    rung, keeps the owner's manual decisions, parks the long-silent, and hands
    the schedule from the drip to the ladder.
  * the inline `_migrations` loop in app.py — the ladder columns really are
    added to a legacy-shaped table. The loop swallows every DDL error as
    "column already exists", so a broken entry is otherwise silent (an
    Alembic-only column took production down on 2026-10-20).
"""
import sys
import uuid
from datetime import timedelta

import pytest
import sqlalchemy as sa

_app = sys.modules['_dat_mailer_app']

from scripts.migrate_to_ladder import (                                        # noqa: E402
    SILENCE_DAYS, _STAGGER_PER_DAY, place_contacts_on_ladder)

NOW = _app._utcnow().replace(microsecond=0)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_base(app, db):
    """Every test here commits contacts, replies and events, and the in-memory DB
    outlives the test. Clear them first, as the other ladder suites do: a few
    hundred stray rows otherwise slow every scheduler scan that runs after them."""
    from app.models import FollowupContact, FollowupEvent, Reply, StopListEntry
    for model in (FollowupEvent, FollowupContact, Reply, StopListEntry):
        model.query.delete()
    db.session.commit()


def _workspace(db):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'mig_{uuid.uuid4().hex[:8]}@test.com', name='M', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.commit()
    return ws


def _contact(db, ws, days_ago=1, **kw):
    """A legacy-shaped contact: on the drip, cold, no ladder history."""
    from app.models import FollowupContact
    seen = NOW - timedelta(days=days_ago)
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'fu1_scheduled')
    kw.setdefault('is_followup_enabled', True)
    fc = FollowupContact(user_id=ws.owner_id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@broker.com',
                         last_activity_at=seen, created_at=seen,
                         next_followup_at=NOW + timedelta(days=3), **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _reply(db, fc, category='gave_info', thread=None, days_ago=1,
           body='load Laredo to Dallas', filter_key=None):
    from app.models import Reply
    r = Reply(user_id=fc.user_id, workspace_id=fc.workspace_id,
              msg_id=f'<{uuid.uuid4().hex}@mail>', thread_id=thread,
              from_email=fc.contact_email, subject='Re: Laredo to Dallas',
              body=body, triage_category=category, reply_filter_key=filter_key,
              received_at=NOW - timedelta(days=days_ago))
    db.session.add(r); db.session.commit()
    return r


def _event(fc, event_type):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id,
                                         event_type=event_type).one()


def _run(db, ws, dry_run=False, now=None, **kw):
    out = place_contacts_on_ladder(ws.id, now or NOW, dry_run=dry_run, **kw)
    db.session.commit()
    return out


def _migration_events(fc):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id,
                                         event_type='migrated_to_ladder').count()


def _migration_event(fc):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id,
                                         event_type='migrated_to_ladder').one()


def _load_events(fc):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id,
                                         event_type=_app._LADDER_LOAD_EVENT).all()


# ── the rung comes from the counted load conversations ───────────────────────

def test_rung_comes_from_counted_load_conversations(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, thread='t1')
    _reply(db, fc, thread='t1', body='still open, can you cover')   # same conversation
    _reply(db, fc, thread='t2', body='another load Houston to Miami')
    out = _run(db, ws)
    db.session.refresh(fc)
    assert (fc.load_count, fc.rung) == (2, 'hot')
    assert out['rungs']['hot'] == 1
    assert out['loads_counted'] == 2
    # the pair that writes and reads load metadata is the only writer, and the
    # events sit on the day the load really arrived
    evts = _load_events(fc)
    assert len(evts) == 2
    assert all(e.event_at < NOW for e in evts)
    assert {_app.json.loads(e.metadata_json)['conv'] for e in evts} == {'thread:t1', 'thread:t2'}


def test_a_reply_that_is_not_a_load_only_lifts_cold_to_neutral(app, db):
    ws = _workspace(db)
    answered = _contact(db, ws)
    _reply(db, answered, category='rate_request', body='what is your rate on this lane?')
    silent = _contact(db, ws)
    _run(db, ws)
    db.session.refresh(answered); db.session.refresh(silent)
    assert (answered.rung, answered.load_count) == ('neutral', 0)
    assert (silent.rung, silent.load_count) == ('cold', 0)


def test_a_reply_from_before_triage_still_counts_as_replied(app, db):
    # Review Focus: rows older than the triage system carry triage_category NULL
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category=None, body='thanks, I will keep you in mind')
    _run(db, ws)
    db.session.refresh(fc)
    assert fc.rung == 'neutral'


def test_a_colleague_reply_counts_for_the_address_we_wrote_to(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    r = _reply(db, fc, thread='t1')
    r.from_email = 'john@broker.com'
    r.matched_recipient = fc.contact_email
    db.session.commit()
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.load_count, fc.rung) == (1, 'warm')


# ── fix round 1: a broker who asked us to stop must stay stopped ─────────────
# The migration used to read only "is there a reply", never what it said, so a
# refusal the live hook parks as dormant/refused came out as neutral — dated,
# with three touches to spend. Nothing else catches it: _auto_triage_new_replies
# deliberately never auto-blocks a negative reply.

@pytest.mark.parametrize('body', [
    'please remove me from your list',
    'take me off this list',
    'we are not interested at all',
    'nothing for us right now',           # 'negative' with no deferral wording
])
def test_a_refusal_is_parked_exactly_as_the_live_hook_parks_it(app, db, body):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body=body)
    assert _app._ladder.interpret_reply('negative', body, NOW)[0] == 'refusal', 'test premise'
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused'), body
    assert fc.next_followup_at is None and fc.touch_enabled is False
    assert _app._ladder_budget(fc.rung, ws) == 0


def test_a_refusal_before_triage_shipped_is_still_read(app, db):
    # the row carries no category; the live hook recovers one with classify_reply_text
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category=None, body='Please remove me from your list, thanks.')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')


def test_a_load_after_a_refusal_brings_them_back(app, db):
    # replayed oldest first, as the live hook applies them: only a load revives
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=20)
    _reply(db, fc, category='gave_info', thread='t1', days_ago=2)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.load_count, fc.exit_reason) == ('warm', 1, None)


def test_a_vague_reply_after_a_refusal_does_not_bring_them_back(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=20)
    _reply(db, fc, category='rate_request', body='what is your rate?', days_ago=2)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')


def test_a_load_from_before_triage_is_recovered_from_its_text(app, db):
    # load_count must not read as a floor: pre-triage rows have no category
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category=None, thread='t1', days_ago=3,
           body='I have a load Laredo TX to Dallas TX picking up 11/05, '
                '42,000 lbs, rate $2,400')
    out = _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.load_count) == ('warm', 1)
    assert out['loads_counted'] == 1


# ── fix round 1: nothing may keep a schedule once it is off the ladder ───────

def test_a_parked_contact_loses_a_one_time_and_recurring_schedule(app, db):
    # Review Focus: Path 0 / Path 2 gate on active + not paused + rung != excluded,
    # and `dormant` passes all three — a kept date would still be mailed
    ws = _workspace(db)
    once = _contact(db, ws, days_ago=SILENCE_DAYS + 5, scheduled_once=True)
    repeating = _contact(db, ws, days_ago=SILENCE_DAYS + 5, recurring_enabled=True,
                         recurring_days='0,2', recurring_time='14:00')
    refuser = _contact(db, ws, scheduled_once=True)
    _reply(db, refuser, category='negative', body='take me off this list')
    out = _run(db, ws)
    for fc in (once, repeating, refuser):
        db.session.refresh(fc)
        assert fc.rung == 'dormant', fc.contact_email
        assert fc.next_followup_at is None and fc.touch_enabled is False
        assert not (fc.scheduled_once or fc.recurring_enabled or fc.is_followup_enabled)
    assert repeating.recurring_days is None and repeating.recurring_time is None
    assert out['keeps_date'] == {}          # and the dry run must not claim they keep one


def test_an_excluded_contact_is_written_to_the_stop_list(app, db):
    # the Stop List is what makes `excluded` permanent for every sender
    from app.models import StopListEntry
    ws = _workspace(db)
    blocked = _contact(db, ws, state='blocked', is_followup_enabled=False)
    _run(db, ws)
    entry = StopListEntry.query.filter_by(user_id=ws.owner_id, type='email',
                                          value=blocked.contact_email).one()
    assert entry.reason == _app._EXCLUDE_STOP_REASON      # so unexclude can undo it
    evt = _app.json.loads(_migration_event(blocked).metadata_json)
    assert evt['stop_list_added'] is True


# ── fix round 1: the backlog is spread, not queued for one morning ──────────

def test_first_touches_are_staggered_over_a_window(app, db):
    ws = _workspace(db)
    made = [_contact(db, ws) for _ in range(25)]
    for fc in made:
        _reply(db, fc, category='rate_request', body='what is your rate?')
    _run(db, ws)
    days = set()
    for fc in made:
        db.session.refresh(fc)
        assert fc.next_followup_at is not None
        days.add(fc.next_followup_at.date())
    assert len(days) >= 4, f'all {len(made)} land on {len(days)} day(s)'


# ── the 90-day silence rule ──────────────────────────────────────────────────

def test_inactive_beyond_ninety_days_starts_dormant(app, db):
    ws = _workspace(db)
    old = SILENCE_DAYS + 30
    fc = _contact(db, ws, days_ago=old)
    for i, t in enumerate(('t1', 't2', 't3')):
        _reply(db, fc, thread=t, days_ago=old + i)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'stale')
    assert fc.load_count == 3                      # the history is still counted
    assert fc.next_followup_at is None and fc.touch_enabled is False
    # the screens must say why it is out, not just that it is
    assert _app._ladder_next_reason(fc, False, ws) == 'dormant: silent for months when the ladder started'


def test_a_recent_reply_keeps_a_contact_off_the_stale_pile(app, db):
    # last_activity_at was never backfilled on every row: a reply is activity too
    ws = _workspace(db)
    fc = _contact(db, ws, days_ago=SILENCE_DAYS + 30)
    _reply(db, fc, thread='t1', days_ago=2)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('warm', None)


def test_silence_does_not_move_a_manual_decision(app, db):
    ws = _workspace(db)
    old = SILENCE_DAYS + 30
    client = _contact(db, ws, days_ago=old, state='loads', is_followup_enabled=False)
    gone = _contact(db, ws, days_ago=old, rung='excluded')
    _run(db, ws)
    db.session.refresh(client); db.session.refresh(gone)
    assert client.rung == 'client'
    assert gone.rung == 'excluded'


# ── fix round 2: an MC request is not a refusal ─────────────────────────────
# The shared 'negative' bucket holds the mc_request filter, so "send me your MC
# and insurance" — a broker opening a carrier packet, the hottest reply there is
# — went straight into interpret_reply and came out a refusal.

def test_an_mc_request_is_not_read_as_a_refusal(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='Sure, send me your MC and insurance',
           filter_key='mc_request')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('neutral', None)
    assert fc.next_followup_at is not None


def test_an_mc_request_with_no_stored_filter_key_is_recovered(app, db):
    # older rows carry a category but no reply_filter_key
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body="What's your MC number?", filter_key=None)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('neutral', None)


def test_a_genuine_refusal_is_still_a_refusal(app, db):
    # the two must not drift back together
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='Please remove me from your list',
           filter_key='declined')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')


def test_an_mc_request_that_also_says_stop_is_a_refusal(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', filter_key='mc_request',
           body='send me your mc, actually never mind, take me off this list')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')


# ── fix round 3: the packet asks reach "Needs you" ──────────────────────────
# The migration flags nobody (hundreds of old replies would drown the panel) —
# except a contact whose NEWEST reply asks for our carrier packet. Those tried to
# open a packet and never got an answer.

def test_a_packet_ask_is_flagged_but_an_ordinary_old_reply_is_not(app, db):
    ws = _workspace(db)
    packet = _contact(db, ws, days_ago=60)
    _reply(db, packet, category='negative', filter_key='mc_request', days_ago=60,
           body='Sure, send me your MC and insurance')
    ordinary = _contact(db, ws, days_ago=60)
    _reply(db, ordinary, category='rate_request', days_ago=60,
           body='what is your rate on this lane?')
    shipper = _contact(db, ws, days_ago=60)
    _reply(db, shipper, category='gave_info', thread='t1', days_ago=60)

    out = _run(db, ws)
    for fc in (packet, ordinary, shipper):
        db.session.refresh(fc)
    assert packet.attention_at is not None
    assert ordinary.attention_at is None, 'the blanket no-flag decision broke'
    assert shipper.attention_at is None
    assert out['attention'] == 1
    assert {r['email'] for r in out['rows'] if r['attention']} == {packet.contact_email}


def test_a_flagged_packet_ask_shows_up_in_needs_you(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws, days_ago=45)
    _reply(db, fc, category='negative', filter_key='mc_request', days_ago=45,
           body='send me your MC and insurance please')
    _run(db, ws)
    db.session.refresh(fc)
    items = _app._ladder_needs_you(ws.owner_id, _app._utcnow())
    mine = [i for i in items if i['id'] == fc.id]
    assert len(mine) == 1 and mine[0]['reason'] == 'unparsed_reply'


def test_only_the_newest_reply_decides_the_flag(app, db):
    ws = _workspace(db)
    answered = _contact(db, ws, days_ago=40)          # packet ask, then moved on
    _reply(db, answered, category='negative', filter_key='mc_request', days_ago=40,
           body='send me your MC and insurance')
    _reply(db, answered, category='gave_info', thread='t1', days_ago=5)
    latest = _contact(db, ws, days_ago=40)            # load first, packet ask last
    _reply(db, latest, category='gave_info', thread='t2', days_ago=40)
    _reply(db, latest, category='negative', filter_key='mc_request', days_ago=5,
           body='send me your MC and insurance')
    _run(db, ws)
    db.session.refresh(answered); db.session.refresh(latest)
    assert answered.attention_at is None
    assert latest.attention_at is not None and latest.rung == 'warm'


def test_a_packet_ask_that_also_says_stop_is_not_flagged(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', filter_key='mc_request',
           body='send me your mc — actually, take me off this list')
    out = _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')
    assert fc.attention_at is None and out['attention'] == 0


def test_a_rerun_does_not_re_flag_or_re_log_a_packet_ask(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws, days_ago=30)
    _reply(db, fc, category='negative', filter_key='mc_request', days_ago=30,
           body='send me your MC and insurance')
    _run(db, ws)
    db.session.refresh(fc)
    first = fc.attention_at
    assert first is not None
    _run(db, ws, now=NOW + timedelta(days=14))
    db.session.refresh(fc)
    assert fc.attention_at == first                # the owner's 🔥 keeps its date
    assert _migration_events(fc) == 1


# ── fix round 2: a duplicate load message must not undo a later refusal ─────

def test_a_duplicate_load_message_does_not_revive_a_refuser(app, db):
    # the conversation was counted, THEN they refused, then wrote again in the
    # same thread: the live hook returns early on the duplicate and leaves them
    # parked, so the replay must too
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='gave_info', thread='t1', days_ago=30)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=20)
    _reply(db, fc, category='gave_info', thread='t1', days_ago=10,
           body='still open, can you cover')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')
    assert fc.load_count == 1                      # the one conversation still counted


def test_a_new_load_conversation_after_a_refusal_still_revives(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='gave_info', thread='t1', days_ago=30)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=20)
    _reply(db, fc, category='gave_info', thread='t2', days_ago=10, body='new load')
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.load_count, fc.exit_reason) == ('hot', 2, None)


def test_a_rerun_does_not_re_park_a_contact_a_load_revived(app, db):
    # Review Focus: on the second run the load is already counted — it must still
    # be the thing that undid the earlier refusal
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=30)
    _reply(db, fc, category='gave_info', thread='t1', days_ago=10)
    _run(db, ws)
    _run(db, ws, now=NOW + timedelta(days=14))
    db.session.refresh(fc)
    assert (fc.rung, fc.load_count, fc.exit_reason) == ('warm', 1, None)


# ── fix round 2: the owner's rescue survives a rerun ────────────────────────

def test_a_rerun_does_not_undo_a_rung_the_owner_set_by_hand(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, category='negative', body='take me off this list', days_ago=10)
    _run(db, ws)
    db.session.refresh(fc)
    assert fc.rung == 'dormant'                    # misread, and the owner fixes it

    fc.rung, fc.exit_reason = 'warm', None
    fc.load_count = 1
    _app._record_event(fc, 'manual_set_rung', actor_type='user',
                       from_state='dormant', to_state='warm', notes='moved by you')
    db.session.commit()

    _run(db, ws, now=NOW + timedelta(days=1))
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('warm', None), 'the rescue was undone'


def test_a_hand_move_older_than_the_newest_reply_does_not_shield_a_refusal(app, db):
    # he moved them, THEN they asked us to stop: the refusal is the newer fact
    ws = _workspace(db)
    fc = _contact(db, ws, rung='warm', load_count=1, is_followup_enabled=False)
    _app._record_event(fc, 'manual_set_rung', actor_type='user',
                       from_state='cold', to_state='warm')
    db.session.commit()
    _event(fc, 'manual_set_rung').event_at = NOW - timedelta(days=20)
    db.session.commit()
    _reply(db, fc, category='negative', body='take me off this list', days_ago=3)
    _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')


# ── fix round 2: a legacy `closed` contact stays off the global Stop List ───

def test_only_a_blocked_contact_reaches_the_stop_list(app, db):
    # the Stop List gates the Send page's INITIAL outreach too, and the app's own
    # `close` action deliberately does not stop-list — only `block` does
    from app.models import StopListEntry
    ws = _workspace(db)
    blocked = _contact(db, ws, state='blocked', is_followup_enabled=False)
    closed = _contact(db, ws, state='closed', is_followup_enabled=False)
    out = _run(db, ws)
    for fc in (blocked, closed):
        db.session.refresh(fc)
        assert fc.rung == 'excluded'               # the rung mapping is unchanged
    listed = {e.value for e in StopListEntry.query.filter_by(user_id=ws.owner_id)}
    assert listed == {blocked.contact_email}
    assert closed.contact_email not in listed
    assert out['stop_listed'] == 1
    assert out['exits'] == {'excluded/blocked': 1, 'excluded/closed': 1}


# ── fix round 2: the report the owner reads ────────────────────────────────

def test_the_summary_splits_dormant_by_reason_and_accounts_for_everyone(app, db):
    ws = _workspace(db)
    _contact(db, ws, days_ago=SILENCE_DAYS + 5)                    # stale
    _contact(db, ws, days_ago=SILENCE_DAYS + 5)                    # stale
    refuser = _contact(db, ws)
    _reply(db, refuser, category='negative', body='take me off this list')
    _contact(db, ws, state='blocked', is_followup_enabled=False)   # excluded
    _contact(db, ws)                                               # cold, live
    out = _run(db, ws)
    assert out['exits'] == {'dormant/stale': 2, 'dormant/refused': 1,
                            'excluded/blocked': 1}
    assert out['total'] == 5
    assert out['placed'] + out['skipped'] + len(out['failed']) == out['total']
    assert sum(out['rungs'].values()) == out['placed'] + out['skipped']


def test_a_row_that_raises_is_accounted_for_in_the_totals(app, db, monkeypatch):
    ws = _workspace(db)
    good, bad = _contact(db, ws), _contact(db, ws)
    import scripts.migrate_to_ladder as mig
    real = mig._plan_contact
    monkeypatch.setattr(mig, '_plan_contact', lambda fc, *a, **k: (_ for _ in ()).throw(
        RuntimeError('boom')) if fc.id == bad.id else real(fc, *a, **k))
    out = _run(db, ws)
    assert out['failed'] == [bad.contact_email]
    assert out['total'] == 2 and out['placed'] == 1
    assert out['placed'] + out['skipped'] + len(out['failed']) == out['total']


# ── fix round 1: the silence rule is the operator's choice ──────────────────
# The owner saw the distribution and does not want four fifths of his book parked.

def test_silence_days_zero_parks_nobody_for_silence(app, db):
    ws = _workspace(db)
    old = SILENCE_DAYS + 200
    quiet = _contact(db, ws, days_ago=old)
    answered = _contact(db, ws, days_ago=old)
    _reply(db, answered, category='rate_request', body='what is your rate?', days_ago=old)
    shipper = _contact(db, ws, days_ago=old)
    _reply(db, shipper, category='gave_info', thread='t1', days_ago=old)

    out = _run(db, ws, silence_days=0)
    for fc in (quiet, answered, shipper):
        db.session.refresh(fc)
    assert (quiet.rung, quiet.exit_reason) == ('cold', None)
    assert (answered.rung, answered.exit_reason) == ('neutral', None)
    assert (shipper.rung, shipper.load_count) == ('warm', 1)
    for fc in (quiet, answered, shipper):
        assert fc.next_followup_at is not None and fc.touch_enabled is True
    assert out['silence_days'] == 0
    assert out['rungs']['dormant'] == 0
    assert out['new_dates'] == 3


def test_silence_days_defaults_to_ninety(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws, days_ago=SILENCE_DAYS + 5)
    out = _run(db, ws)                             # no silence_days given
    db.session.refresh(fc)
    assert out['silence_days'] == SILENCE_DAYS == 90
    assert (fc.rung, fc.exit_reason) == ('dormant', 'stale')


def test_a_refusal_still_parks_them_with_the_silence_rule_off(app, db):
    # Review Focus: "remove me" a year ago is a decision, not a timeout
    ws = _workspace(db)
    fc = _contact(db, ws, days_ago=400)
    _reply(db, fc, category='negative', body='please remove me from your list', days_ago=370)
    _run(db, ws, silence_days=0)
    db.session.refresh(fc)
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')
    assert fc.next_followup_at is None and fc.touch_enabled is False


def test_client_and_excluded_stay_exempt_with_the_silence_rule_off(app, db):
    ws = _workspace(db)
    old = SILENCE_DAYS + 200
    client = _contact(db, ws, days_ago=old, state='loads', is_followup_enabled=False)
    gone = _contact(db, ws, days_ago=old, rung='excluded')
    parked = _contact(db, ws, days_ago=old, rung='dormant', exit_reason='refused',
                      is_followup_enabled=False)
    _run(db, ws, silence_days=0)
    for fc in (client, gone, parked):
        db.session.refresh(fc)
    assert client.rung == 'client' and client.next_followup_at is None
    assert gone.rung == 'excluded'
    assert (parked.rung, parked.exit_reason) == ('dormant', 'refused')


def test_the_whole_population_is_spread_when_nobody_is_parked(app, db):
    # with the rule off, several hundred land on live rungs at once: the stagger
    # window has to widen with the population, not stay at its floor
    n = 10 * _STAGGER_PER_DAY
    ws = _workspace(db)
    made = [_contact(db, ws, days_ago=SILENCE_DAYS + 100) for _ in range(n)]
    out = _run(db, ws, silence_days=0)
    assert out['new_dates'] == n
    assert out['stagger_days'] == 10, 'the window did not widen for the population'
    days = {}
    for fc in made:
        db.session.refresh(fc)
        days[fc.next_followup_at.date()] = days.get(fc.next_followup_at.date(), 0) + 1
    assert len(days) == out['stagger_days']
    # the id hash fills the buckets unevenly, but nothing like the whole base at once
    assert max(days.values()) <= 2 * _STAGGER_PER_DAY, days


# ── the owner's own decisions ────────────────────────────────────────────────

def test_manual_states_are_never_overridden(app, db):
    ws = _workspace(db)
    blocked = _contact(db, ws, state='blocked', is_followup_enabled=False)
    closed = _contact(db, ws, state='closed', is_followup_enabled=False)
    booked = _contact(db, ws, state='loads', is_followup_enabled=False)
    warm = _contact(db, ws, state='warm', is_followup_enabled=False)
    _reply(db, warm, thread='t1')
    _run(db, ws)
    for fc in (blocked, closed, booked, warm):
        db.session.refresh(fc)

    assert (blocked.rung, blocked.exit_reason) == ('excluded', 'blocked')
    assert (closed.rung, closed.exit_reason) == ('excluded', 'closed')
    for fc in (booked, warm):
        assert fc.auto_paused is True, fc.state
        assert fc.next_followup_at is None and fc.touch_enabled is False, fc.state
    assert booked.rung == 'client'
    assert warm.rung == 'warm'                     # its own load history, not the ladder guessing


def test_an_excluded_contact_is_left_completely_alone(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws, rung='excluded', is_followup_enabled=True)
    _reply(db, fc, thread='t1')
    before = (fc.rung, fc.load_count, fc.is_followup_enabled, fc.next_followup_at)
    out = _run(db, ws)
    db.session.refresh(fc)
    assert (fc.rung, fc.load_count, fc.is_followup_enabled, fc.next_followup_at) == before
    assert _load_events(fc) == []
    assert out['skipped'] == 1 and out['placed'] == 0


def test_a_rung_the_ladder_already_set_is_never_lowered(app, db):
    ws = _workspace(db)
    refused = _contact(db, ws, rung='dormant', exit_reason='refused', is_followup_enabled=False)
    by_hand = _contact(db, ws, rung='hot', is_followup_enabled=False)
    _run(db, ws)
    db.session.refresh(refused); db.session.refresh(by_hand)
    assert (refused.rung, refused.exit_reason) == ('dormant', 'refused')
    assert refused.next_followup_at is None
    assert by_hand.rung == 'hot'                   # no loads in history, but the owner put it there


def test_a_dormant_contact_with_no_reason_gets_a_best_effort_one(app, db):
    # the conversion panel groups the lost by exit_reason: a blank one reads as nothing
    ws = _workspace(db)
    stale = _contact(db, ws, days_ago=SILENCE_DAYS + 5, rung='dormant', is_followup_enabled=False)
    recent = _contact(db, ws, days_ago=3, rung='dormant', is_followup_enabled=False)
    _run(db, ws)
    db.session.refresh(stale); db.session.refresh(recent)
    assert stale.exit_reason == 'stale'
    assert recent.exit_reason == 'manual'


# ── one master for the schedule ──────────────────────────────────────────────

def test_the_drip_stops_owning_a_placed_contact(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, thread='t1')
    _run(db, ws)
    db.session.refresh(fc)
    assert fc.is_followup_enabled is False         # the drip scheduler needs this True
    assert fc.stage == 'fu1_scheduled'             # ...but the stage, and its history, stay
    assert _app._ladder_owns_schedule(fc) is True
    assert fc.next_followup_at is not None and fc.touch_enabled is True
    assert _app._ladder_next_reason(fc, False, ws) != 'first follow-up sequence'


def test_a_schedule_the_owner_set_by_hand_keeps_its_date(app, db):
    ws = _workspace(db)
    when = NOW + timedelta(days=9)
    once = _contact(db, ws, scheduled_once=True, is_followup_enabled=False)
    once.next_followup_at = when
    repeating = _contact(db, ws, recurring_enabled=True, recurring_days='0,2',
                         recurring_time='14:00', is_followup_enabled=False)
    repeating.next_followup_at = when
    db.session.commit()
    out = _run(db, ws)
    db.session.refresh(once); db.session.refresh(repeating)
    assert once.next_followup_at == when
    assert repeating.next_followup_at == when
    # the operator must be able to see what the run will NOT change, and why
    assert out['keeps_date'] == {'scheduled_once': 1, 'recurring': 1}
    assert {r['email']: r['keeps_date'] for r in out['rows']} == {
        once.contact_email: 'scheduled_once', repeating.contact_email: 'recurring'}


def test_a_date_a_broker_asked_for_survives(app, db):
    # Review Focus: "come back in six weeks" must not be replaced by today + 1
    ws = _workspace(db)
    fc = _contact(db, ws, rung='neutral', is_followup_enabled=False, touch_enabled=True)
    when = NOW + timedelta(days=40)
    fc.next_followup_at = when
    _app._record_event(fc, 'ladder_deferral', actor_type='system',
                       from_state='neutral', to_state='neutral', notes='asked to come back')
    db.session.commit()
    _run(db, ws)
    db.session.refresh(fc)
    assert fc.next_followup_at == when
    assert fc.rung == 'neutral'


def test_nothing_is_scheduled_for_a_contact_off_the_ladder(app, db):
    ws = _workspace(db)
    for kw in ({'state': 'blocked'}, {'state': 'closed'}, {'state': 'loads'},
               {'days_ago': SILENCE_DAYS + 1}):
        fc = _contact(db, ws, is_followup_enabled=False, **kw)
        _run(db, ws)
        db.session.refresh(fc)
        assert fc.next_followup_at is None, kw
        assert fc.touch_enabled is False, kw


def test_the_migration_never_turns_an_automatic_send_on(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, thread='t1')
    _run(db, ws)
    db.session.refresh(fc)
    assert ws.fu_auto_enabled is False and ws.ladder_auto_enabled is False
    assert _app._ladder_would_send(fc, ws) is False


# ── scope, dry run, idempotence ──────────────────────────────────────────────

def test_only_the_named_workspace_is_touched(app, db):
    mine, theirs = _workspace(db), _workspace(db)
    ours, hers = _contact(db, mine), _contact(db, theirs)
    _reply(db, ours, thread='t1')
    _reply(db, hers, thread='t1')
    out = _run(db, mine)
    db.session.refresh(ours); db.session.refresh(hers)
    assert ours.rung == 'warm'
    assert (hers.rung, hers.load_count, hers.is_followup_enabled) == ('cold', 0, True)
    assert out['placed'] == 1


def test_dry_run_changes_nothing(app, db):
    ws = _workspace(db)
    fc = _contact(db, ws)
    _reply(db, fc, thread='t1')
    _reply(db, fc, thread='t2', body='second load')
    snapshot = {c: getattr(fc, c) for c in
                ('rung', 'load_count', 'touch_attempt', 'auto_paused', 'exit_reason',
                 'state', 'stage', 'is_followup_enabled', 'next_followup_at',
                 'touch_enabled', 'last_load_at')}
    out = place_contacts_on_ladder(ws.id, NOW)          # dry_run defaults to True
    assert out['dry_run'] is True
    assert out['rungs']['hot'] == 1 and out['loads_counted'] == 2 and out['placed'] == 1
    # not a column, and not even a pending change waiting for the next commit
    assert len(db.session.dirty) == 0 and len(db.session.new) == 0
    assert {c: getattr(fc, c) for c in snapshot} == snapshot
    assert _load_events(fc) == []


def test_rerunning_is_idempotent(app, db):
    ws = _workspace(db)
    hot = _contact(db, ws)
    _reply(db, hot, thread='t1')
    _reply(db, hot, thread='t2', body='second load')
    cold = _contact(db, ws)
    stale = _contact(db, ws, days_ago=SILENCE_DAYS + 10)
    blocked = _contact(db, ws, state='blocked', is_followup_enabled=False)

    first = _run(db, ws)
    state = lambda: [(fc.rung, fc.load_count, fc.exit_reason, len(_load_events(fc)))
                     for fc in (hot, cold, stale, blocked)]
    for fc in (hot, cold, stale, blocked):
        db.session.refresh(fc)
    after_first = state()

    dates = [fc.next_followup_at for fc in (hot, cold, stale, blocked)]

    # a fortnight later every first touch has come and gone: a second run must not
    # re-date the overdue ones and quietly empty the Overdue bucket
    second = _run(db, ws, now=NOW + timedelta(days=14))
    for fc in (hot, cold, stale, blocked):
        db.session.refresh(fc)
    assert state() == after_first
    assert second['rungs'] == first['rungs']
    assert second['loads_counted'] == 0             # no conversation counted twice
    assert after_first[0] == ('hot', 2, None, 2)
    assert [fc.next_followup_at for fc in (hot, cold, stale, blocked)] == dates
    # the placement is already recorded: a second run adds no second entry
    assert _migration_events(hot) == 1 and _migration_events(cold) == 1


def test_an_unknown_workspace_is_refused(app, db):
    with pytest.raises(ValueError):
        place_contacts_on_ladder('no-such-workspace', NOW)


def test_one_bad_row_does_not_take_the_rest_down(app, db, monkeypatch):
    ws = _workspace(db)
    good, bad = _contact(db, ws), _contact(db, ws)
    _reply(db, good, thread='t1')
    _reply(db, bad, thread='t2')
    import scripts.migrate_to_ladder as mig
    real = mig._apply_plan
    monkeypatch.setattr(mig, '_apply_plan', lambda fc, *a: (_ for _ in ()).throw(
        RuntimeError('boom')) if fc.id == bad.id else real(fc, *a))
    out = _run(db, ws)
    db.session.refresh(good); db.session.refresh(bad)
    assert out['failed'] == [bad.contact_email]        # named, not a traceback
    assert out['placed'] == 1 and out['rungs']['warm'] == 1
    assert good.rung == 'warm'                         # the good row still landed
    assert bad.rung == 'cold' and bad.load_count == 0  # and the bad one is untouched


# ── the inline migration loop itself (the gap left by Task 2) ────────────────

_LEGACY_DDL = """
CREATE TABLE followup_contacts (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    workspace_id VARCHAR(36) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    contact_name VARCHAR(255),
    state VARCHAR(20) NOT NULL DEFAULT 'active',
    stage VARCHAR(30) NOT NULL DEFAULT 'fu1_scheduled',
    is_followup_enabled BOOLEAN NOT NULL DEFAULT 1,
    next_followup_at TIMESTAMP,
    last_activity_at TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
)
"""
_LADDER_COLUMNS = {
    'rung': 'cold', 'load_count': 0, 'touch_attempt': 0, 'auto_paused': 0,
    'last_load_at': None, 'exit_reason': None,
}


def _legacy_engine(tmp_path):
    engine = sa.create_engine(f'sqlite:///{tmp_path}/legacy.db')
    with engine.connect() as conn:
        conn.execute(sa.text(_LEGACY_DDL))
        conn.execute(sa.text(
            'INSERT INTO followup_contacts (id, user_id, workspace_id, contact_email) '
            "VALUES ('c1', 'u1', 'w1', 'broker@example.com')"))
        conn.commit()
    return engine


def _columns(engine):
    with engine.connect() as conn:
        return {r[1]: r for r in conn.execute(sa.text('PRAGMA table_info(followup_contacts)'))}


def test_inline_migration_adds_the_ladder_columns_to_a_legacy_table(tmp_path):
    """The inline entries, not Alembic, are what reaches production — and the
    loop hides every DDL failure, so assert the columns really appear."""
    engine = _legacy_engine(tmp_path)
    entries = [m for m in _app._migrations if m[0] == 'followup_contacts']
    assert {m[1] for m in entries} >= set(_LADDER_COLUMNS), 'ladder columns missing from _migrations'

    with engine.connect() as conn:
        added = _app._apply_add_column_migrations(conn, entries)
    assert set(added) == {f'followup_contacts.{col}' for _, col, _ in entries}
    assert set(_columns(engine)) >= {col for _, col, _ in entries}


def test_inline_migration_leaves_an_existing_row_valid(tmp_path):
    engine = _legacy_engine(tmp_path)
    entries = [m for m in _app._migrations if m[0] == 'followup_contacts']
    with engine.connect() as conn:
        _app._apply_add_column_migrations(conn, entries)
    cols = ', '.join(_LADDER_COLUMNS)
    with engine.connect() as conn:
        row = conn.execute(sa.text(
            f'SELECT {cols} FROM followup_contacts WHERE id = :i'), {'i': 'c1'}).mappings().one()
    assert dict(row) == _LADDER_COLUMNS
    # NOT NULL columns on an existing row only survive if the entry carries a default
    for name, info in _columns(engine).items():
        if name in _LADDER_COLUMNS and info[3]:            # notnull
            assert info[4] is not None, f'{name} is NOT NULL with no default'


def test_inline_migration_is_safe_to_run_again(tmp_path):
    engine = _legacy_engine(tmp_path)
    entries = [m for m in _app._migrations if m[0] == 'followup_contacts']
    with engine.connect() as conn:
        _app._apply_add_column_migrations(conn, entries)
    before = _columns(engine)
    with engine.connect() as conn:
        assert _app._apply_add_column_migrations(conn, entries) == []
    assert _columns(engine) == before
