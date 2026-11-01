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

import sqlalchemy as sa

_app = sys.modules['_dat_mailer_app']

from scripts.migrate_to_ladder import SILENCE_DAYS, place_contacts_on_ladder   # noqa: E402

NOW = _app._utcnow().replace(microsecond=0)


# ── fixtures ─────────────────────────────────────────────────────────────────

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


def _reply(db, fc, category='gave_info', thread=None, days_ago=1, body='load Laredo to Dallas'):
    from app.models import Reply
    r = Reply(user_id=fc.user_id, workspace_id=fc.workspace_id,
              msg_id=f'<{uuid.uuid4().hex}@mail>', thread_id=thread,
              from_email=fc.contact_email, subject='Re: Laredo to Dallas',
              body=body, triage_category=category,
              received_at=NOW - timedelta(days=days_ago))
    db.session.add(r); db.session.commit()
    return r


def _run(db, ws, dry_run=False):
    out = place_contacts_on_ladder(ws.id, NOW, dry_run=dry_run)
    db.session.commit()
    return out


def _migration_events(fc):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id,
                                         event_type='migrated_to_ladder').count()


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
    _reply(db, answered, category='negative', body='nothing for us right now')
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
    assert _app._ladder_next_reason(fc) == 'dormant: silent for months when the ladder started'


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
    assert _app._ladder_next_reason(fc) != 'first follow-up sequence'


def test_a_schedule_the_owner_set_by_hand_keeps_its_date(app, db):
    ws = _workspace(db)
    when = NOW + timedelta(days=9)
    once = _contact(db, ws, scheduled_once=True, is_followup_enabled=False)
    once.next_followup_at = when
    repeating = _contact(db, ws, recurring_enabled=True, recurring_days='0,2',
                         recurring_time='14:00', is_followup_enabled=False)
    repeating.next_followup_at = when
    db.session.commit()
    _run(db, ws)
    db.session.refresh(once); db.session.refresh(repeating)
    assert once.next_followup_at == when
    assert repeating.next_followup_at == when


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

    second = _run(db, ws)
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
    import pytest
    with pytest.raises(ValueError):
        place_contacts_on_ladder('no-such-workspace', NOW)


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
