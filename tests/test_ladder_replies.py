"""Warmth ladder: an inbound reply moves a contact up, parks it, or stops it."""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']

_DEFAULT_LOADS = {'warm': 1, 'hot': 2}


def _contact(db, rung='cold', **kw):
    """A follow-up contact on `rung`; warm/hot start with the load count that rung implies."""
    import bcrypt as _bcrypt
    from app.models import FollowupContact, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'lr_{uuid.uuid4().hex[:8]}@test.com', name='L', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.flush()
    kw.setdefault('load_count', _DEFAULT_LOADS.get(rung, 0))
    kw.setdefault('state', 'active')
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         stage='completed_fu3', is_followup_enabled=False,
                         rung=rung, **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _reply(db, fc, category, body, thread=None, msg_id=None):
    """Store an inbound Reply and run it through the reply hook; returns the Reply."""
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=msg_id or f'<{uuid.uuid4().hex}@mail>',
              thread_id=thread, from_email=fc.contact_email, subject='Re: Laredo to Dallas',
              body=body, triage_category=category)
    db.session.add(r); db.session.commit()
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit(); db.session.refresh(fc)
    return r


def _events(fc, event_type):
    from app.models import FollowupEvent
    return FollowupEvent.query.filter_by(followup_contact_id=fc.id, event_type=event_type).all()


# ── Load information moves a contact up ──────────────────────────────────────

def test_load_reply_raises_the_rung_and_resets_the_budget(app, db):
    fc = _contact(db, rung='neutral', touch_attempt=2)
    _reply(db, fc, category='gave_info', body='we have a load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('warm', 1, 0)
    assert fc.last_load_at is not None
    assert fc.next_followup_at is not None and fc.next_followup_at > _app._utcnow()
    assert len(_events(fc, 'ladder_load')) == 1


def test_second_load_reaches_hot(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    _reply(db, fc, category='gave_info', body='new load Houston to Miami', thread='t2')
    assert (fc.rung, fc.load_count) == ('hot', 2)


def test_same_thread_twice_counts_one_load(app, db):
    # Review Focus: Gmail re-fetch must not inflate the rung
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    _reply(db, fc, category='gave_info', body='still open, can you cover', thread='t1')
    assert (fc.load_count, fc.rung) == (1, 'warm')


def test_threadless_loads_on_one_day_count_once(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas')
    _reply(db, fc, category='gave_info', body='and a rate on it please')
    assert (fc.load_count, fc.rung) == (1, 'warm')


def test_load_never_lowers_a_hand_set_rung(app, db):
    fc = _contact(db, rung='hot', load_count=0)
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count) == ('hot', 1)


def test_load_from_a_client_counts_but_keeps_them_out_of_automation(app, db):
    fc = _contact(db, rung='client', load_count=5)
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count) == ('client', 6)
    assert fc.next_followup_at is None


def test_rate_request_is_not_a_load(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='rate_request', body='what is your rate Laredo to Dallas?', thread='t1')
    assert (fc.rung, fc.load_count) == ('neutral', 0)
    assert fc.attention_at is not None


# ── Refusal, deferral ────────────────────────────────────────────────────────

def test_refusal_stops_the_contact(app, db):
    fc = _contact(db, rung='warm')
    _reply(db, fc, category='negative', body='remove me from your list')
    assert fc.rung == 'dormant' and fc.exit_reason == 'refused'
    assert fc.next_followup_at is None and not fc.touch_enabled
    assert len(_events(fc, 'ladder_refusal')) == 1


def test_deferral_schedules_their_date_and_does_not_raise_the_rung(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert fc.rung == 'neutral' and fc.load_count == 0
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=6)
    assert len(_events(fc, 'ladder_deferral')) == 1


def test_deferral_without_a_date_keeps_the_normal_rhythm(app, db):
    fc = _contact(db, rung='neutral', touch_attempt=1)
    _reply(db, fc, category='negative', body='nothing right now, thanks')
    assert (fc.rung, fc.touch_attempt) == ('neutral', 1)       # a reply buys no patience
    expected = _app._utcnow() + timedelta(days=3)               # second touch: +3 days
    assert abs((fc.next_followup_at - expected).total_seconds()) < 60


def test_deferral_for_a_paused_contact_schedules_nothing(app, db):
    fc = _contact(db, rung='neutral', auto_paused=True)
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert fc.rung == 'neutral' and fc.next_followup_at is None


# ── Off-ladder states ────────────────────────────────────────────────────────

def test_excluded_contact_is_not_resurrected_by_a_reply(app, db):
    # Review Focus
    fc = _contact(db, rung='excluded')
    _reply(db, fc, category='gave_info', body='we have a load')
    assert fc.rung == 'excluded' and fc.next_followup_at is None
    assert fc.load_count == 0 and fc.attention_at is None


def test_dormant_contact_returns_on_an_inbound_reply(app, db):
    fc = _contact(db, rung='dormant', load_count=1, exit_reason='exhausted')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t9')
    assert fc.rung == 'hot' and fc.exit_reason is None
    assert fc.next_followup_at is not None


def test_dormant_contact_stays_dormant_on_a_deferral(app, db):
    # An exhausted budget is only refilled by a load, so a polite "later" changes nothing.
    fc = _contact(db, rung='dormant', exit_reason='exhausted')
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert (fc.rung, fc.exit_reason, fc.next_followup_at) == ('dormant', 'exhausted', None)


def test_load_for_a_paused_contact_counts_but_schedules_nothing(app, db):
    # Review Focus
    fc = _contact(db, rung='warm', auto_paused=True)
    _reply(db, fc, category='gave_info', body='another load', thread='t2')
    assert (fc.load_count, fc.rung) == (2, 'hot')
    assert fc.next_followup_at is None


# ── Unknown ──────────────────────────────────────────────────────────────────

def test_unparseable_reply_raises_attention_and_changes_nothing(app, db):
    fc = _contact(db, rung='warm', load_count=1)
    _reply(db, fc, category=None, body='ok')
    assert (fc.rung, fc.load_count) == ('warm', 1)
    assert fc.attention_at is not None
    assert len(_events(fc, 'ladder_unknown')) == 1


def test_unclassified_reply_is_classified_from_its_text(app, db):
    # At ingest the hook runs before triage has stored a category on the new row.
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category=None, thread='t1',
           body='Hi, I have a load for you. Laredo, TX to Dallas, TX. 42,000 lbs, 48 ft van.')
    assert (fc.rung, fc.load_count) == ('warm', 1)


def test_quoted_original_does_not_read_as_a_refusal(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='gave_info', thread='t1',
           body='Load Laredo to Dallas, call me.\n\nOn Mon, Oct 5, 2026 at 9:00 AM Me wrote:\n'
                '> reply to remove me from this list\n')
    assert (fc.rung, fc.load_count) == ('warm', 1)


def test_hook_without_a_reply_keeps_the_old_behaviour(app, db):
    fc = _contact(db, rung='neutral')
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id)
    db.session.commit(); db.session.refresh(fc)
    assert (fc.rung, fc.load_count) == ('neutral', 0)
    assert fc.last_reply_at is not None


def test_load_for_a_blocked_contact_counts_but_schedules_nothing(app, db):
    fc = _contact(db, rung='neutral', state='blocked')
    _reply(db, fc, category='gave_info', body='load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count) == ('warm', 1)
    assert fc.next_followup_at is None


# ── A reply lifts cold to neutral ────────────────────────────────────────────

def test_deferral_lifts_cold_to_neutral(app, db):
    fc = _contact(db, rung='cold')
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert (fc.rung, fc.load_count) == ('neutral', 0)


def test_unparseable_reply_lifts_cold_to_neutral(app, db):
    fc = _contact(db, rung='cold')
    _reply(db, fc, category=None, body='ok')
    assert fc.rung == 'neutral'


def test_a_reply_never_lowers_or_moves_a_higher_rung(app, db):
    hot = _contact(db, rung='hot')
    _reply(db, hot, category='negative', body='nothing right now')
    client = _contact(db, rung='client', load_count=5)
    _reply(db, client, category=None, body='ok')
    assert hot.rung == 'hot' and client.rung == 'client'


# ── The entry reply seeds the ladder ─────────────────────────────────────────

def _entry_reply(db, fc, category, body, thread=None):
    """A Reply from fc's address, the message the owner turns into a follow-up."""
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=f'<{uuid.uuid4().hex}@mail>', thread_id=thread,
              from_email=fc.contact_email, subject='Re: Laredo to Dallas',
              body=body, triage_category=category)
    db.session.add(r); db.session.commit()
    return r


def _created_from(db, category, body, thread=None):
    from app.models import FollowupContact
    donor = _contact(db)                       # supplies a user and workspace
    r = _entry_reply(db, donor, category, body, thread)
    r.from_email = f'new_{uuid.uuid4().hex[:8]}@x.com'
    db.session.commit()
    _app.add_to_followups(r)
    fc = FollowupContact.query.filter_by(workspace_id=donor.workspace_id,
                                         contact_email=r.from_email).one()
    return fc, r


def test_load_in_the_entry_reply_starts_the_contact_warm(app, db):
    fc, _ = _created_from(db, 'gave_info', 'we have a load Laredo to Dallas', thread='t1')
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('warm', 1, 0)
    assert fc.next_followup_at is not None


def test_entry_reply_is_not_counted_again_when_the_hook_sees_it(app, db):
    fc, r = _created_from(db, 'gave_info', 'we have a load Laredo to Dallas')
    _app._check_reply_stops_followup(fc.contact_email, fc.user_id, r)
    db.session.commit(); db.session.refresh(fc)
    assert (fc.load_count, fc.rung) == (1, 'warm')


def test_rate_request_entry_reply_starts_neutral_and_needs_you(app, db):
    fc, _ = _created_from(db, 'rate_request', 'what is your rate Laredo to Dallas?')
    assert (fc.rung, fc.load_count) == ('neutral', 0)
    assert fc.attention_at is not None


# ── Unrecognised rung, return contract, call-site lookup ─────────────────────

def test_unrecognised_rung_asks_for_attention_instead_of_raising(app, db):
    fc = _contact(db, rung='legacy-rung')
    _reply(db, fc, category='negative', body='nothing this week, try next week')
    assert fc.rung == 'legacy-rung' and fc.attention_at is not None
    assert fc.next_followup_at is None


def test_return_value_is_the_kind_applied_or_none_for_a_no_op(app, db):
    def apply(fc, category, body, thread=None):
        r = _entry_reply(db, fc, category, body, thread)
        from app.models import Workspace
        ws = db.session.get(Workspace, fc.workspace_id)
        return _app._apply_reply_to_ladder(fc, r, ws, _app._utcnow())

    assert apply(_contact(db, rung='neutral'), 'gave_info', 'load', 't1') == 'load'
    assert apply(_contact(db, rung='neutral'), 'negative', 'remove me') == 'refusal'
    assert apply(_contact(db, rung='neutral'), 'negative', 'nothing right now') == 'deferral'
    assert apply(_contact(db, rung='neutral'), None, 'ok') == 'unknown'
    assert apply(_contact(db, rung='excluded'), 'gave_info', 'load', 't1') is None
    assert apply(_contact(db, rung='dormant'), 'negative', 'nothing right now') is None
    fc = _contact(db, rung='neutral')
    assert apply(fc, 'gave_info', 'load', 'same') == 'load'
    assert apply(fc, 'gave_info', 'load again', 'same') is None     # duplicate: nothing applied


def test_reply_rows_lookup_returns_rows_by_message_id(app, db):
    fc = _contact(db, rung='neutral')
    r = _entry_reply(db, fc, 'gave_info', 'load')
    assert _app._reply_rows_by_msg_id(fc.user_id, [{'msg_id': r.msg_id}]) == {r.msg_id: r}


def test_reply_rows_lookup_warns_when_a_row_is_missing(app, db, caplog):
    fc = _contact(db, rung='neutral')
    with caplog.at_level('WARNING'):
        rows = _app._reply_rows_by_msg_id(fc.user_id, [{'msg_id': '<gone@mail>'}])
    assert rows == {}
    assert '<gone@mail>' in caplog.text


def test_reply_rows_lookup_logs_and_rolls_back_when_the_query_fails(app, db, caplog, monkeypatch):
    fc = _contact(db, rung='neutral')
    rolled_back = []

    def boom(*a, **k):
        raise RuntimeError('db is down')
    monkeypatch.setattr(db.session, 'query', boom)
    monkeypatch.setattr(db.session, 'rollback', lambda: rolled_back.append(True))
    with caplog.at_level('ERROR'):
        rows = _app._reply_rows_by_msg_id(fc.user_id, [{'msg_id': '<x@mail>'}])
    assert rows == {} and rolled_back
    assert 'db is down' in caplog.text
