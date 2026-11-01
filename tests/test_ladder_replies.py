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


def _reply(db, fc, category, body, thread=None, msg_id=None, subject='Re: Laredo to Dallas', **kw):
    """Store an inbound Reply and run it through the reply hook; returns the Reply."""
    from app.models import Reply
    r = Reply(user_id=fc.user_id, msg_id=msg_id or f'<{uuid.uuid4().hex}@mail>',
              thread_id=thread, from_email=fc.contact_email, subject=subject,
              body=body, triage_category=category, **kw)
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
    expected = _app._utcnow() + timedelta(days=3)               # second touch: +3 days...
    assert fc.next_followup_at.date() == expected.date()
    assert fc.next_followup_at.hour == 14                       # ...at the default touch hour


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


# ── A load reply points the contact at the lane it answers ───────────────────

def _send(db, fc, origin, destination, email=None, hours_ago=5, status='sent'):
    from app.models import Send
    db.session.add(Send(user_id=fc.user_id, recipient_email=email or fc.contact_email,
                        origin=origin, destination=destination, status=status,
                        sent_at=_app._utcnow() - timedelta(hours=hours_ago)))
    db.session.commit()


def test_a_load_reply_refreshes_the_route_from_the_only_lane_we_sent(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _send(db, fc, 'Houston, TX', 'Miami, FL')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1', subject='Re: your load')
    assert fc.current_route == 'Houston, TX \u2192 Miami, FL'


def test_with_several_lanes_the_one_named_in_the_subject_wins(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', hours_ago=9)
    _send(db, fc, 'Houston, TX', 'Miami, FL', hours_ago=2)
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1',
           subject='Re: Laredo, TX to Dallas, TX, 1/5, Van')
    assert fc.current_route == 'Laredo, TX \u2192 Dallas, TX'


def test_with_several_lanes_and_no_match_the_route_is_left_alone(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', hours_ago=9)
    _send(db, fc, 'Houston, TX', 'Miami, FL', hours_ago=2)
    _reply(db, fc, category='gave_info', body='we have a load Tampa to Atlanta', thread='t1',
           subject='Re: your load')
    assert fc.current_route == 'Old, TX \u2192 Elsewhere, TX'


def test_no_sends_means_no_change_and_the_lane_is_not_read_from_the_text(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _reply(db, fc, category='gave_info', body='we have a load Tampa, FL to Atlanta, GA',
           thread='t1', subject='Re: your load')
    assert fc.current_route == 'Old, TX \u2192 Elsewhere, TX'


def test_a_send_with_half_a_lane_or_a_failed_send_is_not_a_lane(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _send(db, fc, 'Houston, TX', '')
    _send(db, fc, 'Houston, TX', 'None')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', status='error')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1', subject='Re: your load')
    assert fc.current_route == 'Old, TX \u2192 Elsewhere, TX'


def test_a_colleagues_reply_is_matched_through_the_address_we_wrote_to(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    fc.contact_email = 'dispatch@abc.com'
    db.session.commit()
    _send(db, fc, 'Houston, TX', 'Miami, FL', email='Dispatch@abc.com')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1', subject='Re: your load',
           matched_recipient='dispatch@abc.com')
    assert fc.current_route == 'Houston, TX \u2192 Miami, FL'


def test_a_reply_that_is_not_a_load_leaves_the_route_alone(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX \u2192 Elsewhere, TX')
    _send(db, fc, 'Houston, TX', 'Miami, FL')
    _reply(db, fc, category='rate_request', body='what is your rate?', thread='t1',
           subject='Re: your load')
    assert fc.current_route == 'Old, TX \u2192 Elsewhere, TX'


def test_a_round_trip_lane_is_not_mistaken_for_its_reverse(app, db):
    """Both directions mention both cities: only the order the subject uses tells them apart."""
    fc = _contact(db, rung='neutral', current_route='Old, TX → Elsewhere, TX')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', hours_ago=9)
    _send(db, fc, 'Dallas, TX', 'Laredo, TX', hours_ago=2)           # the newer one
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1',
           subject='Re: Laredo, TX to Dallas, TX, 1/5, Van')
    assert fc.current_route == 'Laredo, TX → Dallas, TX'


def test_the_reverse_subject_picks_the_reverse_lane(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX → Elsewhere, TX')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', hours_ago=2)
    _send(db, fc, 'Dallas, TX', 'Laredo, TX', hours_ago=9)
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1',
           subject='RE: Dallas, TX to Laredo, TX, 1/5, Van')
    assert fc.current_route == 'Dallas, TX → Laredo, TX'


def test_a_longer_city_name_does_not_match_a_shorter_one(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX → Elsewhere, TX')
    _send(db, fc, 'North Houston, TX', 'Miami, FL', hours_ago=9)
    _send(db, fc, 'Houston, TX', 'Miami, FL', hours_ago=2)           # the newer one
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1',
           subject='Re: Houston, TX to Miami, FL, 1/5, Van')
    assert fc.current_route == 'Houston, TX → Miami, FL'
    _reply(db, fc, category='gave_info', body='another load', thread='t2',
           subject='Re: North Houston, TX to Miami, FL, 1/6')
    assert fc.current_route == 'North Houston, TX → Miami, FL'


def test_a_subject_that_only_mentions_the_cities_loosely_changes_nothing(app, db):
    fc = _contact(db, rung='neutral', current_route='Old, TX → Elsewhere, TX')
    _send(db, fc, 'Laredo, TX', 'Dallas, TX', hours_ago=9)
    _send(db, fc, 'Dallas, TX', 'Laredo, TX', hours_ago=2)
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1',
           subject='Re: loads between Dallas, TX and Laredo, TX')
    assert fc.current_route == 'Old, TX → Elsewhere, TX'


def test_a_failed_route_refresh_costs_only_the_route(app, db, monkeypatch):
    """The load is still counted, the rung raised, the attempts reset and a touch scheduled."""
    def boom(*a, **k):
        raise RuntimeError('db hiccup')
    monkeypatch.setattr(_app, '_ladder_refresh_route', boom)
    fc = _contact(db, rung='neutral', touch_attempt=2, current_route='Old, TX → Elsewhere, TX')
    _reply(db, fc, category='gave_info', body='we have a load', thread='t1')
    assert (fc.rung, fc.load_count, fc.touch_attempt) == ('warm', 1, 0)
    assert fc.next_followup_at is not None and fc.next_followup_at > _app._utcnow()
    assert fc.current_route == 'Old, TX → Elsewhere, TX'


# ══ fix round 2 ══════════════════════════════════════════════════════════════
# The shared 'negative' bucket holds the mc_request filter, so a broker opening a
# carrier packet ("send me your MC and insurance") came out of interpret_reply as
# a refusal and was parked. It is the hottest reply in the book: it must reach the
# owner instead. The split lives in Follow-up — the Replies page, its categories
# and its keyword sets are untouched.

def test_an_mc_request_asks_for_a_human_instead_of_parking_the_contact(app, db):
    fc = _contact(db, rung='cold')
    _reply(db, fc, category='negative', body='Sure, send me your MC and insurance',
           reply_filter_key='mc_request')
    assert (fc.rung, fc.exit_reason) == ('neutral', None)
    assert fc.attention_at is not None                 # it lands in "Needs you"
    assert _events(fc, 'ladder_refusal') == []
    assert len(_events(fc, 'ladder_unknown')) == 1


def test_an_mc_request_is_recognised_without_a_stored_filter_key(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='negative', body="What's your MC number?")
    assert (fc.rung, fc.exit_reason) == ('neutral', None)
    assert _events(fc, 'ladder_refusal') == []


def test_a_genuine_refusal_is_untouched_by_the_mc_split(app, db):
    fc = _contact(db, rung='warm')
    _reply(db, fc, category='negative', body='please remove me from your list',
           reply_filter_key='declined')
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')
    assert len(_events(fc, 'ladder_refusal')) == 1


def test_an_mc_request_that_also_asks_us_to_stop_is_a_refusal(app, db):
    fc = _contact(db, rung='neutral')
    _reply(db, fc, category='negative', reply_filter_key='mc_request',
           body='send me your mc — actually, take me off this list')
    assert (fc.rung, fc.exit_reason) == ('dormant', 'refused')
