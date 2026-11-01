from datetime import datetime, timedelta
from app import ladder

NOW = datetime(2026, 11, 2, 9, 0, 0)

def test_rung_from_load_count():
    assert ladder.rung_for(0, replied=False) == 'cold'
    assert ladder.rung_for(0, replied=True) == 'neutral'
    assert ladder.rung_for(1, replied=True) == 'warm'
    assert ladder.rung_for(2, replied=True) == 'hot'
    assert ladder.rung_for(9, replied=True) == 'hot'   # client is set deliberately, never derived

def test_budget_grows_once_a_load_arrived():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.budget_for('neutral', cfg) == 3
    assert ladder.budget_for('cold', cfg) == 3
    assert ladder.budget_for('warm', cfg) == 5
    assert ladder.budget_for('hot', cfg) == 5

def test_cadence_next_day_then_three_then_weekly():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.next_touch_at('neutral', 0, NOW, cfg) == NOW + timedelta(days=1)
    assert ladder.next_touch_at('neutral', 1, NOW, cfg) == NOW + timedelta(days=3)
    assert ladder.next_touch_at('neutral', 2, NOW, cfg) == NOW + timedelta(days=7)

def test_hot_is_weekly_from_the_first_touch():
    cfg = dict(ladder.LADDER_DEFAULTS)
    assert ladder.next_touch_at('hot', 0, NOW, cfg) == NOW + timedelta(days=7)

def test_client_is_never_scheduled():
    assert ladder.next_touch_at('client', 0, NOW, dict(ladder.LADDER_DEFAULTS)) is None

def test_higher_rung_patience_can_be_switched_off():
    cfg = dict(ladder.LADDER_DEFAULTS); cfg['higher_rung_patience'] = False
    assert ladder.budget_for('hot', cfg) == 3

def test_parse_deferral_reads_the_stated_time():
    assert ladder.parse_deferral('check back next week', NOW) == NOW + timedelta(days=7)
    assert ladder.parse_deferral('try us next month', NOW) == NOW + timedelta(days=30)
    assert ladder.parse_deferral('nothing right now', NOW) is None

def test_deferral_never_lands_in_the_past():
    stale = ladder.parse_deferral('next week', NOW - timedelta(days=30))
    assert stale is None or stale > NOW - timedelta(days=30)

def test_interpret_reply_splits_deferral_from_refusal():
    assert ladder.interpret_reply('gave_info', 'we have a load Laredo to Dallas', NOW)[0] == 'load'
    assert ladder.interpret_reply('negative', 'remove me from your list', NOW)[0] == 'refusal'
    # the phrases the shared `declined` keyword set wrongly marks negative
    for text in ('nothing this week', 'no loads this week', 'nothing right now', 'we are covered'):
        assert ladder.interpret_reply('negative', text, NOW)[0] == 'deferral', text
    assert ladder.interpret_reply(None, 'ok', NOW)[0] == 'unknown'


# --- additions beyond the brief -------------------------------------------

def test_load_conversation_key_is_stable_per_thread():
    sent = datetime(2026, 11, 2, 9, 0, 0)
    a = ladder.load_conversation_key('thr-1', 'a@x.com', sent)
    assert a == ladder.load_conversation_key('thr-1', 'other@x.com', sent + timedelta(days=5))
    assert a != ladder.load_conversation_key('thr-2', 'a@x.com', sent)

def test_load_conversation_key_without_thread_falls_back_to_email_and_day():
    sent = datetime(2026, 11, 2, 9, 0, 0)
    k = ladder.load_conversation_key(None, 'A@X.com', sent)
    assert k == ladder.load_conversation_key('', 'a@x.com', sent.replace(hour=17))
    assert k != ladder.load_conversation_key(None, 'a@x.com', sent + timedelta(days=1))
    assert k != ladder.load_conversation_key(None, 'b@x.com', sent)
    assert k != ladder.load_conversation_key('thr-1', 'a@x.com', sent)

def test_parse_deferral_relative_and_explicit_dates():
    assert ladder.parse_deferral('check back in 3 days', NOW) == NOW + timedelta(days=3)
    assert ladder.parse_deferral('ping me in two weeks', NOW) == NOW + timedelta(days=14)
    assert ladder.parse_deferral('check back March 15th', NOW) == datetime(2027, 3, 15, 9, 0, 0)
    assert ladder.parse_deferral('after 20 Nov please', NOW) == datetime(2026, 11, 20, 9, 0, 0)

def test_parse_deferral_returns_none_rather_than_a_past_or_invalid_date():
    assert ladder.parse_deferral('in 0 days', NOW) is None
    assert ladder.parse_deferral('February 30', NOW) is None
    assert ladder.parse_deferral('on November 2', NOW) is None   # today is not "later"
    assert ladder.parse_deferral('', NOW) is None

def test_interpret_reply_deferral_carries_the_date_when_one_is_stated():
    kind, when = ladder.interpret_reply('negative', 'nothing right now, try next month', NOW)
    assert (kind, when) == ('deferral', NOW + timedelta(days=30))
    assert ladder.interpret_reply('negative', 'nothing this week', NOW) == ('deferral', None)

def test_hard_refusal_beats_a_deferral_phrase():
    for text in ('unsubscribe', 'do not contact me, we are covered', 'DNU', 'take me off, try next month'):
        assert ladder.interpret_reply('negative', text, NOW) == ('refusal', None), text

def test_negative_without_a_deferral_phrase_is_a_refusal():
    assert ladder.interpret_reply('negative', 'we cannot use landstar', NOW) == ('refusal', None)

def test_other_categories_never_become_load_or_refusal_by_accident():
    assert ladder.interpret_reply('auto_reply', 'out of office until Monday', NOW)[0] == 'unknown'
    assert ladder.interpret_reply('rate_request', 'what is your rate?', NOW)[0] == 'unknown'

def test_off_ladder_rungs_have_no_budget_or_schedule():
    cfg = dict(ladder.LADDER_DEFAULTS)
    for rung in ladder.OFF_LADDER + ('client',):
        assert ladder.budget_for(rung, cfg) == 0
        assert ladder.next_touch_at(rung, 0, NOW, cfg) is None

def test_partial_cfg_falls_back_to_defaults():
    assert ladder.next_touch_at('neutral', 0, NOW, {}) == NOW + timedelta(days=1)
    assert ladder.budget_for('warm', {'budget_engaged': 7}) == 7

def test_hot_weekly_can_be_switched_off():
    cfg = dict(ladder.LADDER_DEFAULTS); cfg['hot_weekly'] = False
    assert ladder.next_touch_at('hot', 0, NOW, cfg) == NOW + timedelta(days=1)


# --- review fixes: real-world email text -----------------------------------

def test_curly_apostrophes_match_the_straight_phrases():
    for text in ('we’re covered', 'It’s covered, thanks', 'We’RE covered this week'):
        assert ladder.interpret_reply('negative', text, NOW)[0] == 'deferral', text
    assert ladder.interpret_reply('negative', 'please don’t contact me', NOW) == ('refusal', None)

def test_wrapped_lines_and_extra_spaces_do_not_break_phrases():
    for text in ('nothing\nthis week', 'nothing  this   week', 'no loads\r\nthis week', 'we are\tcovered'):
        assert ladder.interpret_reply('negative', text, NOW)[0] == 'deferral', text
    assert ladder.interpret_reply('negative', 'do not\ncontact me', NOW) == ('refusal', None)
    assert ladder.parse_deferral('try us next\nmonth', NOW) == NOW + timedelta(days=30)

def test_the_shared_declined_phrases_are_deferrals_but_mc_blockers_stay_refusals():
    for text in ("we're covered", "it's covered", 'all covered', 'load is covered', 'already covered',
                 'nothing at this time', 'not at this time'):
        assert ladder.interpret_reply('negative', text, NOW)[0] == 'deferral', text
    for text in ("can't work with your mc", 'cannot work with your mc', 'can not work with your mc', 'not interested'):
        assert ladder.interpret_reply('negative', text, NOW) == ('refusal', None), text


# --- review fixes: incidental dates are not deferrals ----------------------

def test_prose_containing_may_is_not_a_date():
    assert ladder.parse_deferral('1 may work', NOW) is None
    assert ladder.interpret_reply(None, '1 may work', NOW)[0] == 'unknown'
    assert ladder.parse_deferral('5 May', NOW) is None            # past, no cue
    assert ladder.parse_deferral('after May 5', NOW) == datetime(2027, 5, 5, 9, 0, 0)

def test_month_stem_inside_a_word_is_not_a_month():
    assert ladder.parse_deferral('check back grammar 12', NOW) is None

def test_a_past_date_is_not_rolled_forward_without_a_forward_cue():
    assert ladder.parse_deferral('we signed with another broker on Oct 12', NOW) is None
    assert ladder.interpret_reply('negative', 'we signed with another broker on Oct 12', NOW) == ('refusal', None)
    assert ladder.interpret_reply(None, 'booked it on Oct 12', NOW)[0] == 'unknown'

def test_a_past_date_rolls_forward_only_with_a_forward_cue():
    nxt = datetime(2027, 10, 12, 9, 0, 0)
    for text in ('check back Oct 12', 'nothing until Oct 12', 'call me after 12 Oct', 'till Oct 12'):
        assert ladder.parse_deferral(text, NOW) == nxt, text

def test_a_future_date_this_year_needs_no_cue():
    assert ladder.parse_deferral('Dec 5', NOW) == datetime(2026, 12, 5, 9, 0, 0)


# ── fix round 2: the 'negative' bucket is not all "no" ───────────────────────

def test_a_carrier_packet_ask_is_not_a_refusal():
    # the Replies page files mc_request under Negative (its action there is
    # Ignore); to the ladder it is a live broker asking for our packet
    body = 'Sure, send me your MC and insurance'
    assert ladder.interpret_reply('negative', body, NOW) == ('refusal', None)
    assert ladder.interpret_reply('negative', body, NOW,
                                  filter_key='mc_request') == ('unknown', None)


def test_the_packet_split_never_rescues_a_real_refusal():
    for text in ('remove me from your list', 'take me off this list', 'do not contact me'):
        assert ladder.interpret_reply('negative', text, NOW,
                                      filter_key='mc_request') == ('refusal', None), text
    # and a stated return date still reads as a deferral, not as a packet ask
    assert ladder.interpret_reply('negative', 'nothing this week', NOW,
                                  filter_key='mc_request')[0] == 'deferral'


def test_an_unrelated_filter_key_changes_nothing():
    assert ladder.interpret_reply('negative', 'not interested', NOW,
                                  filter_key='declined') == ('refusal', None)
    assert ladder.interpret_reply('gave_info', 'we have a load', NOW,
                                  filter_key='mc_request')[0] == 'load'
