"""Warmth ladder: what each rung's email says, and how the body is chosen.

Lookup order: the user's Template(level=<RUNG>) -> the code default for that
rung -> the user's general pool -> nothing (the scheduler then asks a human).
"""
import re
import sys
import uuid

import pytest

_app = sys.modules['_dat_mailer_app']

SENDABLE = ('cold', 'neutral', 'warm', 'hot')
ROUTE = 'Laredo, TX -> Dallas, TX'


def _workspace(db):
    import bcrypt as _bcrypt
    from app.models import EmailAccount, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'lt_{uuid.uuid4().hex[:8]}@test.com', name='L', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=True, ladder_auto_enabled=True)
    db.session.add(ws); db.session.flush()
    db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id, gmail_address='me@test.com',
                                your_name='Me'))
    db.session.commit()
    return user, ws


def _contact(db, rung='warm', **kw):
    from app.models import FollowupContact
    user, ws = _workspace(db)
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'completed_fu3')
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', rung=rung, **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _tmpl(db, fc, level, body, order=0, active=True):
    from app.models import Template
    t = Template(user_id=fc.user_id, type='followup', level=level, name=level or 'x',
                 body=body, sort_order=order, is_active=active)
    db.session.add(t); db.session.commit()
    return t


def _body(fc, rung=None):
    return _app._template_for_rung(fc.user_id, rung or fc.rung, fc)


# ── The user's own copy ──────────────────────────────────────────────────────

def test_rung_template_is_preferred_over_the_general_pool(app, db):
    fc = _contact(db, rung='warm')
    _tmpl(db, fc, 'General', 'GENERAL BODY')
    _tmpl(db, fc, 'WARM', 'WARM BODY')
    assert _body(fc) == 'WARM BODY'


def test_rung_template_is_preferred_over_the_code_default(app, db):
    fc = _contact(db, rung='neutral')
    _tmpl(db, fc, 'NEUTRAL', 'MY NEUTRAL BODY')
    assert _body(fc) == 'MY NEUTRAL BODY'


def test_rung_level_matches_whatever_the_case(app, db):
    fc = _contact(db, rung='hot')
    _tmpl(db, fc, ' Hot ', 'HOT BODY')
    assert _body(fc) == 'HOT BODY'


def test_an_inactive_or_empty_rung_template_is_ignored(app, db):
    fc = _contact(db, rung='warm')
    _tmpl(db, fc, 'WARM', 'OFF', active=False)
    _tmpl(db, fc, 'WARM', '   ')
    assert _body(fc) == _app._render_rung_body(_app.DEFAULT_RUNG_TEMPLATES['warm'][0], fc)


def test_several_rung_templates_rotate_with_the_attempt(app, db):
    fc = _contact(db, rung='warm')
    _tmpl(db, fc, 'WARM', 'ONE', order=1)
    _tmpl(db, fc, 'WARM', 'TWO', order=2)
    got = []
    for attempt in range(4):
        fc.touch_attempt = attempt
        got.append(_body(fc))
    assert got == ['ONE', 'TWO', 'ONE', 'TWO']


# ── The code default ─────────────────────────────────────────────────────────

def test_the_code_default_beats_the_general_pool(app, db):
    """A workspace that only has general / FU templates must still get rung-aware copy."""
    fc = _contact(db, rung='warm', current_route=ROUTE)
    _tmpl(db, fc, 'General', 'Just wanted to follow up')
    _tmpl(db, fc, 'FU1', 'Hi, FU1 text')
    body = _body(fc)
    assert 'Just wanted to follow up' not in body and 'FU1 text' not in body
    assert ROUTE in body


@pytest.mark.parametrize('rung', SENDABLE)
def test_a_workspace_with_no_templates_gets_the_rung_default(app, db, rung):
    fc = _contact(db, rung=rung)
    body = _body(fc)
    assert body and body.strip()
    assert 'wanted to follow up' not in body                  # the generic FU1 default


def test_warm_body_can_reference_the_contact_lane(app, db):
    fc = _contact(db, rung='warm', current_route=ROUTE)
    assert ROUTE in _body(fc)                                 # template uses {route}


def test_the_default_leaves_the_signature_for_the_sender(app, db):
    """{name} {company} {phone} belong to send_followup_email, not to us."""
    fc = _contact(db, rung='neutral', current_route=ROUTE)
    body = _body(fc)
    for var in ('{name}', '{company}', '{phone}'):
        assert var in body


# ── Falling back ─────────────────────────────────────────────────────────────

def test_falls_back_to_the_general_pool_when_there_is_no_rung_copy(app, db):
    """client has no copy of its own: the general pool is the last resort."""
    fc = _contact(db, rung='client')
    _tmpl(db, fc, 'General', 'GENERAL BODY')
    assert _body(fc) == 'GENERAL BODY'


def test_nothing_to_send_returns_none_and_never_a_generic_default(app, db):
    fc = _contact(db, rung='client')
    assert _body(fc) is None


def test_a_blank_rendering_falls_through_to_the_next_source(app, db):
    """A rung template that renders to nothing must not become an empty email."""
    fc = _contact(db, rung='warm')                            # no route, no rate
    _tmpl(db, fc, 'WARM', '{last_rate}')
    body = _body(fc)
    assert body.strip() and '{last_rate}' not in body
    assert body == _app._render_rung_body(_app.DEFAULT_RUNG_TEMPLATES['warm'][0], fc)


# ── Rung-named levels never leak into the general pool ──────────────────────

def test_a_rung_template_is_not_part_of_the_general_pool(app, db):
    fc = _contact(db, rung='cold')
    _tmpl(db, fc, 'WARM', 'WARM ONLY')
    # a cold contact never gets the warm copy, from the ladder or from a manual send
    assert 'WARM ONLY' not in _body(fc)
    assert 'WARM ONLY' not in {_app._followup_copy(fc.user_id, fc) for _ in range(30)}


def test_a_rung_template_does_not_stand_in_for_the_general_pool(app, db):
    fc = _contact(db, rung='client')
    _tmpl(db, fc, 'WARM', 'WARM ONLY')
    assert _body(fc) is None


# ── Variables ────────────────────────────────────────────────────────────────

def test_origin_and_destination_are_split_from_the_route(app, db):
    fc = _contact(db, rung='warm', current_route=ROUTE)
    _tmpl(db, fc, 'WARM', 'From {origin} to {destination}')
    assert _body(fc) == 'From Laredo, TX to Dallas, TX'
    fc.current_route = 'Laredo, TX → Dallas, TX'
    assert _body(fc) == 'From Laredo, TX to Dallas, TX'


def test_missing_variable_does_not_crash_the_send(app, db):
    fc = _contact(db, rung='warm')
    _tmpl(db, fc, 'WARM', 'Hi,\n\nLast rate was {last_rate}.\nAny loads?\n\n{name}')
    body = _body(fc)
    assert '{last_rate}' not in body and 'Last rate' not in body
    assert body == _app._render_rung_body(_app.DEFAULT_RUNG_TEMPLATES['warm'][0], fc)


def test_a_user_template_is_never_cut_down_to_a_greeting_and_a_signature(app, db):
    """Its only content line needs a lane the contact lacks: our copy goes instead."""
    fc = _contact(db, rung='warm')
    _tmpl(db, fc, 'WARM', 'Hi,\n\nAny loads from {origin}?\n\n{name}\n{company} | {phone}')
    body = _body(fc)
    assert body == _app._render_rung_body(_app.DEFAULT_RUNG_TEMPLATES['warm'][0], fc)
    assert 'Any loads from' not in body


def test_a_user_template_is_sent_whole_when_every_value_is_there(app, db):
    fc = _contact(db, rung='warm', current_route=ROUTE)
    _tmpl(db, fc, 'WARM', 'Hi,\n\nAny loads from {origin}?\n\n{name}')
    assert _body(fc) == 'Hi,\n\nAny loads from Laredo, TX?\n\n{name}'


def test_a_general_template_that_needs_a_missing_value_is_not_trimmed(app, db):
    fc = _contact(db, rung='client')
    _tmpl(db, fc, 'General', 'Hi,\n\nAny loads from {origin}?\n\n{name}')
    assert _body(fc) is None


@pytest.mark.parametrize('route', ['Laredo, TX →', '→ Dallas, TX', 'Laredo, TX ->',
                                   'None → Dallas, TX', 'Laredo, TX → None',
                                   'None → None', ' → ', 'Laredo to Dallas'])
def test_a_half_lane_is_not_a_route(app, db, route):
    fc = _contact(db, rung='warm', current_route=route)
    assert _app._rung_template_vars(fc, set())['route'] == ''
    for i in range(len(_app.DEFAULT_RUNG_TEMPLATES['warm'])):
        fc.touch_attempt = i
        body = _body(fc)
        assert '→' not in body and '->' not in body and 'None' not in body


def test_each_side_of_a_half_lane_still_stands_alone(app, db):
    fc = _contact(db, rung='warm', current_route='Laredo, TX →')
    assert _app._rung_template_vars(fc, set()) == {'route': '', 'origin': 'Laredo, TX', 'destination': ''}
    fc.current_route = 'None → Dallas, TX'
    assert _app._rung_template_vars(fc, set()) == {'route': '', 'origin': '', 'destination': 'Dallas, TX'}


def test_the_first_warm_body_is_a_self_standing_question_without_a_route(app, db):
    """The first warm body must still be a complete, self-standing question."""
    fc = _contact(db, rung='warm', current_route=None, touch_attempt=0)
    body = _body(fc)
    assert 'Do you have another load coming up?' in body
    assert 'like it' not in body and 'like that' not in body and 'that lane' not in body


def test_the_route_query_only_runs_when_a_body_asks_for_the_rate(app, db):
    from sqlalchemy import event
    fc = _contact(db, rung='warm', current_route=ROUTE)
    seen = []

    def spy(conn, cursor, statement, *a):
        if 'rate_quotes' in statement:
            seen.append(statement)
    event.listen(db.engine, 'before_cursor_execute', spy)
    try:
        for i in range(len(_app.DEFAULT_RUNG_TEMPLATES['warm'])):
            fc.touch_attempt = i
            _body(fc)
        assert seen == []
        _tmpl(db, fc, 'WARM', 'Rate was {last_rate}.\nAgain?')
        _body(fc)
        assert len(seen) == 1
    finally:
        event.remove(db.engine, 'before_cursor_execute', spy)


def _quote(db, fc, rate, hidden=False):
    from app.models import RateQuote, Reply
    rep = Reply(user_id=fc.user_id, msg_id=f'<lt-{uuid.uuid4().hex}@t>', from_email=fc.contact_email,
                body='quote', status='new')
    db.session.add(rep); db.session.flush()
    db.session.add(RateQuote(user_id=fc.user_id, reply_id=rep.id, contact_email=fc.contact_email,
                             rate=rate, hidden=hidden))
    db.session.commit()


def test_last_rate_comes_from_the_latest_quote(app, db):
    fc = _contact(db, rung='warm')
    _quote(db, fc, 1500)
    _tmpl(db, fc, 'WARM', 'You said {last_rate}.\nAgain?')
    assert _body(fc) == 'You said $1,500.\nAgain?'


def test_a_hidden_quote_is_not_used(app, db):
    fc = _contact(db, rung='warm')
    _quote(db, fc, 900, hidden=True)
    _tmpl(db, fc, 'WARM', 'You said {last_rate}.\nAgain?')
    assert _body(fc) == _app._render_rung_body(_app.DEFAULT_RUNG_TEMPLATES['warm'][0], fc)


# ── The copy itself ──────────────────────────────────────────────────────────

_VARS_OK = {'name', 'company', 'phone', 'route', 'origin', 'destination', 'last_rate'}


def _all_defaults():
    return [(rung, i, text) for rung, bodies in _app.DEFAULT_RUNG_TEMPLATES.items()
            for i, text in enumerate(bodies)]


def test_defaults_cover_every_sendable_rung_and_nothing_else(app):
    assert set(_app.DEFAULT_RUNG_TEMPLATES) == set(SENDABLE)


@pytest.mark.parametrize('rung', SENDABLE)
def test_each_attempt_of_a_rung_reads_differently(app, rung):
    bodies = _app.DEFAULT_RUNG_TEMPLATES[rung]
    assert len(set(bodies)) == len(bodies)
    # one distinct body per attempt in the rung's budget
    assert len(bodies) >= _app._ladder.budget_for(rung, _app._ladder.LADDER_DEFAULTS)


def _walk(db, fc, rung, load_count, attempts, bodies):
    """Send `attempts` touches on `rung` with the counters the scheduler would have."""
    fc.rung, fc.load_count = rung, load_count
    for attempt in range(attempts):
        fc.touch_attempt = attempt
        bodies.append(_body(fc))


def test_no_two_sends_share_a_body_across_a_budget_and_a_new_load(app, db):
    """A contact goes through a full budget, sends a load, and goes through the next:
    the same text never reaches the same broker twice."""
    cfg = _app._ladder.LADDER_DEFAULTS
    fc = _contact(db, rung='warm', current_route=ROUTE)
    sent = []
    _walk(db, fc, 'warm', 1, _app._ladder.budget_for('warm', cfg), sent)     # first load
    _walk(db, fc, 'hot', 2, _app._ladder.budget_for('hot', cfg), sent)       # second load
    assert len(sent) == 10 and len(set(sent)) == 10


def test_a_new_load_does_not_restart_at_the_first_body(app, db):
    cfg = _app._ladder.LADDER_DEFAULTS
    budget = _app._ladder.budget_for('hot', cfg)
    fc = _contact(db, rung='hot', current_route=ROUTE)
    second, third = [], []
    _walk(db, fc, 'hot', 2, budget, second)
    _walk(db, fc, 'hot', 3, budget, third)
    assert third[0] not in (second[0], second[-1])


def test_every_default_asks_something_a_dispatcher_can_answer(app, db):
    """Rendered with no route and no rate, each email still carries its question."""
    for rung, i, _ in _all_defaults():
        fc = _contact(db, rung=rung, touch_attempt=i)
        body = _body(fc)
        assert '?' in body, (rung, i)
        assert not re.findall(r'\{(?!name\}|company\}|phone\})\w+\}', body), (rung, i)


def test_defaults_use_only_variables_the_renderer_knows(app):
    for rung, i, text in _all_defaults():
        assert set(re.findall(r'\{(\w+)\}', text)) <= _VARS_OK, (rung, i)


def test_defaults_keep_the_owners_voice(app):
    for rung, i, text in _all_defaults():
        low = text.lower()
        assert '—' not in text and '–' not in text, (rung, i)
        assert 'hope this' not in low and 'wanted to follow up' not in low, (rung, i)
        assert text.rstrip().endswith('{name}\n{company} | {phone}'), (rung, i)


def test_a_default_without_a_lane_drops_the_lane_line_cleanly(app, db):
    fc = _contact(db, rung='warm', current_route=None)
    for i in range(len(_app.DEFAULT_RUNG_TEMPLATES['warm'])):
        fc.touch_attempt = i
        body = _body(fc)
        assert 'None' not in body and '\n\n\n' not in body


# ── The scheduler uses it ────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    from app.models import FollowupContact, FollowupEvent
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    db.session.commit()


@pytest.fixture
def bodies(monkeypatch):
    out = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (out.append(tpl), (True, None))[1])
    return out


def _due(db, **kw):
    kw.setdefault('next_followup_at', _app._utcnow() - _app.timedelta(hours=2))
    kw.setdefault('touch_enabled', True)
    kw.setdefault('is_followup_enabled', False)
    kw.setdefault('load_count', 1)
    return _contact(db, **kw)


def test_the_copy_asserts_no_more_than_the_data_knows(app):
    """Not that they send us lanes, and not that we run the lane we emailed about."""
    hot3 = _app.DEFAULT_RUNG_TEMPLATES['hot'][2]
    assert 'already send' not in hot3 and hot3.count('{route}') == 0
    assert 'any lanes you already have' in hot3
    warm3 = _app.DEFAULT_RUNG_TEMPLATES['warm'][2]
    assert 'not only' not in warm3 and '{route}' not in warm3


def test_the_scheduler_sends_the_rung_copy(app, db, bodies):
    fc = _due(db, rung='warm', current_route=ROUTE, touch_attempt=0)
    expected = _body(fc)
    assert _app._run_ladder_touches(_app._utcnow()) == 1
    assert bodies == [expected] and ROUTE in bodies[0]


def test_the_scheduler_varies_the_copy_by_attempt(app, db, bodies):
    _due(db, rung='neutral', load_count=0, touch_attempt=0)
    _due(db, rung='neutral', load_count=0, touch_attempt=1)
    assert _app._run_ladder_touches(_app._utcnow()) == 2
    assert len(set(bodies)) == 2


def test_the_scheduler_prefers_the_users_rung_copy(app, db, bodies):
    fc = _due(db, rung='hot', load_count=2)
    _tmpl(db, fc, 'General', 'GENERAL BODY')
    _tmpl(db, fc, 'HOT', 'HOT BODY')
    assert _app._run_ladder_touches(_app._utcnow()) == 1
    assert bodies == ['HOT BODY']
