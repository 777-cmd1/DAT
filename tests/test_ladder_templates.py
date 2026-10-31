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
    # the legacy general-pool picker (drip / manual paths)
    seen = {_app._get_random_fu_template(fc.user_id) for _ in range(30)}
    assert 'WARM ONLY' not in seen
    # and the ladder: a cold contact never gets the warm copy
    assert 'WARM ONLY' not in _body(fc)


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
    assert '{last_rate}' not in body
    assert 'Any loads?' in body and '{name}' in body
    assert 'Last rate' not in body                            # the line that needed it is dropped


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
    assert _body(fc) == 'Again?'


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
    assert len(bodies) >= 2 and len(set(bodies)) == len(bodies)


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
