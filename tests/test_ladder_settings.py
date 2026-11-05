"""Warmth ladder: the owner's settings.

Cadence and patience numbers live in Workspace.pipeline_config['ladder'] and every
engine read goes through _ladder_cfg(ws); the switch that turns the ladder on is a
workspace flag with a control on the Follow-up page; the per-rung email copy is
readable and editable, and an edit becomes the workspace's own Template(level=RUNG).
"""
import sys
import uuid
from datetime import timedelta

import pytest

from app import ladder

_app = sys.modules['_dat_mailer_app']


# ── helpers ──────────────────────────────────────────────────────────────────

def _user(db, ladder_on=False, fu_auto=True, cfg=None, account=True):
    import bcrypt as _bcrypt
    from app.models import EmailAccount, User, Workspace
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=f'set_{uuid.uuid4().hex[:8]}@test.com', name='S', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto,
                   ladder_auto_enabled=ladder_on, pipeline_config=cfg or {})
    db.session.add(ws); db.session.flush()
    if account:
        db.session.add(EmailAccount(user_id=user.id, workspace_id=ws.id,
                                    gmail_address='me@test.com', your_name='Me'))
    db.session.commit()
    return user, ws


def _sign_in(client, user):
    with client.session_transaction() as sess:
        sess['user_email'] = user.email


@pytest.fixture(autouse=True)
def _empty_queue(app, db):
    """The scheduler scans every workspace and committed rows outlive a test."""
    from app.models import FollowupContact, FollowupEvent
    FollowupEvent.query.delete()
    FollowupContact.query.delete()
    db.session.commit()


@pytest.fixture
def me(app, db, client):
    user, ws = _user(db)
    _sign_in(client, user)
    return user, ws


def _fc(db, me, rung='warm', **kw):
    from app.models import FollowupContact
    user, ws = me
    kw.setdefault('state', 'active')
    kw.setdefault('stage', 'completed_fu3')
    kw.setdefault('is_followup_enabled', False)
    kw.setdefault('load_count', {'warm': 1, 'hot': 2}.get(rung, 0))
    if 'next_followup_at' not in kw and rung in ladder.RUNGS and rung != 'client':
        kw['next_followup_at'] = _app._utcnow() + timedelta(days=2)
    kw.setdefault('touch_enabled', kw.get('next_followup_at') is not None)
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id, rung=rung,
                         contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', **kw)
    db.session.add(fc); db.session.commit()
    return fc


def _reload(db, obj):
    db.session.expire_all()
    return db.session.get(type(obj), obj.id)


def _put(client, **body):
    return client.put('/api/followups/pipeline-config', json=body)


def _cfg(db, ws):
    return _app._ladder_cfg(_reload(db, ws))


@pytest.fixture
def sent(monkeypatch):
    out = []
    monkeypatch.setattr(_app, 'send_followup_email',
                        lambda fu, tpl, cfg, uid=None: (out.append(fu['contact_email']), (True, None))[1])
    return out


# ── the config: defaults, overrides, clamping ───────────────────────────────

def test_defaults_apply_when_nothing_is_saved(app, db, me):
    assert _cfg(db, me[1])['budget_no_load'] == 3
    assert _app._ladder_cfg(None) == ladder.LADDER_DEFAULTS


def test_saved_values_override_defaults(app, db, client, me):
    assert _put(client, ladder={'budget_no_load': 2}).status_code == 200
    cfg = _cfg(db, me[1])
    assert cfg['budget_no_load'] == 2 and cfg['weekly_days'] == 7   # untouched keys keep defaults


def test_higher_rung_patience_can_be_switched_off_from_settings(app, db, client, me):
    assert ladder.budget_for('hot', _cfg(db, me[1])) == 5
    _put(client, ladder={'higher_rung_patience': False})
    assert ladder.budget_for('hot', _cfg(db, me[1])) == 3


def test_nonsense_values_are_clamped_not_stored(app, db, client, me):
    _put(client, ladder={'budget_no_load': -5, 'weekly_days': 9999, 'budget_engaged': 500,
                         'first_touch_days': 0})
    cfg = _cfg(db, me[1])
    assert cfg['budget_no_load'] == 1 and cfg['weekly_days'] == 365
    assert cfg['budget_engaged'] == 20 and cfg['first_touch_days'] == 1


def test_values_that_are_not_numbers_or_flags_are_dropped(app, db, client, me):
    _put(client, ladder={'budget_no_load': 'lots', 'weekly_days': True, 'second_touch_days': 2.5,
                         'hot_weekly': 'yes', 'higher_rung_patience': None,
                         'surprise_key': 1, 'budget_engaged': '4'})
    ws = _reload(db, me[1])
    stored = ws.pipeline_config.get('ladder', {})
    assert set(stored) <= set(ladder.LADDER_DEFAULTS)         # unknown keys are dropped
    assert 'surprise_key' not in stored
    cfg = _app._ladder_cfg(ws)
    assert cfg['budget_no_load'] == 3 and cfg['weekly_days'] == 7 and cfg['second_touch_days'] == 3
    assert cfg['hot_weekly'] is True and cfg['higher_rung_patience'] is True
    assert cfg['budget_engaged'] == 4                         # a numeric string is a number


def test_a_hand_edited_bad_value_never_reaches_the_engine(app, db, me):
    ws = me[1]
    ws.pipeline_config = {'ladder': {'budget_no_load': -5, 'weekly_days': 'x', 'surprise': 1}}
    db.session.commit()
    cfg = _cfg(db, ws)
    assert cfg['budget_no_load'] >= 1 and cfg['weekly_days'] == 7 and 'surprise' not in cfg


def test_config_comes_back_on_get_and_put_with_every_key(app, db, client, me):
    got = client.get('/api/followups/pipeline-config').get_json()['ladder']
    assert got == ladder.LADDER_DEFAULTS
    out = _put(client, ladder={'weekly_days': 10}).get_json()['ladder']
    assert out['weekly_days'] == 10 and set(out) == set(ladder.LADDER_DEFAULTS)


def test_ladder_settings_are_the_callers_own_workspace(app, db, client, me):
    other_user, other_ws = _user(db)
    _put(client, ladder={'budget_no_load': 7}, ladder_auto_enabled=True)
    assert _cfg(db, me[1])['budget_no_load'] == 7
    assert _cfg(db, other_ws)['budget_no_load'] == 3
    assert _reload(db, other_ws).ladder_auto_enabled is False


def test_existing_touch_hour_and_digest_settings_still_round_trip(app, db, client, me):
    out = _put(client, touch_hour=9, digest_enabled=False, drip_auto_enabled=False,
               ladder={'budget_no_load': 2}).get_json()
    assert out['touch_hour'] == 9 and out['digest_enabled'] is False
    assert out['drip_auto_enabled'] is False and 'cadence' not in out   # the stage cadence is retired
    # a ladder-only save leaves all of that alone
    again = _put(client, ladder={'weekly_days': 9}).get_json()
    assert again['touch_hour'] == 9 and again['digest_enabled'] is False
    assert again['drip_auto_enabled'] is False
    assert again['ladder']['budget_no_load'] == 2 and again['ladder']['weekly_days'] == 9
    # and a save without a ladder object leaves the ladder alone
    assert _put(client, touch_hour=10).get_json()['ladder']['budget_no_load'] == 2


# ── every engine read goes through the workspace's config ───────────────────

def test_the_scheduler_spends_the_workspace_budget(app, db, sent):
    user, ws = _user(db, ladder_on=True, cfg={'ladder': {'budget_no_load': 1}})
    fc = _fc(db, (user, ws), 'neutral', touch_attempt=0, next_followup_at=_app._utcnow() - timedelta(hours=2))
    assert _app._run_ladder_touches(_app._utcnow()) == 1
    fc = _reload(db, fc)
    assert fc.touch_attempt == 1 and fc.rung == 'dormant' and fc.exit_reason == 'exhausted'


def test_the_scheduler_dates_the_next_touch_from_the_workspace(app, db, sent):
    user, ws = _user(db, ladder_on=True, cfg={'ladder': {'first_touch_days': 2, 'second_touch_days': 9},
                                              'touch_hour': 12})
    fc = _fc(db, (user, ws), 'neutral', touch_attempt=0, next_followup_at=_app._utcnow() - timedelta(hours=2))
    now = _app._utcnow()
    assert _app._run_ladder_touches(now) == 1
    nxt = _reload(db, fc).next_followup_at
    assert now + timedelta(days=8) < nxt < now + timedelta(days=10)      # attempt 1 -> second_touch_days


def test_two_workspaces_in_one_run_each_use_their_own_budget(app, db, sent):
    a = _user(db, ladder_on=True, cfg={'ladder': {'budget_no_load': 1}})
    b = _user(db, ladder_on=True)
    past = _app._utcnow() - timedelta(hours=2)
    fa = _fc(db, a, 'cold', touch_attempt=0, next_followup_at=past)
    fb = _fc(db, b, 'cold', touch_attempt=0, next_followup_at=past)
    _app._run_ladder_touches(_app._utcnow())
    assert _reload(db, fa).rung == 'dormant'                  # one attempt allowed, spent
    assert _reload(db, fb).rung == 'cold'                     # three allowed, two left


def test_schedule_touch_uses_the_workspace_cadence(app, db, me):
    user, ws = me
    ws = _reload(db, ws)
    ws.pipeline_config = {'ladder': {'first_touch_days': 6}, 'touch_hour': 12}
    db.session.commit()
    fc = _fc(db, me, 'neutral', touch_attempt=0, next_followup_at=None, touch_enabled=False)
    now = _app._utcnow()
    assert _app._schedule_touch(fc, ws=None, force=True)          # ws looked up from the contact
    db.session.commit()
    nxt = _reload(db, fc).next_followup_at
    assert now + timedelta(days=5) < nxt < now + timedelta(days=7)


def test_would_send_respects_the_workspace_budget(app, db):
    user, ws = _user(db, ladder_on=True, cfg={'ladder': {'budget_no_load': 2}})
    one = _fc(db, (user, ws), 'cold', touch_attempt=1)
    spent = _fc(db, (user, ws), 'cold', touch_attempt=2)
    assert _app._ladder_would_send(one, ws) is True
    assert _app._ladder_would_send(spent, ws) is False


def test_the_row_budget_and_reason_use_the_workspace_config(app, db, client, me):
    _put(client, ladder={'budget_engaged': 8})
    fc = _fc(db, me, 'warm', touch_attempt=1)
    row = next(c for c in client.get('/api/followups').get_json()['contacts'] if c['id'] == fc.id)
    assert row['budget'] == 8 and row['next_touch_reason'] == 'touch 2 of 8'


def test_a_manual_move_dates_the_contact_from_the_workspace(app, db, client, me):
    _put(client, ladder={'first_touch_days': 5}, touch_hour=12)
    fc = _fc(db, me, 'warm', next_followup_at=None, touch_enabled=False, touch_attempt=0)
    before = _app._utcnow()
    resp = client.post('/api/followups/action', json={'id': fc.id, 'action': 'set-rung', 'rung': 'cold'})
    assert resp.status_code == 200
    nxt = _reload(db, fc).next_followup_at
    assert before + timedelta(days=4) < nxt < before + timedelta(days=6)


def test_a_load_reply_refills_from_the_workspace_config(app, db, me):
    from app.models import Reply
    user, ws = me
    ws = _reload(db, ws)
    ws.pipeline_config = {'ladder': {'first_touch_days': 4}, 'touch_hour': 12}
    db.session.commit()
    fc = _fc(db, me, 'cold', touch_attempt=2)
    reply = Reply(user_id=user.id, msg_id=uuid.uuid4().hex, thread_id='t1', from_email=fc.contact_email,
                  subject='Re: Laredo to Dallas', body='we have a load Laredo to Dallas',
                  triage_category='gave_info', received_at=_app._utcnow())
    db.session.add(reply); db.session.commit()
    now = _app._utcnow()
    _app._apply_reply_to_ladder(fc, reply, ws, now)
    fc = _reload(db, fc)
    assert fc.rung == 'warm' and fc.touch_attempt == 0
    assert now + timedelta(days=3) < fc.next_followup_at < now + timedelta(days=5)


def test_no_engine_path_still_reads_the_global_defaults():
    """The settings are only real if nothing bypasses them: the one allowed code mention of
    LADDER_DEFAULTS outside app/ladder.py is the base _ladder_cfg merges the saved values over.
    Scripts that date contacts (the migration) are engine paths too."""
    import glob
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = [os.path.join(root, 'app.py')] + sorted(glob.glob(os.path.join(root, 'scripts', '*.py')))
    assert len(files) > 1, 'scripts/ not found'
    uses = []
    for path in files:
        src = open(path, encoding='utf-8').read()
        uses += [(os.path.basename(path), l) for l in re.findall(r'^.*LADDER_DEFAULTS.*$', src, re.M)
                 if not l.lstrip().startswith('#')]
    assert len(uses) == 1 and uses[0][0] == 'app.py' and 'dict(_ladder.LADDER_DEFAULTS)' in uses[0][1], uses


def test_the_migration_dates_contacts_from_the_workspace_config(app, db):
    """scripts/migrate_to_ladder.py re-dates with the workspace's first_touch_days too."""
    import importlib.util
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location('migrate_to_ladder', os.path.join(root, 'scripts', 'migrate_to_ladder.py'))
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)
    user, ws = _user(db, cfg={'ladder': {'first_touch_days': 20}, 'touch_hour': 12})
    fc = _fc(db, (user, ws), 'neutral', touch_attempt=0, next_followup_at=None, touch_enabled=False)
    now = _app._utcnow()
    mig._apply_plan(fc, {'from_rung': 'neutral', 'rung': 'neutral', 'load_count': 0, 'new_loads': [],
                         'exit_reason': None, 'auto_paused': False, 'redate': True, 'attention': False,
                         'stop_list': False}, ws, now)
    assert fc.next_followup_at is not None and fc.next_followup_at > now + timedelta(days=19)


# ── the switch ───────────────────────────────────────────────────────────────

def test_the_switch_reads_off_by_default(app, db, client, me):
    got = client.get('/api/followups/pipeline-config').get_json()
    assert got['ladder_auto_enabled'] is False
    assert client.get('/api/followups/funnel').get_json()['ladder_auto_enabled'] is False
    assert client.get('/api/followups/funnel').get_json()['ladder'] == ladder.LADDER_DEFAULTS


def test_the_switch_round_trips_and_only_for_this_workspace(app, db, client, me):
    other_user, other_ws = _user(db)
    assert _put(client, ladder_auto_enabled=True).get_json()['ladder_auto_enabled'] is True
    assert _reload(db, me[1]).ladder_auto_enabled is True
    assert _reload(db, other_ws).ladder_auto_enabled is False
    assert _put(client, ladder_auto_enabled=False).get_json()['ladder_auto_enabled'] is False
    assert _reload(db, me[1]).ladder_auto_enabled is False


def test_the_switch_only_takes_a_real_boolean(app, db, client, me):
    _put(client, ladder_auto_enabled='true')
    assert _reload(db, me[1]).ladder_auto_enabled is False


def test_flipping_the_switch_sends_nothing_and_moves_no_date(app, db, client, me, sent):
    due = _app._utcnow() - timedelta(hours=3)
    fc = _fc(db, me, 'cold', touch_attempt=0, next_followup_at=due)
    assert _put(client, ladder_auto_enabled=True).status_code == 200
    assert sent == []
    fc = _reload(db, fc)
    assert fc.next_followup_at == due and fc.touch_attempt == 0


def test_saving_the_numbers_sends_nothing_and_moves_no_date(app, db, client, me, sent):
    due = _app._utcnow() - timedelta(hours=3)
    _put(client, ladder_auto_enabled=True)
    fc = _fc(db, me, 'cold', touch_attempt=0, next_followup_at=due)
    assert _put(client, ladder={'first_touch_days': 1, 'budget_no_load': 9}).status_code == 200
    assert sent == []
    assert _reload(db, fc).next_followup_at == due


def test_the_switch_is_still_behind_the_other_two_gates(app, db, client, me, sent):
    _put(client, ladder_auto_enabled=True, drip_auto_enabled=False)        # fu_auto off
    _fc(db, me, 'cold', touch_attempt=0, next_followup_at=_app._utcnow() - timedelta(hours=3))
    assert _app._run_ladder_touches(_app._utcnow()) == 0 and sent == []
    _put(client, drip_auto_enabled=True, auto_send_enabled=False)          # master off
    assert _app._run_ladder_touches(_app._utcnow()) == 0 and sent == []
    _put(client, auto_send_enabled=True)
    assert _app._run_ladder_touches(_app._utcnow()) == 1 and len(sent) == 1


def test_the_label_can_say_how_many_emails_turning_it_on_would_send(app, db, client, me):
    past = _app._utcnow() - timedelta(hours=3)
    _fc(db, me, 'cold', touch_attempt=0, next_followup_at=past)                              # overdue
    _fc(db, me, 'warm', touch_attempt=0, next_followup_at=_app._utcnow() + timedelta(hours=5))   # soon
    _fc(db, me, 'warm', touch_attempt=0, next_followup_at=_app._utcnow() + timedelta(days=3))    # later
    _fc(db, me, 'warm', touch_attempt=0, next_followup_at=past, auto_paused=True)            # paused
    _fc(db, me, 'cold', touch_attempt=3, next_followup_at=past)                              # budget spent
    _fc(db, me, 'client', next_followup_at=past)                                             # never emailed
    _fc(db, me, 'cold', touch_attempt=0, next_followup_at=past, touch_enabled=False)         # not on auto
    # with the switch OFF the figure is what turning it ON would do; the real preview stays 0
    assert client.get('/api/followups/pipeline-config').get_json()['ladder_due_24h'] == 2
    assert client.get('/api/followups/funnel').get_json()['ladder_due_24h'] == 2
    assert client.get('/api/followups/pipeline-config').get_json()['auto_send_preview']['touches'] == 0


def test_the_preview_follows_the_workspace_budget(app, db, client, me):
    _put(client, ladder={'budget_no_load': 1})
    _fc(db, me, 'cold', touch_attempt=1, next_followup_at=_app._utcnow() - timedelta(hours=3))
    assert client.get('/api/followups/pipeline-config').get_json()['ladder_due_24h'] == 0


# ── resuming a parked contact ────────────────────────────────────────────────

def test_resume_clears_the_pause_the_reason_and_the_failure_count_together(app, db, client, me):
    fc = _fc(db, me, 'warm', auto_paused=True, exit_reason='send_failed', send_fail_count=5,
             next_followup_at=None, attention_at=_app._utcnow())
    resp = client.post('/api/followups/action', json={'id': fc.id, 'action': 'resume-auto'})
    assert resp.status_code == 200
    fc = _reload(db, fc)
    assert (fc.auto_paused, fc.exit_reason, fc.send_fail_count) == (False, None, 0)
    assert fc.next_followup_at is not None
    # the next failure is a first failure, not an instant give-up
    assert _app._record_send_failure(fc, 'touch_sent', 'smtp down', _app._utcnow()) is False


def test_bulk_resume_clears_all_three_too(app, db, client, me):
    a = _fc(db, me, 'warm', auto_paused=True, exit_reason='send_failed', send_fail_count=5, next_followup_at=None)
    b = _fc(db, me, 'cold', auto_paused=True, exit_reason='send_failed', send_fail_count=4, next_followup_at=None)
    resp = client.post('/api/followups/bulk-action', json={'ids': [a.id, b.id], 'action': 'resume-auto'})
    assert resp.status_code == 200
    for fc in (a, b):
        fc = _reload(db, fc)
        assert (fc.auto_paused, fc.exit_reason, fc.send_fail_count) == (False, None, 0)


# ── the rung copy: readable and editable ────────────────────────────────────

RUNG_COPY = '/api/followups/ladder-copy'


def _own(db, user, level):
    from app.models import Template
    return Template.query.filter(Template.user_id == user.id, Template.type == 'followup',
                                 db.func.upper(Template.level) == level.upper()).all()


def test_copy_starts_as_the_code_defaults(app, db, client, me):
    got = client.get(RUNG_COPY).get_json()
    assert [r['rung'] for r in got['rungs']] == ['cold', 'neutral', 'warm', 'hot']
    for row in got['rungs']:
        assert row['bodies'] == list(_app.DEFAULT_RUNG_TEMPLATES[row['rung']])
        assert row['defaults'] == row['bodies'] and row['custom'] is False
        assert len(row['bodies']) >= ladder.budget_for(row['rung'], ladder.LADDER_DEFAULTS)
    assert got['variables']                                  # the owner is told what {origin} etc. mean


def test_reading_the_copy_writes_nothing(app, db, client, me):
    client.get(RUNG_COPY)
    assert _own(db, me[0], 'cold') == [] and _own(db, me[0], 'hot') == []


def test_an_edit_becomes_the_workspaces_own_template(app, db, client, me):
    user, ws = me
    bodies = ['Hi,\n\nOWNER ONE\n\n{name}', 'Hi,\n\nOWNER TWO\n\n{name}']
    resp = client.put(RUNG_COPY, json={'rungs': {'warm': bodies}})
    assert resp.status_code == 200
    rows = sorted(_own(db, user, 'warm'), key=lambda t: t.sort_order)
    assert [r.body for r in rows] == bodies
    assert all(r.type == 'followup' and r.is_active and r.workspace_id == ws.id for r in rows)
    warm = next(r for r in client.get(RUNG_COPY).get_json()['rungs'] if r['rung'] == 'warm')
    assert warm['bodies'] == bodies and warm['custom'] is True
    assert warm['defaults'] == list(_app.DEFAULT_RUNG_TEMPLATES['warm'])
    # and the scheduler's existing lookup now prefers it
    fc = _fc(db, me, 'warm', touch_attempt=0, load_count=1)
    assert 'OWNER ONE' in _app._template_for_rung(user.id, 'warm', fc)
    fc.touch_attempt = 1
    assert 'OWNER TWO' in _app._template_for_rung(user.id, 'warm', fc)


def test_editing_one_rung_leaves_the_others_on_the_code_default(app, db, client, me):
    client.put(RUNG_COPY, json={'rungs': {'warm': ['Hi,\n\nONLY WARM\n\n{name}']}})
    rungs = {r['rung']: r for r in client.get(RUNG_COPY).get_json()['rungs']}
    assert rungs['warm']['custom'] and not rungs['cold']['custom'] and not rungs['hot']['custom']
    assert _own(db, me[0], 'cold') == []


def test_resaving_text_that_equals_the_default_stores_nothing(app, db, client, me):
    # a workspace that never edits keeps following the code default
    default = list(_app.DEFAULT_RUNG_TEMPLATES['cold'])
    sent_back = [b.replace('\n', '\r\n') for b in default]            # a textarea posts CRLF
    resp = client.put(RUNG_COPY, json={'rungs': {'cold': sent_back}})
    assert resp.status_code == 200
    assert _own(db, me[0], 'cold') == []
    assert resp.get_json()['rungs'][0]['custom'] is False


def test_saving_the_defaults_back_removes_an_earlier_edit(app, db, client, me):
    client.put(RUNG_COPY, json={'rungs': {'hot': ['Hi,\n\nEDITED\n\n{name}']}})
    assert len(_own(db, me[0], 'hot')) == 1
    client.put(RUNG_COPY, json={'rungs': {'hot': list(_app.DEFAULT_RUNG_TEMPLATES['hot'])}})
    assert _own(db, me[0], 'hot') == []


def test_an_edit_replaces_the_previous_edit_it_does_not_pile_up(app, db, client, me):
    client.put(RUNG_COPY, json={'rungs': {'cold': ['one\n\n{name}', 'two\n\n{name}', 'three\n\n{name}']}})
    client.put(RUNG_COPY, json={'rungs': {'cold': ['only\n\n{name}']}})
    assert [r.body for r in _own(db, me[0], 'cold')] == ['only\n\n{name}']


def test_a_rung_with_no_text_is_refused_and_nothing_is_saved(app, db, client, me):
    resp = client.put(RUNG_COPY, json={'rungs': {'cold': ['   ', ''], 'warm': ['Hi\n\n{name}']}})
    assert resp.status_code == 400
    assert _own(db, me[0], 'cold') == [] and _own(db, me[0], 'warm') == []     # all or nothing


@pytest.mark.parametrize('rung', ['client', 'dormant', 'excluded', 'nonsense', ''])
def test_only_the_four_emailed_rungs_have_copy(app, db, client, me, rung):
    assert client.put(RUNG_COPY, json={'rungs': {rung: ['Hi']}}).status_code == 400


def test_the_shape_of_the_request_is_checked(app, db, client, me):
    assert client.put(RUNG_COPY, json={'rungs': {'cold': 'not a list'}}).status_code == 400
    assert client.put(RUNG_COPY, json={'rungs': {'cold': [5]}}).status_code == 400
    assert client.put(RUNG_COPY, json={'rungs': {'cold': ['x'] * 11}}).status_code == 400
    assert client.put(RUNG_COPY, json={'rungs': {'cold': ['x' * 5001]}}).status_code == 400
    assert client.put(RUNG_COPY, json={}).status_code == 400
    assert client.put(RUNG_COPY, json={'rungs': []}).status_code == 400


# ── Adding, deleting and parking a rung's emails ─────────────────────────────
# The owner writes his own variants, and parks the ones he is not using rather than
# losing their wording. A parked email must stay visible to him and invisible to a broker.

def test_the_payload_says_which_emails_are_on_and_how_many_attempts_the_rung_has(app, db, client, me):
    got = client.get(RUNG_COPY).get_json()
    for row in got['rungs']:
        assert row['active'] == [True] * len(row['bodies'])
        assert row['attempts'] == ladder.budget_for(row['rung'], ladder.LADDER_DEFAULTS)
    assert got['max_bodies'] == _app._LADDER_COPY_MAX_BODIES


def test_an_email_can_be_switched_off_without_losing_its_text(app, db, client, me):
    user, _ = me
    sent = [{'body': 'Hi,\n\nONE\n\n{name}', 'active': True},
            {'body': 'Hi,\n\nTWO parked\n\n{name}', 'active': False},
            {'body': 'Hi,\n\nTHREE\n\n{name}', 'active': True}]
    assert client.put(RUNG_COPY, json={'rungs': {'warm': sent}}).status_code == 200
    rows = sorted(_own(db, user, 'warm'), key=lambda t: t.sort_order)
    assert [r.is_active for r in rows] == [True, False, True]
    warm = next(r for r in client.get(RUNG_COPY).get_json()['rungs'] if r['rung'] == 'warm')
    assert warm['active'] == [True, False, True]            # the owner still sees the parked one
    assert 'TWO parked' in warm['bodies'][1]


def test_a_parked_email_is_never_sent(app, db, client, me):
    user, _ = me
    client.put(RUNG_COPY, json={'rungs': {'warm': [
        {'body': 'Hi,\n\nLIVE ONE\n\n{name}', 'active': True},
        {'body': 'Hi,\n\nPARKED\n\n{name}', 'active': False},
        {'body': 'Hi,\n\nLIVE TWO\n\n{name}', 'active': True}]}})
    fc = _fc(db, me, 'warm', touch_attempt=0, load_count=1)
    seen = []
    for attempt in range(4):
        fc.touch_attempt = attempt
        seen.append(_app._template_for_rung(user.id, 'warm', fc))
    assert not any('PARKED' in (t or '') for t in seen)
    assert any('LIVE ONE' in (t or '') for t in seen) and any('LIVE TWO' in (t or '') for t in seen)


def test_a_rung_with_every_email_switched_off_is_refused(app, db, client, me):
    resp = client.put(RUNG_COPY, json={'rungs': {'cold': [
        {'body': 'Hi,\n\nOFF\n\n{name}', 'active': False}]}})
    assert resp.status_code == 400
    assert _own(db, me[0], 'cold') == []                    # all or nothing, as with blank text


def test_added_emails_beyond_the_defaults_are_stored_in_order(app, db, client, me):
    bodies = [f'Hi,\n\nMINE {i}\n\n{{name}}' for i in range(6)]
    assert client.put(RUNG_COPY, json={'rungs': {'warm': bodies}}).status_code == 200
    rows = sorted(_own(db, me[0], 'warm'), key=lambda t: t.sort_order)
    assert [r.body for r in rows] == bodies and [r.sort_order for r in rows] == list(range(6))


def test_the_built_in_text_with_one_email_parked_is_stored_not_skipped(app, db, client, me):
    # text equal to the default is normally stored as "follow the built-in", but a parked
    # email is a decision of the owner's and would be lost by that shortcut
    default = list(_app.DEFAULT_RUNG_TEMPLATES['cold'])
    sent = [{'body': b, 'active': i != 1} for i, b in enumerate(default)]
    assert client.put(RUNG_COPY, json={'rungs': {'cold': sent}}).status_code == 200
    rows = sorted(_own(db, me[0], 'cold'), key=lambda t: t.sort_order)
    assert [r.is_active for r in rows] == [True, False, True]


def test_a_plain_list_of_strings_still_means_every_email_is_on(app, db, client, me):
    assert client.put(RUNG_COPY, json={'rungs': {'hot': ['Hi,\n\nPLAIN\n\n{name}']}}).status_code == 200
    assert [r.is_active for r in _own(db, me[0], 'hot')] == [True]


def test_a_malformed_email_entry_is_refused(app, db, client, me):
    for bad in ([{'active': True}], [{'body': 7}], [None], [['x']]):
        assert client.put(RUNG_COPY, json={'rungs': {'cold': bad}}).status_code == 400
    assert _own(db, me[0], 'cold') == []


def test_copy_is_never_shared_between_users(app, db, client, me):
    other_user, other_ws = _user(db)
    client.put(RUNG_COPY, json={'rungs': {'warm': ['MINE ONLY\n\n{name}']}})
    assert _own(db, other_user, 'warm') == []
    other_fc = _fc(db, (other_user, other_ws), 'warm', touch_attempt=0, load_count=1)
    assert 'MINE ONLY' not in (_app._template_for_rung(other_user.id, 'warm', other_fc) or '')
    # saving the defaults back must not delete the other user's edit either
    other_client = app.test_client()
    _sign_in(other_client, other_user)
    other_client.put(RUNG_COPY, json={'rungs': {'warm': ['THEIRS\n\n{name}']}})
    client.put(RUNG_COPY, json={'rungs': {'warm': list(_app.DEFAULT_RUNG_TEMPLATES['warm'])}})
    assert [r.body for r in _own(db, other_user, 'warm')] == ['THEIRS\n\n{name}']


def test_the_general_pool_and_stage_templates_are_untouched_by_a_rung_save(app, db, client, me):
    from app.models import Template
    user, ws = me
    db.session.add(Template(user_id=user.id, type='followup', level='General', name='G', body='GENERAL'))
    db.session.add(Template(user_id=user.id, type='followup', level='FU2', name='FU2', body='STAGE'))
    db.session.commit()
    client.put(RUNG_COPY, json={'rungs': {'cold': ['mine\n\n{name}']}})
    left = {t.level: t.body for t in Template.query.filter_by(user_id=user.id).all()}
    assert left['General'] == 'GENERAL' and left['FU2'] == 'STAGE'


def test_the_copy_endpoints_need_a_login(app, db):
    anon = app.test_client()
    assert anon.get(RUNG_COPY).status_code in (401, 302)
    assert anon.put(RUNG_COPY, json={'rungs': {'cold': ['x']}}).status_code in (401, 302)


# ── the page ─────────────────────────────────────────────────────────────────

def _html():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(root, 'templates', 'index.html'), encoding='utf-8').read()


def test_the_follow_up_page_carries_the_switch_not_only_settings():
    html = _html()
    funnel = html[html.index('id="fuFunnelTab"'):html.index('id="fuLadderTitle"')]
    assert 'id="fuLadderSwitch"' in funnel
    assert 'ladder_auto_enabled' in html and 'ladder-copy' in html


def test_settings_carry_the_knobs_and_the_copy_editor():
    html = _html()
    for el in ('plLadderAuto', 'plLdFirst', 'plLdSecond', 'plLdWeekly', 'plLdBudgetNo',
               'plLdBudgetEng', 'plLdCap', 'plLdPatience', 'plLdHotWeekly', 'ladderCopyEditor',
               'ladderCopyNote', 'ladderKnobNote'):
        assert f'id="{el}"' in html, el


# ── the daily cap ────────────────────────────────────────────────────────────

def _due(db, me, n, rung='cold', **kw):
    """n overdue contacts, oldest first, returned in that order."""
    out = []
    for i in range(n):
        out.append(_fc(db, me, rung, touch_attempt=0,
                       next_followup_at=_app._utcnow() - timedelta(hours=10 + n - i), **kw))
    return out


def test_the_cap_ships_at_25_and_is_a_setting(app, db, client, me):
    assert ladder.LADDER_DEFAULTS['daily_cap'] == 25 and _cfg(db, me[1])['daily_cap'] == 25
    _put(client, ladder={'daily_cap': 10})
    assert _cfg(db, me[1])['daily_cap'] == 10
    _put(client, ladder={'daily_cap': 0})
    assert _cfg(db, me[1])['daily_cap'] == 1
    _put(client, ladder={'daily_cap': 99999})
    assert _cfg(db, me[1])['daily_cap'] == 500


def test_a_tick_sends_no_more_than_the_cap_oldest_first(app, db, sent):
    me = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 2}})
    fcs = _due(db, me, 5)
    assert _app._run_ladder_touches(_app._utcnow()) == 2
    assert sent == [fcs[0].contact_email, fcs[1].contact_email]
    for fc in fcs[2:]:                                    # capped: nothing spent, nobody flagged
        fc = _reload(db, fc)
        assert fc.touch_attempt == 0 and fc.attention_at is None and fc.rung == 'cold'
        assert fc.next_followup_at < _app._utcnow() and fc.auto_paused is False
    for fc in fcs[:2]:                                    # sent: re-dated from the real send
        assert _reload(db, fc).next_followup_at > _app._utcnow()


def test_the_cap_holds_across_ticks_and_restarts_until_local_midnight(app, db, sent):
    me = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 2}})
    fcs = _due(db, me, 5)
    assert _app._run_ladder_touches(_app._utcnow()) == 2
    # a second run (a new tick, or a restarted process: nothing is kept in memory) sends nothing
    assert _app._run_ladder_touches(_app._utcnow()) == 0 and len(sent) == 2
    # yesterday's sends do not count: move them before the owner's local midnight
    from app.models import FollowupEvent
    midnight = _app._local_day_start(_app._ws_tz(_reload(db, me[1])))
    for ev in FollowupEvent.query.filter_by(event_type='touch_sent'):
        ev.event_at = midnight - timedelta(hours=1)
    db.session.commit()
    assert _app._run_ladder_touches(_app._utcnow()) == 2 and len(sent) == 4
    assert sent[2:] == [fcs[2].contact_email, fcs[3].contact_email]       # the backlog drains in order


def test_the_cap_is_per_workspace(app, db, sent):
    a = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 1}})
    b = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 3}})
    _due(db, a, 3)
    _due(db, b, 4)
    assert _app._run_ladder_touches(_app._utcnow()) == 4         # 1 for a, 3 for b


def test_a_failed_send_does_not_use_up_the_cap(app, db, monkeypatch):
    monkeypatch.setattr(_app, 'send_followup_email', lambda fu, tpl, cfg, uid=None: (False, 'smtp down'))
    me = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 1}})
    _due(db, me, 2)
    _app._run_ladder_touches(_app._utcnow())
    assert _app._ladder_sent_today(_reload(db, me[1])) == 0


def test_a_capped_tick_still_parks_a_contact_whose_attempts_are_spent(app, db, sent):
    me = _user(db, ladder_on=True, cfg={'ladder': {'daily_cap': 1}})
    fcs = _due(db, me, 2)
    spent = _fc(db, me, 'cold', touch_attempt=3, next_followup_at=_app._utcnow() - timedelta(hours=1))
    _app._run_ladder_touches(_app._utcnow())
    assert _reload(db, spent).rung == 'dormant'                  # parked by the exhaust rule, no email
    assert spent.contact_email not in sent


def test_the_label_reports_the_cap_and_the_days_the_backlog_takes(app, db, client, me):
    _put(client, ladder={'daily_cap': 5})
    _due(db, me, 12)
    got = client.get('/api/followups/pipeline-config').get_json()
    assert (got['ladder_due_total'], got['ladder_due_24h'], got['ladder_drain_days']) == (12, 5, 3)
    fun = client.get('/api/followups/funnel').get_json()
    assert (fun['ladder_due_total'], fun['ladder_due_24h'], fun['ladder_drain_days']) == (12, 5, 3)


def test_the_label_counts_what_is_left_of_today_and_a_small_set_is_one_day(app, db, client, me, sent):
    _put(client, ladder={'daily_cap': 5}, ladder_auto_enabled=True)
    _due(db, me, 3)
    assert _app._run_ladder_touches(_app._utcnow()) == 3
    _due(db, me, 4)                                              # 2 of today's 5 are left
    got = client.get('/api/followups/pipeline-config').get_json()
    assert (got['ladder_due_total'], got['ladder_due_24h'], got['ladder_drain_days']) == (4, 2, 2)
    assert client.get('/api/followups/pipeline-config').get_json()['ladder_due_total'] == 4


def test_the_label_for_nobody_due_and_for_a_set_that_fits(app, db, client, me):
    got = client.get('/api/followups/pipeline-config').get_json()
    assert (got['ladder_due_total'], got['ladder_due_24h'], got['ladder_drain_days']) == (0, 0, 0)
    _due(db, me, 3)
    got = client.get('/api/followups/pipeline-config').get_json()
    assert (got['ladder_due_total'], got['ladder_due_24h'], got['ladder_drain_days']) == (3, 3, 1)


# ── the same numbers sent again move nothing ────────────────────────────────

def test_a_save_never_redates_anyone_and_the_retired_cadence_is_ignored(app, db, client, me):
    stage = str(_reload(db, me[1]).get_stages()[0]['id'])
    sentinel = _app._utcnow() + timedelta(days=40)
    fc = _fc(db, me, 'cold', touch_attempt=0, pipeline_stage=int(stage), next_followup_at=sentinel)
    # what the Automation Save does, with a per-stage cadence the old UI used to send
    for cad in ({stage: {'days': 3, 'mode': 'manual'}}, {stage: {'days': 5, 'mode': 'manual'}}):
        assert _put(client, cadence=cad, ladder_auto_enabled=True).status_code == 200
        assert _reload(db, fc).next_followup_at == sentinel


def test_the_engine_reads_need_a_workspace_argument(app, db, me):
    fc = _fc(db, me, 'warm')
    with pytest.raises(TypeError):
        _app._ladder_next_reason(fc)
    with pytest.raises(TypeError):
        _app._ladder_budget('warm')
