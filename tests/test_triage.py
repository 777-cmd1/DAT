"""Semi-automatic reply triage: classifier + ingest auto-actions + API.

Covers classify_reply_text() (categories, precedence, word-boundary matching,
structural gave_info signals), _auto_triage_new_replies() side effects
(auto-ignore, auto-followup + pipeline stage 2, suggest mode = no action),
and the bulk-triage / undo endpoints.
"""
import sys
import uuid

_app = sys.modules['_dat_mailer_app']

classify_reply_text = _app.classify_reply_text


def _default_cfg():
    from app.models import PIPELINE_DEFAULT_REPLY_FILTERS, PIPELINE_DEFAULT_FILTER_KEYWORDS
    filters = [dict(f) for f in PIPELINE_DEFAULT_REPLY_FILTERS]
    keywords = {k: dict(v) for k, v in PIPELINE_DEFAULT_FILTER_KEYWORDS.items()}
    return filters, keywords


def _classify(subject, body=''):
    filters, keywords = _default_cfg()
    return classify_reply_text(subject, body, filters, keywords)


# ── Classifier: negative ─────────────────────────────────────────────────────

def test_dnu_is_negative():
    res = _classify('', 'DNU this carrier please')
    assert res and res['category'] == 'negative'
    assert res['confidence'] >= 0.9

def test_no_landstar_is_negative():
    res = _classify('', 'Sorry, we can not use Landstar at the moment')
    assert res and res['category'] == 'negative'

def test_dont_contact_is_negative():
    res = _classify('', "Please don't contact me anymore, remove me from your list")
    assert res and res['category'] == 'negative'

def test_word_boundary_dnu_not_inside_words():
    # substring matching would fire on 'sandnut'; word-boundary must not
    res = _classify('', 'Sandnut Trucking has a load for you, call us')
    assert not res or res['category'] != 'negative'

def test_negative_beats_gave_info():
    # opt-out buried inside a load dump still wins
    res = _classify('', 'PU Laredo, TX DEL Dallas, TX $1500 15,000 lbs — but do not contact us again')
    assert res and res['category'] == 'negative'


# ── Classifier: auto-reply / OOO ─────────────────────────────────────────────

def test_out_of_office_subject():
    res = _classify('Automatic reply: RE: Load Laredo to SLC', 'I am out of office until Monday')
    assert res and res['category'] == 'auto_reply'

def test_no_longer_with_company():
    res = _classify('', 'John is no longer with the company, please contact dispatch')
    assert res and res['category'] == 'auto_reply'


# ── Classifier: rate request vs gave info ────────────────────────────────────

def test_rate_question_is_rate_request():
    res = _classify('', "What's your rate on this lane?")
    assert res and res['category'] == 'rate_request'

def test_rate_with_dollar_amount_is_gave_info():
    # they QUOTED a rate → info given, not a rate ask
    res = _classify('', 'RATE $5400 PU FCFS 0800 DEL 07/01 15,000 lbs')
    assert res and res['category'] == 'gave_info'

def test_gave_info_structural_load_dump():
    body = ('Still available PU FCFS 0800 - 1700 DEL 07/01 @ 0700 CONSUMER GOODS '
            '15,000 LBS RATE $5400 Let me know On Thu')
    res = _classify('', body)
    assert res and res['category'] == 'gave_info'
    assert res['confidence'] >= 0.7

def test_gave_info_lane_and_weight():
    res = _classify('', "Mentor, OH to Syracuse, UT 42500 lbs Hazmat 53' trl required delv Wed")
    assert res and res['category'] == 'gave_info'

def test_plain_conversational_reply_is_unknown():
    assert _classify('', 'Thanks, I will check and get back to you.') is None

def test_empty_text_is_none():
    assert _classify('', '') is None


# ── Ingest auto-actions ──────────────────────────────────────────────────────

def _make_user_ws(db):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'triage_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='T', password=pw, role='user')
    db.session.add(user)
    db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws)
    db.session.commit()
    return user, ws


def _add_reply(db, user, body, subject='', email=None, status='new'):
    from app.models import Reply
    r = Reply(user_id=user.id, msg_id=f'<{uuid.uuid4().hex}@t>',
              from_email=email or f'{uuid.uuid4().hex[:8]}@carrier.com',
              from_name='Carrier', subject=subject, body=body, status=status)
    db.session.add(r)
    db.session.commit()
    return r


def test_auto_ignore_negative(app, db):
    user, ws = _make_user_ws(db)
    r = _add_reply(db, user, 'DNU. Do not contact us again.')
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(r)
    assert out['auto_ignored'] == 1
    assert r.status == 'not_interested'
    assert r.auto_processed is True
    assert r.auto_action == 'ignored'
    assert r.triage_category == 'negative'

def test_auto_followup_gave_info_creates_contact_at_stage_2(app, db):
    from app.models import FollowupContact
    user, ws = _make_user_ws(db)
    r = _add_reply(db, user, 'Still available PU FCFS 0800 DEL 07/01 15,000 lbs RATE $5400')
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(r)
    assert out['auto_followup'] == 1
    assert r.status == 'follow_up'
    assert r.auto_processed is True and r.auto_action == 'followup'
    fc = FollowupContact.query.filter_by(
        workspace_id=ws.id, contact_email=r.from_email.lower()).first()
    assert fc is not None
    assert fc.pipeline_stage == 2          # "Got info (1st)"
    assert r.auto_advanced is True

def test_suggest_mode_classifies_but_does_not_act(app, db):
    user, ws = _make_user_ws(db)
    ws.pipeline_config = {'triage_modes': {'negative': 'suggest'}}
    db.session.commit()
    r = _add_reply(db, user, 'DNU. Do not contact us again.')
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(r)
    assert out['auto_ignored'] == 0
    assert r.status == 'new'
    assert r.triage_category == 'negative'   # still classified for the chips
    assert r.auto_processed is False

def test_inherited_suppressed_status_not_auto_actioned(app, db):
    user, ws = _make_user_ws(db)
    r = _add_reply(db, user, 'We have loads PU Laredo, TX DEL Dallas, TX $900', status='not_interested')
    _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(r)
    assert r.status == 'not_interested'      # unchanged
    assert r.auto_processed is False

def test_backfill_classifies_without_actions(app, db):
    user, ws = _make_user_ws(db)
    r = _add_reply(db, user, 'DNU please')
    n = _app._backfill_triage(user.id)
    db.session.refresh(r)
    assert n == 1
    assert r.triage_category == 'negative'
    assert r.status == 'new'                 # backfill never auto-actions
    assert r.classified_at is not None
    # second pass skips already-classified rows
    assert _app._backfill_triage(user.id) == 0


# ── API: bulk triage + undo ──────────────────────────────────────────────────

def _login(client, user):
    with client.session_transaction() as sess:
        sess['user_email'] = user.email
        sess['csrf_token'] = 'test-csrf-token'

def test_bulk_ignore_and_restore(app, db, client):
    user, ws = _make_user_ws(db)
    _login(client, user)
    r1 = _add_reply(db, user, 'x'); r2 = _add_reply(db, user, 'y')
    for r in (r1, r2):
        r.triage_category = 'negative'
    db.session.commit()

    res = client.post('/api/replies/bulk-triage',
                      json={'category': 'negative', 'action': 'ignore'})
    assert res.status_code == 200
    data = res.get_json()
    assert data['count'] == 2 and set(data['msg_ids']) == {r1.msg_id, r2.msg_id}
    db.session.refresh(r1)
    assert r1.status == 'not_interested'

    res = client.post('/api/replies/bulk-triage',
                      json={'msg_ids': data['msg_ids'], 'action': 'restore'})
    assert res.status_code == 200 and res.get_json()['count'] == 2
    db.session.refresh(r1); db.session.refresh(r2)
    assert r1.status == 'new' and r2.status == 'new'

def test_bulk_rejects_bad_input(app, db, client):
    user, _ = _make_user_ws(db)
    _login(client, user)
    assert client.post('/api/replies/bulk-triage', json={'action': 'nope'}).status_code == 400
    assert client.post('/api/replies/bulk-triage', json={'action': 'ignore'}).status_code == 400
    assert client.post('/api/replies/bulk-triage',
                       json={'action': 'ignore', 'category': 'bogus'}).status_code == 400

def test_undo_auto_removes_auto_created_contact(app, db, client):
    from app.models import FollowupContact
    user, ws = _make_user_ws(db)
    _login(client, user)
    r = _add_reply(db, user, 'Still available PU FCFS DEL 07/01 15,000 lbs RATE $5400')
    _app._auto_triage_new_replies(user.id, [r.msg_id])
    res = client.post('/api/replies/undo-auto', json={'msg_id': r.msg_id})
    assert res.status_code == 200
    assert res.get_json()['contact_removed'] is True
    db.session.refresh(r)
    assert r.status == 'new' and r.auto_processed is False
    assert FollowupContact.query.filter_by(
        workspace_id=ws.id, contact_email=r.from_email.lower()).first() is None

def test_pipeline_config_exposes_triage_modes(app, db, client):
    user, _ = _make_user_ws(db)
    _login(client, user)
    res = client.get('/api/followups/pipeline-config')
    assert res.status_code == 200
    modes = res.get_json()['triage_modes']
    assert modes == {'negative': 'auto', 'gave_info': 'auto',
                     'rate_request': 'auto', 'auto_reply': 'auto'}

    res = client.put('/api/followups/pipeline-config',
                     json={'triage_modes': {'negative': 'suggest', 'bogus': 'auto',
                                            'gave_info': 'bad-value'}})
    assert res.status_code == 200
    modes = res.get_json()['triage_modes']
    assert modes['negative'] == 'suggest'
    assert modes['gave_info'] == 'auto'      # invalid value ignored
    assert 'bogus' not in modes

def test_new_builtin_filters_appended_to_old_configs(app, db):
    """Workspaces that saved filters before this release must still get the
    rate_request / gave_info / auto_reply built-ins."""
    user, ws = _make_user_ws(db)
    ws.pipeline_config = {'reply_filters': [
        {'key': 'dnu', 'label': 'DNU'},
        {'key': 'my_custom', 'label': 'Custom thing'},
    ]}
    db.session.commit()
    keys = {f['key'] for f in ws.get_reply_filters()}
    assert {'dnu', 'my_custom', 'rate_request', 'gave_info', 'auto_reply'} <= keys
    # category backfilled from defaults on stored built-ins
    dnu = next(f for f in ws.get_reply_filters() if f['key'] == 'dnu')
    assert dnu['category'] == 'negative'
