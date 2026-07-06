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


# ── Classifier: real-world queue texts (user-reported misses) ────────────────

def test_we_dont_use_landstar_is_negative():
    res = _classify('', "Sorry Bogdon, we don't use Landstar -----Original Message----- From: x@y.com")
    assert res and res['category'] == 'negative'

def test_typographic_apostrophe_matches():
    res = _classify('', 'Sorry, we don’t use Landstar at all')
    assert res and res['category'] == 'negative'

def test_whats_your_mc_is_skippable_negative():
    """Per user workflow MC asks are skip-worthy: Ignore recommendation, no
    pipeline advance — they group under the Negative chip."""
    res = _classify('', "What's your MC? ##TSK_ID##1d4fd0fb## Truly Carrier Sales Representative")
    assert res and res['category'] == 'negative'
    assert res['filter_key'] == 'mc_request'

def test_bare_mc_question_is_skippable_negative():
    res = _classify('', 'MC? On Wed, Jun 17, 2026 at 12:35 PM <x@y.com> wrote: > Hello')
    assert res and res['category'] == 'negative'
    assert res['filter_key'] == 'mc_request'

def test_cant_work_with_your_mc_is_negative():
    res = _classify('', "Thanks for checking, but we can't work with your MC at this time. ##TSK_ID##x##")
    assert res and res['category'] == 'negative'

def test_not_at_this_time_is_negative():
    res = _classify('', 'Not at this time Boone Almquist [cid:image001]')
    assert res and res['category'] == 'negative'

def test_nothing_this_week_is_negative():
    res = _classify('', 'Nothing this week Best regards, Siri Carrion Logistics Coordinator')
    assert res and res['category'] == 'negative'

def test_lane_subject_with_generic_footage_is_gave_info():
    res = _classify('Re: Grinnell, IA to Galesville, WI, 6/18, 26 ft', '')
    assert res and res['category'] == 'gave_info'


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

def test_rate_with_comma_thousands_is_gave_info():
    # "$1,500" (comma after a single digit) must count as a quoted rate too
    res = _classify('', 'We can do it for $1,500 PU Friday DEL Monday')
    assert res and res['category'] == 'gave_info'

def test_small_dollar_amount_is_not_a_rate_signal():
    res = _classify('', 'a $5 fee applies')
    assert res is None

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


def _enable_auto(db, ws):
    """Default modes are suggest (except auto_reply) — auto-action tests opt in."""
    cfg = dict(ws.pipeline_config or {})
    cfg['triage_modes'] = {c: 'auto' for c in
                           ('negative', 'gave_info', 'rate_request', 'auto_reply')}
    ws.pipeline_config = cfg
    db.session.commit()


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
    _enable_auto(db, ws)
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
    _enable_auto(db, ws)
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

def test_no_advance_when_filter_advance_disabled(app, db):
    """auto_advance_to=None on the filter means "don't advance" — the auto path
    must respect it exactly like the manual tag path does."""
    from app.models import FollowupContact, PIPELINE_DEFAULT_REPLY_FILTERS
    user, ws = _make_user_ws(db)
    filters = [dict(f) for f in PIPELINE_DEFAULT_REPLY_FILTERS]
    for f in filters:
        if f['key'] in ('gave_info', 'rate_request'):
            f['auto_advance_to'] = None
    ws.pipeline_config = {'reply_filters': filters}
    db.session.commit()
    _enable_auto(db, ws)
    r = _add_reply(db, user, 'Still available PU FCFS 0800 DEL 07/01 15,000 lbs RATE $5400')
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(r)
    assert out['auto_followup'] == 1
    assert r.status == 'follow_up'
    assert r.auto_advanced is False          # no forced fallback to stage 2
    fc = FollowupContact.query.filter_by(
        workspace_id=ws.id, contact_email=r.from_email.lower()).first()
    assert fc is not None and (fc.pipeline_stage or 1) == 1

def test_auto_actions_sync_crm_pipeline(app, db):
    """Auto-ignore/auto-followup must mirror stages into the PipelineContact CRM
    the same way the manual /api/replies/status path does."""
    from app.models import PipelineContact
    user, ws = _make_user_ws(db)
    _enable_auto(db, ws)
    neg = _add_reply(db, user, 'DNU. Do not contact us again.')
    info = _add_reply(db, user, 'Still available PU FCFS DEL 07/01 15,000 lbs RATE $5400')
    _app._auto_triage_new_replies(user.id, [neg.msg_id, info.msg_id])
    stages = {p.email: p.stage for p in PipelineContact.query.filter_by(user_id=user.id).all()}
    assert stages.get(neg.from_email.lower()) == 'lost'
    assert stages.get(info.from_email.lower()) == 'interested'

def test_default_suggest_leaves_reply_in_queue_with_category(app, db):
    """Out of the box (no stored modes): detected replies stay in New with a
    category so the chips/bulk workflow sees them; only OOO noise is auto'd."""
    user, ws = _make_user_ws(db)
    r = _add_reply(db, user, "What's your rate on this lane?")
    ooo = _add_reply(db, user, 'Automatic reply: out of office until Monday')
    out = _app._auto_triage_new_replies(user.id, [r.msg_id, ooo.msg_id])
    db.session.refresh(r); db.session.refresh(ooo)
    assert r.status == 'new' and r.triage_category == 'rate_request'
    assert out['detected'] == {'rate_request': 1}
    assert out['auto_followup'] == 0
    assert ooo.status == 'not_interested' and out['auto_ignored'] == 1

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
    _enable_auto(db, ws)
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

def test_bulk_followup_creates_contacts_and_advances(app, db, client):
    """Bulk 'followup' on a category: status → follow_up, pipeline contact created,
    stage advanced to the filter's configured target, CRM stage 'interested'."""
    from app.models import FollowupContact, PipelineContact
    user, ws = _make_user_ws(db)
    _login(client, user)
    r1 = _add_reply(db, user, 'We can do it for $1,500 PU Friday DEL Monday')
    r2 = _add_reply(db, user, "What's your rate on this lane?")
    r1.triage_category = 'gave_info'
    r2.triage_category = 'rate_request'; r2.reply_filter_key = 'rate_request'
    db.session.commit()

    res = client.post('/api/replies/bulk-triage',
                      json={'category': 'gave_info', 'action': 'followup'})
    assert res.status_code == 200 and res.get_json()['count'] == 1
    res = client.post('/api/replies/bulk-triage',
                      json={'category': 'rate_request', 'action': 'followup'})
    assert res.status_code == 200 and res.get_json()['count'] == 1

    for r in (r1, r2):
        db.session.refresh(r)
        assert r.status == 'follow_up'
        fc = FollowupContact.query.filter_by(
            workspace_id=ws.id, contact_email=r.from_email.lower()).first()
        assert fc is not None and fc.pipeline_stage == 2   # both built-ins target stage 2
    assert r1.reply_filter_key == 'gave_info'              # backfilled from category
    stages = {p.email: p.stage for p in PipelineContact.query.filter_by(user_id=user.id).all()}
    assert stages.get(r1.from_email.lower()) == 'interested'

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
    _enable_auto(db, ws)
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

def test_auto_processed_endpoint_lists_recent(app, db, client):
    user, ws = _make_user_ws(db)
    _enable_auto(db, ws)
    _login(client, user)
    r = _add_reply(db, user, 'DNU')
    _app._auto_triage_new_replies(user.id, [r.msg_id])
    res = client.get('/api/replies/auto-processed')
    assert res.status_code == 200
    data = res.get_json()
    assert data['count'] >= 1
    item = next(i for i in data['items'] if i['msg_id'] == r.msg_id)
    assert item['category'] == 'negative' and item['action'] == 'ignored'

def test_pipeline_config_exposes_triage_modes(app, db, client):
    user, _ = _make_user_ws(db)
    _login(client, user)
    res = client.get('/api/followups/pipeline-config')
    assert res.status_code == 200
    modes = res.get_json()['triage_modes']
    assert modes == {'negative': 'suggest', 'gave_info': 'suggest',
                     'rate_request': 'suggest', 'auto_reply': 'auto'}

    res = client.put('/api/followups/pipeline-config',
                     json={'triage_modes': {'negative': 'auto', 'bogus': 'auto',
                                            'gave_info': 'bad-value'}})
    assert res.status_code == 200
    modes = res.get_json()['triage_modes']
    assert modes['negative'] == 'auto'
    assert modes['gave_info'] == 'suggest'   # invalid value ignored
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
