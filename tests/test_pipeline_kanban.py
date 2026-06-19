"""Kanban / pipeline view (shared data with the Follow-up table).

Covers: pipeline_stage moves (single + bulk), validation, config endpoint,
transition stats, and the per-user view-mode preference.
"""
import sys
import uuid

_app = sys.modules['_dat_mailer_app']


def _make_user_and_login(db, client):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'kanban_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Tester', password=pw, role='user')
    db.session.add(user)
    db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws)
    db.session.commit()
    with client.session_transaction() as sess:
        sess['user_email'] = email
        sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _add_contacts(db, user, ws, n=3):
    from app.models import FollowupContact
    ids = []
    for i in range(n):
        fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                             contact_email=f'c{i}_{uuid.uuid4().hex[:6]}@x.com',
                             state='active', stage='fu1_scheduled')
        db.session.add(fc)
        db.session.flush()
        ids.append(fc.id)
    db.session.commit()
    return ids


def test_pipeline_config_returns_defaults(app, db, client):
    _make_user_and_login(db, client)
    r = client.get('/api/followups/pipeline-config')
    assert r.status_code == 200
    data = r.get_json()
    assert len(data['stages']) == 5
    assert data['stages'][0]['name'] == 'Follow Pending'
    assert data['view_mode'] == 'table'          # default
    assert any(f['key'] == 'can_use' for f in data['reply_filters'])


def test_contacts_default_to_stage_1(app, db, client):
    user, ws = _make_user_and_login(db, client)
    _add_contacts(db, user, ws, 1)
    r = client.get('/api/followups')
    assert r.status_code == 200
    assert r.get_json()['contacts'][0]['pipeline_stage'] == 1


def test_set_pipeline_stage_single_and_validation(app, db, client):
    from app.models import FollowupContact
    user, ws = _make_user_and_login(db, client)
    cid = _add_contacts(db, user, ws, 1)[0]

    # valid move
    r = client.post('/api/followups/action',
                    json={'id': cid, 'action': 'set-pipeline-stage',
                          'pipeline_stage': 3, '_csrf': 'test-csrf-token'})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['contact']['pipeline_stage'] == 3
    db.session.expire_all()
    assert db.session.get(FollowupContact, cid).pipeline_stage == 3

    # out-of-range rejected
    r = client.post('/api/followups/action',
                    json={'id': cid, 'action': 'set-pipeline-stage',
                          'pipeline_stage': 99, '_csrf': 'test-csrf-token'})
    assert r.status_code == 400


def test_bulk_set_pipeline_stage_and_stats(app, db, client):
    user, ws = _make_user_and_login(db, client)
    ids = _add_contacts(db, user, ws, 3)

    r = client.post('/api/followups/bulk-action',
                    json={'ids': ids, 'action': 'set-pipeline-stage',
                          'pipeline_stage': 2, '_csrf': 'test-csrf-token'})
    assert r.status_code == 200
    assert r.get_json()['sent'] == 3

    r = client.get('/api/followups/pipeline-stats')
    stats = r.get_json()
    assert stats['total'] == 3
    assert stats['by_stage']['2'] == 3          # JSON keys are strings
    # each contact logged a 1->2 transition
    assert stats['transitions'].get('1_to_2') == 3


def test_put_pipeline_config_customizes_and_validates(app, db, client):
    user, ws = _make_user_and_login(db, client)
    # a contact parked in stage 5, which we are about to remove
    ids = _add_contacts(db, user, ws, 1)
    client.post('/api/followups/action',
                json={'id': ids[0], 'action': 'set-pipeline-stage',
                      'pipeline_stage': 5, '_csrf': 'test-csrf-token'})

    # save a 3-stage config (drops 4 & 5) + a filter with no explicit key
    r = client.put('/api/followups/pipeline-config', json={
        'stages': [{'id': 1, 'name': 'Lead', 'color': '#111'},
                   {'id': 2, 'name': 'Quoted', 'color': '#222'},
                   {'id': 3, 'name': 'Won', 'color': '#333'}],
        'reply_filters': [{'label': 'we can use you', 'auto_advance_to': 2}],
        '_csrf': 'test-csrf-token'})
    assert r.status_code == 200, r.get_json()
    cfg = r.get_json()
    assert [s['name'] for s in cfg['stages']] == ['Lead', 'Quoted', 'Won']
    assert cfg['reply_filters'][0]['key'] == 'we_can_use_you'   # slugged

    # contact that was in removed stage 5 got reassigned to first stage
    from app.models import FollowupContact
    db.session.expire_all()
    assert db.session.get(FollowupContact, ids[0]).pipeline_stage == 1

    # < 2 stages rejected
    r = client.put('/api/followups/pipeline-config',
                   json={'stages': [{'id': 1, 'name': 'Only'}], '_csrf': 'test-csrf-token'})
    assert r.status_code == 400


def test_reply_tag_auto_advances_forward_only(app, db, client):
    from app.models import Reply, FollowupContact
    user, ws = _make_user_and_login(db, client)
    cid = _add_contacts(db, user, ws, 1)[0]
    fc = db.session.get(FollowupContact, cid)
    email = fc.contact_email
    db.session.add(Reply(user_id=user.id, workspace_id=ws.id, msg_id='MX',
                         from_email=email, from_name='B', subject='re', status='new'))
    db.session.commit()

    # default 'can_use' filter advances to stage 2
    r = client.post('/api/replies/pipeline-tag',
                    json={'msg_id': 'MX', 'filter_key': 'can_use', '_csrf': 'test-csrf-token'})
    body = r.get_json()
    assert r.status_code == 200 and body['advanced'] is True and body['pipeline_stage'] == 2
    db.session.expire_all()
    assert db.session.get(FollowupContact, cid).pipeline_stage == 2
    assert db.session.get(Reply, Reply.query.filter_by(msg_id='MX').first().id).auto_advanced is True

    # re-tagging with the same (target 2) is a no-op forward-only
    r = client.post('/api/replies/pipeline-tag',
                    json={'msg_id': 'MX', 'filter_key': 'can_use', '_csrf': 'test-csrf-token'})
    assert r.get_json()['advanced'] is False

    # a filter with no auto_advance_to just tags, never moves
    r = client.post('/api/replies/pipeline-tag',
                    json={'msg_id': 'MX', 'filter_key': 'dnu', '_csrf': 'test-csrf-token'})
    assert r.get_json()['advanced'] is False
    db.session.expire_all()
    assert db.session.get(FollowupContact, cid).pipeline_stage == 2   # unchanged


def test_user_view_mode_preference_persists(app, db, client):
    _make_user_and_login(db, client)
    r = client.post('/api/user/preferences',
                    json={'followup_view_mode': 'kanban', '_csrf': 'test-csrf-token'})
    assert r.status_code == 200
    assert r.get_json()['followup_view_mode'] == 'kanban'
    # reflected in config
    assert client.get('/api/followups/pipeline-config').get_json()['view_mode'] == 'kanban'

    # invalid value is ignored (stays kanban)
    r = client.post('/api/user/preferences',
                    json={'followup_view_mode': 'bogus', '_csrf': 'test-csrf-token'})
    assert r.get_json()['followup_view_mode'] == 'kanban'


# ── Phase 1: custom reply filters (color / emoji / is_custom / keywords) ──────

def test_config_returns_filter_metadata_and_keywords(app, db, client):
    _make_user_and_login(db, client)
    data = client.get('/api/followups/pipeline-config').get_json()
    can_use = next(f for f in data['reply_filters'] if f['key'] == 'can_use')
    assert can_use['color'] == '#4c6ef5'
    assert can_use['emoji'] == '✅'
    assert can_use['is_custom'] is False
    # keyword sets are exposed for auto-detection
    assert 'filter_keywords' in data
    assert 'we can use you' in data['filter_keywords']['can_use']['keywords']


def test_put_persists_custom_filter_color_emoji_keywords(app, db, client):
    _make_user_and_login(db, client)
    r = client.put('/api/followups/pipeline-config', json={
        'reply_filters': [
            {'key': 'can_use', 'label': 'we can use you', 'color': '#123456',
             'emoji': '👍', 'auto_advance_to': 2},
            {'label': 'My Custom Filter', 'color': '#FF1493', 'emoji': '🔴',
             'keywords': ['Custom Phrase', 'my words']},
        ],
        '_csrf': 'test-csrf-token'})
    assert r.status_code == 200, r.get_json()
    cfg = r.get_json()

    # built-in edited: color/emoji saved, still is_custom False
    can_use = next(f for f in cfg['reply_filters'] if f['key'] == 'can_use')
    assert can_use['color'] == '#123456' and can_use['emoji'] == '👍'
    assert can_use['is_custom'] is False

    # custom filter slugged, marked custom, color/emoji kept
    custom = next(f for f in cfg['reply_filters'] if f['key'] == 'my_custom_filter')
    assert custom['is_custom'] is True
    assert custom['color'] == '#FF1493' and custom['emoji'] == '🔴'
    # keywords travelled with the filter and are lowercased
    assert cfg['filter_keywords']['my_custom_filter']['keywords'] == ['custom phrase', 'my words']

    # malformed color falls back rather than persisting garbage
    r = client.put('/api/followups/pipeline-config', json={
        'reply_filters': [{'key': 'dnu', 'label': 'DNU', 'color': 'red; drop'}],
        '_csrf': 'test-csrf-token'})
    dnu = next(f for f in r.get_json()['reply_filters'] if f['key'] == 'dnu')
    assert dnu['color'] == '#888888'


def test_builtin_filters_cannot_be_deleted(app, db, client):
    _make_user_and_login(db, client)
    # submit ONLY a custom filter — every built-in must be re-added by the server
    r = client.put('/api/followups/pipeline-config', json={
        'reply_filters': [{'label': 'Only Custom', 'color': '#00CED1'}],
        '_csrf': 'test-csrf-token'})
    keys = {f['key'] for f in r.get_json()['reply_filters']}
    from app.models import PIPELINE_BUILTIN_FILTER_KEYS
    assert PIPELINE_BUILTIN_FILTER_KEYS.issubset(keys)
    assert 'only_custom' in keys
