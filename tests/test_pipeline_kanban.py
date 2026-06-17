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
