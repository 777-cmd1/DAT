"""Package 5: Settings tabs — auto-send preview for the Automation banner and
tab-scoped saves of the pipeline config."""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _mk(db, client=None, fu_auto=True, cfg=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'tabs_{uuid.uuid4().hex[:8]}@test.com'
    user = User(email=email, name='T', role='user',
                password=_bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode())
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS', fu_auto_enabled=fu_auto, pipeline_config=cfg or {})
    db.session.add(ws); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
    return user, ws


def _fc(db, user, ws, in_hours=-1, **kw):
    from app.models import FollowupContact
    fields = dict(user_id=user.id, workspace_id=ws.id,
                  contact_email=f'{uuid.uuid4().hex[:8]}@carrier.com', state='active',
                  stage='fu1_scheduled', is_followup_enabled=True,
                  next_followup_at=_app._utcnow() + timedelta(hours=in_hours))
    fields.update(kw)
    fc = FollowupContact(**fields)
    db.session.add(fc); db.session.commit()
    return fc


_CADENCE = {'1': {'days': 3, 'mode': 'auto'}, '2': {'days': 3, 'mode': 'manual'}}


def test_preview_counts_each_auto_path_within_24h(app, db):
    user, ws = _mk(db, cfg={'cadence': _CADENCE})
    _fc(db, user, ws, in_hours=-5)                                   # overdue drip
    _fc(db, user, ws, in_hours=20, stage='fu3_scheduled')            # drip later today
    _fc(db, user, ws, in_hours=30)                                   # beyond 24h
    _fc(db, user, ws, state='paused')                                # not active
    _fc(db, user, ws, stage='completed_fu3')                         # drip finished
    _fc(db, user, ws, is_followup_enabled=False, scheduled_once=True, stage='completed_fu3')
    _fc(db, user, ws, is_followup_enabled=False, recurring_enabled=True, stage='completed_fu3')
    _fc(db, user, ws, in_hours=3, is_followup_enabled=False, touch_enabled=True,
        stage='completed_fu3', pipeline_stage=1)                     # auto touch
    _fc(db, user, ws, in_hours=3, is_followup_enabled=False, touch_enabled=True,
        stage='completed_fu3', pipeline_stage=2)                     # manual touch → not auto
    assert _app._auto_send_preview(ws) == {'drip': 2, 'touches': 1, 'scheduled': 2}


def test_preview_ignores_switch_positions_and_other_workspaces(app, db):
    user, ws = _mk(db, fu_auto=False, cfg={'auto_send_enabled': False})
    _fc(db, user, ws)
    other_user, other_ws = _mk(db)
    _fc(db, other_user, other_ws)
    _fc(db, other_user, other_ws)
    # counted "as if on" so the banner can update live while the user flips switches
    assert _app._auto_send_preview(ws) == {'drip': 1, 'touches': 0, 'scheduled': 0}
    assert _app._auto_send_preview(None) == {'drip': 0, 'touches': 0, 'scheduled': 0}


def test_pipeline_config_get_and_put_return_preview(app, db, client):
    user, ws = _mk(db, client)
    _fc(db, user, ws)
    got = client.get('/api/followups/pipeline-config').get_json()
    assert got['auto_send_preview'] == {'drip': 1, 'touches': 0, 'scheduled': 0}
    put = client.put('/api/followups/pipeline-config', json={'auto_send_enabled': False}).get_json()
    assert put['auto_send_enabled'] is False
    assert put['auto_send_preview']['drip'] == 1


def test_pipeline_tab_save_leaves_automation_untouched(app, db, client):
    user, ws = _mk(db, client, fu_auto=False,
                   cfg={'auto_send_enabled': False, 'digest_enabled': False, 'cadence': _CADENCE})
    stages = [{'id': s['id'], 'name': s['name'] + ' X', 'color': s['color']} for s in ws.get_stages()]
    res = client.put('/api/followups/pipeline-config', json={'stages': stages})
    assert res.status_code == 200
    db.session.refresh(ws)
    assert ws.fu_auto_enabled is False
    assert ws.pipeline_config['auto_send_enabled'] is False
    assert ws.pipeline_config['digest_enabled'] is False
    assert ws.get_cadence()['1']['mode'] == 'auto'
    assert all(s['name'].endswith(' X') for s in ws.get_stages())


def test_automation_tab_save_leaves_stages_untouched(app, db, client):
    user, ws = _mk(db, client, fu_auto=False)
    before = ws.get_stages()
    res = client.put('/api/followups/pipeline-config', json={
        'cadence': {'1': {'days': 4, 'mode': 'manual'}}, 'touch_hour': 9,
        'digest_enabled': True, 'drip_auto_enabled': True, 'auto_send_enabled': True})
    assert res.status_code == 200
    db.session.refresh(ws)
    assert ws.get_stages() == before
    assert ws.fu_auto_enabled is True
    assert ws.pipeline_config['touch_hour'] == 9
    assert ws.get_cadence()['1'] == {'days': 4, 'mode': 'manual'}
