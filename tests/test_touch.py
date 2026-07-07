"""Follow-up cadence engine (Phase 1): per-stage touch cadence, the
"no active contact without a next step" invariant, warm-reply attention flag,
Today-queue quick actions, and config plumbing."""
import sys
import uuid
from datetime import timedelta

_app = sys.modules['_dat_mailer_app']


def _mk(db, client=None):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'touch_{uuid.uuid4().hex[:8]}@test.com'
    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='T', password=pw, role='user')
    db.session.add(user); db.session.flush()
    ws = Workspace(owner_id=user.id, name='WS')
    db.session.add(ws); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
            sess['csrf_token'] = 'test-csrf-token'
    return user, ws


def _fc(db, user, ws, stage=2, drip=False, state='active'):
    from app.models import FollowupContact
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email=f'{uuid.uuid4().hex[:8]}@x.com',
                         state=state, stage='completed_fu3' if not drip else 'fu1_scheduled',
                         is_followup_enabled=drip, pipeline_stage=stage)
    db.session.add(fc); db.session.commit()
    return fc


# ── Cadence config ────────────────────────────────────────────────────────────

def test_cadence_defaults(app, db):
    _, ws = _mk(db)
    cad = ws.get_cadence()
    assert cad['2'] == {'days': 3, 'mode': 'manual'}
    assert cad['1']['mode'] == 'off' and cad['5']['mode'] == 'off'

def test_cadence_override_and_validation(app, db):
    _, ws = _mk(db)
    ws.pipeline_config = {'cadence': {
        '2': {'days': 2, 'mode': 'auto'},
        '3': {'days': 999, 'mode': 'manual'},   # clamped to 60
        '4': {'days': 5, 'mode': 'bogus'},      # ignored
    }}
    db.session.commit()
    cad = ws.get_cadence()
    assert cad['2'] == {'days': 2, 'mode': 'auto'}
    assert cad['3'] == {'days': 60, 'mode': 'manual'}
    assert cad['4'] == {'days': 7, 'mode': 'manual'}   # default kept


# ── _schedule_touch invariant ─────────────────────────────────────────────────

def test_schedule_touch_sets_next_for_warm_stage(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)
    assert _app._schedule_touch(fc, ws, force=True) is True
    assert fc.touch_enabled is True
    assert fc.next_followup_at is not None

def test_schedule_touch_off_stage_disables(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=5)          # Booked: off by default
    fc.touch_enabled = True
    assert _app._schedule_touch(fc, ws, force=True) is False
    assert fc.touch_enabled is False and fc.next_followup_at is None

def test_schedule_touch_skips_active_drip(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2, drip=True)
    assert _app._schedule_touch(fc, ws, force=True) is False
    assert fc.touch_enabled is False

def test_schedule_touch_no_churn_without_force(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)
    _app._schedule_touch(fc, ws, force=True)
    first = fc.next_followup_at
    assert _app._schedule_touch(fc, ws) is False     # already scheduled
    assert fc.next_followup_at == first


# ── Hooks: reply-stop, stage move, normalize sweep ────────────────────────────

def test_warm_reply_sets_attention_and_next_touch(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2, drip=True)
    _app._check_reply_stops_followup(fc.contact_email, user.id)
    db.session.commit()
    db.session.refresh(fc)
    assert fc.is_followup_enabled is False           # drip stopped
    assert fc.attention_at is not None               # 🔥 warm reply
    assert fc.touch_enabled is True                  # iron rule: next touch set
    assert fc.next_followup_at is not None

def test_cold_reply_no_attention(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=1, drip=True)
    _app._check_reply_stops_followup(fc.contact_email, user.id)
    db.session.commit(); db.session.refresh(fc)
    assert fc.attention_at is None
    assert fc.is_followup_enabled is False

def test_stage_move_reschedules_cadence(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)
    _app._schedule_touch(fc, ws, force=True)
    ok, err = _app._apply_pipeline_stage(fc, 3, actor_user_id=user.id)
    assert ok
    db.session.commit(); db.session.refresh(fc)
    # stage 3 default cadence = 7d → next pushed further out than stage 2's 3d
    assert fc.touch_enabled is True
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=5)

def test_normalize_sweep_fills_missing_touch(app, db):
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)          # no drip, no touch scheduled
    changed = _app._normalize_followup_contact(fc)
    assert changed is True
    assert fc.touch_enabled is True and fc.next_followup_at is not None


# ── Today-queue quick actions ─────────────────────────────────────────────────

def test_touch_snooze_and_skip(app, db, client):
    user, ws = _mk(db, client)
    fc = _fc(db, user, ws, stage=2)
    fc.attention_at = _app._utcnow()
    db.session.commit()

    res = client.post('/api/followups/touch', json={'id': fc.id, 'action': 'snooze', 'days': 3})
    assert res.status_code == 200
    db.session.refresh(fc)
    assert fc.attention_at is None
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=2)

    res = client.post('/api/followups/touch', json={'id': fc.id, 'action': 'skip'})
    assert res.status_code == 200
    db.session.refresh(fc)
    assert fc.touch_enabled is True          # rescheduled by stage cadence

    assert client.post('/api/followups/touch',
                       json={'id': fc.id, 'action': 'bogus'}).status_code == 400


# ── Counters include cadence touches ──────────────────────────────────────────

def test_overdue_counts_touch_due(app, db, client):
    user, ws = _mk(db, client)
    fc = _fc(db, user, ws, stage=2)
    fc.touch_enabled = True
    fc.next_followup_at = _app._utcnow() - timedelta(hours=2)
    db.session.commit()
    data = client.get('/api/followups').get_json()
    assert data['counts']['overdue'] >= 1
    assert data['counts']['attention'] == 0
    ids = {c['id'] for c in client.get('/api/followups?filter=overdue').get_json()['contacts']}
    assert fc.id in ids

def test_overdue_counts_any_dated_active_contact(app, db, client):
    """A date is a commitment even when both auto-engines are off (e.g. triage
    created the contact while workspace auto-FU was disabled)."""
    from app.models import FollowupContact
    user, ws = _mk(db, client)
    fc = FollowupContact(user_id=user.id, workspace_id=ws.id,
                         contact_email='dated@x.com', state='active',
                         stage='fu1_scheduled', is_followup_enabled=False,
                         pipeline_stage=1, touch_enabled=False,
                         next_followup_at=_app._utcnow() - timedelta(days=1))
    db.session.add(fc); db.session.commit()
    data = client.get('/api/followups').get_json()
    assert data['counts']['overdue'] >= 1
    ids = {c['id'] for c in client.get('/api/followups?filter=overdue').get_json()['contacts']}
    assert fc.id in ids


# ── Config endpoint round-trip + sweep on save ────────────────────────────────

def test_put_cadence_roundtrip_and_sweep(app, db, client):
    user, ws = _mk(db, client)
    fc = _fc(db, user, ws, stage=2)
    res = client.put('/api/followups/pipeline-config',
                     json={'cadence': {'2': {'days': 2, 'mode': 'auto'},
                                       '99': {'days': 3, 'mode': 'manual'},   # unknown stage ignored
                                       '3': {'days': 4, 'mode': 'nope'}}})    # bad mode ignored
    assert res.status_code == 200
    cad = res.get_json()['cadence']
    assert cad['2'] == {'days': 2, 'mode': 'auto'}
    assert '99' not in cad
    assert cad['3'] == {'days': 7, 'mode': 'manual'}
    db.session.refresh(fc)
    assert fc.touch_enabled is True and fc.next_followup_at is not None   # sweep ran


# ── Dashboard endpoint ────────────────────────────────────────────────────────

def test_dashboard_endpoint_shape(app, db, client):
    user, ws = _mk(db, client)
    fc = _fc(db, user, ws, stage=2)
    fc.attention_at = _app._utcnow()
    fc.next_followup_at = _app._utcnow()
    db.session.commit()
    data = client.get('/api/dashboard').get_json()
    assert data['touches']['due_today'] >= 1
    assert data['attention'] == 1
    assert set(data['funnel'].keys()) == {'7', '30'}
    assert {'sent', 'replied', 'got_info', 'repeat', 'booked'} <= set(data['funnel']['30'].keys())
    assert len(data['activity']) == 14
    assert 'no_next_step' in data['health'] and 'rotting' in data['health']


# ── OOO auto-pause (Wave A) ───────────────────────────────────────────────────

def test_ooo_reply_pushes_next_touch_a_week(app, db):
    from app.models import Reply
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)
    fc.next_followup_at = _app._utcnow() + timedelta(days=1)
    fc.attention_at = _app._utcnow()
    db.session.commit()
    r = Reply(user_id=user.id, msg_id=f'<ooo-{uuid.uuid4().hex}@t>',
              from_email=fc.contact_email, from_name='X',
              subject='Automatic reply: RE: load', body='Out of office until Monday',
              status='new')
    db.session.add(r); db.session.commit()
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(fc)
    assert out.get('ooo_paused') == 1
    assert fc.next_followup_at > _app._utcnow() + timedelta(days=6)
    assert fc.attention_at is None           # a bounce needs no answer

def test_ooo_never_pulls_touch_closer(app, db):
    from app.models import Reply
    user, ws = _mk(db)
    fc = _fc(db, user, ws, stage=2)
    far = _app._utcnow() + timedelta(days=21)
    fc.next_followup_at = far; db.session.commit()
    r = Reply(user_id=user.id, msg_id=f'<ooo2-{uuid.uuid4().hex}@t>',
              from_email=fc.contact_email, subject='Automatic reply', body='on vacation',
              status='new')
    db.session.add(r); db.session.commit()
    _app._auto_triage_new_replies(user.id, [r.msg_id])
    db.session.refresh(fc)
    assert fc.next_followup_at == far        # kept, not pulled closer

def test_ooo_from_unknown_sender_is_noop(app, db):
    from app.models import Reply
    user, ws = _mk(db)
    r = Reply(user_id=user.id, msg_id=f'<ooo3-{uuid.uuid4().hex}@t>',
              from_email='stranger@x.com', subject='Automatic reply', body='out of office',
              status='new')
    db.session.add(r); db.session.commit()
    out = _app._auto_triage_new_replies(user.id, [r.msg_id])
    assert out.get('ooo_paused', 0) == 0


# ── Contact timeline (Wave C) ─────────────────────────────────────────────────

def test_timeline_merges_sends_replies_events(app, db, client):
    from app.models import Reply, Send
    user, ws = _mk(db, client)
    fc = _fc(db, user, ws, stage=2)
    fc.notes = 'good guy, has reefers'
    db.session.add(Send(user_id=user.id, workspace_id=ws.id, recipient_email=fc.contact_email,
                        origin='Laredo, TX', destination='SLC, UT', status='sent'))
    db.session.add(Reply(user_id=user.id, msg_id=f'<tl-{uuid.uuid4().hex}@t>',
                         from_email=fc.contact_email, body='Still available $1,500',
                         status='follow_up', triage_category='gave_info'))
    db.session.commit()
    _app._apply_pipeline_stage(fc, 3, actor_user_id=user.id)   # generates an event
    db.session.commit()
    data = client.get(f'/api/followups/timeline?id={fc.id}').get_json()
    kinds = {i['kind'] for i in data['items']}
    assert {'send', 'reply', 'event'} <= kinds
    assert data['notes'] == 'good guy, has reefers'
    ev = next(i for i in data['items'] if i['title'] == 'Stage moved')
    assert 'Got info' in ev['detail']                          # stage names resolved
    assert client.get('/api/followups/timeline?id=nope').status_code == 404
