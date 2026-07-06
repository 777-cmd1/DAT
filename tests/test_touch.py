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
