"""Package 4: the user's time zone drives "today", the fixed touch hour and the
digest; Overdue/Today/Needs Action use one definition everywhere."""
import sys
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

_app = sys.modules['_dat_mailer_app']
CT = 'America/Chicago'


def _mk(db, client=None, tz=CT, **cfg):
    import bcrypt as _bcrypt
    from app.models import User, Workspace
    email = f'tz_{uuid.uuid4().hex[:8]}@test.com'
    u = User(email=email, name='T', role='user', password=_bcrypt.hashpw(b'p', _bcrypt.gensalt()).decode())
    db.session.add(u); db.session.flush()
    if tz:
        cfg['timezone'] = tz
    ws = Workspace(owner_id=u.id, name='WS', pipeline_config=cfg)
    db.session.add(ws); db.session.commit()
    if client is not None:
        with client.session_transaction() as sess:
            sess['user_email'] = email
    return u, ws


def _fc(db, u, ws, due, **kw):
    from app.models import FollowupContact
    fields = dict(user_id=u.id, workspace_id=ws.id, contact_email=f'{uuid.uuid4().hex[:8]}@c.com',
                  state='active', stage='completed_fu3', is_followup_enabled=False,
                  touch_enabled=True, next_followup_at=due)
    fields.update(kw)
    fc = FollowupContact(**fields); db.session.add(fc); db.session.commit()
    return fc


def test_local_day_start_follows_zone_and_dst():
    tz = ZoneInfo(CT)
    # 03:00 UTC on Sep 30 is still Sep 29 in Chicago (CDT, UTC-5)
    now = datetime(2026, 9, 30, 3, 0)
    assert _app._local_day_start(tz, 0, now) == datetime(2026, 9, 29, 5, 0)
    assert _app._local_day_start(tz, -1, now) == datetime(2026, 9, 30, 5, 0)
    # after the November DST change midnight is 06:00 UTC
    assert _app._local_day_start(tz, 0, datetime(2026, 12, 1, 12)) == datetime(2026, 12, 1, 6, 0)
    assert _app._local_at_hour(datetime(2026, 10, 3, 1), 9, tz) == datetime(2026, 10, 2, 14, 0)


def test_followup_today_and_overdue_use_local_day(app, db, client, monkeypatch):
    now = datetime(2026, 9, 30, 3, 0)                      # Sep 29, 22:00 in Chicago
    monkeypatch.setattr(_app, '_utcnow', lambda: now)
    u, ws = _mk(db, client)
    late = _fc(db, u, ws, now - timedelta(hours=2))                  # overdue (touch, not drip)
    tonight = _fc(db, u, ws, datetime(2026, 9, 30, 4, 30))           # 23:30 CT → today
    tomorrow = _fc(db, u, ws, datetime(2026, 9, 30, 12, 0))          # 07:00 CT → tomorrow
    data = client.get('/api/followups').get_json()
    assert data['counts']['overdue'] == 1 and data['counts']['due_today'] == 1
    today_ids = {c['id'] for c in client.get('/api/followups?filter=due_today').get_json()['contacts']}
    assert today_ids == {tonight.id}
    # select-all uses the same buckets as the list (it used to require the drip flag)
    assert client.get('/api/followups/ids?filter=overdue').get_json()['ids'] == [late.id]
    assert client.get('/api/followups/ids?filter=due_today').get_json()['ids'] == [tonight.id]
    assert tomorrow.id not in today_ids


def test_fixed_touch_hour_is_local(app, db):
    u, ws = _mk(db, touch_hour=9, cadence={'1': {'days': 3, 'mode': 'manual'}})
    fc = _fc(db, u, ws, None, touch_enabled=False, pipeline_stage=1)
    assert _app._schedule_touch(fc, ws, force=True)
    local = fc.next_followup_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(ZoneInfo(CT))
    assert (local.hour, local.minute) == (9, 0)


def test_setting_timezone_keeps_touch_moment(app, db, client):
    u, ws = _mk(db, client, tz=None, touch_hour=14)        # 14:00 UTC, zone never set
    res = client.put('/api/followups/pipeline-config', json={'timezone': CT}).get_json()
    expected = datetime.now(ZoneInfo('UTC')).replace(hour=14).astimezone(ZoneInfo(CT)).hour
    assert res['timezone'] == CT and res['touch_hour'] == expected
    assert client.put('/api/followups/pipeline-config', json={'timezone': 'Mars/Base'}).get_json()['timezone'] == CT
    assert client.get('/api/followups/pipeline-config').get_json()['timezone'] == CT


def test_digest_waits_for_local_monday_morning(app, db, monkeypatch):
    sent = []
    monkeypatch.setattr(_app, '_send_self_email', lambda uid, subj, body: (sent.append(uid), (True, None))[1])
    monkeypatch.setattr(_app, '_compose_digest', lambda uid: 'digest')
    u, ws = _mk(db)
    _app._maybe_send_digests(datetime(2026, 10, 5, 8, 0))    # Monday 03:00 CT — too early
    assert u.id not in sent
    _app._maybe_send_digests(datetime(2026, 10, 5, 12, 0))   # Monday 07:00 CT
    assert sent.count(u.id) == 1
    _app._maybe_send_digests(datetime(2026, 10, 5, 13, 0))   # deduped by local date
    assert sent.count(u.id) == 1


def test_dashboard_activity_buckets_by_local_day(app, db, monkeypatch):
    from app.models import Send
    now = datetime(2026, 9, 30, 3, 0)                        # Sep 29 evening in Chicago
    monkeypatch.setattr(_app, '_utcnow', lambda: now)
    u, ws = _mk(db)
    db.session.add(Send(user_id=u.id, workspace_id=ws.id, recipient_email='a@x.com', status='sent',
                        sent_at=datetime(2026, 9, 30, 2, 0)))  # Sep 29 21:00 CT
    db.session.commit()
    act = _app._dashboard_data(u.id)['activity']
    assert act[-1]['day'] == 'Sep 29' and act[-1]['sends'] == 1
