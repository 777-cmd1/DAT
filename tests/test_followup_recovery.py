import sys
from datetime import datetime, timedelta
from unittest.mock import patch


_m = sys.modules['_dat_mailer_app']
_recover_followup_data = _m._recover_followup_data
_run_scheduled_followups = _m._run_scheduled_followups


def _create_user_with_workspace(db, email, fu_auto=True):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount

    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Test', password=pw, role='user')
    db.session.add(user)
    db.session.flush()

    ws = Workspace(owner_id=user.id, name='WS', plan='free', fu_auto_enabled=fu_auto)
    db.session.add(ws)
    db.session.flush()

    acct = EmailAccount(
        user_id=user.id,
        gmail_address=f'send_{user.id[:8]}@gmail.com',
        gmail_password='app-password',
    )
    db.session.add(acct)
    db.session.commit()
    return user, ws


def _create_auth_client(app, db, email):
    client = app.test_client()
    with app.app_context():
        user, ws = _create_user_with_workspace(db, email)
        with client.session_transaction() as sess:
            sess['user_email'] = email
        return client, user.id, ws.id


def test_recovery_migrates_legacy_followups_and_creates_settings(app, db):
    from app.models import FollowUp, FollowupContact, FollowupEvent, FollowupSettings

    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'legacy_fu@test.com')
        legacy = FollowUp(
            user_id=user.id,
            workspace_id=ws.id,
            contact_email='legacy@example.com',
            contact_name='Legacy Broker',
            route='Chicago, IL → Dallas, TX',
            reply_subject='Need capacity',
            reply_msg_id='<legacy-msg@example.com>',
            level='FU2',
            status='pending',
            added_at=datetime.utcnow() - timedelta(days=8),
            last_contact=datetime.utcnow() - timedelta(days=7),
            scheduled_at=datetime.utcnow() + timedelta(days=1),
            notes='Legacy note',
            auto_enabled=True,
        )
        db.session.add(legacy)
        db.session.commit()

        stats = _recover_followup_data()

        fc = FollowupContact.query.filter_by(workspace_id=ws.id, contact_email='legacy@example.com').first()
        assert fc is not None
        assert fc.stage == 'fu2_scheduled'
        assert fc.state == 'active'
        assert fc.current_route == 'Chicago, IL → Dallas, TX'
        assert fc.reply_subject == 'Need capacity'
        assert fc.reply_msg_id == '<legacy-msg@example.com>'
        assert FollowupSettings.query.filter_by(workspace_id=ws.id).first() is not None
        evt = FollowupEvent.query.filter_by(followup_contact_id=fc.id, event_type='created').first()
        assert evt is not None
        assert stats['legacy_created'] >= 1
        assert stats['settings_created'] >= 1


def test_scheduler_skips_paused_scheduled_once_contacts(app, db):
    from app.models import FollowupContact

    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'paused_sched@test.com')
        fc = FollowupContact(
            user_id=user.id,
            workspace_id=ws.id,
            contact_email='paused@example.com',
            state='paused',
            stage='fu1_scheduled',
            is_followup_enabled=False,
            scheduled_once=True,
            next_followup_at=datetime.utcnow() - timedelta(minutes=5),
        )
        db.session.add(fc)
        db.session.commit()

        with patch.object(_m, 'send_followup_email', return_value=(True, None)) as mocked_send:
            _run_scheduled_followups()

        refreshed = db.session.get(FollowupContact, fc.id)
        assert mocked_send.call_count == 0
        assert refreshed.scheduled_once is True
        assert refreshed.last_followup_sent_at is None


def test_scheduled_once_send_restores_recurring_schedule(app, db):
    from app.models import FollowupContact

    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'recurring_sched@test.com')
        fc = FollowupContact(
            user_id=user.id,
            workspace_id=ws.id,
            contact_email='recurring@example.com',
            state='active',
            stage='fu2_scheduled',
            is_followup_enabled=True,
            scheduled_once=True,
            recurring_enabled=True,
            recurring_days='0,1,2,3,4,5,6',
            recurring_time='00:00',
            next_followup_at=datetime.utcnow() - timedelta(minutes=5),
        )
        db.session.add(fc)
        db.session.commit()

        with patch.object(_m, 'send_followup_email', return_value=(True, None)):
            _run_scheduled_followups()

        refreshed = db.session.get(FollowupContact, fc.id)
        assert refreshed.scheduled_once is False
        assert refreshed.recurring_enabled is True
        assert refreshed.next_followup_at is not None
        assert refreshed.next_followup_at > datetime.utcnow()
        assert refreshed.last_followup_sent_at is not None


def test_bulk_schedule_once_sets_flag(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'bulk_schedule_user@test.com')

    with app.app_context():
        fc = FollowupContact(
            user_id=user_id,
            workspace_id=ws_id,
            contact_email='bulk_schedule@example.com',
            state='active',
            stage='fu1_scheduled',
            is_followup_enabled=True,
        )
        db.session.add(fc)
        db.session.commit()
        fc_id = fc.id

    scheduled_at = (datetime.utcnow() + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
    res = client.post('/api/followups/bulk-action', json={
        'ids': [fc_id],
        'action': 'schedule-once',
        'scheduled_at': scheduled_at,
    })
    assert res.status_code == 200

    with app.app_context():
        refreshed = db.session.get(FollowupContact, fc_id)
        assert refreshed.scheduled_once is True
        assert refreshed.next_followup_at is not None


def test_followups_list_counts_include_all_states_by_default(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'followups_list_user@test.com')

    with app.app_context():
        contacts = [
                FollowupContact(
                    user_id=user_id,
                    workspace_id=ws_id,
                contact_email='active_fu@example.com',
                state='active',
                stage='fu1_scheduled',
                is_followup_enabled=True,
            ),
                FollowupContact(
                    user_id=user_id,
                    workspace_id=ws_id,
                contact_email='warm_fu@example.com',
                state='warm',
                stage='fu2_sent',
                is_followup_enabled=False,
            ),
                FollowupContact(
                    user_id=user_id,
                    workspace_id=ws_id,
                contact_email='closed_fu@example.com',
                state='closed',
                stage='completed_fu3',
                is_followup_enabled=False,
            ),
        ]
        db.session.add_all(contacts)
        db.session.commit()

    res = client.get('/api/followups')
    assert res.status_code == 200
    data = res.get_json()
    emails = {c['contact_email'] for c in data['contacts']}
    assert 'active_fu@example.com' in emails
    assert 'warm_fu@example.com' in emails
    assert 'closed_fu@example.com' in emails
    assert data['counts']['total'] >= 3
    assert data['counts']['warm'] >= 1
    assert data['counts']['closed'] >= 1


def test_cancel_schedule_restores_recurring_next_followup(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'cancel_schedule_user@test.com')

    with app.app_context():
        fc = FollowupContact(
            user_id=user_id,
            workspace_id=ws_id,
            contact_email='cancel_schedule@example.com',
            state='active',
            stage='fu1_scheduled',
            is_followup_enabled=True,
            scheduled_once=True,
            recurring_enabled=True,
            recurring_days='0,1,2,3,4,5,6',
            recurring_time='00:00',
            next_followup_at=datetime.utcnow() + timedelta(hours=2),
        )
        db.session.add(fc)
        db.session.commit()
        fc_id = fc.id

    res = client.post('/api/followups/action', json={
        'id': fc_id,
        'action': 'cancel-schedule',
    })
    assert res.status_code == 200

    with app.app_context():
        refreshed = db.session.get(FollowupContact, fc_id)
        assert refreshed.scheduled_once is False
        assert refreshed.recurring_enabled is True
        assert refreshed.next_followup_at is not None


def test_stop_recurring_restores_sequence_schedule(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'stop_recurring_user@test.com')

    with app.app_context():
        fc = FollowupContact(
            user_id=user_id,
            workspace_id=ws_id,
            contact_email='stop_recurring@example.com',
            state='active',
            stage='fu2_scheduled',
            is_followup_enabled=True,
            recurring_enabled=True,
            recurring_days='1,3,5',
            recurring_time='12:30',
            next_followup_at=datetime.utcnow() + timedelta(hours=3),
        )
        db.session.add(fc)
        db.session.commit()
        fc_id = fc.id

    res = client.post('/api/followups/action', json={
        'id': fc_id,
        'action': 'stop-recurring',
    })
    assert res.status_code == 200

    with app.app_context():
        refreshed = db.session.get(FollowupContact, fc_id)
        assert refreshed.recurring_enabled is False
        assert refreshed.recurring_days is None
        assert refreshed.recurring_time is None
        assert refreshed.next_followup_at is not None


def test_save_fu_templates_preserves_extra_pool_templates(app, db):
    from app.models import Template

    client, user_id, _ws_id = _create_auth_client(app, db, 'fu_pool_preserve_user@test.com')

    with app.app_context():
        db.session.add(Template(
            user_id=user_id,
            type='followup',
            level='General',
            name='General Pool',
            body='General template',
            is_active=True,
        ))
        db.session.commit()

    res = client.post('/api/fu-templates', json={
        'FU1': 'FU1 body',
        'FU2': 'FU2 body',
        'FU3': 'FU3 body',
    })
    assert res.status_code == 200

    with app.app_context():
        rows = Template.query.filter_by(user_id=user_id, type='followup', is_active=True).all()
        levels = {r.level for r in rows}
        assert 'FU1' in levels
        assert 'FU2' in levels
        assert 'FU3' in levels
        assert 'General' in levels


def test_stage_template_selection_randomizes_within_stage_and_general_pool(app, db):
    from app.models import Template

    with app.app_context():
        user, _ws = _create_user_with_workspace(db, 'fu_rotation_user@test.com')
        db.session.add_all([
            Template(user_id=user.id, type='followup', level='FU1', name='FU1 A', body='FU1 A body', is_active=True),
            Template(user_id=user.id, type='followup', level='FU1', name='FU1 B', body='FU1 B body', is_active=True),
            Template(user_id=user.id, type='followup', level='General', name='General', body='General body', is_active=True),
        ])
        db.session.commit()

        with patch.object(_m.random, 'choice', side_effect=lambda seq: seq[-1]):
            picked = _m._get_fu_template_for_stage(user.id, 'fu1_scheduled', allow_random_fallback=True)
            assert picked in {'FU1 B body', 'General body'}

        with patch.object(_m.random, 'choice', side_effect=lambda seq: seq[0]):
            picked_stage_only = _m._get_fu_template_for_stage(user.id, 'fu1_scheduled', allow_random_fallback=False)
            assert picked_stage_only in {'FU1 A body', 'FU1 B body'}


def test_restart_fu1_from_completed_sequence(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'restart_done_user@test.com')

    with app.app_context():
        fc = FollowupContact(
            user_id=user_id,
            workspace_id=ws_id,
            contact_email='restart_done@example.com',
            state='active',
            stage='completed_fu3',
            is_followup_enabled=False,
            next_followup_at=None,
        )
        db.session.add(fc)
        db.session.commit()
        fc_id = fc.id

    res = client.post('/api/followups/action', json={
        'id': fc_id,
        'action': 'restart-fu1',
    })
    assert res.status_code == 200

    with app.app_context():
        refreshed = db.session.get(FollowupContact, fc_id)
        assert refreshed.state == 'active'
        assert refreshed.stage == 'fu1_scheduled'
        assert refreshed.is_followup_enabled is True
        assert refreshed.next_followup_at is not None


def test_restart_fu1_from_terminal_state(app, db):
    from app.models import FollowupContact

    client, user_id, ws_id = _create_auth_client(app, db, 'restart_terminal_user@test.com')

    with app.app_context():
        fc = FollowupContact(
            user_id=user_id,
            workspace_id=ws_id,
            contact_email='restart_terminal@example.com',
            state='loads',
            stage='fu3_sent',
            is_followup_enabled=False,
            scheduled_once=True,
            recurring_enabled=True,
            recurring_days='1,3,5',
            recurring_time='12:00',
            next_followup_at=None,
        )
        db.session.add(fc)
        db.session.commit()
        fc_id = fc.id

    res = client.post('/api/followups/action', json={
        'id': fc_id,
        'action': 'restart-fu1',
    })
    assert res.status_code == 200

    with app.app_context():
        refreshed = db.session.get(FollowupContact, fc_id)
        assert refreshed.state == 'active'
        assert refreshed.stage == 'fu1_scheduled'
        assert refreshed.is_followup_enabled is True
        assert refreshed.scheduled_once is False
        assert refreshed.recurring_enabled is False
        assert refreshed.recurring_days is None
        assert refreshed.recurring_time is None
        assert refreshed.next_followup_at is not None
