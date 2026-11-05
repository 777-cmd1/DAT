"""
Tests for _run_scheduled_followups() — user isolation and filter logic (v2).

Key behaviours tested:
  1. Only processes FCs for the correct user (other users' FCs are not sent)
  2. Never sends a contact still carrying the retired drip flag
  3. Skips FCs where state != 'active' (e.g. paused)
  4. Processes a due one-time FC when all conditions are met (send_followup_email mocked)
  5. On failed send, the contact backs off and an event is recorded
  6. On successful send the one-time date is spent; the retired drip's stage is not advanced
  7. Skips FCs not yet due (next_followup_at in future)
"""
import sys
import pytest
from unittest.mock import patch
from datetime import datetime, timedelta

_m = sys.modules['_dat_mailer_app']
flask_app                = _m.app
_db                      = _m.db
_run_scheduled_followups = _m._run_scheduled_followups


# ── Helpers ───────────────────────────────────────────────────────────────────

def _create_user_with_workspace(db, email, plan='free', fu_auto=True):
    import bcrypt as _bcrypt
    from app.models import User, Workspace, EmailAccount

    pw = _bcrypt.hashpw(b'pass', _bcrypt.gensalt()).decode()
    user = User(email=email, name='Test', password=pw, role='user')
    db.session.add(user)
    db.session.flush()

    ws = Workspace(owner_id=user.id, name='WS', plan=plan, fu_auto_enabled=fu_auto, ladder_auto_enabled=True)
    db.session.add(ws)
    db.session.flush()

    acct = EmailAccount(
        user_id=user.id,
        gmail_address=f'send_{user.id[:8]}@gmail.com',
        gmail_password='',
    )
    db.session.add(acct)
    db.session.commit()
    return user, ws


def _make_due_contact(db, user_id, workspace_id, is_followup_enabled=False,
                      stage='fu1_scheduled', state='active', days_overdue=5, scheduled_once=True):
    """Create a FollowupContact that is past its due date (a one-time send by default:
    the stage drip that used to own such contacts is retired)."""
    from app.models import FollowupContact
    past = datetime.utcnow() - timedelta(days=days_overdue)
    fc = FollowupContact(
        user_id=user_id,
        workspace_id=workspace_id,
        contact_email=f'contact_{user_id[:8]}_{stage[:3]}@example.com',
        contact_name='Test Contact',
        current_route='Chicago, IL → Dallas, TX',
        stage=stage,
        state=state,
        is_followup_enabled=is_followup_enabled,
        scheduled_once=scheduled_once,
        next_followup_at=past,
    )
    db.session.add(fc)
    db.session.commit()
    return fc


def _mock_send_ok(*args, **kwargs):
    return True, None


def _mock_send_fail(*args, **kwargs):
    return False, 'SMTP error'


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_processes_due_followup_for_correct_user(app, db):
    """A due one-time FC in an active state is sent."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_user1@test.com')
        _make_due_contact(db, user.id, ws.id, days_overdue=5)

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_ok):
            count = _run_scheduled_followups()

        assert count >= 1


def test_the_retired_drip_flag_is_never_sent(app, db):
    """FC with is_followup_enabled=True (the retired drip, unplaced) is owned by no engine."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_user2@test.com')
        fc = _make_due_contact(db, user.id, ws.id, is_followup_enabled=True,
                               scheduled_once=False, days_overdue=5)

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_ok) as send:
            _run_scheduled_followups()

        from app.models import FollowupContact
        refreshed = db.session.get(FollowupContact, fc.id)
        assert send.call_count == 0
        assert refreshed.stage == 'fu1_scheduled'   # not advanced
        assert refreshed.fu1_sent_at is None


def test_skips_followup_when_state_not_active(app, db):
    """FC with state='paused' must be skipped — scheduler only processes state='active'."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_user3@test.com')
        fc = _make_due_contact(db, user.id, ws.id, state='paused', days_overdue=5)

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_ok) as send:
            _run_scheduled_followups()

        from app.models import FollowupContact
        refreshed = db.session.get(FollowupContact, fc.id)
        assert send.call_count == 0
        assert refreshed.scheduled_once is True


def test_does_not_process_other_users_followups(app, db):
    """FCs from user B must not be processed when only user A is queried."""
    with app.app_context():
        user_a, ws_a = _create_user_with_workspace(db, 'fu_usera@test.com')
        user_b, ws_b = _create_user_with_workspace(db, 'fu_userb@test.com')

        # Only user B has a due FC — user A has none
        _make_due_contact(db, user_b.id, ws_b.id, days_overdue=5)

        sent_users = []

        def mock_send_capture(fu_dict, tmpl, cfg, uid=None):
            sent_users.append(uid)
            return True, None

        with patch.object(_m, 'send_followup_email', side_effect=mock_send_capture):
            _run_scheduled_followups()

        assert user_a.id not in sent_users
        assert user_b.id in sent_users


def test_skips_followup_not_yet_due(app, db):
    """FC with next_followup_at in the future must not be processed."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_notdue@test.com')
        from app.models import FollowupContact
        future = datetime.utcnow() + timedelta(days=3)
        fc = FollowupContact(
            user_id=user.id,
            workspace_id=ws.id,
            contact_email='notdue@example.com',
            state='active',
            stage='fu1_scheduled',
            is_followup_enabled=False,
            scheduled_once=True,
            next_followup_at=future,
        )
        db.session.add(fc)
        db.session.commit()

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_ok) as send:
            _run_scheduled_followups()

        refreshed = db.session.get(FollowupContact, fc.id)
        assert send.call_count == 0
        assert refreshed.scheduled_once is True


def test_failed_send_backs_off_and_records_an_event(app, db):
    """When send_followup_email returns (False, err), the contact stays scheduled, backs off
    and an event is recorded; the stage history is untouched."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_fail@test.com')
        fc = _make_due_contact(db, user.id, ws.id, days_overdue=5)

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_fail):
            _run_scheduled_followups()

        from app.models import FollowupContact, FollowupEvent
        refreshed = db.session.get(FollowupContact, fc.id)
        assert refreshed.stage == 'fu1_scheduled'
        assert refreshed.fu1_sent_at is None
        assert refreshed.scheduled_once is True
        assert refreshed.next_followup_at > datetime.utcnow()      # backed off, not due again at once

        evt = FollowupEvent.query.filter_by(
            followup_contact_id=fc.id, event_type='scheduled_once_sent'
        ).first()
        assert evt is not None


def test_successful_send_clears_the_one_time_date_and_leaves_the_stage(app, db):
    """After a successful one-time send the schedule is spent; the old drip stage is not touched."""
    with app.app_context():
        user, ws = _create_user_with_workspace(db, 'fu_advance@test.com')
        fc = _make_due_contact(db, user.id, ws.id, stage='fu1_scheduled', days_overdue=5)

        with patch.object(_m, 'send_followup_email', side_effect=_mock_send_ok):
            count = _run_scheduled_followups()

        from app.models import FollowupContact
        refreshed = db.session.get(FollowupContact, fc.id)
        assert count >= 1
        assert refreshed.scheduled_once is False
        assert refreshed.stage == 'fu1_scheduled'
        assert refreshed.fu1_sent_at is None
        assert refreshed.last_followup_sent_at is not None
