"""Follow-up sends must respect the user's stop list (C1 audit fix)."""
import sys

_app_module = sys.modules['_dat_mailer_app']


def test_followup_blocked_by_stoplist(app, db, auth_client):
    from app.models import StopListEntry
    uid = auth_client._test_user_id
    db.session.add(StopListEntry(user_id=uid, type='email', value='blocked@example.com'))
    db.session.add(StopListEntry(user_id=uid, type='domain', value='spamco.com'))
    db.session.commit()
    _app_module._cache_del(f'stop_list:{uid}')

    # Blocked by exact email
    ok, err = _app_module.send_followup_email(
        {'contact_email': 'blocked@example.com'},
        'Hi {name}', {'gmail_address': 'me@test.com'}, uid=uid,
    )
    assert ok is False
    assert 'stop list' in err

    # Blocked by domain
    ok, err = _app_module.send_followup_email(
        {'contact_email': 'anyone@spamco.com'},
        'Hi {name}', {'gmail_address': 'me@test.com'}, uid=uid,
    )
    assert ok is False
    assert 'stop list' in err

    # Not blocked → proceeds past the guard (fails later on missing Gmail creds)
    ok, err = _app_module.send_followup_email(
        {'contact_email': 'fine@other.com'},
        'Hi {name}', {'gmail_address': 'me@test.com'}, uid=uid,
    )
    assert err is None or 'stop list' not in (err or '')
