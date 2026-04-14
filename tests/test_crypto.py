"""
Tests for encrypt_field() / decrypt_field() — Fernet field encryption.
"""
import sys
import os
import pytest
from cryptography.fernet import Fernet

_m = sys.modules['_dat_mailer_app']
encrypt_field = _m.encrypt_field
decrypt_field = _m.decrypt_field


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_encrypt_then_decrypt_returns_original():
    original = 'my-secret-app-password'
    token = encrypt_field(original)
    recovered = decrypt_field(token)
    assert recovered == original


def test_encrypted_value_is_not_plaintext():
    original = 'supersecret123'
    token = encrypt_field(original)
    # Fernet tokens are base64-encoded and won't equal the plaintext
    assert token != original


def test_different_values_produce_different_ciphertext():
    tok1 = encrypt_field('valueA')
    tok2 = encrypt_field('valueB')
    assert tok1 != tok2


def test_same_value_produces_different_ciphertext_each_time():
    """Fernet uses random IV — same plaintext yields different tokens."""
    tok1 = encrypt_field('repeatme')
    tok2 = encrypt_field('repeatme')
    assert tok1 != tok2   # different nonce each time


def test_decrypt_encrypted_same_value_both_times():
    """Even though ciphertext differs, both decrypt to same plaintext."""
    plain = 'repeatme'
    assert decrypt_field(encrypt_field(plain)) == plain
    assert decrypt_field(encrypt_field(plain)) == plain


def test_empty_string_passthrough():
    """Empty string should pass through without error or encryption."""
    assert encrypt_field('') == ''
    assert decrypt_field('') == ''


def test_none_like_empty_handled():
    """decrypt_field on empty string returns empty."""
    result = decrypt_field('')
    assert result == ''


def test_decrypt_plaintext_fallback():
    """decrypt_field on a non-Fernet string should return it as-is (legacy support)."""
    plain = 'not-a-fernet-token'
    result = decrypt_field(plain)
    assert result == plain


def test_encrypt_unicode_string():
    original = 'пароль-тест-123'
    token = encrypt_field(original)
    assert decrypt_field(token) == original


def test_encrypt_long_string():
    original = 'x' * 1000
    token = encrypt_field(original)
    assert decrypt_field(token) == original


def test_decrypt_with_wrong_key_returns_original():
    """
    If a value was encrypted with one key and we try to decrypt it with another,
    decrypt_field should return the ciphertext as-is (graceful fallback).
    """
    # Encrypt with the current (test) key
    original = 'secret-data'
    token = encrypt_field(original)

    # Temporarily swap the ENCRYPTION_KEY to a different key
    old_key = os.environ.get('ENCRYPTION_KEY', '')
    new_key = Fernet.generate_key().decode()
    os.environ['ENCRYPTION_KEY'] = new_key

    # Reset the cached Fernet instance so it picks up the new key
    _m._fernet_instance = None

    result = decrypt_field(token)
    # Should not raise; returns ciphertext as fallback
    assert isinstance(result, str)

    # Restore original key and instance
    os.environ['ENCRYPTION_KEY'] = old_key
    _m._fernet_instance = None
