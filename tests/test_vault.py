import time
from unittest.mock import patch

import pytest

from vault.vault import DistributedKeyVault
from vault.session import SessionManager


@pytest.fixture
def vault(tmp_path):
    return DistributedKeyVault(audit_log_path=str(tmp_path / "audit.json"))


# ---------------------------------------------------------------------------
# Full integration
# ---------------------------------------------------------------------------

def test_full_split_and_reconstruct(vault):
    secret = "MySecretPassword123!"
    n, k = 5, 3
    passwords = [f"pass{i}" for i in range(1, n + 1)]

    result = vault.split_secret(secret, n, k, passwords)

    # Reconstruct using shares 1, 3, 5 (indices 0, 2, 4)
    sel = [result["shares"][0], result["shares"][2], result["shares"][4]]
    sel_pwds = [passwords[0], passwords[2], passwords[4]]
    recovered = vault.reconstruct_secret(sel, sel_pwds, result["commitments"])
    assert recovered == secret


def test_audit_log_populated_after_operations(vault):
    secret = "AuditTest"
    result = vault.split_secret(secret, 3, 2, ["a", "b", "c"])
    vault.reconstruct_secret(result["shares"][:2], ["a", "b"], result["commitments"])

    log = vault.get_audit_log()
    event_types = {e["event_type"] for e in log}
    assert "SPLIT" in event_types
    assert "RECONSTRUCT_SUCCESS" in event_types
    assert vault.verify_audit_chain()


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_reconstruct_with_tampered_ciphertext_raises(vault):
    secret = "TamperTest"
    result = vault.split_secret(secret, 3, 2, ["p1", "p2", "p3"])

    tampered = dict(result["shares"][0])
    ct = bytes.fromhex(tampered["ciphertext"])
    tampered["ciphertext"] = bytes([ct[0] ^ 0xFF, *ct[1:]]).hex()

    with pytest.raises((ValueError, Exception)):
        vault.reconstruct_secret(
            [tampered, result["shares"][1]],
            ["p1", "p2"],
            result["commitments"],
        )


def test_reconstruct_with_tampered_share_value_raises(vault):
    """A decryptable-but-wrong y value should trigger Feldman rejection."""
    from vault.crypto import ShareCrypto
    from vault.sss import ShamirSSS

    secret = "FeldmanTest"
    result = vault.split_secret(secret, 3, 2, ["p1", "p2", "p3"])

    # Decrypt share 0, corrupt y, re-encrypt
    crypto = ShareCrypto()
    x, y = crypto.decrypt_share(result["shares"][0], "p1")
    bad_share = crypto.encrypt_share((x, y + 1), "p1")  # y+1 won't match commitments

    with pytest.raises(ValueError, match="Feldman"):
        vault.reconstruct_secret(
            [bad_share, result["shares"][1]],
            ["p1", "p2"],
            result["commitments"],
        )


# ---------------------------------------------------------------------------
# Session / replay protection
# ---------------------------------------------------------------------------

def test_session_expires():
    mgr = SessionManager()
    session = mgr.create_session(3)
    assert mgr.validate_session(session)

    # Patch time to 400 seconds in the future
    future = time.time() + 400
    with patch("vault.session.time") as mock_time:
        mock_time.time.return_value = future
        assert not mgr.validate_session(session)


def test_duplicate_share_rejected():
    mgr = SessionManager()
    session = mgr.create_session(3)

    assert mgr.add_share(session, 1)
    assert not mgr.add_share(session, 1)   # duplicate
    assert mgr.add_share(session, 2)       # different index — accepted
    assert not mgr.add_share(session, 2)   # duplicate again


def test_session_is_complete_at_threshold():
    mgr = SessionManager()
    session = mgr.create_session(3)

    assert not mgr.is_complete(session)
    mgr.add_share(session, 1)
    mgr.add_share(session, 2)
    assert not mgr.is_complete(session)
    mgr.add_share(session, 3)
    assert mgr.is_complete(session)


# ---------------------------------------------------------------------------
# verify_share
# ---------------------------------------------------------------------------

def test_verify_share_valid(vault):
    result = vault.split_secret("verify_me", 3, 2, ["a", "b", "c"])
    assert vault.verify_share(result["shares"][0], "a", result["commitments"])


def test_verify_share_wrong_password(vault):
    result = vault.split_secret("verify_me", 3, 2, ["a", "b", "c"])
    assert not vault.verify_share(result["shares"][0], "wrong", result["commitments"])
