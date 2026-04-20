import pytest
from vault.crypto import ShareCrypto


@pytest.fixture
def crypto():
    return ShareCrypto()


def test_encrypt_decrypt_roundtrip(crypto):
    share = (1, 12345678901234567890)
    encrypted = crypto.encrypt_share(share, "correct_password")
    decrypted = crypto.decrypt_share(encrypted, "correct_password")
    assert decrypted == share


def test_wrong_password_fails(crypto):
    share = (2, 98765432109876543210)
    encrypted = crypto.encrypt_share(share, "correct_password")
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt_share(encrypted, "wrong_password")


def test_tampered_ciphertext_fails(crypto):
    share = (3, 11111111111111111111)
    encrypted = crypto.encrypt_share(share, "password")

    ct = bytes.fromhex(encrypted["ciphertext"])
    # Flip the first byte
    tampered = bytes([ct[0] ^ 0xFF, *ct[1:]]) if ct else ct
    encrypted["ciphertext"] = tampered.hex()

    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt_share(encrypted, "password")


def test_tampered_tag_fails(crypto):
    share = (4, 99999999999999999999)
    encrypted = crypto.encrypt_share(share, "password")
    encrypted["tag"] = "ff" * 16  # replace with garbage tag
    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt_share(encrypted, "password")


def test_each_encryption_is_unique(crypto):
    """Same share encrypted twice should produce different ciphertexts (random nonce/salt)."""
    share = (1, 42)
    enc1 = crypto.encrypt_share(share, "password")
    enc2 = crypto.encrypt_share(share, "password")
    assert enc1["ciphertext"] != enc2["ciphertext"]
    assert enc1["nonce"] != enc2["nonce"]
    assert enc1["salt"] != enc2["salt"]
