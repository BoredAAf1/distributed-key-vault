"""
AES-256-GCM encryption for individual shares, with PBKDF2-SHA256 key derivation.
"""

import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from vault.randomness import RandomSource, get_random_source

_KDF_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_TAG_BYTES = 16


class ShareCrypto:
    def __init__(self, rng: RandomSource | None = None):
        self.rng = rng or get_random_source()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_share(self, share_tuple: tuple, password: str) -> dict:
        """Encrypt (x, y) share tuple; returns hex-encoded {salt, nonce, ciphertext, tag}."""
        data = json.dumps({"x": share_tuple[0], "y": share_tuple[1]}).encode("utf-8")

        salt = self.rng.random_bytes(_SALT_BYTES)
        nonce = self.rng.random_bytes(_NONCE_BYTES)
        key = self.derive_key(password, salt)

        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, data, None)

        # cryptography appends 16-byte GCM tag at the end
        ciphertext = ct_with_tag[:-_TAG_BYTES]
        tag = ct_with_tag[-_TAG_BYTES:]

        return {
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex(),
        }

    def decrypt_share(self, encrypted: dict, password: str) -> tuple:
        """Decrypt and return (x, y) tuple. Raises ValueError on auth failure."""
        salt = bytes.fromhex(encrypted["salt"])
        nonce = bytes.fromhex(encrypted["nonce"])
        ciphertext = bytes.fromhex(encrypted["ciphertext"])
        tag = bytes.fromhex(encrypted["tag"])

        key = self.derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        except Exception:
            raise ValueError("Decryption failed: wrong password or tampered ciphertext")

        obj = json.loads(plaintext.decode("utf-8"))
        return (obj["x"], obj["y"])
