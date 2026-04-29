"""
Session management with nonce-based replay-attack protection.

A session is a plain dict so it can be pickled / serialised without
circular references; the manager provides operations on it.
"""

import time
import uuid

from vault.randomness import RandomSource, get_random_source

_SESSION_TTL = 300  # seconds


class SessionManager:
    def __init__(self, rng: RandomSource | None = None):
        self.rng = rng or get_random_source()

    def create_session(self, threshold: int) -> dict:
        now = time.time()
        return {
            "session_id": str(uuid.uuid4()),
            "nonce": self.rng.token_hex(16),
            "created_at": now,
            "expires_at": now + _SESSION_TTL,
            "threshold": threshold,
            "submitted_shares": [],
        }

    def validate_session(self, session: dict) -> bool:
        """Return True if the session has not expired."""
        return time.time() < session["expires_at"]

    def add_share(self, session: dict, share_index: int) -> bool:
        """
        Record that share *share_index* has been submitted.

        Returns False (and rejects) if the same index is submitted twice
        (replay protection).
        """
        if share_index in session["submitted_shares"]:
            return False
        session["submitted_shares"].append(share_index)
        return True

    def is_complete(self, session: dict) -> bool:
        return len(session["submitted_shares"]) >= session["threshold"]
