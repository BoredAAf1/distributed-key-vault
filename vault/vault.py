"""
Orchestrator that wires together SSS, Feldman VSS, crypto, audit, and sessions.
"""

import time

from vault.sss import ShamirSSS
from vault.feldman import FeldmanVSS
from vault.crypto import ShareCrypto
from vault.audit import AuditLog
from vault.session import SessionManager
from vault.randomness import RandomSource, get_random_source


class DistributedKeyVault:
    def __init__(
        self,
        audit_log_path: str = "audit_log.json",
        use_quantum_rng: bool = False,
        rng: RandomSource | None = None,
    ):
        self.rng = rng or get_random_source(use_quantum_rng)
        self.sss = ShamirSSS(self.rng)
        self.feldman = FeldmanVSS()
        self.crypto = ShareCrypto(self.rng)
        self.audit = AuditLog(audit_log_path)
        self.session_mgr = SessionManager(self.rng)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def split_secret(
        self,
        secret: str,
        n: int,
        k: int,
        passwords: list[str],
    ) -> dict:
        """
        Split *secret* into *n* encrypted shares with threshold *k*.

        Returns:
            {
                "shares":      [encrypted_share_dict, ...],
                "commitments": [int, ...],          # Feldman VSS commitments
                "metadata":    {"n": n, "k": k, "timestamp": float},
            }
        """
        if k < 2 or n < k:
            raise ValueError(f"Invalid parameters: need 2 <= k <= n, got k={k}, n={n}")
        if len(passwords) != n:
            raise ValueError(f"Expected {n} passwords, got {len(passwords)}")

        shares, coeffs = self.sss.split(secret.encode("utf-8"), n, k)
        commitments = self.feldman.generate_commitments(coeffs)

        encrypted_shares = [
            self.crypto.encrypt_share(share, pwd)
            for share, pwd in zip(shares, passwords)
        ]

        self.audit.log("SPLIT", {"n": n, "k": k, "timestamp": time.time()})

        return {
            "shares": encrypted_shares,
            "commitments": commitments,
            "metadata": {"n": n, "k": k, "timestamp": time.time()},
        }

    def reconstruct_secret(
        self,
        encrypted_shares: list[dict],
        passwords: list[str],
        commitments: list[int],
    ) -> str:
        """
        Decrypt shares, verify each via Feldman VSS, then reconstruct.

        Raises ValueError if any share fails verification (tamper detected)
        or if the session has expired / a duplicate share is submitted.
        """
        if len(encrypted_shares) != len(passwords):
            raise ValueError("Number of shares and passwords must match")

        session = self.session_mgr.create_session(len(encrypted_shares))

        self.audit.log(
            "RECONSTRUCT_ATTEMPT",
            {"num_shares": len(encrypted_shares), "session_id": session["session_id"]},
        )

        if not self.session_mgr.validate_session(session):
            self.audit.log("RECONSTRUCT_FAIL", {"reason": "session_expired"})
            raise RuntimeError("Session expired before reconstruction could begin")

        decrypted_shares: list[tuple[int, int]] = []

        for i, (encrypted, password) in enumerate(zip(encrypted_shares, passwords)):
            # Decrypt
            try:
                share = self.crypto.decrypt_share(encrypted, password)
            except ValueError as exc:
                self.audit.log(
                    "RECONSTRUCT_FAIL",
                    {"reason": "decryption_failed", "share_index": i},
                )
                raise ValueError(f"Share {i}: decryption failed — {exc}") from exc

            x, y = share

            # Feldman verification
            if not self.feldman.verify_share(x, y, commitments):
                self.audit.log("TAMPER_DETECTED", {"share_index": i, "x": x})
                raise ValueError(
                    f"Share {i} (x={x}) failed Feldman verification — possible tampering"
                )

            self.audit.log("SHARE_VERIFY", {"share_index": i, "x": x, "valid": True})

            # Replay protection
            if not self.session_mgr.add_share(session, x):
                self.audit.log(
                    "RECONSTRUCT_FAIL", {"reason": "duplicate_share", "x": x}
                )
                raise ValueError(f"Duplicate share x={x} rejected (replay attack?)")

            decrypted_shares.append(share)

        secret_bytes = self.sss.reconstruct(decrypted_shares)
        secret = secret_bytes.decode("utf-8")

        self.audit.log(
            "RECONSTRUCT_SUCCESS",
            {
                "session_id": session["session_id"],
                "num_shares_used": len(decrypted_shares),
            },
        )
        return secret

    def verify_share(
        self,
        encrypted_share: dict,
        password: str,
        commitments: list[int],
    ) -> bool:
        """Decrypt a single share and check it against Feldman commitments."""
        try:
            share = self.crypto.decrypt_share(encrypted_share, password)
        except ValueError:
            return False

        x, y = share
        result = self.feldman.verify_share(x, y, commitments)
        self.audit.log("SHARE_VERIFY", {"x": x, "valid": result})
        return result

    def get_audit_log(self) -> list[dict]:
        return self.audit.get_log()

    def verify_audit_chain(self) -> bool:
        return self.audit.verify_chain()
