"""
Hash-chained append-only audit log.

Each entry's hash covers: prev_hash + timestamp + event_type + str(details),
forming a tamper-evident chain.
"""

import hashlib
import json
import os
import time


class AuditLog:
    def __init__(self, log_path: str = "audit_log.json"):
        self.log_path = log_path
        self._entries: list[dict] = []
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    self._entries = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._entries = []

    def log(self, event_type: str, details: dict) -> None:
        timestamp = str(time.time())
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else "0" * 64

        raw = prev_hash + timestamp + event_type + str(details)
        entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        self._entries.append(entry)
        self._save()

    def verify_chain(self) -> bool:
        """Re-compute every hash and confirm chain linkage."""
        prev_hash = "0" * 64
        for entry in self._entries:
            if entry["prev_hash"] != prev_hash:
                return False
            raw = (
                entry["prev_hash"]
                + entry["timestamp"]
                + entry["event_type"]
                + str(entry["details"])
            )
            expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if entry["entry_hash"] != expected:
                return False
            prev_hash = entry["entry_hash"]
        return True

    def get_log(self) -> list[dict]:
        return list(self._entries)

    def _save(self) -> None:
        with open(self.log_path, "w") as f:
            json.dump(self._entries, f, indent=2)
