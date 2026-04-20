import json
import pytest
from vault.audit import AuditLog


def test_log_creates_entries(tmp_path):
    log = AuditLog(str(tmp_path / "audit.json"))
    log.log("SPLIT", {"n": 5, "k": 3})
    log.log("RECONSTRUCT_SUCCESS", {"session_id": "abc123"})

    entries = log.get_log()
    assert len(entries) == 2
    assert entries[0]["event_type"] == "SPLIT"
    assert entries[1]["event_type"] == "RECONSTRUCT_SUCCESS"


def test_chain_is_valid_after_logging(tmp_path):
    log = AuditLog(str(tmp_path / "audit.json"))
    for i in range(5):
        log.log("TEST_EVENT", {"i": i})
    assert log.verify_chain()


def test_tampered_log_fails_verification(tmp_path):
    path = str(tmp_path / "audit.json")
    log = AuditLog(path)
    log.log("SPLIT", {"n": 5, "k": 3})
    log.log("RECONSTRUCT_SUCCESS", {})

    # Tamper with details in the first entry
    with open(path) as f:
        entries = json.load(f)
    entries[0]["details"]["n"] = 99
    with open(path, "w") as f:
        json.dump(entries, f)

    reloaded = AuditLog(path)
    assert not reloaded.verify_chain()


def test_chain_links_entries(tmp_path):
    log = AuditLog(str(tmp_path / "audit.json"))
    log.log("A", {})
    log.log("B", {})
    log.log("C", {})

    entries = log.get_log()
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hash"]


def test_persists_across_instances(tmp_path):
    path = str(tmp_path / "audit.json")
    log1 = AuditLog(path)
    log1.log("FIRST", {"x": 1})

    log2 = AuditLog(path)  # new instance reading same file
    log2.log("SECOND", {"x": 2})

    entries = log2.get_log()
    assert len(entries) == 2
    assert log2.verify_chain()
