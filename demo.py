"""
End-to-end demo of the Distributed Key Vault.

Demonstrates:
  1. Splitting "MyMasterPassword123!" into 5 shares (threshold 3)
  2. Printing encrypted shares (truncated)
  3. Reconstructing from shares 1, 3, 5
  4. Verifying share 2 independently
  5. Displaying the audit log
  6. Tamper detection
"""

import copy
import json
import os

# Remove any leftover demo audit log from a previous run
_DEMO_LOG = "demo_audit.json"
if os.path.exists(_DEMO_LOG):
    os.remove(_DEMO_LOG)

from vault.vault import DistributedKeyVault


def separator(title: str = "") -> None:
    width = 62
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"{'─' * pad} {title} {'─' * (width - pad - len(title) - 2)}")
    else:
        print("─" * width)


def main() -> None:
    separator("Distributed Key Vault — Demo")

    vault = DistributedKeyVault(audit_log_path=_DEMO_LOG)

    # ── 1. Split ──────────────────────────────────────────────────────────
    separator("1  Split")
    secret = "MyMasterPassword123!"
    n, k = 5, 3
    passwords = ["pass1", "pass2", "pass3", "pass4", "pass5"]

    print(f"  Secret    : {secret!r}")
    print(f"  Shares    : {n}  (threshold {k})")

    result = vault.split_secret(secret, n, k, passwords)
    commitments = result["commitments"]

    # ── 2. Print encrypted shares (truncated) ─────────────────────────────
    separator("2  Encrypted shares")
    for i, share in enumerate(result["shares"]):
        ct = share["ciphertext"]
        preview = ct[:32] + ("…" if len(ct) > 32 else "")
        print(f"  Share {i + 1}: salt={share['salt'][:12]}… ct={preview}")

    print(
        f"\n  Commitments: {len(commitments)} values (first={commitments[0] % 10**12}…)"
    )

    # ── 3. Reconstruct from shares 1, 3, 5 ───────────────────────────────
    separator("3  Reconstruct (shares 1, 3, 5)")
    sel_shares = [result["shares"][0], result["shares"][2], result["shares"][4]]
    sel_pwds = ["pass1", "pass3", "pass5"]

    recovered = vault.reconstruct_secret(sel_shares, sel_pwds, commitments)
    status = "OK ✓" if recovered == secret else "FAIL ✗"
    print(f"  Recovered : {recovered!r}  [{status}]")

    # ── 4. Verify share 2 ─────────────────────────────────────────────────
    separator("4  Verify share 2")
    valid = vault.verify_share(result["shares"][1], "pass2", commitments)
    print(f"  Share 2   : {'VALID' if valid else 'INVALID'}")

    # ── 5. Audit log ──────────────────────────────────────────────────────
    separator("5  Audit log")
    for entry in vault.get_audit_log():
        print(f"  [{entry['event_type']:25s}] hash={entry['entry_hash'][:16]}…")
    chain_ok = vault.verify_audit_chain()
    print(f"\n  Chain integrity: {'VALID' if chain_ok else 'INVALID'}")

    # ── 6. Tamper detection ───────────────────────────────────────────────
    separator("6  Tamper detection")
    tampered = copy.deepcopy(result["shares"][0])
    raw = bytes.fromhex(tampered["ciphertext"])
    # Flip first byte of ciphertext → AESGCM tag check will fail
    tampered["ciphertext"] = bytes([raw[0] ^ 0xFF, *raw[1:]]).hex()

    print("  Corrupted share 1 ciphertext (first byte flipped).")
    try:
        vault.reconstruct_secret(
            [tampered, result["shares"][2], result["shares"][4]],
            ["pass1", "pass3", "pass5"],
            commitments,
        )
        print("  ERROR: tamper was not detected!")
    except Exception as exc:
        print(f"  TAMPER DETECTED: {exc}")

    separator("Demo complete")
    print()


if __name__ == "__main__":
    main()
