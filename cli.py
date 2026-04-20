"""
Distributed Key Vault — Click CLI entrypoint.

Commands: split, reconstruct, verify, audit
"""

import glob
import json
import os
import sys

import click

from vault.vault import DistributedKeyVault


@click.group()
def cli():
    """Distributed Key Vault — Shamir's Secret Sharing CLI."""


# ---------------------------------------------------------------------------
# split
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--secret", prompt="Secret to split", hide_input=True, help="The secret to protect")
@click.option("--shares", "n", default=5, show_default=True, help="Total number of shares")
@click.option("--threshold", "k", default=3, show_default=True, help="Minimum shares needed to reconstruct")
@click.option("--output-dir", default="shares", show_default=True, help="Directory for output files")
def split(secret, n, k, output_dir):
    """Split a secret into n encrypted shares with threshold k."""
    if k < 2:
        click.echo("Error: threshold must be at least 2", err=True)
        sys.exit(1)
    if k > n:
        click.echo(f"Error: threshold ({k}) cannot exceed shares ({n})", err=True)
        sys.exit(1)

    passwords = []
    for i in range(1, n + 1):
        pwd = click.prompt(
            f"Password for custodian {i}",
            hide_input=True,
            confirmation_prompt=True,
        )
        passwords.append(pwd)

    vault = DistributedKeyVault()
    result = vault.split_secret(secret, n, k, passwords)

    os.makedirs(output_dir, exist_ok=True)

    for i, share in enumerate(result["shares"]):
        path = os.path.join(output_dir, f"share_{i + 1}.json")
        with open(path, "w") as f:
            json.dump(share, f, indent=2)
        click.echo(f"  Saved share {i + 1} → {path}")

    commitments_path = os.path.join(output_dir, "commitments.json")
    with open(commitments_path, "w") as f:
        json.dump(result["commitments"], f, indent=2)
    click.echo(f"  Saved commitments → {commitments_path}")

    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(result["metadata"], f, indent=2)
    click.echo(f"  Saved metadata → {metadata_path}")

    click.echo(f"\nSecret split into {n} shares (threshold: {k}).")


# ---------------------------------------------------------------------------
# reconstruct
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--shares-dir", default=None, help="Directory containing share_*.json files")
@click.option("--share-files", multiple=True, help="Explicit share file paths (repeatable)")
@click.option("--commitments", "commitments_path", default=None, help="Path to commitments.json")
def reconstruct(shares_dir, share_files, commitments_path):
    """Reconstruct a secret from k or more encrypted shares."""
    # Resolve share files
    files_to_load: list[str] = []
    if share_files:
        files_to_load = list(share_files)
    elif shares_dir:
        files_to_load = sorted(glob.glob(os.path.join(shares_dir, "share_*.json")))
    else:
        click.echo("Error: provide --shares-dir or one or more --share-files", err=True)
        sys.exit(1)

    if not files_to_load:
        click.echo("Error: no share files found", err=True)
        sys.exit(1)

    # Resolve commitments
    if not commitments_path:
        if shares_dir:
            commitments_path = os.path.join(shares_dir, "commitments.json")
        else:
            click.echo("Error: --commitments is required when using --share-files", err=True)
            sys.exit(1)

    if not os.path.exists(commitments_path):
        click.echo(f"Error: commitments file not found: {commitments_path}", err=True)
        sys.exit(1)

    with open(commitments_path) as f:
        commitment_list = json.load(f)

    encrypted_shares = []
    for path in files_to_load:
        with open(path) as f:
            encrypted_shares.append(json.load(f))

    passwords = [
        click.prompt(f"Password for {os.path.basename(p)}", hide_input=True)
        for p in files_to_load
    ]

    vault = DistributedKeyVault()
    try:
        secret = vault.reconstruct_secret(encrypted_shares, passwords, commitment_list)
        click.echo(f"\nReconstructed secret: {secret}")
    except Exception as exc:
        click.echo(f"Reconstruction failed: {exc}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--share-file", required=True, help="Share file to verify")
@click.option("--commitments", "commitments_path", required=True, help="Path to commitments.json")
def verify(share_file, commitments_path):
    """Verify a single share against Feldman VSS commitments."""
    for path in (share_file, commitments_path):
        if not os.path.exists(path):
            click.echo(f"Error: file not found: {path}", err=True)
            sys.exit(1)

    with open(share_file) as f:
        encrypted_share = json.load(f)
    with open(commitments_path) as f:
        commitment_list = json.load(f)

    password = click.prompt("Password for share", hide_input=True)

    vault = DistributedKeyVault()
    if vault.verify_share(encrypted_share, password, commitment_list):
        click.echo("VALID")
    else:
        click.echo("INVALID")
        sys.exit(1)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--log-file", default="audit_log.json", show_default=True, help="Audit log path")
@click.option("--verify-chain", is_flag=True, help="Check hash-chain integrity")
def audit(log_file, verify_chain):
    """Pretty-print the audit log (and optionally verify chain integrity)."""
    if not os.path.exists(log_file):
        click.echo(f"Error: audit log not found: {log_file}", err=True)
        sys.exit(1)

    from vault.audit import AuditLog

    audit_log = AuditLog(log_file)
    entries = audit_log.get_log()

    if not entries:
        click.echo("Audit log is empty.")
        return

    click.echo(f"\nAudit Log  ({len(entries)} entries)")
    click.echo("─" * 62)
    for entry in entries:
        click.echo(f"  Timestamp : {entry['timestamp']}")
        click.echo(f"  Event     : {entry['event_type']}")
        click.echo(f"  Details   : {json.dumps(entry['details'])}")
        click.echo(f"  Hash      : {entry['entry_hash'][:24]}…")
        click.echo("─" * 62)

    if verify_chain:
        ok = audit_log.verify_chain()
        status = "VALID" if ok else "INVALID — possible tampering!"
        click.echo(f"\nChain integrity: {status}")
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    cli()
