# Distributed Key Vault

A production-quality CLI tool that splits a secret using **Shamir's Secret Sharing (SSS)** into *n* encrypted shares with a *k*-of-*n* reconstruction threshold.  No single party can reconstruct the secret with fewer than *k* shares.

---

## Security Model

| Property | Detail |
|---|---|
| Algorithm | Shamir's Secret Sharing over F_p (secp256k1 prime, 256-bit) |
| Threshold | k-of-n: information-theoretically secure — *k-1* shares reveal **zero** information |
| Share encryption | AES-256-GCM with PBKDF2-SHA256 (600 000 iterations, random salt per share) |
| Randomness | OS CSPRNG by default; optional Qiskit-backed quantum random generation with `--use-quantum` |
| Share verification | Feldman Verifiable Secret Sharing — detect corrupted/tampered shares before reconstruction |
| Audit trail | Hash-chained, append-only audit log — tampering is detectable |
| Replay protection | Per-reconstruction session with 300-second expiry and per-share duplicate rejection |

---

## Installation

```bash
git clone <repo-url>
cd distributed-key-vault
pip install -r requirements.txt
```

---

## CLI Usage

### Split a secret

```bash
python cli.py split \
  --shares 5 \
  --threshold 3 \
  --output-dir shares/
# Prompts for the secret (hidden) and a password for each custodian
```

### Use quantum random generation

To opt into Qiskit-backed quantum random generation for a CLI run, pass `--use-quantum` before the command:

```bash
python cli.py --use-quantum split \
  --shares 5 \
  --threshold 3 \
  --output-dir shares/
```

### Reconstruct

```bash
# From a directory
python cli.py reconstruct --shares-dir shares/

# From specific files
python cli.py reconstruct \
  --share-files shares/share_1.json \
  --share-files shares/share_3.json \
  --share-files shares/share_5.json \
  --commitments shares/commitments.json
```

### Verify a single share

```bash
python cli.py verify \
  --share-file shares/share_2.json \
  --commitments shares/commitments.json
# Prints VALID or INVALID
```

### View the audit log

```bash
python cli.py audit --log-file audit_log.json --verify-chain
```

---

## Architecture

```
distributed-key-vault/
├── vault/
│   ├── sss.py        Shamir's Secret Sharing (Lagrange interpolation over F_p)
│   ├── feldman.py    Feldman VSS — commitment-based share verification
│   ├── crypto.py     AES-256-GCM encryption + PBKDF2 key derivation
│   ├── audit.py      Hash-chained append-only audit log
│   ├── session.py    Nonce + timestamp replay-attack protection
│   └── vault.py      Orchestrator combining all modules
├── cli.py            Click CLI (split / reconstruct / verify / audit)
├── demo.py           Self-contained end-to-end demo
└── tests/            pytest test suite
```

### Module interactions

```
cli.py → vault.py
           ├── sss.py        (split / reconstruct)
           ├── feldman.py    (verify shares against commitments)
           ├── crypto.py     (AES-GCM encrypt / decrypt each share)
           ├── session.py    (replay protection during reconstruct)
           └── audit.py      (append-only hash-chain log)
```

---

## Running tests

```bash
pytest tests/ -v
```

---

## Running the demo

```bash
python demo.py
```

The demo:
1. Splits `"MyMasterPassword123!"` into 5 shares (threshold 3)
2. Prints encrypted shares (truncated)
3. Reconstructs from shares 1, 3, 5
4. Verifies share 2 independently
5. Prints the audit log with chain-integrity check
6. Demonstrates tamper detection by corrupting a share
