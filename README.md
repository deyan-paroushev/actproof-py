# actproof

Verifiable receipts of regulated acts. Canonical JSON (RFC 8785), RFC 3161
trusted timestamps, Algorand ARC-2 anchoring, independent verification by
any party with a Python install.

`actproof` produces cryptographic receipts that any third party can verify
without trusting the issuing platform. A receipt binds: the regulated act
being recorded (from the `actproof-events` catalogue), the canonical JSON
of the issuer's evidence, a qualified timestamp from a trusted timestamp
authority, and a transaction on the Algorand public ledger that carries
the same hash. The verifier reproduces the bytes locally and confirms each
binding.

## What actproof does not claim

The substrate creates verifiable evidence trails. It does not:

* **make documents compliant** with any regulation.
* **certify compliance** or guarantee regulatory acceptance by any authority.
* **prove legal sufficiency** of any document. Legal sufficiency is determined
  by the relevant authority, not by `actproof`.
* **verify the truthfulness** of the source documents the issuer submits.
  The verifier confirms integrity, timing, issuer signature, catalogue
  classification, and ledger anchor. Underlying document truth is the
  issuer's responsibility.

See [SECURITY.md](SECURITY.md) for the full scope and out-of-scope statement.

## What actproof does

```
   ┌─────────────────┐
   │  JSON manifest  │  ← act_type_id from actproof-events catalogue
   │  (your event)   │     claim block + evidence + recipients + issuer
   └────────┬────────┘
            │
            │  1. canonicalize per RFC 8785 (deterministic bytes)
            │  2. SHA-256 → manifest_hash
            ▼
   ┌─────────────────┐     ┌──────────────────┐
   │  manifest_hash  │ ──→ │ RFC 3161 token   │  ← QuoVadis / Sectigo /
   │  (32 bytes)     │     │ from a QTSP      │     Belgium / Izenpe /
   └────────┬────────┘     └──────────────────┘     DigiCert / freetsa
            │                       │
            │     ┌─────────────────┘
            │     │
            ▼     ▼
   ┌─────────────────────────────────────────┐
   │  Algorand transaction (mainnet)         │
   │    note: actproof:j{"h":...,"t":...}   │
   │    txid: ABCDEF... (52 base32 chars)    │
   │    sender = receiver = signer's address │
   │    amount: 0                            │
   └────────┬────────────────────────────────┘
            │
            │
            ▼
   ┌─────────────────────────────────────────┐
   │  Receipt JSON                           │
   │    manifest (full)                      │
   │    manifest_hash                        │
   │    anchor (txid, block_round, network)  │
   │    trusted_timestamp (TSA token)        │
   │    receipt_profile = actproof-jcs-v1   │
   └─────────────────────────────────────────┘
```

Any verifier with the receipt can independently confirm: the manifest was
canonicalized correctly, its hash matches the on-chain note bytes, the
RFC 3161 token timestamps that hash, the manifest validates against the
catalogue at the named commit. No trust in the issuing platform is needed.

## Install

```bash
pip install actproof
```

For production anchoring with Google Cloud KMS (Ed25519 keys held in
HSM-backed KMS, never exposed to process memory):

```bash
pip install 'actproof[gcp]'
```

## Quick start (CLI)

```bash
# Verify a receipt end-to-end (no platform trust needed)
actproof verify receipt.json \
    --catalogue ./actproof-events/catalogue/acts \
    --git-commit a1b2c3d4... \
    --source-uri https://github.com/deyan-paroushev/actproof-events

# Validate a manifest against a local checkout of actproof-events
actproof validate manifest.json \
    --catalogue ./actproof-events/catalogue/acts \
    --git-commit a1b2c3d4... \
    --source-uri https://github.com/deyan-paroushev/actproof-events

# Anchor a manifest in draft mode (no submission, just build the note)
export ACTPROOF_MNEMONIC="your 25-word algorand mnemonic"
actproof anchor manifest.json \
    --mode draft \
    --output receipt.json \
    --skip-timestamp
```

Mnemonic in env var only; the CLI does NOT accept mnemonics via
command-line args (they would leak to shell history and the kernel
process table).

## Quick start (Python API)

```python
import actproof

# Load the actproof-events catalogue at a pinned git commit.
cat = actproof.load_catalogue(
    acts_path="./actproof-events/catalogue/acts",
    source_uri="https://github.com/deyan-paroushev/actproof-events",
    git_commit="a1b2c3d4...",
)
nis2 = cat.get("op:eu.nis2.art20.management_body_approval.v1")

# Build a manifest.
manifest = actproof.build_manifest(
    act_type_id=nis2.act_type_id,
    catalogue_entry_version=nis2.version,
    catalogue_source_uri=cat.source_uri,
    catalogue_git_commit=cat.git_commit,
    catalogue_entry_hash=nis2.entry_hash,
    catalogue_schema_hash=cat.schema_hash,
    issuer_org_name="Acme AD",
    issuer_authority_label="Management Body",
    title="NIS2 Article 20 approval, May 2026",
    claim={...},  # per the catalogue entry's claim_schema
    evidence=[...],  # files with their hashes
    recipients=[...],
    issued_at="2026-05-14T08:23:11Z",
)

# Validate the manifest before anchoring.
issues = actproof.validate_manifest(manifest, cat)
assert not issues, issues

# Get an RFC 3161 timestamp.
result = actproof.acquire_timestamp_token(
    actproof.hash_manifest(manifest)
)
token = result.token

# Anchor (DRAFT mode here; switch to DEMO or PRODUCTION for real).
import os
signer = actproof.MnemonicSigner(os.environ["ACTPROOF_MNEMONIC"])
anchor = actproof.anchor_manifest(
    actproof.hash_manifest(manifest),
    signer=signer,
    mode=actproof.AnchorMode.DRAFT,
)

# Build and write the receipt.
receipt = actproof.build_receipt(
    manifest=manifest,
    anchor=anchor,
    trusted_timestamp=token,
)
actproof.write_receipt("receipt.json", receipt)

# Anyone with the receipt can verify it.
loaded = actproof.read_receipt("receipt.json")
result = actproof.verify_receipt(loaded, catalogue=cat)
print(f"Verification: {'OK' if result.ok else 'FAIL'}")
for check in result.checks:
    print(f"  {check.name}: {check.status.value}")
```

## Architecture

actproof composes five published standards rather than inventing new ones:

* **RFC 8785** (JSON Canonicalization Scheme) for deterministic manifest
  bytes. Same manifest, anywhere, produces the same bytes, produces the
  same hash. Verifiers re-derive the canonical form from the receipt's
  embedded manifest.

* **RFC 3161** (Time-Stamp Protocol) for qualified timestamps. The default
  chain falls over six TSAs in priority order: four EU-qualified
  candidates (Sectigo Qualified, QuoVadis EU, Izenpe, Belgium TSA), then
  two public fallbacks (DigiCert, freetsa.org).

* **ARC-2** (Algorand Application Reference Convention 2) for the on-chain
  note format. Disclosed-mode JSON payload after the `actproof:j` prefix.
  Single SHA-256 anchor today; the format is forward-compatible with
  Merkle-batched anchors for higher-throughput scenarios.

* **actproof-events catalogue** (sibling repository) for the regulatory
  act types. Each act type has a JSON schema for its claim block, a list
  of regulatory citations, a list of evidence labels, and a signature
  policy. Versioned, git-pinned, immutable per commit.

* **RFC 9943 / IETF SCITT** (Supply Chain Integrity, Transparency, and
  Trust) reserved for a v2 wire format. The receipt's `receipt_profile`
  discriminator (`actproof-jcs-v1` today) lets verifiers route to the
  v2 parser when COSE_Sign1 + SCITT Transparent Statement becomes
  standardised.

## What's NOT in v0.1.0

* **EU Trusted List chain validation** for RFC 3161 tokens. The current
  verifier checks the token is well-formed and self-consistent; full
  chain validation against EUTL is v0.2.x.
* **Conformance test vectors** for cross-implementation interop. The
  conformance suite lands in v0.3.0.
* **GitHub Action wrapper** for one-call anchoring from a CI step. Lands
  in v0.2.0.
* **Worked examples** for NIS2, EUDR, and software-release use cases.
  Land in v0.2.0.

## License

MIT. The actproof-events catalogue is CC0 / Apache-2.0.
