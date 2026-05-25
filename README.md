# actproof

Verifiable evidence receipts for institutional records, regulated acts, and
public attestations. Canonical JSON (RFC 8785), RFC 3161 trusted timestamps,
Algorand ARC-2 anchoring, independent verification by any party with a Python
install.

**Project site: [actproof.org](https://actproof.org).** The site explains
the full ActProof stack and the reasoning behind it. ActProof Events
defines the act, `actproof` proves the record, and applications consume
both. Start there for the architecture. This README is the package
reference.

`actproof` produces cryptographic receipts that any third party can verify
without trusting the issuing platform. A receipt binds: the record or act
being documented (optionally classified against the `actproof-events`
catalogue for regulated acts), the canonical JSON of the issuer's evidence,
a qualified timestamp from a trusted timestamp authority, and a transaction
on the Algorand public ledger that carries the same hash. The verifier
reproduces the bytes locally and confirms each binding.

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

## Independent use outside Quoruna

`actproof` is a standalone Python library. It does not require Quoruna, an
account, a hosted service, or any vendor trust. The intended use cases:

* **Regulated industries.** Compliance evidence with verifiable timestamps:
  pharma batch records, financial reporting attestations, NIS2 incident
  reports, EUDR due-diligence statements, AI Act risk assessments.
* **Civil society and journalism.** Verifiable provenance of reporting,
  research outputs, and document releases without a trusted intermediary.
* **Academic research.** Pre-registration of analysis plans, anchored
  research artifacts, reproducibility receipts.
* **Public-sector records.** Public decisions, council resolutions,
  procurement evidence, transparency anchors.
* **Other receipt and attestation systems.** Any application that today
  emits "trust us" PDFs can emit an actproof receipt instead and let the
  recipient verify without contacting the issuer.

Quoruna is one consuming application. It is not the only intended
consumer. The library API is independent of any particular product or
hosted service.

## API stability

The package currently exposes a deliberately large API surface to let
adopters work at whatever level suits them. Before the v1.0 release,
the following discipline applies:

* **Stable.** `canonicalize`, `hash_canonical`, `hash_canonical_hex`,
  `build_manifest`, `manifest_to_dict`, `manifest_from_dict`,
  `hash_manifest`, `hash_manifest_hex`, `Receipt`, `read_receipt`,
  `write_receipt`, `verify_receipt`, `CheckResult`, `VerificationResult`.
  These will not break between minor versions before v1.0.
* **Experimental.** `Catalogue`, `validate_manifest`, RFC 3161 TSA
  chain configuration, the `AnchorMode` enum, and the signer
  abstraction. Subject to refinement before v1.0.
* **Internal-but-exported.** Constants like `IJSON_MAX_SAFE_INT`,
  `ARC2_NOTE_FORMAT`, and `SCHEMA_DISCRIMINATOR_V3`. Available for
  power users but may change.

The full list is in `actproof/__init__.py`. v1.0.0 will declare the final
stable surface and freeze it under semantic versioning.

## Roadmap

* **v0.4.0** — Pluggable anchor backend architecture (`AnchorBackend`
  Protocol). Algorand stays as the production backend; the protocol
  abstraction makes Hedera Consensus Service, Stellar memo-hash, Bitcoin
  OP_RETURN, and Ethereum implementations feasible without changes to
  the canonicalisation, receipt, or verifier code. Also migrates off
  `tsp-client` 0.2.1 onto `rfc3161-client` (Trail of Bits) to remove
  the legacy pyOpenSSL cap.
* **v0.5.0** — Receipt profile registry. Explicit named profiles
  (`actproof-jcs-v1`, `actproof-algorand-arc2-v1`, `actproof-rfc3161-v1`)
  and a stable verifier dispatch surface for adopters.
* **v1.0.0** — Stable API frozen. Conformance test vectors finalised.
* **v2.0.0** — COSE_Sign1 + SCITT Transparent Statement bridge once
  RFC 9943 publishes.

## What actproof does NOT yet ship

* **EU Trusted List chain validation** for RFC 3161 tokens. The current
  verifier checks the token is well-formed and self-consistent; full
  chain validation against EUTL is on the v0.5.x roadmap.
* **GitHub Action wrapper** for one-call anchoring from a CI step.
* **Worked end-to-end examples** for NIS2, EUDR, AI Act, and
  software-release use cases. Conformance vectors and example receipts
  land in `examples/` and `docs/CONFORMANCE_VECTORS.md` in v0.3.x.

## License

Apache-2.0. See `LICENSE`. The `actproof-events` catalogue (sibling
repository) is CC0 / Apache-2.0.

## Why Apache-2.0

`actproof` is intended as reusable verification infrastructure. Apache-2.0
provides:

* The same broad permission to embed in commercial or proprietary work
  as MIT.
* An explicit contributor patent licence (Section 3 of the licence text),
  which matters for cryptographic and protocol code.
* A clearer legal posture for institutional and public-sector adopters.

If you previously consumed `actproof <= 0.3.1` under MIT, those releases
remain available on PyPI under MIT. All `actproof >= 0.3.2` releases are
governed by Apache-2.0.
