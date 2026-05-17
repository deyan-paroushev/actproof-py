# Integration guide

This document is for downstream applications that want to anchor
their own evidence through actproof. The first such application is
Quoruna (verifiable governance decisions for private companies). The
guidance here is the path that integration follows.

## What actproof is and is not

actproof is a substrate library. It provides:

- RFC 8785 canonical JSON.
- RFC 3161 trusted timestamps (with multi-TSA failover and chain
  validation).
- An ARC-2 disclosed-mode note format for on-chain commitments.
- An Algorand anchoring path that takes a manifest hash and produces
  an on-chain receipt.
- An independent verifier that re-derives every check from public
  inputs.

actproof is not:

- A receipt schema registry. Downstream applications define their own
  manifest fields under their own catalogue.
- A storage layer. Receipts and evidence files belong to the
  application.
- A signing-policy framework. The signer enforces a strict anchoring
  shape; non-anchoring transactions are out of scope.

## Recommended integration shape (v0.3.0)

The clean integration is "thin consumer":

```python
from actproof import anchor_manifest, AnchorMode, build_manifest
from actproof.signers import GoogleKMSSigner

# 1. Build your manifest using your application's catalogue.
manifest = build_manifest(
    issuer=...,
    claim=...,
    evidence=...,
    recipients=...,
    catalogue_binding=...,
)

# 2. Compute the manifest hash (SHA-256 of canonical JSON).
manifest_hash = hash_manifest(manifest)

# 3. Construct the signer. The key never leaves GCP KMS.
signer = GoogleKMSSigner(
    kms_resource_name=settings.ACTPROOF_KMS_RESOURCE_NAME,
)

# 4. Anchor.
anchor_record = anchor_manifest(
    manifest_hash,
    signer=signer,
    mode=AnchorMode.PRODUCTION,
    wait_for_confirmation=True,
)
```

The anchor builds an ARC-2 note with the default `actproof:j` prefix,
submits a 0-ALGO self-payment to the signer's address, and returns an
`AnchorRecord` you can drop into your own receipt.

## Requirements declaration

Downstream applications that use `GoogleKMSSigner` must install the
GCP optional extra:

```
actproof[gcp]==0.3.0
```

NOT plain `actproof==0.3.0`. Plain installs leave
`google-cloud-kms` and `google-crc32c` absent; instantiating
`GoogleKMSSigner` then raises a clear `RuntimeError` with the install
hint.

## Note prefix

In v0.3.0 the recommended note prefix is the default `actproof:j`. The
signer accepts a configurable `allowed_note_prefixes` argument, but
the bundled `actproof.anchor.build_transaction` and
`actproof.verify._check_anchor_on_chain` are hardcoded to the default
prefix. Using a custom prefix requires bringing your own anchor
builder and verifier, which is out of scope for the v0.3.0
integration story.

A future release may make the prefix configurable end-to-end; this is
tracked in `docs/ANCHOR_BACKENDS.md` as part of the v0.4.0 anchor-
backend abstraction.

## What NOT to do

- **Do not maintain a parallel local KMS signer.** The actproof signer
  enforces strict transaction validation (rejects `rekey_to`,
  `close_remainder_to`, `group`, `lease`, non-payment types, fees
  above 1000 microALGO). Reimplementing that policy locally adds
  maintenance burden and the risk of drift.
- **Do not pass `allowed_note_prefixes=b"yourdapp/v1:"` while using
  `actproof.anchor_manifest()`.** The signer will accept your note
  but the bundled anchor builder will produce an `actproof:j` note,
  which the signer will then reject. End-to-end mismatch.
- **Do not pass per-byte fee rates expecting the signer to accept
  them.** `actproof.anchor.build_transaction` forces a flat 1000
  microALGO fee internally; the signer enforces the same upper bound.
  Callers who legitimately need higher fees during congestion should
  construct the signer with `max_fee_microalgos=<n>` AND bring their
  own transaction builder (the bundled builder always forces 1000).

## Verification

The actproof verifier resolves any anchor through the public Algorand
indexer (no API keys required) and re-derives every check from public
inputs:

```python
from actproof import verify_receipt

result = verify_receipt(receipt, catalogue=catalogue)
if result.ok:
    for check in result.checks:
        print(f"{check.name}: {check.status.value}")
```

For the strongest evidence statement, ensure all material checks pass
(not just `result.ok` which currently treats SKIP as OK; a stricter
`fully_verified` mode is planned for v0.3.1).
