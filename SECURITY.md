# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

The project follows semantic versioning. Pre-1.0.0 minor versions may receive
security fixes; older minor versions on the 0.x line will not be backported
to once a newer minor lands.

## Reporting a vulnerability

Please report security vulnerabilities by email to **security@advisa.tech**.

- Expected acknowledgment within 5 business days.
- Coordinated disclosure: default 90-day window from acknowledgment to public
  disclosure; the window can be accelerated or extended by mutual agreement.
- Please do not open public GitHub issues for security reports. Use the email
  channel above so a fix can be prepared before the issue becomes public.

If you prefer encrypted email, please request a PGP key via the same address.

## Scope

In scope for the security policy:

- Correctness of canonical JSON serialization (RFC 8785) for receipt envelopes
  and manifests
- Correctness of manifest hashing and the resulting `manifest_hash`
- Correctness of RFC 3161 trusted-timestamp token acquisition, parsing, and
  verification
- Correctness of Algorand ARC-2 note payload construction and round-tripping
- Correctness of the receipt envelope structure, including the catalogue
  binding (commit hash and entry hash pinning)
- Correctness of the verifier's per-check results (PASS, FAIL, SKIP) and the
  exit-code mapping in the CLI
- Authentication and authorization of operations that take signing material
  (mnemonic env var, GCP KMS resource path)
- Behaviour of the public Python API surface (`actproof.*` exports listed in
  `__init__.py`)

## Out of scope

The substrate intentionally takes no position on:

- **Legal sufficiency** of any document referenced by a receipt. The substrate
  produces verifiable evidence trails; legal sufficiency is determined by the
  relevant authority, not by `actproof`.
- **Regulatory acceptance** of any compliance evidence. National authorities
  and EU competent authorities determine acceptance of compliance evidence
  under the regulation each receipt cites; `actproof` does not.
- **Truthfulness of source documents.** The substrate verifies integrity,
  timing, issuer signature, catalogue classification, and ledger anchor. It
  does not verify whether the underlying document's claims are factually
  correct.
- **Algorand finality guarantees.** Once a transaction is confirmed and
  indexable, `actproof` treats the note as anchored. Underlying blockchain
  finality is the responsibility of the network.
- **Issuer key management.** If the issuer's signing key is compromised, the
  attacker can issue receipts that pass verification. Key rotation, HSM
  policies, and access controls are the issuer's responsibility.
- **GCP Cloud KMS service security.** When using the `GoogleKMSSigner`, the
  security of the KMS service itself is Google Cloud's responsibility.
- **Trusted Timestamping Authority (TSA) legal qualification.** The substrate
  verifies the technical validity of an RFC 3161 token returned by a TSA. It
  does not assert that the TSA holds eIDAS qualified status; consumers needing
  qualified-trust-service guarantees must validate the TSA's status through
  the EU Trusted List separately.
- **Catalogue semantics.** The substrate verifies that a receipt's
  `catalogue_binding` matches the catalogue commit hash and entry hash it
  claims. It does not assert that the catalogue entry's specification
  accurately reflects the legal or regulatory requirement it cites.

## Reporter recognition

Security reporters who follow coordinated disclosure are credited in
`CHANGELOG.md` for the release that contains the fix, unless they request
otherwise.
