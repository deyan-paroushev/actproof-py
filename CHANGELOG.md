# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, breaking changes may occur in any minor or patch
release. Once 1.0.0 ships, semantic versioning will be strictly followed.

## [Unreleased]

### Planned

- **v0.4.0** — Pluggable anchor backend architecture. Generalize the chain-agnostic substrate (canonicalization, RFC 3161 timestamps, receipt format, verifier) into an `AnchorBackend` protocol with chain-specific implementations (Hedera Consensus Service, Stellar memo-hash, Bitcoin OP_RETURN, Ethereum). See `docs/ANCHOR_BACKENDS.md` for the design intent.
- **v1.0.0** — API frozen.
- **v2.0.0** — COSE_Sign1 + SCITT Transparent Statement bridge, once RFC 9943 publishes.

## [0.3.0] — 2026-05-17

**Security hardening release.** Closes a transaction-validation gap present in v0.2.0. See `SECURITY.md` for the advisory.

### Security

- **`AlgorandSigner.validate_transaction` now rejects attack-vector fields unconditionally.** `rekey_to`, `close_remainder_to`, `group`, and `lease` are rejected on every transaction. v0.2.0 accepted these fields if the sender, receiver, amount, and note prefix passed validation; a `rekey_to=attacker` payment was therefore accepted as a benign-looking 0-ALGO self-payment. This is the same attack class that drained roughly 3.3 million USD across 25 accounts in the February 2023 MyAlgo wallet incident.
- **Transaction type restricted to `PaymentTxn`.** v0.2.0 accepted any `algosdk.transaction.Transaction` subclass. v0.3.0 rejects `AssetTransferTxn`, `ApplicationCallTxn`, `KeyregTxn`, and any other non-payment type.
- **Fee bounded and forced flat.** `txn.fee` must lie in `[ALGORAND_MIN_FEE_MICROALGOS, max_fee_microalgos]` (default 1000 microALGOs). `build_transaction` now forces `flat_fee=True` and `fee=1000` on the copy of `SuggestedParams` it passes to `PaymentTxn`, so per-byte fee rates returned by algod under congestion do not produce a transaction the signer would reject.
- **Note size bounded.** New constant `ALGORAND_MAX_NOTE_BYTES = 1024` enforced explicitly by the signer before any KMS call.
- **`GoogleKMSSigner`: fail-closed end-to-end integrity verification.** Every KMS call now requires `response.name == request.name`, `response.verified_data_crc32c is True`, `crc32c(signature) == response.signature_crc32c`, and `len(signature) == 64`. Same pattern for `get_public_key` (`response.name`, `pem_crc32c`). v0.2.0 used `hasattr(...)` guards that silently bypassed missing fields; v0.3.0 raises `RuntimeError` if any required field is missing or invalid. Implementation follows Google's recommended pattern documented at `cloud.google.com/kms/docs/data-integrity-guidelines`.
- **`_assemble_signed_transaction` validates signature length.** Refuses to wrap a non-64-byte signature into a `SignedTransaction` (Ed25519 signatures are always 64 octets per RFC 8032).
- **Release workflow now runs the test suite before publishing.** `.github/workflows/release.yml` adds a pytest gate plus wheel smoke-test job that the publish job depends on. A failing test now blocks the PyPI upload.

### Changed

- **`AlgorandSigner.__init__` accepts `allowed_note_prefixes` and `max_fee_microalgos` only.** The earlier v0.3.0 draft had also exposed `require_self_payment` and `require_zero_amount` as configurable booleans; these were removed because disabling them turned the signer into a general-purpose Algorand signing adapter, broader than its stated scope. The strict 0-ALGO self-payment shape is now a non-configurable invariant.
- **`allowed_note_prefixes` accepts a single `bytes` value.** Passing `allowed_note_prefixes=b"quoruna/v1:"` now works without wrapping in a list. The constructor also raises a clearer `TypeError` when a non-bytes element is found.
- **`__init_subclass__` walks the full MRO.** Forbidden method names inherited via mixin (`class BadSigner(RawSigningMixin, AlgorandSigner)`) are now caught at class-definition time, not only methods defined directly on the subclass.
- **`validate_transaction` fails closed on missing `super().__init__()`.** Earlier drafts silently set defaults if a subclass forgot to call the base init. v0.3.0 raises `RuntimeError` listing every missing policy attribute.
- **GCP KMS protection level wording.** Module and class docstrings no longer claim "HSM-backed" unconditionally. The signer accepts keys with any protection level (`SOFTWARE`, `HSM`, `HSM_SINGLE_TENANT`, `EXTERNAL`); operators who need HSM-residency guarantees should create the key version accordingly.
- **`GoogleKMSSigner` without `[gcp]` deps.** Previously `actproof.signers.GoogleKMSSigner` was set to `None` if the GCP optional dependencies were missing, producing a confusing `TypeError: 'NoneType' object is not callable` on instantiation. v0.3.0 substitutes a stub subclass that raises a clear `RuntimeError` with the install command.
- **`tsp-client` dependency loosened to `>=0.2.1,<0.3`.** Downstream applications that pull a slightly newer compatible patch release are no longer blocked by the exact-pin requirement.

### Added

- `ALGORAND_MIN_FEE_MICROALGOS`, `ALGORAND_DEFAULT_MAX_FEE_MICROALGOS`, `ALGORAND_MAX_NOTE_BYTES` constants on `actproof.signers.interface`.
- New test module `tests/test_signers_v030_policy.py` with 52 tests covering the rejection paths above plus KMS response-verification fail-closed semantics. Includes a cryptographic-equivalence regression test that confirms v0.3.0 produces byte-identical signatures to v0.2.0 for the original strict-policy use case.
- Two new tests in `tests/test_anchor.py` for `build_transaction`: confirms the resulting transaction carries `fee=1000` regardless of caller-supplied fee rate, and confirms the caller's `SuggestedParams` object is not mutated.
- `SECURITY.md` documenting the v0.2.0 gap, the v0.3.0 fix, and the threat model. Now included in the sdist.
- `docs/ANCHOR_BACKENDS.md` design note for v0.4.0 multi-chain anchor abstraction.
- `docs/INTEGRATION.md` integration guide for downstream applications consuming actproof.
- `actproof/py.typed` PEP 561 marker so downstream type-checkers honor inline annotations.

### Migration from v0.2.0

Existing callers using the strict actproof policy (default constructors, anchoring with `actproof:j{...}` notes, 0-ALGO self-payments, fee 1000) see no behavioural change: the signed bytes are byte-identical. Previously-accepted transactions carrying `rekey_to`, `close_remainder_to`, `group`, `lease`, fees above 1000 microALGOs, or notes longer than 1024 bytes are now rejected with `SignerValidationError`. Audit your transaction-construction code to confirm none of these fields should have been set; for a higher `fee` ceiling during network congestion, pass `max_fee_microalgos=<n>` to the signer constructor.

Callers of any earlier v0.3.0 draft that used `require_self_payment=False` or `require_zero_amount=False` need to refactor: those kwargs were removed. If you need to sign other transaction shapes, write your own `AlgorandSigner` subclass and override `validate_transaction`.

### Acknowledgements

Independent review by ChatGPT (May 2026, three review rounds) flagged the original `rekey_to`/`close_remainder_to` gap, the KMS integrity-check weakening, the MRO walk gap, the configurable-policy footgun, the test-gating mistake, the flat-fee deployment issue, the release-workflow missing test gate, and seven additional release-quality items. All findings are addressed in this release.

## [0.2.0] — 2026-05-17

Version bump for the initial PyPI publication path. See [0.1.0] notes below for the substrate API description; v0.2.0 was the version that actually shipped to PyPI (the 0.1.0 slot was skipped per immutable-release policy).

## [0.1.0] — 2026-05-17

**First PyPI release of `actproof`.** This is the inaugural published version of the substrate library under its canonical name. The library is installable via `pip install actproof`.

### Project history

The code in this release was developed under the working name `openproof` on GitHub. The repository at `github.com/deyan-paroushev/openproof-py` was renamed to `github.com/deyan-paroushev/actproof-py` on 2026-05-17; the old URL auto-redirects to the new one. GitHub tags `v0.1.0` (initial public-API surface) and `v0.1.1` (additive schema v3 support) under the previous repository name are the development history of this code; this `v0.1.0` on PyPI is the first published release under the canonical name and supersedes both working-name tags.

The PyPI namespace under `openproof` is unrelated to this project.

### Public contract

- **PyPI distribution name:** `actproof`
- **Python import:** `actproof`
- **CLI command:** `actproof`
- **Receipt profile identifier:** `actproof-jcs-v1`
- **ARC-2 dApp name on Algorand notes:** `actproof`
- **Catalogue schema discriminators:** `actproof.act_catalogue_entry.v2` and `actproof.act_catalogue_entry.v3`
- **Catalogue act-type ID prefix:** `op:` (preserved as historical opaque identifier; migration deferred to v1.6)
- **Environment variables:** `ACTPROOF_CATALOGUE_PATH`, `ACTPROOF_MNEMONIC`

### Functional scope

This release ships the same functional API as the `openproof` working-name `v0.1.1` GitHub tag. 443 tests pass. No code path differs from the renamed source.

- **`actproof/canonical.py`** — JSON Canonicalization Scheme (RFC 8785) implementation. `canonicalize`, `canonicalize_str`, `canonicalize_from_json`, `hash_canonical`, `hash_canonical_hex`.
- **`actproof/manifest.py`** — Manifest construction and hashing. `build_manifest`, `manifest_to_dict`, `manifest_from_dict`, `hash_manifest`, `hash_manifest_hex`. Receipt profile constant `RECEIPT_PROFILE_V1 = "actproof-jcs-v1"`. Manifest validation surface (`validate_manifest_shape`, `ManifestValidationError`).
- **`actproof/catalogue.py`** — Catalogue loader supporting schema v2 (legacy) and schema v3 (current, with four optional sub-objects: `RegulatedContextProfile`, `PriorReceiptsProfile`, `RelianceContext`, `DisclosureProfile`). `load_catalogue`, `validate_manifest`, `hash_entry_file`, `hash_schema_file`.
- **`actproof/receipt.py`** — Receipt envelope, anchor record, timestamp token, issuer evidence (the holder receipt with salts retained). `ARC2_DAPP_NAME = "actproof"`. Receipt I/O (`read_receipt`, `write_receipt`, `read_issuer_evidence`, `write_issuer_evidence`).
- **`actproof/timestamp.py`** — RFC 3161 trusted-timestamp acquisition with multi-TSA failover. `acquire_timestamp_token`, `TimestampAuthority`, `TSAAttempt`, `AcquisitionResult`. Default TSA chain pre-configured with three EU qualified TSAs.
- **`actproof/anchor.py`** — Algorand ARC-2 anchoring. `anchor_manifest` (the high-level entry point), `build_note_payload`, `build_note_bytes`, `build_transaction`. Mainnet/testnet/betanet support.
- **`actproof/signers/`** — `AlgorandSigner` interface plus two implementations: `MnemonicSigner` (env-var-fed mnemonic) and `GoogleKMSSigner` (GCP Cloud KMS Ed25519-backed signer).
- **`actproof/verify.py`** — Six-check verification: profile, manifest hash, note payload, catalogue, anchor (ledger round-trip), timestamp. `verify_receipt`, `CheckResult`, `CheckStatus`, `VerificationResult`. `SUPPORTED_RECEIPT_PROFILES = ("actproof-jcs-v1",)`.
- **`actproof/cli.py`** — `actproof verify`, `actproof issue`, `actproof inspect`. Reads `ACTPROOF_MNEMONIC` env var; mnemonic NEVER from command-line argument.

### Added in this release (beyond the renamed source)

- **`SECURITY.md`** at the repo root. Vulnerability reporting policy. Scope statement (what is and is not protected by the substrate). Coordinated-disclosure timeline. Out-of-scope items explicitly enumerated (legal sufficiency, regulatory acceptance, source-document truthfulness, blockchain finality, issuer key management, TSA qualification status, catalogue semantics).
- **`.github/workflows/release.yml`** — GitHub Actions workflow for PyPI Trusted Publishing. Triggered by `release.published` event only (not tag push). Uses the `pypi` GitHub Environment with required-reviewer protection. Builds wheel + sdist, runs `twine check`, publishes via `pypa/gh-action-pypi-publish@release/v1`. PEP 740 Sigstore attestations enabled by default.

### Changed (the rename itself)

- **Package name:** `openproof` → `actproof` across all 26 Python files, 6 documentation files, and pyproject.toml. 311 source references and 133 documentation references updated. Directory `openproof/` renamed to `actproof/`. Imports `from openproof.X` become `from actproof.X`. CLI entry-point `openproof` becomes `actproof`. Environment variables `OPENPROOF_*` become `ACTPROOF_*`.
- **Receipt profile identifier:** `openproof-jcs-v1` → `actproof-jcs-v1`. This is a wire-protocol change visible in every receipt issued from v0.1.0 onward. Since the openproof working-name code never issued public production receipts (only mock/demo samples), no legacy alias is preserved.
- **ARC-2 dApp name:** `openproof` → `actproof`. The on-chain note prefix is `actproof:j` for JSON notes. The internal constant `_OPENPROOF_NOTE_PREFIX` is now `_ACTPROOF_NOTE_PREFIX = b"actproof:j"`.
- **Catalogue schema discriminator:** `openproof.act_catalogue_entry.v2` → `actproof.act_catalogue_entry.v2` (and v3). Since no public catalogues exist under the openproof working name beyond development snapshots, both discriminator strings are renamed. The matching change in `actproof-events` v1.5-rc1 lands in the same release window.
- **Environment variable names:** `OPENPROOF_CATALOGUE_PATH` → `ACTPROOF_CATALOGUE_PATH`. `OPENPROOF_MNEMONIC` → `ACTPROOF_MNEMONIC`. The `cli.py` references and the catalogue loader's env-var lookup are updated together.
- **pyproject.toml metadata:** description rewritten as "Verifiable receipts of regulated acts. Canonical JSON (RFC 8785), RFC 3161 trusted timestamps, Algorand ARC-2 anchoring, independent verification." Author/maintainer email added (`deyan@advisa.tech`). Keywords extended with `governance`, `evidence`, `transparency`. Classifiers extended with `Intended Audience :: Government`. Development Status remains `3 - Alpha` (API stability not yet promised across minor versions).
- **Project URLs:** updated to the new `actproof-py` repository URLs throughout, with `Security` added pointing to `SECURITY.md`.

### Notes for consumers

If you depended on the `openproof` working-name code via the git+https URL (`openproof @ git+https://github.com/deyan-paroushev/openproof-py.git@v0.1.1`), the upgrade path is:

1. Replace the requirement line with `actproof==0.1.0`.
2. Update imports: `from openproof.X import Y` → `from actproof.X import Y`.
3. Update CLI invocations: `openproof verify ...` → `actproof verify ...`.
4. Update environment variables: `OPENPROOF_CATALOGUE_PATH` → `ACTPROOF_CATALOGUE_PATH`, etc.
5. If you issued any receipts under the working name with `receipt_profile = "openproof-jcs-v1"`, those receipts will not verify against this release. Reissue with the new profile. (In practice, only demo receipts existed under the working name.)
6. Catalogue files using `"schema": "openproof.act_catalogue_entry.v3"` must update to `"schema": "actproof.act_catalogue_entry.v3"`. The matching catalogue release (`actproof-events` v1.5-rc1) ships with the renamed discriminator.

## Historical: working-name development under `openproof`

The entries below describe the development history under the working name `openproof`. They are preserved for transparency. Tags `v0.1.0` and `v0.1.1` exist in the git history of this repository; both were superseded by the canonical `v0.1.0` PyPI release described above.

### [openproof v0.1.1] — 2026-05-16

#### actproof-events schema v3 support

Additive support for actproof-events catalogue schema v3. v3 is a strict superset of v2: existing v2 catalogues load unchanged, v3 catalogues parse the four new optional sub-objects on each entry. Backward-compatible: no breaking changes to the public API. Consumers pinned to v0.1.0 reading v2 entries continue to work without modification.

The companion schema file `act_catalogue_entry.v3.json` lives in actproof-events. This release of actproof-py is what reads and validates entries against it.

### Added

- **`actproof/catalogue.py`** — Four new frozen dataclasses for the v3 optional sub-objects:
  - `RegulatedContextProfile` — constrains the receipt envelope `regulated_context` shape (allowed context types, allowed submission stages, default context type).
  - `PriorReceiptsProfile` — declares bilateral lifecycle expectations (required and optional `prior_receipts` roles).
  - `RelianceContext` — names the issuer role, counterparty action, later verifiers, and optional reliance statement.
  - `DisclosureProfile` — declares per-field disclosure tiers (`public_fields`, `commitment_fields`, `private_fields`) and `back_propagation_scope` mapping prior-receipt roles to field references visible in the automatic disclosure receipt generated at settlement.
- **`actproof/catalogue.py`** — Four new constants:
  - `SCHEMA_DISCRIMINATOR_V2` (= `"actproof.act_catalogue_entry.v2"`).
  - `SCHEMA_DISCRIMINATOR_V3` (= `"actproof.act_catalogue_entry.v3"`).
  - `SCHEMA_DISCRIMINATORS` (frozenset of the above two).
  - `SCHEMA_DISCRIMINATOR` retained as a backward-compatible alias for `SCHEMA_DISCRIMINATOR_V2`.
- **`actproof/catalogue.py`** — `CatalogueEntry` gains four optional fields (`regulated_context_profile`, `prior_receipts_profile`, `reliance_context`, `disclosure_profile`) defaulting to `None`. Fields are placed after the derived `source_path` and `entry_hash` fields so positional construction with the v2 field order continues to work.
- **`tests/test_catalogue_v3.py`** — 42 new tests in eight groups covering: v3 dataclass construction and immutability, discriminator constants, full and partial v3 entry parsing, missing-required-field error paths, schema file resolution preference (v3 > v2), mixed v2/v3 catalogues, backward compatibility (v2-only catalogues load identically, v3 blocks on v2 entries are ignored), and a regression check against the real actproof-events v1.4-rc1 catalogue. Existing `tests/test_catalogue.py` is unchanged; its 40 tests continue to pass.

### Changed

- **`actproof/catalogue.py`** — `_parse_entry` accepts either v2 or v3 discriminators. v3 entries with present optional blocks populate the corresponding `CatalogueEntry` fields; absent blocks leave them at `None`. v2 entries always yield `None` for all four v3 fields, even if the JSON happens to carry v3 keys (extras are tolerated, mirroring v0.1.0 permissiveness for unknown dict keys; the JSON schema file enforces strict `additionalProperties: false` for consumers that validate at the schema-file level).
- **`actproof/catalogue.py`** — `_scan_acts_directory` filter uses membership in `SCHEMA_DISCRIMINATORS` instead of equality with the single old discriminator. Files whose `schema` is unrecognised are silently skipped (unchanged behaviour for unrelated JSON files in the tree).
- **`actproof/catalogue.py`** — `_resolve_schema_path` tries `act_catalogue_entry.v3.json` first, falls back to `act_catalogue_entry.v2.json`. `Catalogue.schema_hash` reflects whichever file was found. Catalogues that ship the v3 schema file (actproof-events v1.5-rc1 and later) get the v3 hash; catalogues with only the v2 file (actproof-events v1.4-rc1 and earlier) get the v2 hash unchanged.
- **`actproof/catalogue.py`** — Error message for unrecognised discriminators in `_parse_entry` now names both accepted discriminators rather than just v2. Reachable only via direct `_parse_entry` calls; the directory walker silently skips unknown-discriminator files.
- **`actproof/__init__.py`**: version bumped to 0.1.1. Re-exports the four new dataclasses and three new constants at the package level (`from actproof import DisclosureProfile` works).
- **`pyproject.toml`**: version bumped to 0.1.1.

### Design notes

**Why v3 and not a relaxation of v2.** The four new sub-objects on each entry are not just new optional leaf fields; they introduce a structural concept (per-field disclosure tiers, multilateral bilateral propagation scope). Mutating what `"actproof.act_catalogue_entry.v2"` means while keeping the discriminator string the same would be cheap versioning: consumers that pinned to v2 would silently get a different contract. Clean v3 bump preserves the property that a discriminator string identifies a stable schema shape. v2-aware consumers continue to read v2 entries; v3-aware consumers read either.

**Why the v2 schema file stays in the repository.** Receipts issued against v1.4-rc1 entries are pinned to the v2 `schema_hash`. Verifying those receipts years later requires the v2 schema file at that hash. Removing it would break the receipt-binding chain. v2 and v3 schema files coexist; each receipt verifies against whichever was current at issue time.

**Why `SCHEMA_DISCRIMINATOR` is kept as an alias.** It was the only discriminator name exported by actproof v0.1.0. Renaming or removing it would break any external consumer that imported it. The alias makes the rename non-breaking. New code is encouraged to use `SCHEMA_DISCRIMINATOR_V2` and `SCHEMA_DISCRIMINATOR_V3` directly, and `SCHEMA_DISCRIMINATORS` for membership checks.

**Why the four new `CatalogueEntry` fields come after the derived fields.** Dataclass field order determines positional-construction order. Inserting the four new optional fields between the fifteen v2 wire-schema fields and the two derived fields would have shifted `source_path` and `entry_hash` positions, breaking any caller using positional construction of `CatalogueEntry` with the v2 layout. Putting the new fields at the end is semantically odd (wire-schema fields after derived fields) but kindlier to backward compatibility. `_parse_entry` uses keyword arguments throughout, so this is invisible to the loader.

**Type-level permissiveness is consistent across v2 and v3.** Wrong-type values inside present sub-objects (for instance, `public_fields: "not-a-list"` where a list is expected) do not raise in the Python loader. `tuple("not-a-list")` yields a tuple of characters, which is valid Python though semantically nonsense. This matches the existing v2 parser's permissiveness. Strict type validation is the JSON schema file's job, applied by external tooling such as `ajv` or `jsonschema`. The Python loader catches structural errors (missing required keys, wrong dict shape, non-iterable where iteration is needed) but not type-level errors. A separate hardening pass could tighten this uniformly across v2 and v3 in a future release if desired.

### Status: 485 tests across eleven modules

`tests/test_catalogue.py` (40 tests) + `tests/test_catalogue_v3.py` (42 tests) + all other test modules unchanged. Total actproof-py test count: 485 (up from 443 at v0.1.0).



### First usable release

The complete `actproof` library plus a working CLI. Every planned v0.0.x module has landed and is exercised by 423+ tests. v0.1.0 wires those modules into the `actproof` command-line tool, making the library usable end-to-end from a shell.

This is the version pushed to `main` on https://github.com/deyan-paroushev/actproof-py for the STS Standards Network application.

### Added

- **`actproof/cli.py`** — Click-based command-line interface, replacing the v0.0.1 placeholder. Three subcommands:
  - **`actproof anchor MANIFEST_PATH`** - read a manifest JSON file, optionally acquire an RFC 3161 timestamp, anchor to Algorand in the requested mode, write the resulting receipt.
    - `--mode {draft,demo,production}` (required, no default).
    - `--output PATH` (required) - where to write the receipt.
    - `--kms-resource PATH` - GCP KMS Ed25519 key version path for production signing. Mutually exclusive with the `ACTPROOF_MNEMONIC` env var.
    - `--skip-timestamp` - skip RFC 3161 acquisition (offline testing only).
    - `--wait/--no-wait` - poll algod until confirmation (default: wait).
    - `--evidence-output PATH` - optional path to write the issuer evidence JSON (private addendum).
  - **`actproof verify RECEIPT_PATH`** - read a receipt and run the six checks from `actproof.verify`. Exits 1 on any failure.
    - `--catalogue PATH` - optional actproof-events catalogue path.
    - `--git-commit SHA` - required when `--catalogue` is provided.
    - `--source-uri URI` - required when `--catalogue` is provided.
    - `--skip-anchor`, `--skip-timestamp` - skip the respective checks.
    - `--json` - JSON output for scripting.
  - **`actproof validate MANIFEST_PATH`** - validate a manifest against an actproof-events catalogue.
    - `--catalogue PATH`, `--git-commit SHA`, `--source-uri URI` (all required).
    - `--json` - JSON output for scripting.
- Each command supports `--help` (Click default) and exits with conventional codes: 0 on success, 1 on operational failure, 2 on usage error.
- Top-level `--verbose` flag enables DEBUG logging to stderr.
- `--version` flag prints the actproof version.

- **`tests/test_cli.py`** — 19 tests across six groups using Click's `CliRunner`. Covers `--version` and `--help`, validate happy path / JSON / catches unknown act / missing file, verify honest / tampered / skip-catalogue / JSON / requires-git-commit, anchor DRAFT-with-mnemonic / mode-required, anchor signer selection error paths (no source / both sources), exit codes. All tests offline; no real algod or TSA calls.

### Changed

- **`pyproject.toml`**: version bumped to 0.1.0. Development Status classifier moves from "2 - Pre-Alpha" to "3 - Alpha" reflecting feature completeness.
- **`actproof/__init__.py`**: version bumped to 0.1.0. No new public Python API (CLI is invoked via the `actproof` binary, not via import).
- **`README.md`**: rewritten to reflect that actproof is now a usable tool. Architecture diagram, install instructions, Quick Start sections for both CLI and Python API, honest scope statement of what v0.1.0 does NOT include.

### Design notes

**Mnemonic via env var only.** The CLI does NOT accept mnemonics as command-line arguments. Command-line args leak to shell history (`~/.bash_history`, `~/.zsh_history`), to the kernel's process table (visible via `ps aux` to other users on shared systems), to docker layer metadata, and to log aggregation systems. The env var path (`ACTPROOF_MNEMONIC`) is the lower-risk channel; the env var lives only in the shell session that invoked the command and is dropped when the process exits. Production users avoid mnemonics entirely and use `--kms-resource` for GCP KMS signing.

**Mode is required on `actproof anchor`.** No silent default. A user who runs `actproof anchor manifest.json --output receipt.json` gets a Click usage error pointing at the `--mode` flag, not a quiet submission to mainnet because someone changed the default. This is the same principle as the `anchor_manifest()` Python API: explicit choice is the only valid choice.

**No "anchor and verify" combined command.** Some early designs had a `commit` subcommand that anchored and then immediately verified. Removed: separating anchor from verify keeps the security model clean (the verifier is independent of the issuer), keeps the failure modes legible (verify failures after anchor are someone else's job to detect, not the issuer's job to silently retry), and matches the actual workflow (anchor at issuance time, verify at audit time, possibly years later).

**JSON output is opt-in via `--json`.** Default is human-readable colorised output (ANSI colors for terminals, plain text when stdout is redirected). Scripts wanting structured output pass `--json` and parse the result. This split keeps the human path obvious and the machine path explicit.

**Click chosen over argparse.** Click's group/command/option model maps cleanly to subcommands. Click's automatic help generation, automatic env-var binding (`envvar=`), automatic file-exists validation (`click.Path(exists=True)`), and `CliRunner` for testing each save substantial boilerplate over argparse equivalent. The added dependency cost (one pure-Python library) is modest.

### Status: v0.0.x → v0.1.0 milestone reached

This release closes the v0.0.x build phase. Every module in the architecture is implemented, tested, and exposed:

- `canonical.py` (v0.0.2) - RFC 8785 JCS wrapper.
- `manifest.py` (v0.0.3) - the canonical envelope schema.
- `catalogue.py` (v0.0.4) - actproof-events catalogue loader and validator.
- `receipt.py` (v0.0.5) - the artifact, public + private split.
- `timestamp.py` (v0.0.6) - RFC 3161 acquisition with QTSP failover.
- `anchor.py` (v0.0.7) - ARC-2 disclosed-mode Algorand submission.
- `signers/` (v0.0.8) - the AlgorandSigner ABC, MnemonicSigner, GoogleKMSSigner.
- `verify.py` (v0.0.9) - the six-check audit-facing verifier.
- `cli.py` (v0.1.0) - the Click-based command-line tool.

Total: 442 tests across ten modules, all passing offline. Next: v0.2.0 adds docs, worked examples, and the GitHub Action wrapper.

## [0.0.9] — 2026-05-14

### Added

- **`actproof/verify.py`**: six-check audit-facing verifier. Per-check status (PASS/FAIL/SKIP/ERROR), never short-circuits, structured `VerificationResult` output.
- **`tests/test_verify.py`**: 33 tests across 16 groups.

### Changed

- **`pyproject.toml`**: version bumped to 0.0.9.

## [0.0.8] — 2026-05-14

### Added

- **`actproof/signers/` package**: AlgorandSigner ABC with `__init_subclass__` enforcement, MnemonicSigner for testing, GoogleKMSSigner for production GCP users.
- **`tests/test_signers_*.py`**: 65 tests across three modules.

### Changed

- **`pyproject.toml`**: version bumped to 0.0.8. Added `[gcp]` optional dependency group.

## [0.0.7] — 2026-05-14

### Added

- **`actproof/anchor.py`**: three-mode anchoring (DRAFT/DEMO/PRODUCTION), Signer Protocol, ARC-2 disclosed-mode note construction.
- **`tests/test_anchor.py`**: 45 tests across 12 groups.

## [0.0.6] — 2026-05-14

### Added

- **`actproof/timestamp.py`**: RFC 3161 timestamp acquisition with six-TSA QTSP failover chain.
- **`tests/test_timestamp.py`**: 41 tests across 12 groups.

## [0.0.5] — 2026-05-14

### Added

- **`actproof/receipt.py`**: public Receipt + private IssuerEvidence, reserved COSE_Sign1 forward-compat slot.
- **`tests/test_receipt.py`**: 51 tests across 11 groups.

## [0.0.4] — 2026-05-14

### Added

- **`actproof/catalogue.py`**: actproof-events catalogue loader and manifest validator.
- **`tests/test_catalogue.py`**: 44 tests against synthetic + real v1.4-rc1 fixtures.

## [0.0.3] — 2026-05-14

### Added

- **`actproof/manifest.py`**: canonical envelope schema with label-bound evidence.
- **`tests/test_manifest.py`**: 68 tests across 11 groups.

## [0.0.2] — 2026-05-14

### Added

- **`actproof/canonical.py`**: RFC 8785 JCS wrapping the `rfc8785` library from Trail of Bits.
- **`tests/test_canonical.py`**: 76 tests.

## [0.0.1] — 2026-05-14

### Added

- Project skeleton: pyproject.toml, LICENSE (MIT), README.md, package layout, Hatchling build, Ruff/mypy/pytest configuration.
