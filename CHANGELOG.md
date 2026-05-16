# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is 0, breaking changes may occur in any minor or patch
release. Once 1.0.0 ships, semantic versioning will be strictly followed.

## [Unreleased]

### Planned

- **v0.2.0** — `docs/` complete with three worked examples (NIS2 / EUDR / software release), GitHub Action wrapper `release-anchor.yml`, EU Trusted List chain validation for RFC 3161 tokens.
- **v0.3.0** — Cross-implementation conformance test suite landing.
- **v1.0.0** — API frozen.
- **v2.0.0** — COSE_Sign1 + SCITT Transparent Statement bridge, once RFC 9943 publishes.

## [0.1.1] — 2026-05-16

### openproof-events schema v3 support

Additive support for openproof-events catalogue schema v3. v3 is a strict superset of v2: existing v2 catalogues load unchanged, v3 catalogues parse the four new optional sub-objects on each entry. Backward-compatible: no breaking changes to the public API. Consumers pinned to v0.1.0 reading v2 entries continue to work without modification.

The companion schema file `act_catalogue_entry.v3.json` lives in openproof-events. This release of openproof-py is what reads and validates entries against it.

### Added

- **`openproof/catalogue.py`** — Four new frozen dataclasses for the v3 optional sub-objects:
  - `RegulatedContextProfile` — constrains the receipt envelope `regulated_context` shape (allowed context types, allowed submission stages, default context type).
  - `PriorReceiptsProfile` — declares bilateral lifecycle expectations (required and optional `prior_receipts` roles).
  - `RelianceContext` — names the issuer role, counterparty action, later verifiers, and optional reliance statement.
  - `DisclosureProfile` — declares per-field disclosure tiers (`public_fields`, `commitment_fields`, `private_fields`) and `back_propagation_scope` mapping prior-receipt roles to field references visible in the automatic disclosure receipt generated at settlement.
- **`openproof/catalogue.py`** — Four new constants:
  - `SCHEMA_DISCRIMINATOR_V2` (= `"openproof.act_catalogue_entry.v2"`).
  - `SCHEMA_DISCRIMINATOR_V3` (= `"openproof.act_catalogue_entry.v3"`).
  - `SCHEMA_DISCRIMINATORS` (frozenset of the above two).
  - `SCHEMA_DISCRIMINATOR` retained as a backward-compatible alias for `SCHEMA_DISCRIMINATOR_V2`.
- **`openproof/catalogue.py`** — `CatalogueEntry` gains four optional fields (`regulated_context_profile`, `prior_receipts_profile`, `reliance_context`, `disclosure_profile`) defaulting to `None`. Fields are placed after the derived `source_path` and `entry_hash` fields so positional construction with the v2 field order continues to work.
- **`tests/test_catalogue_v3.py`** — 42 new tests in eight groups covering: v3 dataclass construction and immutability, discriminator constants, full and partial v3 entry parsing, missing-required-field error paths, schema file resolution preference (v3 > v2), mixed v2/v3 catalogues, backward compatibility (v2-only catalogues load identically, v3 blocks on v2 entries are ignored), and a regression check against the real openproof-events v1.4-rc1 catalogue. Existing `tests/test_catalogue.py` is unchanged; its 40 tests continue to pass.

### Changed

- **`openproof/catalogue.py`** — `_parse_entry` accepts either v2 or v3 discriminators. v3 entries with present optional blocks populate the corresponding `CatalogueEntry` fields; absent blocks leave them at `None`. v2 entries always yield `None` for all four v3 fields, even if the JSON happens to carry v3 keys (extras are tolerated, mirroring v0.1.0 permissiveness for unknown dict keys; the JSON schema file enforces strict `additionalProperties: false` for consumers that validate at the schema-file level).
- **`openproof/catalogue.py`** — `_scan_acts_directory` filter uses membership in `SCHEMA_DISCRIMINATORS` instead of equality with the single old discriminator. Files whose `schema` is unrecognised are silently skipped (unchanged behaviour for unrelated JSON files in the tree).
- **`openproof/catalogue.py`** — `_resolve_schema_path` tries `act_catalogue_entry.v3.json` first, falls back to `act_catalogue_entry.v2.json`. `Catalogue.schema_hash` reflects whichever file was found. Catalogues that ship the v3 schema file (openproof-events v1.5-rc1 and later) get the v3 hash; catalogues with only the v2 file (openproof-events v1.4-rc1 and earlier) get the v2 hash unchanged.
- **`openproof/catalogue.py`** — Error message for unrecognised discriminators in `_parse_entry` now names both accepted discriminators rather than just v2. Reachable only via direct `_parse_entry` calls; the directory walker silently skips unknown-discriminator files.
- **`openproof/__init__.py`**: version bumped to 0.1.1. Re-exports the four new dataclasses and three new constants at the package level (`from openproof import DisclosureProfile` works).
- **`pyproject.toml`**: version bumped to 0.1.1.

### Design notes

**Why v3 and not a relaxation of v2.** The four new sub-objects on each entry are not just new optional leaf fields; they introduce a structural concept (per-field disclosure tiers, multilateral bilateral propagation scope). Mutating what `"openproof.act_catalogue_entry.v2"` means while keeping the discriminator string the same would be cheap versioning: consumers that pinned to v2 would silently get a different contract. Clean v3 bump preserves the property that a discriminator string identifies a stable schema shape. v2-aware consumers continue to read v2 entries; v3-aware consumers read either.

**Why the v2 schema file stays in the repository.** Receipts issued against v1.4-rc1 entries are pinned to the v2 `schema_hash`. Verifying those receipts years later requires the v2 schema file at that hash. Removing it would break the receipt-binding chain. v2 and v3 schema files coexist; each receipt verifies against whichever was current at issue time.

**Why `SCHEMA_DISCRIMINATOR` is kept as an alias.** It was the only discriminator name exported by openproof v0.1.0. Renaming or removing it would break any external consumer that imported it. The alias makes the rename non-breaking. New code is encouraged to use `SCHEMA_DISCRIMINATOR_V2` and `SCHEMA_DISCRIMINATOR_V3` directly, and `SCHEMA_DISCRIMINATORS` for membership checks.

**Why the four new `CatalogueEntry` fields come after the derived fields.** Dataclass field order determines positional-construction order. Inserting the four new optional fields between the fifteen v2 wire-schema fields and the two derived fields would have shifted `source_path` and `entry_hash` positions, breaking any caller using positional construction of `CatalogueEntry` with the v2 layout. Putting the new fields at the end is semantically odd (wire-schema fields after derived fields) but kindlier to backward compatibility. `_parse_entry` uses keyword arguments throughout, so this is invisible to the loader.

**Type-level permissiveness is consistent across v2 and v3.** Wrong-type values inside present sub-objects (for instance, `public_fields: "not-a-list"` where a list is expected) do not raise in the Python loader. `tuple("not-a-list")` yields a tuple of characters, which is valid Python though semantically nonsense. This matches the existing v2 parser's permissiveness. Strict type validation is the JSON schema file's job, applied by external tooling such as `ajv` or `jsonschema`. The Python loader catches structural errors (missing required keys, wrong dict shape, non-iterable where iteration is needed) but not type-level errors. A separate hardening pass could tighten this uniformly across v2 and v3 in a future release if desired.

### Status: 485 tests across eleven modules

`tests/test_catalogue.py` (40 tests) + `tests/test_catalogue_v3.py` (42 tests) + all other test modules unchanged. Total openproof-py test count: 485 (up from 443 at v0.1.0).



### First usable release

The complete `openproof` library plus a working CLI. Every planned v0.0.x module has landed and is exercised by 423+ tests. v0.1.0 wires those modules into the `openproof` command-line tool, making the library usable end-to-end from a shell.

This is the version pushed to `main` on https://github.com/deyan-paroushev/openproof-py for the STS Standards Network application.

### Added

- **`openproof/cli.py`** — Click-based command-line interface, replacing the v0.0.1 placeholder. Three subcommands:
  - **`openproof anchor MANIFEST_PATH`** - read a manifest JSON file, optionally acquire an RFC 3161 timestamp, anchor to Algorand in the requested mode, write the resulting receipt.
    - `--mode {draft,demo,production}` (required, no default).
    - `--output PATH` (required) - where to write the receipt.
    - `--kms-resource PATH` - GCP KMS Ed25519 key version path for production signing. Mutually exclusive with the `OPENPROOF_MNEMONIC` env var.
    - `--skip-timestamp` - skip RFC 3161 acquisition (offline testing only).
    - `--wait/--no-wait` - poll algod until confirmation (default: wait).
    - `--evidence-output PATH` - optional path to write the issuer evidence JSON (private addendum).
  - **`openproof verify RECEIPT_PATH`** - read a receipt and run the six checks from `openproof.verify`. Exits 1 on any failure.
    - `--catalogue PATH` - optional openproof-events catalogue path.
    - `--git-commit SHA` - required when `--catalogue` is provided.
    - `--source-uri URI` - required when `--catalogue` is provided.
    - `--skip-anchor`, `--skip-timestamp` - skip the respective checks.
    - `--json` - JSON output for scripting.
  - **`openproof validate MANIFEST_PATH`** - validate a manifest against an openproof-events catalogue.
    - `--catalogue PATH`, `--git-commit SHA`, `--source-uri URI` (all required).
    - `--json` - JSON output for scripting.
- Each command supports `--help` (Click default) and exits with conventional codes: 0 on success, 1 on operational failure, 2 on usage error.
- Top-level `--verbose` flag enables DEBUG logging to stderr.
- `--version` flag prints the openproof version.

- **`tests/test_cli.py`** — 19 tests across six groups using Click's `CliRunner`. Covers `--version` and `--help`, validate happy path / JSON / catches unknown act / missing file, verify honest / tampered / skip-catalogue / JSON / requires-git-commit, anchor DRAFT-with-mnemonic / mode-required, anchor signer selection error paths (no source / both sources), exit codes. All tests offline; no real algod or TSA calls.

### Changed

- **`pyproject.toml`**: version bumped to 0.1.0. Development Status classifier moves from "2 - Pre-Alpha" to "3 - Alpha" reflecting feature completeness.
- **`openproof/__init__.py`**: version bumped to 0.1.0. No new public Python API (CLI is invoked via the `openproof` binary, not via import).
- **`README.md`**: rewritten to reflect that openproof is now a usable tool. Architecture diagram, install instructions, Quick Start sections for both CLI and Python API, honest scope statement of what v0.1.0 does NOT include.

### Design notes

**Mnemonic via env var only.** The CLI does NOT accept mnemonics as command-line arguments. Command-line args leak to shell history (`~/.bash_history`, `~/.zsh_history`), to the kernel's process table (visible via `ps aux` to other users on shared systems), to docker layer metadata, and to log aggregation systems. The env var path (`OPENPROOF_MNEMONIC`) is the lower-risk channel; the env var lives only in the shell session that invoked the command and is dropped when the process exits. Production users avoid mnemonics entirely and use `--kms-resource` for GCP KMS signing.

**Mode is required on `openproof anchor`.** No silent default. A user who runs `openproof anchor manifest.json --output receipt.json` gets a Click usage error pointing at the `--mode` flag, not a quiet submission to mainnet because someone changed the default. This is the same principle as the `anchor_manifest()` Python API: explicit choice is the only valid choice.

**No "anchor and verify" combined command.** Some early designs had a `commit` subcommand that anchored and then immediately verified. Removed: separating anchor from verify keeps the security model clean (the verifier is independent of the issuer), keeps the failure modes legible (verify failures after anchor are someone else's job to detect, not the issuer's job to silently retry), and matches the actual workflow (anchor at issuance time, verify at audit time, possibly years later).

**JSON output is opt-in via `--json`.** Default is human-readable colorised output (ANSI colors for terminals, plain text when stdout is redirected). Scripts wanting structured output pass `--json` and parse the result. This split keeps the human path obvious and the machine path explicit.

**Click chosen over argparse.** Click's group/command/option model maps cleanly to subcommands. Click's automatic help generation, automatic env-var binding (`envvar=`), automatic file-exists validation (`click.Path(exists=True)`), and `CliRunner` for testing each save substantial boilerplate over argparse equivalent. The added dependency cost (one pure-Python library) is modest.

### Status: v0.0.x → v0.1.0 milestone reached

This release closes the v0.0.x build phase. Every module in the architecture is implemented, tested, and exposed:

- `canonical.py` (v0.0.2) - RFC 8785 JCS wrapper.
- `manifest.py` (v0.0.3) - the canonical envelope schema.
- `catalogue.py` (v0.0.4) - openproof-events catalogue loader and validator.
- `receipt.py` (v0.0.5) - the artifact, public + private split.
- `timestamp.py` (v0.0.6) - RFC 3161 acquisition with QTSP failover.
- `anchor.py` (v0.0.7) - ARC-2 disclosed-mode Algorand submission.
- `signers/` (v0.0.8) - the AlgorandSigner ABC, MnemonicSigner, GoogleKMSSigner.
- `verify.py` (v0.0.9) - the six-check audit-facing verifier.
- `cli.py` (v0.1.0) - the Click-based command-line tool.

Total: 442 tests across ten modules, all passing offline. Next: v0.2.0 adds docs, worked examples, and the GitHub Action wrapper.

## [0.0.9] — 2026-05-14

### Added

- **`openproof/verify.py`**: six-check audit-facing verifier. Per-check status (PASS/FAIL/SKIP/ERROR), never short-circuits, structured `VerificationResult` output.
- **`tests/test_verify.py`**: 33 tests across 16 groups.

### Changed

- **`pyproject.toml`**: version bumped to 0.0.9.

## [0.0.8] — 2026-05-14

### Added

- **`openproof/signers/` package**: AlgorandSigner ABC with `__init_subclass__` enforcement, MnemonicSigner for testing, GoogleKMSSigner for production GCP users.
- **`tests/test_signers_*.py`**: 65 tests across three modules.

### Changed

- **`pyproject.toml`**: version bumped to 0.0.8. Added `[gcp]` optional dependency group.

## [0.0.7] — 2026-05-14

### Added

- **`openproof/anchor.py`**: three-mode anchoring (DRAFT/DEMO/PRODUCTION), Signer Protocol, ARC-2 disclosed-mode note construction.
- **`tests/test_anchor.py`**: 45 tests across 12 groups.

## [0.0.6] — 2026-05-14

### Added

- **`openproof/timestamp.py`**: RFC 3161 timestamp acquisition with six-TSA QTSP failover chain.
- **`tests/test_timestamp.py`**: 41 tests across 12 groups.

## [0.0.5] — 2026-05-14

### Added

- **`openproof/receipt.py`**: public Receipt + private IssuerEvidence, reserved COSE_Sign1 forward-compat slot.
- **`tests/test_receipt.py`**: 51 tests across 11 groups.

## [0.0.4] — 2026-05-14

### Added

- **`openproof/catalogue.py`**: openproof-events catalogue loader and manifest validator.
- **`tests/test_catalogue.py`**: 44 tests against synthetic + real v1.4-rc1 fixtures.

## [0.0.3] — 2026-05-14

### Added

- **`openproof/manifest.py`**: canonical envelope schema with label-bound evidence.
- **`tests/test_manifest.py`**: 68 tests across 11 groups.

## [0.0.2] — 2026-05-14

### Added

- **`openproof/canonical.py`**: RFC 8785 JCS wrapping the `rfc8785` library from Trail of Bits.
- **`tests/test_canonical.py`**: 76 tests.

## [0.0.1] — 2026-05-14

### Added

- Project skeleton: pyproject.toml, LICENSE (MIT), README.md, package layout, Hatchling build, Ruff/mypy/pytest configuration.
