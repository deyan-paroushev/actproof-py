# Bugfix delivery for actproof-py Steps 4 and 5a

Applies the "minimal patch" from ChatGPT's review of the May 19 sprint's
actproof-py changes. Six fixes across two source modules and three test
files. Verified end-to-end: **569 passed, 10 skipped, 0 failures**.

## Files

### Modified

- `actproof/catalogue.py`
  - **Fix 6**: `_resolve_from_packaged_events()` now coerces the return
    value of `actproof_events.get_catalogue_path()` via `Path(value)`,
    so `str`, `os.PathLike`, and `Path` all work. Returns `None` when
    the value cannot be coerced (e.g. `int`) rather than raising. This
    keeps catalogue resolution robust against future actproof-events
    releases that change their return type.
  - **Fix 4**: `load_catalogue()` now reads the installed-distribution
    version via `importlib.metadata.version("actproof-events")` rather
    than `actproof_events.__version__`. Distribution metadata is the
    authoritative source for installed-package version (the
    `__version__` attribute is convenience that may not be set or may
    drift from the distribution metadata). Handles `PackageNotFoundError`
    gracefully: when present, sets the package provenance fields; when
    not, leaves them None and the catalogue still loads.
  - **Fix 5**: `validate_manifest()` gains two new diagnostic checks,
    `SOURCE_PACKAGE_NAME_MISMATCH` and `SOURCE_PACKAGE_VERSION_MISMATCH`.
    Both fire only when the manifest AND the loaded catalogue both have
    package provenance set; one-sided cases never trigger (a verifier
    may legitimately load the catalogue a different way than the issuer
    did). These are diagnostic only: the cryptographic binding remains
    `entry_hash` and `schema_hash`. The new codes give operators a
    clearer error message ("you have actproof-events 1.4.1 installed
    but the receipt was issued against 1.4.0rc1") than `entry_hash`
    mismatch alone would.
  - `ValidationIssue` docstring updated with the two new codes.
  - `validate_manifest` docstring updated: "up to nine checks" (was
    "seven"). The two new checks are diagnostic and only fire when both
    sides have package provenance.

- `actproof/manifest.py`
  - **Fix 1** (the real correctness bug): `manifest_from_dict()` and
    `build_manifest()` now enforce **both-or-neither** for the optional
    `source_package_name` and `source_package_version` fields. Previously
    a manifest with only one of them parsed successfully but
    `manifest_to_dict()` (which emits the pair only when both are set)
    would silently drop the set field on re-serialisation. The bug
    meant a parsed Manifest no longer faithfully represented its input
    dict.
  - Both functions now also type-check the fields: must be `str` when
    present.
  - Both raise `ManifestValidationError` with a clear message on
    violation.

- `tests/test_catalogue_v3.py`
  - **Fix 9 (part 1)**: The `TestRealV1_4Catalogue` class previously
    asserted that all v1.4-rc1 entries are v2-only with all v3 fields
    `None`. The actual v1.4-rc1 catalogue ships v3 entries
    authoritatively (the test's own comment said: "Update or split the
    test once v1.5-rc1 lands"). The tests now assert the inverse:
    every entry is v3 with all four v3 fields populated. Historical
    context retained in the class docstring.

- `tests/test_signers_google_kms.py`
  - **Fix 9 (part 2)**: Added `pytest.importorskip("google.cloud.kms")`
    and `pytest.importorskip("google_crc32c")` at module top. The 16
    tests in this file now skip cleanly (rather than fail) in
    environments without the optional `[gcp]` extra installed. The
    skip reason is descriptive: "Install actproof's optional GCP
    extra: pip install 'actproof[gcp]'".

### New

- `tests/test_catalogue_package_provenance_bugfix.py` — 25 tests across
  six groups covering every bugfix:
  - `TestPackageFieldsBothOrNeither_FromDict` (5 tests): both-absent
    succeeds, both-present succeeds, name-only raises, version-only
    raises, explicit-null variant raises.
  - `TestPackageFieldsBothOrNeither_BuildManifest` (4 tests): same
    coverage at the construction path.
  - `TestPackageFieldsTypeChecks` (4 tests): non-string raises in both
    parser and builder.
  - `TestImportlibMetadataVersion` (2 tests): version is read via
    `importlib.metadata.version()`; `PackageNotFoundError` handled
    gracefully (catalogue still loads with `None` provenance).
  - `TestResolveFromPackagedEventsTypeCoercion` (5 tests): accepts
    `Path`, `str`, `os.PathLike`; returns `None` for unconvertible
    types or nonexistent paths; never raises.
  - `TestValidationIssueCodes_PackageMismatch` (5 tests): no issue
    when match; name and version mismatches flagged with correct
    codes and messages; no issue when only one side has package
    provenance.

## Test results

Fresh venv with `actproof-events-1.4.0rc1` installed:

    Before bugfix:
      tests/test_catalogue.py                                44 passed
      tests/test_catalogue_packaged_events.py                17 passed
      tests/test_catalogue_package_provenance.py             15 passed
      tests/test_catalogue_v3.py             passed except 2 stale assertions
      tests/test_signers_google_kms.py                       16 failed
      ...

    After bugfix:
      Full pytest run                  569 passed, 10 skipped, 0 failed

The 10 skipped tests are GCP-signer tests that gracefully skip when
google-cloud-kms is not installed (a common case in catalogue-only
development environments and CI runs that do not touch the signer
subsystem). They run normally in environments with the `[gcp]` extra.

## On the trust model (ChatGPT's Fix 2: framing correction)

The STEP-5A-NOTES.md from the original delivery said:

> "A verifier in 2031 can now run `pip install actproof-events==<version>`
> instead of having to `git checkout <SHA>` to reproduce the source bytes."

That framing was too strong. The correct framing is:

> Package name and version identify the pip-installable release expected
> to contain the catalogue bytes. They are **convenience provenance**
> that helps a verifier locate the source. They are **not** the trust
> root. The cryptographic binding between a manifest and the catalogue
> entry bytes remains `entry_hash` and `schema_hash`, and the binding
> between the manifest and its on-chain anchor remains the manifest
> hash. A verifier doing the work must still recompute `entry_hash` and
> `schema_hash` against whatever bytes they obtained, regardless of
> how those bytes reached their machine.

The two new `SOURCE_PACKAGE_*_MISMATCH` validation codes operationalise
this: they are diagnostic, not cryptographic. They make a misaligned
deployment visible. They do not authorise a verifier to skip
`entry_hash` verification.

A future enhancement (out of scope for tonight) would be to add an
optional `source_package_artifact_hash` field that pins to the exact
wheel/sdist SHA-256, giving cryptographic binding to the distribution
bytes too. That would close the gap between "convenience" and
"cryptographic" for package-sourced provenance.

## What I deliberately did not change

- `git_commit` is still a required field on `CatalogueBinding`. ChatGPT's
  Fix 3 suggested making `actproof-events` expose `__source_uri__` and
  `__git_commit__` so `load_catalogue` could populate them when sourcing
  from the package. That is a cross-repo change with implications for
  the events package's release process (someone has to update
  `__git_commit__` on every release). For tonight, the consumer Quoruna
  mint flow already passes `catalogue_git_commit` explicitly through
  `build_standards_engagement_manifest(catalogue_git_commit=...)` (or
  leaves it empty, in which case the receipt is anchored on the
  package-provenance fields). The framing correction above makes the
  trust-model story honest either way.
- Refactor of `_resolve_acts_path` into a `CatalogueResolution`
  dataclass (ChatGPT's Fix 7). Pure refactor, not urgent.
- Per-discriminator schema hashes (ChatGPT's Fix 8). Future-proofing
  for v0.4.0, not required for v0.3.3.

## Apply order

Apply this bugfix zip on top of your existing actproof-py working tree
that has Steps 4 and 5a applied. The five files overlay the previous
versions:

    actproof/catalogue.py                                   replace
    actproof/manifest.py                                    replace
    tests/test_catalogue_v3.py                              replace
    tests/test_signers_google_kms.py                        replace
    tests/test_catalogue_package_provenance_bugfix.py       new

Then rebuild: `python -m build --wheel`. Install into Quoruna: `pip
install --force-reinstall --no-deps dist/actproof-0.3.2-py3-none-any.whl`.
Run the full test suite to confirm: `pytest`. Expected: **569 passed,
10 skipped, 0 failed**.

## Commit suggestion

    git add actproof/catalogue.py actproof/manifest.py \
            tests/test_catalogue_v3.py tests/test_signers_google_kms.py \
            tests/test_catalogue_package_provenance_bugfix.py
    git commit -m "catalogue: enforce both-or-neither for package provenance, fix test hygiene

    Six bugfixes per ChatGPT's review of Steps 4 and 5a:

    1. manifest_from_dict and build_manifest reject manifests where exactly
       one of source_package_name and source_package_version is present.
       Previously a one-sided manifest parsed but lost the set field on
       round-trip through manifest_to_dict (which emits the pair only when
       both are set). Both functions now also type-check the values.
    2. load_catalogue reads the installed distribution version via
       importlib.metadata.version() rather than the package's __version__
       attribute. Handles PackageNotFoundError gracefully.
    3. _resolve_from_packaged_events coerces the return value of
       get_catalogue_path() via Path(value), accepting str, os.PathLike,
       and Path. Returns None on unconvertible types rather than raising.
    4. validate_manifest gains SOURCE_PACKAGE_NAME_MISMATCH and
       SOURCE_PACKAGE_VERSION_MISMATCH diagnostic codes. They fire only
       when both manifest and catalogue have package provenance set.
       The cryptographic binding remains entry_hash and schema_hash.
    5. test_catalogue_v3.py TestRealV1_4Catalogue assertions updated to
       match the actual v1.4-rc1 catalogue (v3 entries, populated v3
       fields). The original assumption (v2-only entries) was already
       outdated; the test code's own comment said 'Update once v1.5-rc1
       lands'.
    6. test_signers_google_kms.py gains pytest.importorskip for
       google.cloud.kms and google_crc32c so the 16 tests cleanly skip
       in environments without the [gcp] extra. The full pytest run now
       reports 569 passed, 10 skipped, 0 failed.

    25 new tests added in tests/test_catalogue_package_provenance_bugfix.py
    covering every fix."
