# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
openproof command-line interface.

Three subcommands wired to the openproof Python API:

* ``openproof anchor`` - read a manifest JSON file, optionally acquire an
  RFC 3161 timestamp, anchor the manifest hash to the Algorand ledger,
  write the resulting receipt.

* ``openproof verify`` - read a receipt JSON file and run the six checks
  defined in ``openproof.verify``. Prints per-check status. Exits
  non-zero if any check fails.

* ``openproof validate`` - read a manifest JSON file and validate against
  an openproof-events catalogue. Prints any validation issues. Exits
  non-zero if the manifest does not conform.

Security note on mnemonics
--------------------------

For testing/demo anchoring, the mnemonic is read from the
``OPENPROOF_MNEMONIC`` environment variable, NEVER from command-line
arguments. Command-line arguments leak to shell history (``~/.bash_history``,
``~/.zsh_history``), to the kernel's process table (visible via ``ps aux``
to other users on shared systems), to docker layer metadata, and to log
aggregation systems. The env var path is the lower-risk channel and the
only path supported.

Production anchoring uses GCP KMS via ``--kms-resource``; the key never
leaves the HSM. AWS users implement their own signer subclass (see
``openproof.signers.interface``).

Exit codes
----------

* 0 - success
* 1 - operation failed (verification failed, anchor failed, validation
  found issues)
* 2 - usage error (missing file, bad arguments, etc.) - Click default
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import warnings
from pathlib import Path
from typing import Any, Optional

import click


# ─────────────────────────────────────────────────────────────────
# VERSION (read lazily so the CLI works even before openproof is fully
# importable, e.g. for `openproof --version` early-exit cases)
# ─────────────────────────────────────────────────────────────────

def _get_version() -> str:
    try:
        from openproof import __version__
        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


# ─────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    """Configure logging level based on the --verbose flag."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ─────────────────────────────────────────────────────────────────
# THE MAIN GROUP
# ─────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version=_get_version(), prog_name="openproof")
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable DEBUG logging to stderr.",
)
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """openproof: anchor signed JSON manifests; verify anchored receipts.

    See ``openproof <command> --help`` for per-command help. The three
    commands are ``anchor`` (commit), ``verify`` (audit), and ``validate``
    (lint a manifest against a catalogue).
    """
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# ─────────────────────────────────────────────────────────────────
# COMMAND: validate
# ─────────────────────────────────────────────────────────────────

@main.command()
@click.argument(
    "manifest_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalogue", "catalogue_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
    help="Path to the openproof-events catalogue acts/ directory.",
)
@click.option(
    "--git-commit",
    required=True,
    help=(
        "Git commit SHA at which the catalogue was loaded. "
        "Recorded in the validation context for reproducibility."
    ),
)
@click.option(
    "--source-uri",
    required=True,
    help=(
        "Source URI of the catalogue "
        "(e.g. https://github.com/deyan-paroushev/openproof-events)."
    ),
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output validation result as JSON for scripting.",
)
def validate(
    manifest_path: Path,
    catalogue_path: Path,
    git_commit: str,
    source_uri: str,
    as_json: bool,
) -> None:
    """Validate a manifest against an openproof-events catalogue.

    Reads MANIFEST_PATH, loads the catalogue at the specified git commit,
    runs all catalogue checks, prints any issues. Exits non-zero if the
    manifest does not conform.
    """
    from openproof.catalogue import load_catalogue, validate_manifest
    from openproof.manifest import manifest_from_dict

    # Read the manifest.
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = manifest_from_dict(data)
    except Exception as exc:  # noqa: BLE001
        click.echo(
            f"Error: Cannot read manifest {manifest_path}: {exc}",
            err=True,
        )
        sys.exit(1)

    # Load the catalogue.
    try:
        catalogue = load_catalogue(
            acts_path=catalogue_path,
            source_uri=source_uri,
            git_commit=git_commit,
        )
    except Exception as exc:  # noqa: BLE001
        click.echo(
            f"Error: Cannot load catalogue {catalogue_path}: {exc}",
            err=True,
        )
        sys.exit(1)

    # Validate.
    issues = validate_manifest(manifest, catalogue)

    # Output.
    if as_json:
        result = {
            "ok": len(issues) == 0,
            "manifest_path": str(manifest_path),
            "issues": [
                {"code": i.code, "field": i.field, "message": i.message}
                for i in issues
            ],
        }
        click.echo(json.dumps(result, indent=2))
    else:
        if not issues:
            click.echo(click.style(f"OK  ", fg="green", bold=True) + f"{manifest_path}")
            click.echo("  No validation issues.")
        else:
            click.echo(
                click.style(f"FAIL  ", fg="red", bold=True)
                + f"{manifest_path}"
            )
            click.echo(f"  {len(issues)} issue(s) found:")
            for issue in issues:
                where = f" at {issue.field}" if issue.field else ""
                click.echo(
                    f"  - {click.style(issue.code, fg='yellow')}"
                    f"{where}: {issue.message}"
                )

    sys.exit(1 if issues else 0)


# ─────────────────────────────────────────────────────────────────
# COMMAND: verify
# ─────────────────────────────────────────────────────────────────

@main.command()
@click.argument(
    "receipt_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--catalogue", "catalogue_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help=(
        "Optional path to the openproof-events catalogue acts/ directory. "
        "If not provided, catalogue_conformance check is skipped."
    ),
)
@click.option(
    "--git-commit",
    help=(
        "Git commit SHA at which the catalogue was loaded. Required if "
        "--catalogue is provided."
    ),
)
@click.option(
    "--source-uri",
    help=(
        "Source URI of the catalogue. Required if --catalogue is provided."
    ),
)
@click.option(
    "--skip-anchor", is_flag=True,
    help="Skip the on-chain anchor check.",
)
@click.option(
    "--skip-timestamp", is_flag=True,
    help="Skip the RFC 3161 timestamp signature check.",
)
@click.option(
    "--json", "as_json", is_flag=True,
    help="Output verification result as JSON for scripting.",
)
def verify(
    receipt_path: Path,
    catalogue_path: Optional[Path],
    git_commit: Optional[str],
    source_uri: Optional[str],
    skip_anchor: bool,
    skip_timestamp: bool,
    as_json: bool,
) -> None:
    """Verify a receipt end-to-end.

    Reads RECEIPT_PATH and runs the six checks defined in openproof.verify.
    Prints per-check status. Exits non-zero if any check fails.
    """
    from openproof.catalogue import load_catalogue
    from openproof.receipt import read_receipt
    from openproof.verify import verify_receipt

    # Read the receipt.
    try:
        receipt = read_receipt(receipt_path)
    except Exception as exc:  # noqa: BLE001
        click.echo(
            f"Error: Cannot read receipt {receipt_path}: {exc}",
            err=True,
        )
        sys.exit(1)

    # Optionally load the catalogue.
    catalogue = None
    skip_catalogue = False
    if catalogue_path is not None:
        if not git_commit or not source_uri:
            click.echo(
                "Error: --git-commit and --source-uri are required when "
                "--catalogue is provided.",
                err=True,
            )
            sys.exit(2)
        try:
            catalogue = load_catalogue(
                acts_path=catalogue_path,
                source_uri=source_uri,
                git_commit=git_commit,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"Error: Cannot load catalogue {catalogue_path}: {exc}",
                err=True,
            )
            sys.exit(1)
    else:
        skip_catalogue = True

    # Run verification.
    result = verify_receipt(
        receipt,
        catalogue=catalogue,
        skip_anchor_check=skip_anchor,
        skip_timestamp_check=skip_timestamp,
        skip_catalogue_check=skip_catalogue,
    )

    # Output.
    if as_json:
        out = {
            "ok": result.ok,
            "receipt_path": str(receipt_path),
            "manifest_hash": receipt.manifest_hash,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "detail": c.detail,
                    "elapsed_seconds": c.elapsed_seconds,
                }
                for c in result.checks
            ],
        }
        click.echo(json.dumps(out, indent=2))
    else:
        header = (
            click.style("OK  ", fg="green", bold=True)
            if result.ok
            else click.style("FAIL  ", fg="red", bold=True)
        )
        click.echo(header + f"{receipt_path}")
        click.echo(f"  manifest_hash: {receipt.manifest_hash}")
        click.echo(f"  Checks:")
        for c in result.checks:
            status_color = {
                "pass": "green",
                "fail": "red",
                "skip": "yellow",
                "error": "red",
            }[c.status.value]
            status_str = c.status.value.upper().rjust(5)
            elapsed_ms = (c.elapsed_seconds or 0.0) * 1000
            line = (
                f"    [{click.style(status_str, fg=status_color, bold=True)}]"
                f"  {c.name:<32}  ({elapsed_ms:.2f} ms)"
            )
            click.echo(line)
            if c.detail and c.status.value in ("fail", "error", "skip"):
                # Wrap the detail to fit reasonable width.
                detail = c.detail.replace("\n", " ")[:200]
                click.echo(f"           {detail}")

    sys.exit(0 if result.ok else 1)


# ─────────────────────────────────────────────────────────────────
# COMMAND: anchor
# ─────────────────────────────────────────────────────────────────

_MNEMONIC_ENV_VAR = "OPENPROOF_MNEMONIC"


@main.command()
@click.argument(
    "manifest_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--mode",
    type=click.Choice(["draft", "demo", "production"], case_sensitive=False),
    required=True,
    help=(
        "Anchoring mode. draft = build the note bytes without submission. "
        "demo = submit to testnet. production = submit to mainnet."
    ),
)
@click.option(
    "--kms-resource",
    help=(
        "GCP KMS Ed25519 key version resource path for production signing. "
        "Mutually exclusive with the OPENPROOF_MNEMONIC env var."
    ),
)
@click.option(
    "--output", "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Path to write the resulting receipt JSON.",
)
@click.option(
    "--evidence-output", "evidence_output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        "Optional path to write the issuer evidence JSON (the private "
        "addendum containing plaintext recipient emails). If omitted, "
        "no issuer evidence file is produced."
    ),
)
@click.option(
    "--skip-timestamp", is_flag=True,
    help=(
        "Skip RFC 3161 timestamp acquisition. The receipt will contain a "
        "placeholder TimestampToken; verifiers will fail the timestamp "
        "signature check. Useful for offline tests only."
    ),
)
@click.option(
    "--wait/--no-wait", default=True,
    help=(
        "If --wait (default), poll algod until the transaction confirms. "
        "If --no-wait, return immediately after submission with block_round=None."
    ),
)
def anchor(
    manifest_path: Path,
    mode: str,
    kms_resource: Optional[str],
    output_path: Path,
    evidence_output_path: Optional[Path],
    skip_timestamp: bool,
    wait: bool,
) -> None:
    """Anchor a manifest to the Algorand ledger and write a receipt.

    Reads MANIFEST_PATH, builds a signer (from OPENPROOF_MNEMONIC env var
    or --kms-resource), optionally acquires an RFC 3161 timestamp, anchors
    the manifest hash to Algorand in the requested mode, writes the
    resulting receipt to --output.
    """
    from openproof.anchor import AnchorMode, anchor_manifest
    from openproof.manifest import manifest_from_dict, hash_manifest
    from openproof.receipt import TimestampToken, build_receipt, write_receipt
    from openproof.signers import GoogleKMSSigner, MnemonicSigner
    from openproof.timestamp import acquire_timestamp_token

    # Read the manifest.
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = manifest_from_dict(data)
    except Exception as exc:  # noqa: BLE001
        click.echo(
            f"Error: Cannot read manifest {manifest_path}: {exc}",
            err=True,
        )
        sys.exit(1)

    # Build the signer.
    mnemonic_value = os.environ.get(_MNEMONIC_ENV_VAR)
    if kms_resource and mnemonic_value:
        click.echo(
            f"Error: Both --kms-resource and {_MNEMONIC_ENV_VAR} are set. "
            f"Choose one.",
            err=True,
        )
        sys.exit(2)

    signer: Any = None
    if kms_resource:
        try:
            signer = GoogleKMSSigner(kms_resource_name=kms_resource)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"Error: Cannot build GoogleKMSSigner: {exc}", err=True)
            sys.exit(1)
    elif mnemonic_value:
        try:
            with warnings.catch_warnings():
                # The MnemonicSigner emits a UserWarning every time; for CLI
                # use the warning would interleave with the normal output.
                # The "do not use for production" warning is documented at
                # the env var level (this command's --help) and at the
                # MnemonicSigner class level (its docstring), so suppressing
                # it here keeps CLI output clean.
                warnings.simplefilter("ignore", category=UserWarning)
                signer = MnemonicSigner(mnemonic_value)
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"Error: Cannot build MnemonicSigner from "
                f"{_MNEMONIC_ENV_VAR}: {exc}",
                err=True,
            )
            sys.exit(1)
    else:
        click.echo(
            f"Error: Either --kms-resource or {_MNEMONIC_ENV_VAR} env "
            f"var must be set. The CLI does NOT read mnemonics from "
            f"command-line arguments (they would leak to shell history).",
            err=True,
        )
        sys.exit(2)

    # Compute the manifest hash.
    manifest_hash_bytes = hash_manifest(manifest)

    # Optionally acquire a trusted timestamp.
    if skip_timestamp:
        click.echo(
            click.style(
                "Note: --skip-timestamp set; using placeholder TimestampToken.",
                fg="yellow",
            ),
            err=True,
        )
        token = TimestampToken(
            tsa_url="", tsa_name="(placeholder)",
            token_b64="",
            policy_oid=None,
            hash_alg="sha-256",
            imprint_hex=manifest_hash_bytes.hex(),
            timestamp="",
        )
    else:
        try:
            ts_result = acquire_timestamp_token(manifest_hash_bytes)
            if not ts_result.ok:
                click.echo(
                    "Error: RFC 3161 timestamp acquisition failed for all "
                    "TSAs in the chain.", err=True,
                )
                for a in ts_result.attempts:
                    click.echo(
                        f"  - {a.tsa_name}: {a.error}", err=True,
                    )
                sys.exit(1)
            token = ts_result.token  # type: ignore[assignment]
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"Error: timestamp acquisition raised: {exc}", err=True,
            )
            sys.exit(1)

    # Build the AnchorMode.
    mode_map = {
        "draft": AnchorMode.DRAFT,
        "demo": AnchorMode.DEMO,
        "production": AnchorMode.PRODUCTION,
    }
    anchor_mode = mode_map[mode.lower()]

    # Anchor.
    try:
        anchor_record = anchor_manifest(
            manifest_hash_bytes,
            signer=signer,
            mode=anchor_mode,
            wait_for_confirmation=wait,
        )
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: anchor failed: {exc}", err=True)
        sys.exit(1)

    # Build and write the receipt.
    receipt = build_receipt(
        manifest=manifest,
        anchor=anchor_record,
        trusted_timestamp=token,
    )
    try:
        write_receipt(output_path, receipt)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"Error: cannot write receipt to {output_path}: {exc}", err=True)
        sys.exit(1)

    # Output: human-readable summary.
    click.echo(click.style("OK  ", fg="green", bold=True) + f"{output_path}")
    click.echo(f"  Mode:           {anchor_mode.value}")
    click.echo(f"  Manifest hash:  {receipt.manifest_hash}")
    if anchor_record.txid:
        click.echo(f"  Txid:           {anchor_record.txid}")
        click.echo(f"  Network:        {anchor_record.network}")
        if anchor_record.block_round:
            click.echo(f"  Block round:    {anchor_record.block_round}")
    else:
        click.echo(f"  Txid:           (draft - not submitted)")
    if token.tsa_name and token.tsa_name != "(placeholder)":
        click.echo(f"  TSA:            {token.tsa_name}")
        click.echo(f"  TSA time:       {token.timestamp}")
