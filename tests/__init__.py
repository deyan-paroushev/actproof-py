# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Shared catalogue path resolution for the openproof-py test suite.

Tests that exercise the real openproof-events catalogue import their
catalogue path constants from this module instead of hardcoding paths.

Resolution priority:
  1. ``OPENPROOF_EVENTS_ROOT`` environment variable, if set.
  2. ``../openproof-events`` sibling repository, if it exists.
  3. The sibling fallback path is returned as a placeholder; tests that
     need the directory will skip via :data:`skip_if_no_real_catalogue`.

CI and contributors who do not have openproof-events available can set
``OPENPROOF_EVENTS_ROOT`` or skip the catalogue-dependent tests entirely.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def _resolve_openproof_events_root() -> Path:
    """Resolve the openproof-events repo root.

    Always returns a :class:`Path` object. The path may or may not exist
    on disk; callers should branch on directory presence rather than on
    None vs Path.
    """
    env = os.environ.get("OPENPROOF_EVENTS_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    # Fallback: sibling repository, e.g. /workspaces/openproof-events
    # next to /workspaces/openproof-py.
    sibling = Path(__file__).resolve().parent.parent.parent / "openproof-events"
    return sibling.resolve()


REAL_OPENPROOF_EVENTS_ROOT: Path = _resolve_openproof_events_root()
REAL_ACTS_PATH: Path = REAL_OPENPROOF_EVENTS_ROOT / "catalogue" / "acts"
REAL_SCHEMA_PATH: Path = (
    REAL_OPENPROOF_EVENTS_ROOT
    / "spec"
    / "schemas"
    / "act_catalogue_entry.v2.json"
)


skip_if_no_real_catalogue = pytest.mark.skipif(
    not REAL_ACTS_PATH.is_dir(),
    reason=(
        "openproof-events catalogue not available. "
        f"Set OPENPROOF_EVENTS_ROOT to a checked-out openproof-events repo, "
        f"or clone openproof-events at {REAL_OPENPROOF_EVENTS_ROOT}."
    ),
)
