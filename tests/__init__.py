# SPDX-FileCopyrightText: 2026 Deyan Paroushev
# SPDX-License-Identifier: MIT
"""
Shared catalogue path resolution for the actproof-py test suite.

Tests that exercise the real actproof-events catalogue import their
catalogue path constants from this module instead of hardcoding paths.

Resolution priority:
  1. ``ACTPROOF_EVENTS_ROOT`` environment variable, if set.
  2. ``../actproof-events`` sibling repository, if it exists.
  3. The sibling fallback path is returned as a placeholder; tests that
     need the directory will skip via :data:`skip_if_no_real_catalogue`.

CI and contributors who do not have actproof-events available can set
``ACTPROOF_EVENTS_ROOT`` or skip the catalogue-dependent tests entirely.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def _resolve_actproof_events_root() -> Path:
    """Resolve the actproof-events repo root.

    Always returns a :class:`Path` object. The path may or may not exist
    on disk; callers should branch on directory presence rather than on
    None vs Path.
    """
    env = os.environ.get("ACTPROOF_EVENTS_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    # Fallback: sibling repository, e.g. /workspaces/actproof-events
    # next to /workspaces/actproof-py.
    sibling = Path(__file__).resolve().parent.parent.parent / "actproof-events"
    return sibling.resolve()


REAL_ACTPROOF_EVENTS_ROOT: Path = _resolve_actproof_events_root()
REAL_ACTS_PATH: Path = REAL_ACTPROOF_EVENTS_ROOT / "catalogue" / "acts"
REAL_SCHEMA_PATH: Path = (
    REAL_ACTPROOF_EVENTS_ROOT
    / "spec"
    / "schemas"
    / "act_catalogue_entry.v2.json"
)


skip_if_no_real_catalogue = pytest.mark.skipif(
    not REAL_ACTS_PATH.is_dir(),
    reason=(
        "actproof-events catalogue not available. "
        f"Set ACTPROOF_EVENTS_ROOT to a checked-out actproof-events repo, "
        f"or clone actproof-events at {REAL_ACTPROOF_EVENTS_ROOT}."
    ),
)
