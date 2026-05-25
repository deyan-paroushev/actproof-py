#!/usr/bin/env bash
# actproof 0.3.4 deploy.
# Run from the repo root as:   bash deploy-0.3.4.sh
# Do NOT paste this into the terminal and do NOT run it as a VS Code task.
set -uo pipefail   # no -e during preflight: collect every failure

fail=0; warn=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }
note() { printf '  warn  %s\n' "$1"; warn=1; }

echo "actproof 0.3.4 deploy"
echo "== preflight =="
grep -q 'name = "actproof"' pyproject.toml 2>/dev/null \
  && ok "actproof repo root" || bad "not in actproof repo root"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && ok "git repo, branch $(git branch --show-current)" || bad "not a git repository"

CRIT=( pyproject.toml LICENSE README.md CHANGELOG.md
  actproof/__init__.py actproof/canonical.py actproof/manifest.py
  actproof/catalogue.py actproof/receipt.py actproof/timestamp.py
  actproof/anchor.py actproof/verify.py actproof/cli.py
  actproof/signers/__init__.py actproof/py.typed
  tests/test_receipt.py tests/test_anchor.py )
for f in "${CRIT[@]}"; do [ -f "$f" ] && ok "$f" || bad "missing: $f"; done

grep -q 'version = "0.3.4"' pyproject.toml \
  && ok "pyproject 0.3.4" || bad "pyproject not 0.3.4"
grep -q '__version__ = "0.3.4"' actproof/__init__.py \
  && ok "__init__ 0.3.4" || bad "__init__ not 0.3.4"
grep -q '## \[0.3.4\]' CHANGELOG.md \
  && ok "CHANGELOG has [0.3.4]" || bad "CHANGELOG missing [0.3.4]"

if [ "$fail" -ne 0 ]; then
  echo
  echo "PREFLIGHT FAILED. Fix the FAIL items above, then re-run. Nothing was pushed."
  exit 1
fi
[ "$warn" -ne 0 ] && echo "(warnings are non-blocking)"
echo "preflight passed."
echo

set -e   # abort on error from here

echo "== tests =="
# The full suite is the release gate. If pre-existing catalogue tests fail,
# this step stops the deploy. Resolve those before cutting the release.
python3 -m pip install --quiet --upgrade build twine pytest
python3 -m pip install --quiet -e .
python3 -m pytest -q

echo "== build =="
rm -rf dist build ./*.egg-info
python3 -m build
python3 -m twine check dist/*
ls -la dist/

echo "== git =="
git add -A
if git diff --cached --quiet; then
  echo "nothing staged, skipping commit"
else
  git commit -F- <<'MSG'
actproof 0.3.4: on-chain note in three encodings

- Add OnChainNote dataclass and on_chain_note_from_bytes builder
- Add optional AnchorRecord.on_chain_note, populated by anchor_manifest
- Reconstruct the field losslessly on read for pre-0.3.4 receipts
- Add eight tests for the encodings, the builder, and round-tripping
- README: add the actproof.org project-site block
MSG
fi
git push origin "$(git branch --show-current)"

echo "== build artifacts ready =="
read -r -p "Upload actproof 0.3.4 to PyPI? [y/N] " up
if [ "${up:-}" = "y" ]; then
  python3 -m twine upload dist/*
else
  echo "upload skipped"
fi

if git rev-parse v0.3.4 >/dev/null 2>&1; then
  echo "tag v0.3.4 exists, skipping"
else
  git tag -a v0.3.4 -m "actproof v0.3.4: on-chain note in three encodings"
  git push origin v0.3.4
fi
echo "done."
