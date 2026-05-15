# Deployment

This is the openproof-py v0.1.0 source tree, ready to push to
`github.com/deyan-paroushev/openproof-py`.

## What's inside

```
openproof-py/
├── README.md                       Project README
├── CHANGELOG.md                    Full v0.0.1 → v0.1.0 history
├── LICENSE                         MIT
├── DEPLOY.md                       This file
├── pyproject.toml                  Hatchling build, dependencies pinned
├── .gitignore
├── openproof/                      Library source (~3,500 lines, 10 modules)
│   ├── __init__.py
│   ├── canonical.py                RFC 8785 JCS, strict-mode discipline
│   ├── manifest.py                 Manifest envelope (issuer/claim/evidence/recipients)
│   ├── catalogue.py                openproof-events loader + validator
│   ├── receipt.py                  Public Receipt + private IssuerEvidence
│   ├── timestamp.py                RFC 3161 with QTSP failover chain
│   ├── anchor.py                   ARC-2 disclosed-mode notes on Algorand
│   ├── signers/                    AlgorandSigner ABC + Mnemonic + GoogleKMS
│   ├── verify.py                   Six-check end-to-end verification
│   └── cli.py                      Click-based CLI (anchor / verify / validate)
├── tests/                          11 test files, 443 tests, all passing
│   └── ...
└── docs/
    └── STS-STANDARDS-APPLICATION.md   Maintainer application narrative
```

## First push to GitHub

```bash
cd openproof-py

git init
git add -A
git commit -m "Initial release: openproof-py v0.1.0

Library and CLI for anchoring signed JSON manifests to Algorand mainnet
with RFC 3161 qualified timestamps, plus an independent verifier for
anyone's anchored receipts.

10 modules, 443 passing tests, MIT licensed.

Implements RFC 8785 JCS, RFC 3161 TSP, Algorand ARC-2 disclosed-mode
notes, and tracks draft-ietf-scitt-architecture for the v2 COSE_Sign1
bridge once RFC 9943 publishes."

git branch -M main
git remote add origin git@github.com:deyan-paroushev/openproof-py.git
git push -u origin main

git tag -a v0.1.0 -m "v0.1.0: first usable release"
git push origin v0.1.0
```

## Local verification

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev,gcp]"

# Sanity checks
openproof --version              # openproof, version 0.1.0
python -c "import openproof; print(openproof.__version__)"

# Full test suite — expect 443 passed (with OPENPROOF_EVENTS_ROOT set, see Notes below)
OPENPROOF_EVENTS_ROOT=/path/to/openproof-events python -m pytest tests/ -q

# CLI help
openproof --help
openproof anchor --help
openproof verify --help
openproof validate --help
```

## Notes for the catalogue

Several tests and the `openproof validate` command need the
openproof-events catalogue to be present somewhere resolvable.

The library (CLI flag, env var, error):

1. The `--catalogue` CLI flag (a path to the `acts/` directory)
2. The `OPENPROOF_CATALOGUE_PATH` environment variable
3. Otherwise raises `CatalogueLoadError`

The test suite (env var, sibling repo, skip):

1. The `OPENPROOF_EVENTS_ROOT` environment variable (a path to the
   openproof-events repo root, not the `acts/` directory)
2. Falls back to `../openproof-events` as a sibling of this repo
3. Tests that need the real catalogue skip cleanly if neither is
   available; tests using synthetic `tmp_path` catalogues run regardless

For local development against `github.com/deyan-paroushev/openproof-events`:

```bash
# Clone as a sibling of this repo
git clone https://github.com/deyan-paroushev/openproof-events.git ../openproof-events

# Or set the env vars explicitly
export OPENPROOF_EVENTS_ROOT=/path/to/openproof-events                  # tests
export OPENPROOF_CATALOGUE_PATH=$OPENPROOF_EVENTS_ROOT/catalogue/acts   # library/CLI
```

## STS Standards Network application

The maintainer's statement of practice is at
`docs/STS-STANDARDS-APPLICATION.md`. It is written against the four
sections of the Sovereign Tech Standards Network application form
(maintainer profile, standards relation, twelve-month plan, track
record) plus a conflicts-and-disclosures appendix.

It is structured to be read by the application reviewer; nothing in it
is load-bearing for the library itself.
