# actproof v0.3.1 hotfix patch

Three changed files vs v0.3.0:

- pyproject.toml             (version bump + cryptography pin relaxed)
- actproof/__init__.py       (version bump)
- CHANGELOG.md               (new [0.3.1] block)

## Apply to your actproof-py clone

Paths inside this zip are repo-relative. Extract at the clone root with overwrite:

    cd /path/to/actproof-py
    unzip -o /path/to/actproof-v0.3.1-hotfix.zip

The -o flag overwrites the three files.

## Verify

    grep '^version' pyproject.toml          # → version = "0.3.1"
    grep 'cryptography>=' pyproject.toml    # → cryptography>=41.0,<46.0
    grep '__version__' actproof/__init__.py # → __version__ = "0.3.1"
    grep '^## \[0.3.1\]' CHANGELOG.md       # → ## [0.3.1] — 2026-05-19

## Commit + tag + push

    git status                              # confirm only these three files changed
    git diff                                # eyeball the actual diff
    git add pyproject.toml actproof/__init__.py CHANGELOG.md
    git commit -m "0.3.1: relax cryptography pin to >=41 to resolve internal conflict with tsp-client 0.2.1"
    git tag v0.3.1
    git push origin main
    git push origin v0.3.1

## Then update Quoruna

In Quoruna's requirements.txt the line is already in place:

    actproof @ git+https://github.com/deyan-paroushev/actproof-py.git@v0.3.1

Commit, push, Railway redeploys with the working dep set.

## Path A: publish to PyPI immediately after Railway boots green

    cd /path/to/actproof-py
    python -m build
    python -m twine upload dist/actproof-0.3.1*

Then switch Quoruna's requirements.txt line from the git URL to:

    actproof==0.3.1
