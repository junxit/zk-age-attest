# Contributing

## Development setup

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+ (3.13 is the pinned dev version).

```bash
uv sync --all-packages   # install every workspace package (editable) + dev tools
```

## Commands

```bash
uv run pytest            # full test suite (unit, integration, adversarial, linkability sim)
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy              # type-check zkage-core and zkage-verifier
```

## Layout

uv workspace monorepo — see the repo map in [README.md](README.md). The dependency
direction is load-bearing: `zkage-verifier` may depend on `zkage-core` only, and
`zkage-core` on `cryptography` only. CI enforces this (purity test); do not add
dependencies to those two packages.

## Style

- Google-style docstrings on public functions and classes.
- Wire formats are normative: any change to byte layouts in `zkage_core.token` or
  `zkage_core.translog` must update `docs/DESIGN.md` and the golden-token test fixture
  in the same change.
- Every protocol-level change needs an adversarial test demonstrating the failure it
  prevents.

## Commits

`<type>: <summary>` (types: feat, fix, docs, test, refactor, chore, init). Add a line to
`changelog.txt` for user-visible changes. No co-author trailers.
