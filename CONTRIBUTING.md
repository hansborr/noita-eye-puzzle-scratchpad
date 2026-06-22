# Contributing

## Prerequisites

- Rust (the pinned toolchain installs automatically via `rust-toolchain.toml`;
  see `rust-version` for the MSRV).
- Optional dev tools used by the full gate:
  `cargo install cargo-deny cargo-machete` and `pipx install codespell`
  (or `pip install codespell`).

## From clone to running

```sh
make setup          # install the pre-commit hook
cargo run -- demo   # run the CLI against the (placeholder) sample corpus
```

## Inner loop

```sh
make verify   # fmt-check + clippy(-D warnings) + tests + rustdoc(-D warnings) + cargo-deny
make check    # everything in verify + cargo-machete + codespell + release build
```

`make verify` is the gate the pre-commit hook runs and must pass before every
commit. CI (`.github/workflows/ci.yml`) runs the same checks plus the release
build, so a green `make check` locally means a green CI.

## Conventions

- No `unsafe`; no panics/unwraps in library or CLI code (relaxed in tests).
- Document every public item; keep doc examples compiling.
- Commit `Cargo.lock` changes deliberately; everything runs with `--locked`.
- Don't commit numbers derived from the placeholder `corpus.rs` as if they were
  real findings — see `AGENTS.md`.
