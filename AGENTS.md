# AGENTS.md

Guidance for humans and AI agents working in this repo. (`CLAUDE.md` imports
this file, so there is one source of truth.)

## What this is

A Rust workbench for analyzing and attempting to decode the **Noita eye-glyph
puzzle**. The aim is *trustworthy* cryptanalysis: primitives that constrain the
hypothesis space, not premature claims about what the glyphs mean.

## Commands

```sh
make verify   # the correctness gate: fmt-check + clippy(-D) + tests + rustdoc(-D) + cargo-deny
make check    # verify + cargo-machete + codespell + shellcheck + release build (full local CI)
make setup    # install the git pre-commit hook (core.hooksPath = .githooks)
make run ARGS=demo
```

## Golden rules

- **`make check` (or at least `make verify`) must be green before every commit.**
  The pre-commit hook runs the correctness gate automatically once installed;
  CI runs the same gate plus the release build.
- **`unsafe` is forbidden** crate-wide (`unsafe_code = "forbid"`). Don't reach for it.
- **No panics or silent failures in library/CLI code.** `unwrap`/`panic`/
  `indexing_slicing`/`unused_results` and friends are lints (warn → `-D warnings`
  in CI). They are relaxed inside tests via `clippy.toml`. If you must allow one,
  use `#[allow(..., reason = "...")]` — bare `#[allow]` is itself linted.
- **Document every public item** (`missing_docs`), and keep doc examples
  compiling: `cargo doc` runs with `RUSTDOCFLAGS="-D warnings"`.
- **`--locked` everywhere.** Don't let a command silently re-resolve `Cargo.lock`;
  commit lockfile changes deliberately.
- **Never present unverified numbers as findings.** `corpus.rs` is now the real,
  Experiment-0-verified corpus — the engine base-7 decode is cross-checked
  byte-for-byte against the ngraham20 transcription for all nine messages — so
  statistics computed from it are meaningful. The discipline still holds for
  anything *unverified or model-conditional*: label guessed/assumed choices as
  such (e.g. Exp 12's unknown symbol→letter mappings, Exp 7B's
  additive-relationship model) and never report a number more strongly than its
  construction supports.
- **Transcription is the risk.** A single mis-read glyph invalidates downstream
  analysis. When adding real data, record its in-game source and cross-check.

## Design notes

- A `Glyph` is an opaque `u16` index into an `Alphabet`, **not** a closed enum,
  because the broader analysis alphabet still has multiple layers. The rendered
  orientation inventory is settled separately: digits `0`-`4` are the five
  displayed orientations, and `5` is a non-rendered row delimiter. Do not encode
  unverifiable pixel-direction names into those orientation digits.
- The CLI in `main.rs` is intentionally thin; logic lives in the library so it
  stays testable. Move to `clap` subcommands as the CLI grows.

## Guardrail map

| Concern            | Mechanism                                             |
| ------------------ | ----------------------------------------------------- |
| Lints / format     | `Cargo.toml [lints]`, `clippy.toml`, `rustfmt.toml`   |
| Supply chain       | `deny.toml` (cargo-deny), `cargo machete`             |
| Toolchain          | `rust-toolchain.toml`, MSRV in `Cargo.toml`+`clippy.toml` |
| Spelling / text    | `.codespellrc`, `.editorconfig`, `.gitattributes`     |
| Shell scripts      | `.shellcheckrc`, `shellcheck` (CI + pre-commit)       |
| Local gate         | `.githooks/pre-commit` (install via `make setup`)     |
| CI                 | `.github/workflows/ci.yml`                            |
| Dangerous commands | `.claude/settings.json` deny list                     |
