# CLAUDE.md

Guidance for working in this repo.

## What this is

A Rust workbench for analyzing and attempting to decode the **Noita eye-glyph
puzzle**. The aim is *trustworthy* cryptanalysis: primitives that constrain the
hypothesis space, not premature claims about what the glyphs mean.

## Golden rules

- **Run `make check` before every commit.** It must be green: `cargo fmt
  --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, release
  build. CI enforces the same.
- **Keep the build green for real.** Don't silence clippy with blanket
  `#[allow]`s to dodge work; fix the cause or justify a narrow, commented allow.
- **`unsafe` is forbidden** crate-wide. Don't reach for it.
- **Document every public item** — `missing_docs` is on.
- **Never present placeholder-derived numbers as findings.** `corpus.rs` is
  fake sample data until real eye messages are transcribed (see README). Any
  statistic computed from it is meaningless; say so.
- **Transcription is the risk.** A single mis-read glyph invalidates downstream
  analysis. When adding real data, record its in-game source and cross-check.

## Dependencies

The crate is std-only because crates.io was unreachable at init. Intended deps
(clap, rayon, serde, serde_json, anyhow; proptest for dev) are listed and
commented in `Cargo.toml` — add them when online, then re-run `make check`.

## Design notes

- A `Glyph` is an opaque `u16` index into an `Alphabet`, **not** a closed enum,
  because the glyph inventory isn't settled yet. Promote to an `enum` (for
  exhaustiveness checking) once it is.
- The CLI in `main.rs` is intentionally thin; logic lives in the library so it
  stays testable. Move to `clap` subcommands when deps are available.

## Commands

```sh
make check          # full guardrail suite
make run ARGS=demo  # run the CLI
cargo test          # tests only
```
