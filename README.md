# noita-eye-puzzle

Tooling for analyzing and attempting to decode the **Noita eye-glyph puzzle** —
the sequences of eye symbols hidden in the game that are widely suspected to
encode something, and which the community has not conclusively cracked.

This repo is a workbench for that effort: trustworthy primitives for
representing the glyph sequences and measuring their statistical properties, so
that decoding hypotheses can be tested rather than guessed at.

## Status

Early scaffold. The analysis library works and is tested; the **corpus is still
a placeholder** (see below). Built std-only for now because crates.io was
unreachable when the repo was initialized — see `Cargo.toml` for the
dependencies (clap, rayon, serde, …) to add once you're online.

## Layout

```
src/
  lib.rs        crate root + module overview
  glyph.rs      Glyph / Alphabet / Sequence — how transcribed messages are modelled
  analysis.rs   frequencies, Shannon entropy, index of coincidence, n-grams
  corpus.rs     transcribed eye-message data (PLACEHOLDER — needs real data)
  main.rs       thin CLI (`noita-eye`)
```

## Quick start

```sh
make check                 # fmt + clippy(-D warnings) + tests + release build
cargo run -- demo          # run analysis on the built-in placeholder sample
cargo run -- stats abcabc  # analyse a sequence typed in the placeholder alphabet
```

## The data problem (read before trusting any output)

The `corpus` module currently contains **made-up placeholder sequences** so the
analysis code can run end to end. They are not real puzzle data and any
statistics derived from them are meaningless.

Before doing real work, transcribe the actual eye messages into `corpus.rs`:

1. Decide and document the **glyph inventory** (how many distinct glyphs exist
   and a stable name/character for each). Until this is settled, glyphs are
   modelled as opaque indices (`Glyph(u16)`) rather than a closed `enum`; once
   it is settled, promote it to an `enum` to get exhaustiveness checking.
2. Transcribe each in-game message into a `Sequence`, recording its **source**
   (location in the game / screenshot reference) alongside it.
3. Treat transcription as fallible: a single mis-read glyph poisons downstream
   analysis. Cross-check against community catalogues and keep the raw evidence.

## Guardrails

This repo is set up to keep results trustworthy:

- **`unsafe` is forbidden** (`unsafe_code = "forbid"`).
- **Every public item must be documented** (`missing_docs`).
- **Clippy `all` + `pedantic`**, run as `-D warnings` in CI.
- **`rustfmt`** enforced (`cargo fmt --check`).
- **Pinned toolchain** via `rust-toolchain.toml` (Rust 1.96.0).
- **CI** (`.github/workflows/ci.yml`) runs fmt + clippy + tests + build.
- `make check` runs the whole suite locally — green it before every commit.

## License

Dual-licensed under MIT or Apache-2.0.
