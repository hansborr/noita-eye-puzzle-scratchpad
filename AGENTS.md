# AGENTS.md

Guidance for humans and AI agents working in this repo. (`CLAUDE.md` imports
this file, so there is one source of truth.)

## What this is

A Rust workbench for analyzing and attempting to decode the Noita eye-glyph
puzzle. The aim is *trustworthy* cryptanalysis: primitives that constrain the
hypothesis space, not premature claims about what the glyphs mean.

## Commands

```sh
make verify   # the correctness gate: fmt-check + clippy(-D) + filesize + tests + rustdoc(-D) + cargo-deny
make check    # verify + cargo-machete + codespell + shellcheck + release build (full local CI)
make setup    # install the git pre-commit hook (core.hooksPath = .githooks)
make run ARGS=demo
```

## Golden rules

These are the judgment calls. The mechanical rules (`unsafe`, panics, missing
docs, formatting, `--locked`, file size, supply chain) are enforced by the lints
and gate in the Guardrail map below — they fail the build, so they aren't repeated
here.

- **Commit completed work.** Once a logical change is done, commit it with a clear
  message — don't wait to be asked. Branch off `main` first if you're on it. The
  pre-commit hook gates the commit on the correctness gate, so there's no need to
  run `make check`/`make verify` by hand first.
- **Build instruments, not throwaway scripts or frozen fixtures.** Quick scratch
  exploration is fine — but if a result is worth reporting or handing off, land the
  capability that produced it as a runnable Rust CLI instrument, not a one-off
  script (Python or otherwise) that gets tossed. The instrument accepts arbitrary
  input (`--input-file`/`--stdin` + `--alphabet`, via `cli::shared`), self-validates
  with a planted positive control + matched null, and is exercised by tests through
  the same library functions the CLI calls. A `#[cfg(test)]`-only validation or an
  analysis hardwired to the eye corpus is a regression test, not a tool; a discarded
  scratch script leaves nothing the next agent can rerun.
- **Keep the dependency surface minimal.** Vetted external crates are allowed, but
  justify each by use. The in-crate `SplitMix64` PRNG stays for reproducible null
  models — don't swap it for a crates.io RNG.
- **Never present unverified numbers as findings.** `src/data/corpus.rs` is the
  Experiment-0-verified corpus — the engine base-7 decode is cross-checked
  byte-for-byte against the ngraham20 transcription for all nine messages — so
  statistics from it are meaningful. For anything *unverified or
  model-conditional*, label guessed/assumed choices as such and never report a
  number more strongly than its construction supports. In particular, a
  file-driven *attack* emits a **candidate**, never a "decode": it is believable
  only behind a passing positive control and a matched null, a high
  n-gram/structure score is not a recovery, and a bounded search must state its
  limits and what it dropped. The cross-cutting process lessons live in
  `research/attack-methodology.md`.

## Design notes

- A `Glyph` is an opaque `u16` index into an `Alphabet`, not a closed enum,
  because the broader analysis alphabet still has multiple layers. The rendered
  orientation inventory is settled separately: digits `0`-`4` are the five
  displayed orientations, and `5` is a non-rendered row delimiter. Do not encode
  unverifiable pixel-direction names into those orientation digits.
- The CLI in `main.rs` is intentionally thin: `clap` owns argument parsing and
  subcommands, while all domain logic lives in the library so it stays testable.

## Guardrail map

| Concern            | Mechanism                                             |
| ------------------ | ----------------------------------------------------- |
| Lints / format     | `Cargo.toml [lints]`, `clippy.toml`, `rustfmt.toml`   |
| File size / god-files | `scripts/check-file-size.sh` + `scripts/file-size-allowlist.txt` (ratchet) |
| Supply chain       | `deny.toml` (cargo-deny), `cargo machete`             |
| Toolchain          | `rust-toolchain.toml`, MSRV in `Cargo.toml`+`clippy.toml` |
| Spelling / text    | `.codespellrc`, `.editorconfig`, `.gitattributes`     |
| Shell scripts      | `.shellcheckrc`, `shellcheck` (CI + pre-commit)       |
| Local gate         | `.githooks/pre-commit` (install via `make setup`)     |
| CI                 | `.github/workflows/ci.yml`                            |
| Dangerous commands | `.claude/settings.json` deny list                     |
