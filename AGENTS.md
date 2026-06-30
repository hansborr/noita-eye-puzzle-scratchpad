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
make check    # verify + blob-size + suppressions + cargo-machete + codespell + shellcheck + test-scripts + release build (full local CI)
make test-scripts  # run scripts/tests/*.sh shell smoke tests
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

### Fast-commit mode

For cheap intermediate commits on feature branches only, enable the worktree-local
pre-commit shortcut with `touch "$(git rev-parse --git-dir)/noita-fast-commit"`.
It skips only `cargo test` and the rustdoc check; it still runs rustfmt, clippy,
file-size, blob-size, suppressions, and cargo-deny. CI and `make verify` /
`make check` always remain the full gate. Disable it with
`rm "$(git rev-parse --git-dir)/noita-fast-commit"`.

`PRECOMMIT_PLAN_ONLY=1` and `PRECOMMIT_GUARDS_ONLY=1` are direct dry-run
inspection shortcuts. They exit 0 only when `.githooks/pre-commit` is run
directly; during a real `git commit`, they abort instead of bypassing the gate.

### Agent hooks

Claude Code and Codex hooks use shared bodies in `scripts/ai-hooks/` with thin
`.claude/hooks/` and `.codex/hooks/` adapters. Hook errors fail open (they emit
"continue" rather than blocking a tool call); only a confident commit-bypass
match is intentionally denied.

Codex only runs this repo's `.codex/hooks.json` after each hook entry is trusted
for this worktree. Start Codex in `/home/node/persist/noita-eye-puzzle-maint` and
accept the hook trust prompts, or preseed equivalent entries in
`~/.codex/config.toml` using the hashes shown by Codex:

```toml
[features]
hooks = true

[hooks.state."/home/node/persist/noita-eye-puzzle-maint/.codex/hooks.json:pre_tool_use:0:0"]
trusted_hash = "sha256:<codex-reported hash>"

[hooks.state."/home/node/persist/noita-eye-puzzle-maint/.codex/hooks.json:pre_tool_use:1:0"]
trusted_hash = "sha256:<codex-reported hash>"

[hooks.state."/home/node/persist/noita-eye-puzzle-maint/.codex/hooks.json:post_tool_use:0:0"]
trusted_hash = "sha256:<codex-reported hash>"

[hooks.state."/home/node/persist/noita-eye-puzzle-maint/.codex/hooks.json:stop:0:0"]
trusted_hash = "sha256:<codex-reported hash>"
```

- `commit-bypass-guard` (PreToolUse Bash) blocks pre-commit/history bypasses
  such as `--no-verify`, `-n`, `--amend`, and `git -c core.hooksPath=...` while
  allowing normal commits.
- `cargo-run-quiet` (PreToolUse Bash) summarizes and caches whitelisted
  `cargo test`/`clippy`/`build`/`check` and `cargo fmt --check` output. Opt out
  with `NOITA_QUIET_OFF=1` (including an inline prefix) or `.noita-quiet-off`.
- `protected-files-advisory` (Claude PreToolUse Edit|Write, Codex PreToolUse
  apply_patch) gives throttled heads-up notes when editing guardrails, Cargo
  policy/dependency files, the verified corpus, or embedded research fixtures.
- `tidy-on-edit` (Claude PostToolUse Edit|Write, Codex PostToolUse apply_patch)
  runs `rustfmt` on edited in-repo `.rs` files; failures are advisory.
- `stop-nudge` (Stop, non-blocking) reminds about uncommitted work. Disable it
  with `.no-stop-uncommitted`.

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
| File-size debt log | `scripts/file-size-debt-log.jsonl` (`scripts/check-file-size.sh --summary`) |
| Large staged blobs | `scripts/check-blob-size.sh` + `scripts/blob-size-allowlist.txt` |
| Safety-lint suppressions | `scripts/check-suppressions.sh` + `scripts/suppression-register.txt` |
| Supply chain       | `deny.toml` (cargo-deny), `cargo machete`             |
| Toolchain          | `rust-toolchain.toml`, MSRV in `Cargo.toml`+`clippy.toml` |
| Spelling / text    | `.codespellrc`, `.editorconfig`, `.gitattributes`     |
| Shell scripts      | `.shellcheckrc`, `shellcheck` (CI + pre-commit)       |
| Harness shell tests | `scripts/tests/` (`make test-scripts`, CI)           |
| Local gate         | `.githooks/pre-commit` (install via `make setup`)     |
| CI                 | `.github/workflows/ci.yml`                            |
| Dangerous commands | `.claude/settings.json` deny list                     |
| Agent hooks        | `.claude/settings.json` + `.codex/hooks.json` hooks, thin adapters in `.claude/hooks/` and `.codex/hooks/`, shared bodies in `scripts/ai-hooks/` |
