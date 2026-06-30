# Changelog

A public history of this workbench: a Rust toolkit for *trustworthy* cryptanalysis
of Noita's "Eye Messages." Every measurement is paired with a null model or a
positive control, so a negative result is meaningful rather than a blind spot.
Entries are grouped by date, newest first, loosely following
[Keep a Changelog](https://keepachangelog.com/).

> Current honest state. The decode remains blocked on the unknown
> symbol→meaning mapping. Everything here *constrains the hypothesis space* — it
> excludes cipher families, pairs each test with a matched null distribution,
> and isolates a single positive structural constraint. It is not a claimed
> solution. The strongest defensible statement remains: deterministic,
> engine-generated, strikingly structured data of unknown meaning; unsolved; no
> primary developer source confirms it encodes recoverable plaintext.

## 2026-06-30 — Harness guardrails and agent hooks

### Added
- **Development harness guardrails.** The pre-commit hook now guards protected
  branches and source-relevant dirty worktrees, checks staged blob size, audits
  safety-lint suppressions against a register, validates the file-size debt log,
  and supports feature-branch fast-commit mode that skips only tests and rustdoc.
- **Claude Code agent hooks.** Added shared `scripts/ai-hooks/` bodies plus thin
  `.claude/hooks/` adapters for commit-bypass guarding, quiet cached cargo runs,
  protected-file advisories, post-edit rustfmt, and a non-blocking stop nudge;
  `.claude/settings.json` also broadens destructive-command deny patterns.
- **Codex agent hook parity.** Added `.codex/hooks.json` plus thin `.codex/hooks/`
  adapters for the same commit-bypass guard, quiet cached cargo runs,
  protected-file advisories, post-edit rustfmt, and stop nudge, with Codex-shaped
  payload parsing/output and documented hook trust setup.
- **Shell smoke-test harness.** Added `scripts/tests/*.sh` coverage and
  `make test-scripts`; CI runs the shell smoke suite.

### Fixed
- **Pre-commit inspection modes cannot bypass real commits.**
  `PRECOMMIT_PLAN_ONLY=1` and `PRECOMMIT_GUARDS_ONLY=1` now abort when invoked
  by `git commit`; they remain direct hook inspection shortcuts.
- **Agent hook hardening.** The commit-bypass guard now recognizes `git` behind
  `command`, path-qualified `*/git`, and `env` prefixes with flags, including
  the Codex hook path.
- **Cargo quiet cache correctness.** `NOITA_QUIET_OFF` uses the same truthy
  values in hook and inline forms, and cached cargo successes now fingerprint
  rustc/toolchain plus Cargo/Rust environment inputs.
- **Guardrail scan coverage.** Safety-suppression inventory now scans all
  tracked Rust files, and file-size ratcheting measures indexed blobs to align
  with staged blob checks.
- **Edit hook coverage.** Claude edit hook matchers include `MultiEdit`, quoted
  project paths, and the cargo quiet smoke suite ignores ambient opt-outs.

## 2026-06-26 — GAK attack threads

Work aligned to the community's Group Autokey (GAK / S₈₃ deck-cipher) framing,
plus a few low-cost open questions.

### Added
- **Known-answer validation of the GAK recovery machinery (G1).** The GCTAK solver,
  previously shown only ciphers it generated itself, is now driven against two
  externally-sourced practice puzzles. Puzzle `one` (a cyclic ±1 walk on C5) is
  recovered [confirmed] as a positive control, while a matched within-message
  shuffle null does *not* recover — proving the tool fires on real known signal.
- **Hidden-state GAK attack (G1b).** A marginalization-based attack for many-valued
  (hidden-state) readouts, validated on a synthetic miniature matched to practice
  puzzle `two`. On `two` itself the result is an honest negative: the positive
  control fires, but `two` dies via coverage collapse, with the attack-conditional
  failure point recorded. The first attack exercising the eyes' hidden-state blocker
  on a verifiable miniature.
- **Held-out survival gate (T1).** A fold-vs-fold test so any candidate decode must
  survive on data it was not fit to.

### Excluded / answered
- **AGL(1,83)-GAK family exhaustively excluded** — a wiki-postable write-up ruling
  out the affine keystream family over the 83-state alphabet by exhaustion.
- **Base-5 first-trigram ("Message-Starts") structure.** Over all nine messages
  (n=9), the first-trigram-as-index, as-checksum, and as-last-character hypotheses
  are each rejected — answering a standing community question with a clean negative.

## 2026-06-24 — Extended structural battery and binary confirmation

### Confirmed
- **Corpus cross-checked against the binary [confirmed].** It is already
  community knowledge — and we re-derived it with Ghidra on the shipping
  `noita.exe` for our own corpus validation — that the nine messages are
  hardcoded `(low, high)` u32 constants selected only by message id, with the
  world seed randomizing only *where* eyes appear, not their content. All 150
  transcription pairs match the decompiled immediates byte-for-byte, which
  re-validates the project's #1 risk (transcription error). The storage path holds
  opaque integers with no symbol→meaning table, so the decode block is a real
  cryptanalytic gap rather than missing reverse-engineering.

### Positive result
- **Zero-adjacency forbidden-successor null** — *the one positive structural result.*
  The eyes' 0/1027 adjacent-equal trigrams sit *below* a within-message
  multiset-preserving shuffle band (~6..19; analytic E = 12.008), add-one lower-tail
  p ≈ 2.0e-4. A genuine no-doubled-trigram (forbidden-successor) constraint, not
  a frequency-flatness artifact.

### Excluded / honest negatives (all mapping-independent; none decode)
- **Incrementing-wheel fingerprint disfavored** — the k=1 mod-83 difference stream is
  structureless, landing in the deck/flat band rather than a single-dominant-difference.
- **No first-order memory** — successor-graph mutual information ≈0 (~1e-4 of max);
  nothing beyond the known no-adjacent-repeat constraint.
- **No isolated 2D structure** on the honeycomb lattice (vertical equality collapses
  to a disclosed 1D autocorrelation; parity and position checks unremarkable).
- **No second reused-key layer** — after masking the Perseus trunk, residual tails
  show only a marginal k=3 excess that does not survive multiplicity.
- **Cross-message orientation homogeneity** sits in the null bulk (p = 0.188):
  constrains source homogeneity, not meaning.
- **Pyry's nine conditions.** Encoding the community's 9-point checklist as
  predicates, monoalphabetic / Vigenère / deck-S₈₃ / incrementing-wheel fixtures are
  each falsified, while only the autokey/Alberti self-modifying family stays
  consistent with all nine — favoring a plaintext-dependent self-modifying
  direction. Candidate-consistency screen only, not a decode.

Together the battery tightens the cipher-family space toward a non-commutative /
no-fixed-successor / self-modifying direction, while decoding nothing.

## 2026-06-22 — Core structural battery (Experiments 2-12)

Each experiment pairs a measurement with a null or a positive control. Eye results
are uniformly negative; calibration controls fire positive.

### Excluded
- **Exp 2 — generation-pipeline artifact null.** The base-7 engine pipeline does
  not manufacture the bounded 0–82 contiguity ⇒ the anomaly is not a generation
  artifact.
- **Exp 4 — frequency / entropy / IoC across orders.** Flat per-symbol frequency
  (reproducing the community IoC ≈ 1.066, mean 12.48; χ² = 150.355) rules out
  monoalphabetic substitution — but does not rule a real message *in*.
- **Exp 5A — periodicity / autocorrelation.** No period or lag clears the random
  null band (beyond the order-contingent distance-4 spike, honestly reconciled with
  Exp 1B as family-wise vs pointwise).
- **Exp 7A — isomorph shuffle null.** The eyes carry no isomorph structure beyond
  a within-message shuffle of their own symbols.
- **Exp 7B — alphabet chaining.** The eyes match the known-fail chaining
  signature, not the known-succeed Vigenère band (additive-relationship model).
- **Exp 7C — Perseus recurrence null.** 0/185 non-shared→later-shared
  recurrences (add-one lower-tail p = 0.006993; multi-seed range 4/1001..9/1001).
  Corroborates a structural permutation direction; decodes nothing.
- **Global transposition disfavored.** The nine honeycomb trigram streams have
  distinct lengths while shared runs hold the same offsets, so one shared global
  transposition route is disfavored (evidence against, not an impossibility proof).
- **Exp 8 — grouping + state count.** No grouping is both alphabet- and
  entropy-compatible with a language; an independent collision estimator (not
  assuming 83) puts the state count at ≈ 73–90 — ~83 genuine near-uniform states.
- **Exp 12 — candidate ciphers.** Caesar, Vigenère, incrementing-wheel, Chaocipher,
  and an S₈₃ deck cipher, scored against English/Finnish under *guessed* (unverifiable)
  mappings, yield no decryption above chance (~21–293× below a plant the same
  harness recovers).

### Positive controls
- Exp 11 (solved monoalphabetic + polyalphabetic ciphers) and Exp 5B-1
  (English-vs-Finnish n-gram discrimination) confirm the tooling recovers known
  signal — so the eye negatives are meaningful. One isomorph control was caught
  degenerate (two "different" fixtures were byte-identical) and redesigned to
  recover a real Kasiski period honestly.

## 2026-06-21 to 2026-06-22 — Foundation: verified corpus and the decisive null

### Added / confirmed
- **Experiment 0 — verified corpus [confirmed].** The nine real messages are ingested
  with provenance; a test independently re-derives the engine base-7 decode from
  the raw `[u32, u32]` pairs and asserts it equals the ngraham20 transcription
  byte-for-byte for all nine messages. Raw inputs are vendored in-repo.
- **Experiment 3 — counts.** Eye counts all divisible by 3; 1036 trigrams total;
  `(83/125)^1036 = 5.836e-185`. All as tests.
- **Experiments 1A / 6 — reading orders.** Reconstruct the nine glyph grids and a
  data-independent honeycomb traversal. The honeycomb winner is the only order
  yielding 83 distinct, contiguous 0–82 values with zero adjacent-equal and a clean
  distance-4 spike — confirming the order-contingency thesis.
- **Experiment 1B — the decisive null.** A deterministic Monte-Carlo over
  shape-matched random grids: the contiguous-0–82 headline is 0/1000 across five
  seeds, and the analytic Bonferroni/Šidák correction (~2.10e-183) does not deflate
  the per-order improbability.
- **Researcher-DoF adaptive null.** A calibrated min-p null over the
  traversal × grouping × statistic search space. The empirical adaptive p is a
  finite-resolution *floor diagnostic* (it censors the eyes' effect at the
  calibration floor), while the analytic configured-DoF correction remains ≈1e-182,
  so the bounded 0–82 anomaly survives the multiplicity correction analytically.
