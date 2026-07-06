# Handoff - unknown-base GAK / deck-cipher recovery

**Status:** task 01 built; task 02 is the next solver rung
**Priority:** active when the goal is to help Lymm's stated GAK-attack interests,
rather than to move the eyes decode directly
**Depends on:** `gak-swap-recovery/`, especially `gak-swap-recover` and
`research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-METHOD.md`

## Mission

Build a measured method for solving smaller GAK/deck ciphers faster than brute
force when the shared base permutation is not provided.

The current `gak-swap-recover` instrument answers the public-base,
known-plaintext practice task: given plaintext, ciphertext, group size, swap
budget, generator family, and base permutation, recover the observed per-letter
permutations and verify by exact re-encryption. That is useful, but it does not
cover Lymm's key objection for any eyes-facing transfer: the real eyes would not
come with a known base permutation.

This track removes that assumption on controlled smaller instances first. It is
community GAK tooling, not an eye decode.

## Research Question

Given:

- known plaintext/ciphertext pairs;
- a deck size `n`;
- a generator family, initially top-card swaps `(0,k)`;
- a swap budget `s`;
- identity restarts per message;
- one shared per-letter key of the form `perm(L) = B o sigma_L`;

but **not** the base permutation `B`, can we recover one of the following faster
than brute force?

1. the planted base `B` and observed per-letter perturbations `sigma_L`;
2. an equivalent key that re-encrypts byte-for-byte;
3. a smaller recoverable invariant, with the non-identifiability measured rather
   than hidden.

The acceptance oracle is exact re-encryption for known plaintext. Language
scoring is out of scope until this algebraic surface is understood.

## Why This Helps Lymm

Lymm's stated interest is a general method for solving smaller GAK ciphers faster
than brute force. The known-base practice solver is a good first rung, but it
still assumes away the base permutation. This handoff targets the next rung:
base recovery or base marginalization on synthetic and practice-sized instances.

This is also the right response to the "symbol-to-meaning mapping" problem. No
fixed eye-symbol table is being requested or assumed. The plaintext-letter to
group-action assignment is the key being recovered, and in this track even the
shared base action is hidden.

## Non-Goals

- Do not point this at the real eyes first. The eyes are ciphertext-only and have
  no known plaintext crib.
- Do not report a language-like string as a recovery. The first surface is
  known-plaintext key recovery with exact re-encryption.
- Do not silently assume the planted base is uniquely identifiable. If multiple
  bases explain the stream, that is a result.
- Do not generalize a top-swap result to arbitrary GAK. Report the measured
  model surface and its limits.

## Suggested Implementation Ladder

### 01 - Hidden-base fixture and identifiability audit

**Built:** see
[`01-hidden-base-fixture-audit.md`](01-hidden-base-fixture-audit.md). The landed
instrument is `gak-hidden-base-audit`, backed by
`plant_hidden_base_fixture`, `audit_hidden_base_mapping`,
`run_hidden_base_identifiability_audit`, and `hidden_base_audit_self_test`.
It plants synthetic known-plaintext hidden-base fixtures, accepts only by exact
re-encryption of a supplied mapping, and audits whether that mapping's
decomposition as `perm(L) = B o sigma_L` identifies the planted base or leaves an
equivalent hidden-base class. Default controls include a planted positive, random
full-permutation null, over-budget null, true-budget positive, and
ciphertext-label-shuffle null.

Add a fixture generator beside the Lymm deck machinery that can plant:

- `n in {7, 11, 17}` initially;
- swap budgets `s in {1, 2, 3}`;
- a random or structured hidden base `B`;
- top-card-swap perturbations per observed plaintext letter;
- several identity-reset known-plaintext messages under one shared key.

The first result should be an identifiability report, not a solver claim:

- how often the planted `B` is uniquely determined;
- how often only an equivalent re-encrypting key is determined;
- how many plaintext letters and off-top positions are genuinely unconstrained;
- what minimal corpus shape is needed before the public-base solver's
  substitution-first trick has enough signal.

Acceptance:

- planted positive controls fire end-to-end;
- exact re-encryption is the only success condition;
- a random full-permutation key, an over-budget key, and a ciphertext-label
  shuffle fail cleanly under the same search surface.

### 02 - Known-plaintext unknown-base solver, `s = 1`

Start with `s = 1` because the per-letter perturbation has one target and the
candidate surface is small enough to inspect exhaustively on small `n`.

The useful output is not necessarily "recover the planted base exactly." Prefer a
report with explicit states:

- `RecoveredPlantedBase`;
- `RecoveredEquivalentKey`;
- `AmbiguousEquivalentClass`;
- `NoCandidate`;
- `SearchCapExceeded`.

Measure against brute force in both candidate count and wall time.

### 03 - Base-marginalized substitution-first local search, `s = 2..3`

Adapt the existing substitution-first coordinate-descent idea:

1. propose or refine the visible top mapping per letter;
2. infer constraints on the hidden base positions consistent with those tops;
3. search/refine per-letter perturbations inside the current base hypothesis;
4. accept only by exact re-encryption;
5. basin-hop with a deterministic PRNG if the prefix score stalls.

The important measurement is where this beats direct enumeration and where it
collapses into non-identifiability.

### 04 - Optional ciphertext-only bridge

Only after the known-plaintext unknown-base track has a calibrated positive
control, add a ciphertext-only experiment. If this happens, the first question is
power calibration on planted English/Finnish corpora, not the eyes.

Any language-scored candidate remains a candidate unless independently anchored.

## Reporting Requirements

Every result should record:

- the exact cipher convention: compose direction, emission index, base side, and
  generator set;
- the searched `n`, swap budget, corpus size, and message restart structure;
- whether the planted base, an equivalent key, or only a partial invariant was
  recovered;
- exact re-encryption counts;
- positive-control and matched-null outcomes;
- how the result compares to brute force.

## Reuse Map

- `src/attack/gak_attack/lymm_deck/` for the Lymm deck convention and corpus
  parsing.
- `src/attack/gak_attack/lymm_deck/recovery/local_search.rs` for the
  substitution-first local-search pattern.
- `src/cli/args_gak_swap.rs` and `src/cli/commands/gak_swap*.rs` for CLI shape if
  this becomes a command.
- `src/nulls/` and the existing `SplitMix64` helpers for deterministic controls.
- `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-METHOD.md` for the
  public-base baseline and its honesty limits.

## First Concrete Task

Write a small design/fixture task file under this directory for `01`, then build
the fixture plus an identifiability-only report. Do not start with an eyes run or
a language-scored ciphertext-only attack.
