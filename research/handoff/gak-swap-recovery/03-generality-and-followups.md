# Task 03 — generality, shareability, and reach (optional follow-ups)

**Mission.** Once Tasks 01–02 land (oracle + recovery + controls proven on the
vendored ns=1/2/3 files), generalize the instrument toward Lymm's actual ask
("work on larger groups than these small examples") and make it shareable with the
Python-first community. This is a menu of independent follow-ups — pick per
marginal value; it is fine to do a subset.

Read `research/handoff/gak-swap-recovery/README.md` first. House rules:
`research/handoff/README.md`.

## Follow-ups (independent; each is its own small commit)

1. **`num_swaps` inference (`--infer-swaps a..b`).** Run increasing `s` and report
   the smallest `s` whose exact final-perm support closes with a passing round-trip.
   Report the *support* size, not the swap-word length — identity/repeat swaps make
   a length-3 key equivalent to a shorter permutation.

2. **Generator-set generality.** Today `σ` is a top-swap chain `{(0 k)}`.
   Generalize the model to `perm(L) = base ∘ (word of length ≤ K over a generator
   set G)` and let the engine pick its branch representation automatically:
   - *support-based fast path* when generators are small-support (transpositions) —
     branch over which few positions moved (what makes S₈₃/top-swaps tractable);
   - *word-based general path* otherwise (rotations/decimations move everything, so
     "small Hamming distance to base" no longer holds) — branch over generator
     words `|G|^K` with the forced-top prune and MITM split.
   Expose `--generator-set top-swaps | --generator-file`.

3. **Reach for higher `num_swaps` / larger `n`.** Wire the fallbacks:
   per-letter **meet-in-the-middle** over generator words (`O(|G|^⌈m/2⌉)`), and an
   optional **SAT / CP-SAT** encoding (variables = `perm(L)[i]` one-hot;
   constraints = all-different, small-support cardinality vs base, and the
   state-walk emission equalities as channelling). Keep SAT behind a flag and off
   the default path — it trades transparency for reach and is only worth it when
   the propagation frontier is genuinely too wide (ns ≳ 5). Add a **larger-group
   stress self-test**: plant + recover at a couple of `n` values and a swap sweep,
   asserting exact recovery and reporting the measured feasibility frontier. Never
   claim "scales arbitrarily" — publish the measured `(n, num_swaps)` boundary.

4. **Shareability surface.** Emit `--output json` (recovered mapping, swap words,
   support, verdict, round-trip) and a copy-pasteable **Python `pt_mapping` dict**
   so Lymm can plug a recovered key straight back into `noita_test_cipher.py`. Ship
   a **thin reference-Python oracle** (encrypt + mapping generator only — not the
   attack) under `research/data/practice-puzzles/deck-swap/` or a `tools/` path,
   with a differential test asserting the Rust oracle reproduces it byte-for-byte
   on the vendored files. A PyO3 binding is more than this needs; a file-I/O CLI
   the community can shell out to is enough.

5. **Compose-direction / emission-index / secret-initial-state knobs.** Finish
   wiring `--compose-direction left|right` (right = multiply by inverse; math is
   symmetric) and `--emit-index` (the forced-entry deduction generalizes to
   `perm(L)[emit_index]`). If `initial_state` is ever secret it becomes an extra
   unknown and the bootstrap changes — do not hardwire the identity-start
   assumption into the core recovery.

## Acceptance criteria

- `make verify` green for whatever subset is implemented.
- Any new capability is a file-driven, self-validated library fn + CLI knob with a
  planted control + matched null (`AGENTS.md`) — no test-only or throwaway code.
- The measured-frontier claims are labeled model-conditional; a bounded search
  states its limits and what it dropped.

## Why this ordering

The community request is explicitly about *generality* ("larger groups"), but the
trustworthy path is oracle → recovery-proven-on-known-data → generalize. Doing
generality before the ns=1/2/3 proof risks a fast, wrong engine. Land 01–02 first.
