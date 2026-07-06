# General small-N GAK solver with unknown base permutation

**Tier:** active research direction · **Size:** L · **Type:** code+doc · **Status:** Todo
**Depends on:** `gak-swap-recover --strategy local-search` and the existing GAK
generator/oracle code
**Touches:** likely `src/attack/gak_attack/`, `src/cli/args_gak_swap.rs`,
`src/cli/commands/gak_swap*.rs`, tests, and a new result note

## Goal

[Lymm] stated on 2026-07-06 that the highest-value direction is not another
direct attack on the eyes, but "giving a general method of solving smaller GAK
ciphers that is faster than bruteforce."

Build a reusable small-`N` GAK solver that beats brute force on planted instances
where the base permutation is unknown. Cover both:

1. **Known-plaintext recovery:** plaintext/ciphertext pairs are available, but
   the shared base permutation and letter-to-action assignment are hidden.
2. **Ciphertext-only recovery:** plaintext is hidden; the solver may recover
   structural candidates or partial key constraints, but must not report a decode.

The existing `gak-swap-recover --strategy local-search` path is rung 0: it solves
known-plaintext practice puzzles when the base permutation is public by
construction. This task asks what survives once that base permutation becomes an
unknown to recover or marginalize over.

## Non-goal

Do not point this at the real eyes first. The eyes publish-and-close stance is
unchanged: the real corpus has no known plaintext, unknown base permutation, and
too little text for an uncalibrated search claim. Any eyes-facing transfer comes
only after planted controls, matched nulls, and a measured small-`N` scaling
frontier.

## Rungs

1. **State the public-base baseline.**
   Document the exact assumptions of `gak-swap-recover`: known plaintext, known
   group size, known generator family, public base permutation, identity/reset
   convention, and exact re-encryption acceptance. The report should make the
   public-base dependency impossible to miss.

2. **Plant unknown-base fixtures.**
   Add a file-driven generator for small `N` GAK instances with a hidden base
   permutation, per-letter actions generated as small words or small-support
   perturbations around that base, configurable message count/length, and a saved
   ground-truth sidecar for tests. Keep the planted fixture format independent of
   the eyes.

3. **Known-plaintext unknown-base solver.**
   Beat a declared brute-force baseline on small `N` by recovering the base
   permutation plus the observed letter actions, or by narrowing them to an
   exact-reencryption-equivalent class whose ambiguity is explicitly reported.
   Acceptance is byte-for-byte re-encryption of held-out known plaintext/ciphertext
   pairs, not a high score.

4. **Ciphertext-only structural solver.**
   Use isomorph/chaining constraints to recover candidate transformations,
   partial coset action, or base-permutation hypotheses without plaintext. Report
   held-out structural prediction against a matched null. If the result is only a
   candidate set or a negative, say that plainly.

5. **Scaling boundary.**
   Publish the measured frontier: `(N, alphabet size, message budget, generator
   radius, base-search strategy, runtime, exact/partial recovery)`. State what the
   bounded search drops. "Faster than brute force" must be a measured comparison
   against the same planted distribution, not a vague complexity claim.

## Validation rules

- Every rung needs a planted positive control that fires and a matched null under
  the same scoring rule.
- The same library functions must power tests and CLI reports. A `#[cfg(test)]`
  only solver or discarded scratch script is not a deliverable.
- File-driven input is required for any new instrument (`--input-file`/`--stdin`
  style via the existing CLI shared helpers where applicable).
- Use deterministic seeds and the in-crate reproducible PRNG patterns; record
  every seed and bound needed to reproduce a number.
- A real or synthetic candidate is a candidate until exact re-encryption or a
  held-out structural gate promotes it within its stated model.

## Definition of done

- [ ] Public-base assumptions are surfaced in the existing swap-recovery report or
      a companion note.
- [ ] Unknown-base planted fixtures exist and round-trip.
- [ ] Known-plaintext unknown-base recovery beats its brute-force baseline on at
      least one nontrivial small-`N` setting with an exact held-out gate.
- [ ] Ciphertext-only mode either beats its matched null on a planted structural
      target or logs an honest negative with the positive control still firing.
- [ ] A result note records the measured frontier and claim ceiling.
- [ ] `make verify` green, then committed.

## Pointers

- `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-METHOD.md`
- `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-RESULTS.md`
- `research/handoff/gak-swap-recovery/README.md`
- `src/attack/gak_attack/lymm_deck/recovery/local_search.rs`
- `src/cli/commands/gak_swap.rs`
- `research/findings/eyes-structural-summary.md` for the eyes-side claim ceiling
