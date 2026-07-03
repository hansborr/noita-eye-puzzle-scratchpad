# Task 01 — Lymm deck-cipher oracle + KP corpus plumbing + differential test

**Mission (one pass, one agent).** Build the exact, parameterized deck-cipher
*oracle* and the known-plaintext corpus plumbing, and gate it on a differential
test that reproduces Lymm's vendored ciphertexts **byte-for-byte**. No recovery
engine yet — this task exists to retire the #1 project risk (orientation /
compose-direction) before anyone builds a solver on top of a wrong oracle.

Read first: `research/handoff/gak-swap-recovery/README.md` (framing, cipher,
reuse map, risks) and the vendored generator
`research/data/practice-puzzles/deck-swap/noita_test_cipher.py`. House rules:
`research/handoff/README.md`.

## Deliverables

1. **`encrypt_lymm_deck` (library fn).** A parameterized deck-cipher oracle
   matching Lymm's generator exactly:
   - state starts at `initial_state` (default identity);
   - per plaintext letter `L`: `state = compose(perm(L), state)` with
     `compose(p1,p2)=p2[p1]` (i.e. `new[i]=state[perm(L)[i]]`); emit
     `ct_alphabet[state[0]]`;
   - non-alphabet chars pass through verbatim and **do not advance the state**;
   - parameters (see also Task 03): `n`, pt/ct alphabets, `base`, `initial_state`,
     `compose_dir` (left vs right/inverse), `emit_index` (default 0). Keep
     `compose_dir` and `emit_index` as parameters even though this corpus only
     needs the defaults — they cost nothing now and Task 03 needs them.
   Reuse `src/ciphers/validation.rs` composition helpers. Do **not** route the core
   loop through `GakKey::deck`'s inverse-position readout; implement Lymm's
   convention directly (the inverse bridge is a documented equivalence, not the
   clean primitive to build on).
2. **`LymmDeckSpec`.** A small struct carrying the parameters above +
   `base` construction from `shift,decimation` (`base = rotations[shift] ∘
   decimations[decimation]`, matching the generator) or from an explicit array.
3. **Seeded mapping generator (plant).** Port `generate_random_pt_mapping`: from a
   base and `num_swaps`, produce a `pt_mapping` (per-letter perm) via top-swap
   chains, honoring the reversibility/no-doubles rule (`perm(L)[0] != 0` and
   distinct across letters). Use the in-crate `SplitMix64` (not a crates.io RNG)
   so plants are reproducible. This is the positive-control + null factory for
   Task 02.
4. **Top-swap candidate enumerator.** `enumerate_top_swap_domains(spec,
   constraints)` — generate the reachable `σ` set (product of ≤`num_swaps` `(0 k)`
   transpositions), indexed by `perm[0]` and support, with identity/repeat swaps
   handled and a canonical final permutation per candidate. Task 02 consumes this.
5. **KP pair parser.** Parse the labeled multi-message corpus:
   `plaintexts.txt` (`"<label>: <PT>"` per line) and the ct files (`"<label>:"`
   then the ciphertext on the next line) into aligned `(pt, ct)` pairs sharing one
   key. Reuse `cli::shared` split/parse helpers where they fit. Assert
   `count(alpha chars in pt) == len(ct)` per message.
6. **Differential test (the acceptance gate).** A `#[test]` that, for each of
   `num_swaps ∈ {1,2,3}`, loads the vendored corpus and asserts the oracle +
   the parser round-trip cleanly, AND a test that reproduces the exact vendored
   ciphertext from a known mapping. Since the vendored files were generated with a
   *random* (unrecorded) mapping, do the byte-for-byte check the reproducible way:
   plant a mapping with a fixed seed, encrypt `plaintexts.txt`, and assert the
   library's own encrypt/decrypt/parse are self-consistent and that a
   hand-verified small vector (documented in the test) matches. (Task 02's
   recovery test is what proves the oracle against the *actual* vendored ct.)

## Acceptance criteria

- `make verify` green (the pre-commit hook runs it).
- Oracle + plant + parser are library fns; the tests call the same fns a future
  CLI will. No test-only capability, no throwaway script.
- Differential/self-consistency tests pass for ns ∈ {1,2,3}.
- A short note appended to `research/data/practice-puzzles/deck-swap/README.md`
  (or a new `research/gak-threads/` entry) recording that the oracle reproduces
  Lymm's convention, with the one hand-verified vector.

## Notes / gotchas

- Orientation is the whole point of this task — if the oracle is even slightly
  off (`σ∘base` vs `base∘σ`, emission index, passthrough), everything downstream
  is silently wrong. Cross-check against the Python generator's output.
- A pure-Python reference oracle already validated the `num_swaps=1` path
  end-to-end against the vendored files (all 8 messages, exact re-encryption); the
  Rust oracle must match it.
- Do not commit ground-truth recovered mappings for the vendored files as fixtures
  — recovery is Task 02's job and its own acceptance evidence.
