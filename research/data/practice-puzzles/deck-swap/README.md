# `deck-swap` — GAK deck-cipher known-plaintext swap-recovery corpus

External samples from the Noita eye-messages community (author: **Lymm**),
supplied 2026-07-03 as a request for a *general* GAK deck-cipher attack. Unlike
the other practice puzzles (which are ciphertext-only), this is a genuine
**known-plaintext** corpus: the plaintexts are public (below), and the task is to
recover the secret per-letter permutation key (the "swaps").

Provenance / honesty note: these files are external cipher artifacts —
transcription-integrity rule applies (`AGENTS.md`); do not alter them. This
directory is `codespell`-skipped along with the rest of `practice-puzzles`.

## Files

| File | What it is |
| --- | --- |
| `noita_test_cipher.py` | Lymm's reference generator (the exact cipher + `generate_random_pt_mapping`). Authoritative spec. |
| `plaintexts.txt` | The 8 labeled known plaintexts (`"<label>: <PT>"`), extracted verbatim from the generator's `encrypt()` calls. |
| `1_swap_ct.txt` | Ciphertexts for the 8 messages at `num_swaps = 1`. |
| `2_swap_ct.txt` | Ciphertexts at `num_swaps = 2`. |
| `3_swap_ct.txt` | Ciphertexts at `num_swaps = 3`. |

Each ct file is 8 independent messages (labels `1,2,3,4,5,6,8,9`) under **one
shared 26-letter key**, each encrypted from the identity deck. The three files use
*different* random keys (one per `num_swaps` level). The keys are **not** recorded
— recovering them from the known plaintext is the whole exercise.

## The cipher (see `noita_test_cipher.py` for the exact code)

Deck `n = 83`; `ct_alphabet = chr(33+i)` for `i in 0..82`; `pt_alphabet = A..Z`
(non-letters pass through and do not advance the deck). `base = rotations[26] ∘
decimations[3]`. Per plaintext letter `L`: `state = compose(perm(L), state)` with
`compose(p1,p2)=p2[p1]`, then emit `ct_alphabet[state[0]]`. Each `perm(L) = base ∘
(num_swaps top-transpositions (0,k))`, subject to no-doubles (`perm(L)[0] != 0`,
distinct across letters).

## Status / how it's used

Attack tooling proposal + delegatable tasks live in
`research/handoff/gak-swap-recovery/`. Measured so far (two Python prototypes):
`num_swaps=1` is closed-form and recovers exactly (all 8 messages re-encrypt
byte-for-byte). `num_swaps≥2` is genuinely hard: forward left-to-right search
*wanders* — not just naive DFS but MRV + cross-message forward-checking capped
without a solution, even on a *planted* ns=2 with the answer in the search space.
The recommended path is propagation-first deduction (R-top/R-read) + a CP-SAT
residual solver (see the handoff), and ns≥2 is **not yet verified end-to-end**. No
result here relaxes the project honesty ceiling — a recovered key is a *candidate*
until it re-encrypts the ciphertext exactly.

## Oracle differential fixture

Task 01 of `research/handoff/gak-swap-recovery/` landed a Rust oracle for Lymm's
deck convention in `attack::gak_attack::lymm_deck`. The committed fixture
`python-reference-vectors.txt` was generated with:

```sh
python3 research/data/practice-puzzles/deck-swap/generate_reference_vectors.py > research/data/practice-puzzles/deck-swap/python-reference-vectors.txt
```

The generator executes Lymm's vendored `compose`/`encrypt` definitions, injects
SplitMix64-planted mappings for two seeds at each `num_swaps` level 1, 2, and 3,
and records both mappings and ciphertexts. The Rust test
`rust_oracle_matches_python_reference_vectors_byte_for_byte` regenerates the
planted mappings and asserts byte-for-byte ciphertext equality. Inline hand vector:
with `n=5`, identity base, `A=(0 2)`, `B=(0 3)`, and ciphertext alphabet `abcde`,
plaintext `A!B` encrypts to `c!d`; `!` passes through and does not advance state.
