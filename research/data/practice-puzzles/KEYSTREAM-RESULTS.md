# Keystream-cracker results — letter puzzles (three/four/five/seven)

Engine-first attack on the polyalphabetic *letter* puzzles, landed as a tested
Rust engine path (the `keystream` subcommand) rather than throwaway scripts. The
headline is a **clean honest-negative** for the searchable families — which is a
*success* on the credibility ladder, not a failure: the engine recovers planted
ciphers and refuses to manufacture a decode from these real ones.

> Honesty ceiling (binding): a high n-gram score on gibberish is **not** a decode.
> Nothing here is presented as a recovered message. The negatives below are
> claims only about the *families and key lengths actually searched*.

## What was built (commits on `exploration`)

| Commit | What |
| --- | --- |
| `336806c` | `src/quadgram.rs` — A..Z quadgram English model built at load from a new 1.48 MB corpus (`english-corpus-large.txt`); English beats random by ~4 nats/quadgram. The bigram-on-3 KB model was far too weak to guide a key search. |
| `19987e9` | `src/keystream.rs` + `keystream` CLI — Vigenère, Beaufort, plaintext-autokey, ciphertext-autokey (encrypt+decrypt over A..Z); annealed multi-restart key search (mirrors `solve.rs` `search_mapping`); planted-recovery tests. |
| `e7a8ce8` | Matched-null survival gate (the correctness crux — see below). |

The slice is deliberately **self-contained**: it implements its own cipher math
over letter indices and does not touch `ciphers.rs` / `solve.rs` / `language.rs` /
`codec.rs`, so it does not collide with the engine-spine refactor. Engine-spine's
`english.txt` is untouched, so its reported scoring numbers are unaffected.

## The methodology that makes a negative trustworthy

A naive gate (score the best decrypt vs decrypts under random *keys*) is **wrong**
for a key search: the anneal has *L* free parameters and overfits short
ciphertext. Measured: at key-length 40 on 274 chars the search reaches the same
score (~−12.8, "z"≈20 vs the random-key null) on **real `five`, shuffled `five`,
and uniform-random text alike**. The random-key null does not capture the
*search's own optimization power*.

Survival therefore requires clearing **two** nulls (mirroring `solve.rs`'s
matched-null discipline), each at z ≥ 6 **and** a ≥ 1-nat absolute margin:

1. **Matched null** — rerun the *identical* search on Fisher–Yates-shuffled copies
   of the ciphertext (same letter multiset; higher-order structure destroyed).
   This is what catches search overfitting.
2. **Random-key null** — retained because it is the only one that catches the
   ciphertext-autokey key-independence leak (`p_i = c_i − c_{i−L}`), which
   shuffling would hide.

Plus a round-trip check and a held-out odd-fold check (> matched mean).

**Validation:** planted ciphers of real English recover their key and survive
(matched_z 48–122 at L=5); pure-noise overfits (L=60/80) beat the random-key null
but are killed by the matched null (regression test
`matched_null_rejects_overfitting_at_high_key_len`). The 1-nat margin floor is a
second guard against a small-trial matched-null std fluking a high z.

## Battery result — honest-negative

Sweep: puzzles {three, four, five, seven} × families {vigenère, beaufort,
plaintext-autokey, ciphertext-autokey} × key length **L = 1..20**
(`--restarts 24 --iterations 12000 --matched-null-trials 8 --null-trials 150
--seed 1`), plus `five` at **L = 40** (the gap-40 repeat clue) run separately.

**No (puzzle, family, key length) cell survived.** Highest overfitting-gate
matched_z reached (threshold 6.0; planted true positives ran 48–122; pure-random
~0–1):

| puzzle | max matched_z | where | note |
| --- | --- | --- | --- |
| three | 3.45 | autokey-pt, L=5 | below threshold |
| four  | 9.81 | vigenère, L=18 | **fluke** — see below |
| five  | 4.09 | beaufort, L=4 | below threshold |
| seven | 3.37 | autokey-pt, L=2 | below threshold |

`four`/vigenère/L=18 poked above 6.0 in the 8-trial screen but was still
non-surviving (its matched margin was 0.48 nat < the 1-nat floor). Re-run with
32 matched trials + more restarts/iterations: **matched_z collapses to 1.25**
(decrypt is gibberish with scattered fragments). It was a small-sample matched-std
fluctuation, correctly rejected by the margin floor. Lesson: prefer ≥16 matched
trials (the CLI default) for confirmatory runs; 8 is a fast screen only.

`five` at L = 40 (period | 40, the only `UXECHTINIT`-gap-40 period not already
excluded by IoC): real `five`, shuffled `five`, and random-274 all land at
matched_z 0–4 — **no period-40 keystream signal**.

This is consistent with the prior diagnosis (these are non-periodic
polyalphabetic; periodic Vigenère/Beaufort and short-primer autokey were already
disfavoured by IoC/Kasiski). It is now reproduced **in the engine** with a
defensible null.

## What is NOT ruled out (next steps)

The negative covers only the searched families/lengths. Still open:

1. **Running-key** (key = a long English text). `decrypt` is implemented and
   round-trip-tested, but the *attack* (jointly maximising quadgram likelihood of
   plaintext **and** key, or crib-dragging) is a different algorithm — not yet
   built. (`five`'s exact repeat argues against pure running-key anyway.)
2. **Autokey with a long word-primer** beyond the searched `primer-length = key-
   length` formulation, and primer lengths > 20.
3. **Alberti with explicit index markers** — `seven`'s `#` appears mid-word
   (`KB#K`, `B#TV`, `OG#PJ`): a disk-rotation index suspect. Currently `#` is
   stripped; treating it as a re-key signal is untested.
4. **Finnish plaintext** — the quadgram model is English-only (the committed
   `finnish.txt` is 2 KB, too small for a quadgram model). A Finnish-corpus rerun
   of the whole battery is needed before declaring a language-independent negative.
5. Key lengths > 20 (other than `five`@40), Quagmire I–IV, Porta.

## Reproduce

```sh
cargo build --release --locked
# one puzzle, all families, L=1..20:
./target/release/noita-eye keystream --puzzle four --min-key-len 1 --max-key-len 20 \
  --restarts 24 --iterations 12000 --matched-null-trials 16 --null-trials 150 --seed 1
# five at the gap-40 period:
./target/release/noita-eye keystream --puzzle five --key-len 40 \
  --restarts 40 --iterations 40000 --matched-null-trials 16 --null-trials 200 --seed 1
```

Survivors (if any ever appear) are written to `research/gak-threads/candidates/`
as labelled HYPOTHESIS records; otherwise the tool prints the honest-negative line
and still exits `SUCCESS`.
