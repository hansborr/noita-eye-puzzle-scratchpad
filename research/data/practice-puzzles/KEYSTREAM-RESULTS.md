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

`five` at L = 40: real `five`, shuffled `five`, and random-274 all land at
matched_z 0–4 — **no period-40 keystream signal**. (See the 2026-06-26 update: the
gap-40 `UXECHTINIT` repeat is *not* a key-period clue at all — it is a continuous-
keystream repeat that **crosses a word boundary**, so chasing "period | 40" was a
red herring. The `profile` subcommand prints the `DUXECHTINIT` len-11 repeat at
offsets 124/164 with `crosses-word-boundary=[yes, yes]`.)

This is consistent with the prior diagnosis (these are non-periodic
polyalphabetic; periodic Vigenère/Beaufort and short-primer autokey were already
disfavoured by IoC/Kasiski). It is now reproduced **in the engine** with a
defensible null.

## 2026-06-26 follow-up: structural profile + multi-cipher battery

A second wave hardened the structural negatives into the engine (`profile`
subcommand, `src/attack/profile.rs`) and ran a broader **validated** cipher
battery. The methodological rule that makes these trustworthy: *every "not
cipher-X" claim has a PASSING positive control and a real wordlist* (an early
anneal-based pass produced two FALSE negatives — the keyed-alphabet anneal failed
its own planted-cipher control, and the keyword list was the 3-novel corpus that
didn't even contain "MOUNTAIN"; both were redone with a 370k-word dictionary and
controls that cleanly recover the plant).

**Newly RULED OUT (validated):**
- **Monoalphabetic substitution** — flat whole-stream IoC (~0.036–0.044 vs English
  ~0.0667) for all four. (Corrects the inventory README's old "letter substitution"
  hypothesis.)
- **Periodic polyalphabetic at any period 2..40** — per-period IoC flat under both
  the letters-only and full-character keystream-advance conventions ⇒ Vigenère,
  Beaufort, **Quagmire I–IV**, Gronsfeld, **Porta** of recoverable period are out.
- **Per-word-reset Vigenère** — per-word column IoC flat (~0.04) vs English
  positional (~0.07–0.10).
- **Keyword-keyed Ragbaby** (all four; std + per-word numbering, both signs, bases
  24/25/26) and **keyword-keyed per-word Bifid** (`three`/`four`; `five`/`seven`
  excluded a priori — Bifid fixes 1-letter words but English 1-letter words are a/I).
- **Long-primer ciphertext-autokey** — the key-independent leak `p_i = c_i − c_{i−L}`
  checked exhaustively for L=1..60, three sign conventions: nothing English.

**Weak / inconclusive:**
- **Running-key** two-stream beam on `five` (joint quadgram of plaintext + key):
  a *positive but non-surviving* z ≈ 2.4 vs a shuffled matched null (below the z≥6
  gate, margin << 1 nat). The lone non-zero signal; worth a stronger beam.

## What is STILL NOT ruled out (next steps)

1. **General (non-keyword) Ragbaby** — DONE (2026-06-26). A strong keyed-alphabet
   optimizer (sum-objective SA + slide/revseg + basin-hopping) that *passes* its
   planted-Ragbaby control now exists (`ragbaby` subcommand). Result: HONEST-NEGATIVE
   on all four puzzles, calibrated — **five RULED OUT** (planted recovery 1.00 @274),
   three/seven/four reasonably-to-fully powered (0.70–0.83). See `RAGBABY-RESULTS.md`.
2. **Running-key** with a stronger beam + crib constraints (the z≈2.4 lead), and
   **plaintext** long-autokey (a recurrence `p_i = c_i − p_{i−L}`, not the key-
   independent ciphertext form, so it needs a real search).
3. **Alberti with explicit index markers** — `seven`'s `#` (`KB#K`, `B#TV`,
   `OG#PJ`) as a disk-rotation index; currently stripped. (Ragbaby with `#` as a
   null-delete or word-break is already negative — see `RAGBABY-RESULTS.md`.)

Plaintext is **English** (maintainer-confirmed), so the earlier "Finnish plaintext"
open item is dropped: every English-scored negative is language-correct.

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
