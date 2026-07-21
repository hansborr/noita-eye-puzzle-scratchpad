# Keystream attack — bounded results for `three`/`four`/`five`/`seven`

Status: **no recorded practice-puzzle run produced a surviving candidate**.
This is a calibrated heuristic negative over the listed families, key lengths,
and budgets. The attack does not discover a group and does not exhaust the
`26^L` keyspace.

## Method

For each cipher family and key length `L`, `keystream` starts multiple random
length-`L` keys and uses simulated annealing. Each move changes one key
coordinate; the objective is English quadgram likelihood. The supported families
are Vigenère, Beaufort, plaintext-autokey, and ciphertext-autokey over A..Z.

The recorded screen used:

```text
4 puzzles × 4 families × L=1..20
24 restarts × 12,000 proposals
8 matched-null trials + 150 random-key null trials per cell
```

That is about 2.59 million annealing score evaluations per `(puzzle, family, L)`
after the matched searches are included, but they are stochastic proposals with
revisits—not 2.59 million distinct keys. For comparison, the raw keyspace is
`26^L`: 11,881,376 at `L=5`, about `2.0 × 10^28` at `L=20`, and about
`4.0 × 10^56` at `L=40`. Fixed-budget coverage therefore collapses rapidly as
`L` grows.

## Acceptance and controls

A candidate survives only if it passes all of these checks:

- exact encrypt/decrypt round trip;
- the full search beats identical searches on Fisher–Yates-shuffled ciphertext
  by `z >= 6` and at least 1 nat;
- it also beats unoptimized random-key decryptions by the same thresholds; and
- its odd-position held-out fold beats the matched null's odd-position fold.

The matched null catches the optimizer's ability to manufacture language-like
scores from short text. The random-key null catches the key-independent tail of
ciphertext-autokey. At `L=5`, planted Vigenère, Beaufort, and plaintext-autokey
ciphers recover at least 95% of the plaintext and survive the full gate.
Ciphertext-autokey is intentionally rejected because its tail is key-independent.
Noise and high-`L` controls demonstrate overfit rejection. These controls do not
establish uniform power at every longer key length.

## Recorded result

No screened cell survived. The largest matched-null z score per puzzle was:

| Puzzle | Best screened cell | Matched z | Reading |
| --- | --- | ---: | --- |
| `three` | plaintext-autokey, `L=5` | 3.45 | below gate |
| `four` | Vigenère, `L=18` | 9.81 in 8-null screen | failed 1-nat margin; a larger-budget rerun with 32 nulls gave 1.25 |
| `five` | Beaufort, `L=4` | 4.09 | below gate |
| `seven` | plaintext-autokey, `L=2` | 3.37 | below gate |

`five` at `L=40` was also negative. The repeated string that motivated that run
crosses a word boundary, so it is not evidence for a period-40 key.

Separate profile and exact instruments also found no periodic polyalphabetic
signal at periods 2..40 and no long-primer ciphertext-autokey signal at lengths
1..60. The exhaustive position-polynomial result lives in
`POLYSHIFT-RESULTS.md`.

## What remains open

- Longer or differently parameterized keys: the annealer still runs, but a miss
  becomes less informative as `26^L` grows.
- A stronger running-key search; the existing two-stream beam on `five` gave a
  weak, non-surviving signal around `z = 2.4`.
- Plaintext long-autokey, which lacks the ciphertext-autokey key-independent
  reduction and needs a genuine search.
- An explicit index-marker model for `seven`'s `#`.

General Ragbaby is recorded separately in `RAGBABY-RESULTS.md`.

## Recommended confirmatory runs

The recorded table used eight matched-null trials as a screen. The commands
below use 16 for a safer confirmation; run the first once for each puzzle to
repeat the full battery.

```sh
cargo build --release --locked
./target/release/noita-eye keystream --puzzle four \
  --min-key-len 1 --max-key-len 20 \
  --restarts 24 --iterations 12000 \
  --matched-null-trials 16 --null-trials 150 --seed 1

./target/release/noita-eye keystream --puzzle five --key-len 40 \
  --restarts 40 --iterations 40000 \
  --matched-null-trials 16 --null-trials 200 --seed 1
```

Any future survivor is still a candidate and is written to
`research/gak-threads/candidates/`; a non-surviving run exits successfully after
printing the bounded negative.
