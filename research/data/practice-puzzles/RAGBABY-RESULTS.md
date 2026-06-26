# General (non-keyword) Ragbaby — results (letter puzzles three/four/five/seven)

Engine-first attack on the **general Ragbaby** cipher: unlike the previously
ruled-out *keyword*-keyed Ragbaby, here the keyed alphabet is an arbitrary
permutation, recovered by a strong simulated-annealing optimizer scored with the
English quadgram model. Landed as the tested `ragbaby` CLI subcommand
(`src/attack/ragbaby.rs`), mirroring `keystream.rs`.

> Honesty ceiling (binding): a high quadgram score on gibberish is **not** a
> decode. Nothing here is a recovered message. Every negative is a claim only
> about the *cipher family, conventions, and ciphertext length actually searched*,
> and is reported alongside a quantified positive-control recovery rate.

## Headline: the positive control now PASSES (the prior blocker), and so does the gate

The prior single-swap annealer (and the earlier keyword-Ragbaby pass) **failed its
own planted-Ragbaby control**, so its Ragbaby negative was untrustworthy. Root
cause: the SA objective scored the *mean* quadgram log-prob, so a single-move delta
was ~0.01 while the temperature was ~1–4 ⇒ `exp(Δ/T) ≈ 1` — the search accepted
almost everything and just random-walked, never converging (0% planted recovery).

Fix (the engine recipe): anneal on the **sum** of log-quadgram probs (deltas of
~1–100 nats), geometric schedule t0=12→t1=0.3, move set {transposition×3, slide,
segment-reversal}, multi-restart, basin-hopping. With this the optimizer recovers a
planted random-alphabet Ragbaby reliably (see the curve below).

A reduced-base correctness bug was caught and fixed: the keyed alphabet must
permute the *real* A..Z letter indices of the kept set (base 25 drops J→I; base 24
drops J→I, V→U) and scoring stays in real-letter space; relabeling to a contiguous
0..base-1 space silently zeroes base-24/25 recovery.

## Positive-control recoverability vs ciphertext length (the calibration)

Planted random-alphabet Ragbaby of English text, recovered by the *same* engine
search; "recovery" = fraction of trials reaching ≥0.9 char-accuracy vs the known
plaintext. The **matched base** (from each puzzle's absent-letter profile —
three/four absent {J,V}→base 24, five absent {J}→base 25, seven all 26) is the
right calibration; reduced bases recover *more* easily (smaller alphabet).

| Length | puzzle | recovery @ base 26 (restarts 150) | recovery @ MATCHED base |
| ------ | ------ | --------------------------------- | ----------------------- |
| 121    | four   | 0.33                              | **0.70** (b24, 10 trials) |
| 139    | three  | 0.67                              | **0.80** (b24, 10 trials) |
| 152    | seven  | 0.83                              | 0.83 (b26 is matched)   |
| 274    | five   | 1.00                              | **1.00** (b25, 8 trials) |

At each puzzle's matched base the optimizer recovers a *planted* Ragbaby in
**0.70–1.00** of trials — so a negative on the real puzzle has 0.70–1.00
statistical power. four/121 at base 26 (0.33) is near the information floor for a
26-letter alphabet, but at its actual base 24 (0.70) the negative is reasonably
powered.

## The survival gate is validated by a planted full-gate control (codex review catch)

A second-opinion review (codex) flagged that the original control proved only that
the *optimizer* recovers a plant, not that the *gate* would pass a real decode — and
indeed the gate had a **miscalibrated held-out check**: it scored the odd-indexed
fold of the decrypt and compared it to the *full-stream* matched mean. Every-other-
letter of English is not contiguous English, so a **perfectly recovered planted
decode failed `survives`** (matched_z ≈ 82–97, round-trip true, yet survives=false).

Fixed: the held-out fold is compared apples-to-apples against the **matched null's
held-out fold**. A recovered planted decode now **survives** (regression test
`planted_decode_survives_full_gate`), while the puzzles still do not — they fail on
matched_z < 6, which the fix does not touch. This is the positive-control-for-the-
gate that makes the negatives sound: the gate demonstrably **passes a true decode
and rejects all four puzzles**.

## Per-puzzle verdict

All bases 24/25/26 × numbering {std, perword, continuous} × both signs (18 cells
each). No cell produced readable English or cleared the survival gate. Highest
matched_z reached (gate threshold 6.0):

| Puzzle | best decrypt | max matched_z | verdict | trust of NEGATIVE |
| ------ | ------------ | ------------- | ------- | ----------------- |
| five (274)  | gibberish (best mean ≈ −13.2, ~random) | 3.11 | HONEST-NEGATIVE | **trustworthy — RULED OUT** (control 1.00 @274) |
| seven (152) | gibberish (best mean ≈ −12.6)          | 1.90 | HONEST-NEGATIVE | trustworthy (control 0.83); `#` see below |
| three (139) | gibberish (best mean ≈ −12.5)          | 5.63→**0.33** | HONEST-NEGATIVE | trustworthy (control 0.80) |
| four (121)  | gibberish-with-fragments (best ≈ −12.1)| 3.10 | HONEST-NEGATIVE | reasonably powered (control 0.70) |

three's base-24/continuous/+1 cell poked to matched_z 5.63 in an 8-trial screen but
**collapsed to 0.33 at 32 trials** (a small-sample fluke, mirroring the prior
keystream four/vig/L=18 case; the ≥1-nat margin floor already rejected it).

`seven`'s `#` was additionally tested under Ragbaby as a deletable null
(`KB#K`→`KBK`) and as a word break (`KB#K`→`KB K`): both gibberish (best mean
≈ −12.5). The Alberti-rotation-index reading of `#` is a *different cipher* and
remains untested (open).

## What this establishes vs leaves open

- **five is not general Ragbaby** (any tested convention) — a calibrated exclusion,
  the first trustworthy Ragbaby-family negative on these puzzles.
- **three / seven / four**: general Ragbaby disfavoured with 0.70–0.83 power at
  their matched bases — reasonably-to-fully trustworthy negatives, four the weakest.
- **Open**: seven's `#` as an Alberti rotation index (different cipher); a
  punctuation-in-alphabet variant; running-key (separate thread, weak z≈2.4 on
  five). Plaintext is English (maintainer-confirmed); language is not the gap.

## Reproduce

```sh
cargo build --release --locked
# positive control — planted-recovery curve (optimizer strength):
./target/release/noita-eye ragbaby --control --control-lengths 121,139,152,274 \
  --control-trials 8 --bases 24,25,26 --restarts 150
# attack a puzzle, all conventions, with the survival gate:
./target/release/noita-eye ragbaby --puzzle five --bases 24,25,26 \
  --numbering std,perword,continuous --sign both --restarts 80 \
  --matched-null-trials 12 --seed 1
```
