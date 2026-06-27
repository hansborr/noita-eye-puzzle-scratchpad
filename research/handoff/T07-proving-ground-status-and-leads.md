# T07 — Proving-ground status + remaining low-value classical leads (menu)

**Tier:** 3 (opportunistic) · **Size:** XS for the status note; each lead is its own
multi-pass effort · **Type:** doc (+ optional code) · **Status:** TODO
**Depends on:** none · **Conflicts with:** per-lead (see below)

## Why this is a menu, not a task
A codex review confirmed the sample-puzzle / proving-ground work is **mostly done or
low-value**, and its attack code **does not transfer** to the eyes (`frontier.md`).
So this file is an honest **status + menu**: pick a lead only if you specifically
want sample-suite progress, and **split it before starting** — do not attempt any
lead as one pass.

## Status — what is already done (do NOT redo)
- **`one`, `six`, `two` codec/grouping decodes are logged HONEST-NEGATIVES.** All
  were run through `solve … --codec-search` (records in
  `research/gak-threads/candidates/solve-{one,six,two}-*.md`): `six` → 56 round-trip
  candidates, 0 survivors; `one` → 0 round-trip candidates (the classical pipeline
  cannot represent its C5 GCTAK keystream); `two` → honest negative.
- **`one`'s C5 GCTAK keystream STRUCTURE was recovered** separately by G1
  (`solve_gctak`), byte-for-byte — that is the valuable, transferable-discipline part.
- The letter puzzles (`three/four/five/seven`) are aperiodic-polyalphabetic; mono /
  periodic / keyword-Ragbaby / general-Ragbaby / long-primer CT-autokey are ruled out
  (`KEYSTREAM-RESULTS.md`, `RAGBABY-RESULTS.md`).

## Remaining low-value leads (each: split before starting; honesty-gated)
1. **Running-key two-stream beam on `five`** (the lone z≈2.4 battery signal; never
   engine-ified). *Touches `keystream.rs` + `main.rs`.* Split into three passes:
   (a) planted-running-key fixture + two-stream joint-quadgram scoring;
   (b) a minimal beam that recovers the plant and **fires as the positive control**
   (no control firing → STOP); (c) real `five` behind the matched-null + fold-vs-fold
   gate. Expected outcome: HONEST-NEGATIVE (z≈2.4 is below the gate).
2. **Plaintext LONG-autokey** (`p_i = c_i − p_{i−L}`, key = the L-length primer) on the
   letter puzzles. Note: *short-primer* plaintext-autokey was already swept L=1..20
   (negative, `KEYSTREAM-RESULTS.md`); what remains open is the **long-primer /
   real-key-search** plaintext recurrence. Different, **non-transferring** branch (the
   eyes' autokey is ciphertext-side). Split: planted control → gated real run.
3. **`seven`'s `#` as an Alberti disk-rotation index.** `#`-as-null/word-break is
   already negative; Alberti rotation is the remaining reading. Lowest priority —
   Alberti is explicitly ruled out for the eyes, so pure classical validation.

## Definition of done (for the status note)
- [ ] A short `research/data/practice-puzzles/STATUS.md` (or an addition to its
      README) cross-linking the done codec negatives + this menu, so nobody re-runs them.
- [ ] `make check` green; `docs/deslop-audit` merged in; committed.

## Honesty guardrails
Every classical result here is **non-transferring** to the eyes — say so in any
write-up. No ground-truth cleartext is held in-repo for any sample, so any survivor
is a HYPOTHESIS, logged to `gak-threads/candidates/`, never a decode. Do not present
sub-gate signals (z≈2.4) as findings.

## Pointers
- `research/data/practice-puzzles/{README,KEYSTREAM-RESULTS,RAGBABY-RESULTS}.md`
- `research/gak-threads/candidates/solve-{one,six,two}-*.md` (the logged negatives)
- `research/gak-threads/G1-RESULTS.md` (the `one` structure recovery)
- `src/attack/keystream.rs`, `src/attack/quadgram.rs`, `src/nulls/heldout.rs`
