# Attack methodology — building trustworthy cipher attacks

Cross-cutting *process* lessons learned (usually the hard way) while building the
`solve` / `keystream` / `ragbaby` attacks in this workbench. They transfer to any new
attack even when the cipher math does not — each was paid for with a real false
negative or false positive, and the demonstrating write-up is cited.

The overarching rule (see also `AGENTS.md` and `NEXT-STEPS.md`): a high n-gram or
structure score is not a decode, and "ruled out" is meaningless without a *passing*
positive control and an adequate model/wordlist.

## 1. Null against the search's degrees of freedom, not against random keys

A search-based attack (annealed key/mapping search) overfits short ciphertext and will
"survive" a random-key null on pure noise (real / shuffled / random-length all hit
z≈20 at L=40). Gate on a matched null: rerun the *same search* on a
Fisher-Yates-shuffled ciphertext and require z ≥ 6 and a ≥ 1-nat margin. Keep a
random-key null too — it catches key-independent leaks (e.g. ciphertext-autokey
`p_i = c_i − c_{i−L}`) that shuffling hides. Demonstrated:
`data/practice-puzzles/KEYSTREAM-RESULTS.md`.

## 2. A positive control must exercise the gate end-to-end

Plant true plaintext → encrypt → run the *whole* attack → assert `survives == true`.
A control that only checks the optimizer (plant → assert recovered) passes while the
survival gate is silently miscalibrated, so it certifies nothing about your negatives.
Demonstrated by the held-out gate bug in `data/practice-puzzles/RAGBABY-RESULTS.md`.

## 3. Held-out scoring compares fold-vs-fold

Compare the candidate's held-out fold against the matched null's held-out fold, not
against the full-stream mean. Odd-index English is not contiguous English, so a
*perfectly* recovered decode fails a fold-vs-full check (a real false negative we hit).
Fixed by factoring a shared held-out-null helper. Write-up:
`findings/T1-heldout-gate-fix.md`.

## 4. Simulated annealing anneals the sum of log-probs, not the mean

With a mean objective, per-move deltas are ~0.01, so any temperature degenerates to a
random walk and even planted controls fail to recover. Use the sum of
log-quadgram probabilities, plus slide / reverse-segment moves and basin-hopping.
Demonstrated: `data/practice-puzzles/RAGBABY-RESULTS.md`.

## 5. Reduced-base alphabets must permute the real A..Z indices

When a cipher drops letters (Ragbaby base-25 folds J→I; base-24 also folds V→U),
permute and score in real-letter space. Relabeling the kept set to a contiguous
`0..base-1` range silently zeroes recovery. Demonstrated:
`data/practice-puzzles/RAGBABY-RESULTS.md`.

## 6. Calibrate power with a matched-base planted control

"Not cipher X" is only as strong as your ability to *recover* a planted cipher-X at the
same length and alphabet. Report that power (e.g. `five` Ragbaby ruled out at
planted-recovery 1.00 @274; `four`/121 near the information floor at ~0.70). A negative
below ~0.7 recovery power is "couldn't find it," not "isn't there." Demonstrated:
`data/practice-puzzles/RAGBABY-RESULTS.md`.
