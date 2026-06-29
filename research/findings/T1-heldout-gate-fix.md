# T1 — held-out survival-gate calibration fix (fold-vs-fold)

**Date:** 2026-06-26. **Thread:** T1 (correctness; shared eyes Gate-1 hardening).
**Status:** done — landed on `exploration`; `make verify` green.

## The bug

The survival gate's generalization check (Gate 2) compared a candidate's held-out
fold score against the matched null's full-stream mean. A fold of natural-language
text is not itself contiguous text, so it scores *below* the full stream — a penalty the
full-stream null never pays. Comparing the two is apples-to-oranges and can falsely
fail a true decode on Gate 2.

It was already fixed in `ragbaby.rs` (compare the candidate's odd-index fold against the
matched null's odd-index fold). T1 centralizes that fix and applies it to the two
remaining sites:

- `src/attack/keystream.rs` — `heldout_ok` compared `heldout_score` to the full-stream
  `matched_mean`.
- `src/attack/solve/` — `candidate_survives` compared `heldout_mapping_score` to the
  full-stream `null_mean`.

## What changed

### Shared helper — `src/nulls/heldout.rs` (new, 121 lines)
- `odd_index_fold<T: Copy>(&[T]) -> Vec<T>` — the alternating held-out fold extraction,
  de-duplicating the three hand-rolled copies (ragbaby, keystream, solve-fixed).
- `MatchedNullStats { full_mean, full_std, heldout_mean }` + `matched_null_stats(&[(f64,
  f64)])` — aggregates per-trial `(full_score, heldout_score)` pairs into the full-stream
  mean/std (overfit bar) and the held-out fold mean (generalization baseline).

### `ragbaby.rs` — de-dup
`heldout_fold_score` and the `matched_null` aggregation now call the shared helper. The
returned `(full_mean, full_std, heldout_mean)` and the gate are byte-for-byte unchanged
(file ratcheted down 1739 → 1736).

### `keystream.rs` — fix
`matched_null` now returns `(full_mean, full_std, heldout_mean)`; the new
`KeystreamCandidate::matched_heldout_mean` field carries it; the record renders it; the
gate is now `heldout_score > matched_heldout_mean`. The full-stream `matched_mean`/`std`
(the overfit gate) are computed identically to before, so no overfit-gate behavior
changes.

### `solve/` — fix across all three null paths
Every null path now also returns the held-out fold mean, computed with the same fold
scheme as the candidate it gates (the apples-to-apples requirement):
- **Fixed-mapping** (`eval.rs`): alternating odd-index fold (`best_family_score` carries
  the held-out of the max-in-sample cipher; `matched_null_mean` averages it).
- **Searched mapping** (`search.rs`): *contiguous* train/test fold (`best_family_search_score`
  recomputes `heldout_search_score` once for the per-trial winner). The contiguous split is
  deliberate — a searched mapping re-fits on the train fold and an alternating split would
  shred the bigram adjacency it must generalize. The held-out seed derivation is now a
  shared `HELDOUT_SEED_TAG` const so the null mirrors the candidate exactly.
- **Codec enumeration** (`codec_search.rs`): the held-out of the max-in-sample
  `(codec × cipher × mapping)` per shuffle.

`Candidate::null_heldout_mean` carries it; `candidate_survives` now compares
`heldout_mapping_score > null_heldout_mean`. The full-stream `null_mean` (and therefore
`beats_null` / the overfit gate, and the byte-exact `solve_caesar_s123_nt4` golden stdout)
are unchanged.

### Regression tests
- `keystream::planted_decode_survives_full_gate` and the existing
  `ragbaby::planted_decode_survives_full_gate`: a planted true decode, run through the full
  gate, must survive (and `heldout_score > matched_heldout_mean`).
- `nulls::heldout` unit tests pin the fold extraction and the full/held-out split.
- The solve positive controls (`codec_search_heldout_above_null_on_plant` etc.) assert
  both `candidate_survives` and the fold-vs-fold comparison.

## Finding — the eyes' honest-negative reason was mis-attributed

Wiring the corrected gate through the eyes-search test surfaced a real (if small) result.
Under the old bug the eyes' top searched candidate "failed" Gate 2 (its held-out fold
sat below the full-stream null mean), which over-attributed the honest negative to a
generalization failure. With the corrected fold-vs-fold comparison the eyes' top
candidate's held-out fold actually sits *marginally above* the null's held-out fold
(−3.0488 vs −3.0608 at the test's seed/config — a near-tie, within search noise), so
Gate 2 is not load-bearing for the eyes.

The honest negative still holds — the decode remains blocked — but now for the honest
reason: the eyes fail Gate 3 (the in-sample overfit bar, `beats_null = false`): the
re-fit mapping's in-sample score does not clear the matched null's in-sample mean. The
`eyes_search_surfaces_no_surviving_candidate` test was updated to pin Gate 3 as the
load-bearing reason and documents (rather than asserts, given the near-tie) the Gate-2
flip. Nothing here touches the standing claim ceiling: the eyes remain deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved.

## Audit — no prior negative flips

- The keystream battery on practice puzzle `four` (L=1..12) still returns a clean
  honest-negative: the more-lenient (corrected) held-out gate produces no survivor because
  survival still requires clearing the matched-null overfit bar and the random-key
  key-independence bar, which the puzzles fail.
- All solve corpus/e2e tests, golden masters, and the `solve_caesar_s123_nt4` byte-exact
  stdout fixture pass unchanged.

## Files
- New: `src/nulls/heldout.rs`; `src/lib.rs` module decl + doc bullet.
- Changed: `src/attack/ragbaby.rs`, `src/attack/keystream.rs`,
  `src/attack/solve/{eval,search,codec_search,types,record,mod}.rs`,
  `scripts/file-size-allowlist.txt` (keystream 1280→1360, solve/mod 2282→2304 bumped with
  reasons; ragbaby 1739→1736 ratcheted down).

## Addendum (2026-06-28) — solve `--codec-search` on puzzle two does flip (a false positive)

The "no prior negative flips" audit above checked the keystream battery (puzzle
`four`) but not the solve `--codec-search` path on puzzle `two`, which does flip.
Under the corrected fold-vs-fold gate, `solve --codec-search` on puzzle two reports
2 survivors (was 0): the held-out null baseline drops from the full-stream mean
(−2.6617) to the held-out fold mean (−3.5327), so the top candidate's held-out score
(−3.1923) now clears it (generalizes: true).

This is a confirmed false positive, not a decode lead. Puzzle two's plaintext is known
to be English; the surviving candidate is Finnish gibberish (`AITTEAHISTOTEMMENO…`),
and its Gate-3 in-sample margin is a 0.0096-bit squeak over the 0.15 guard. Root cause:
a free many-to-one mapping search (144→29) over genuinely non-random text (real encoded
English) can beat a Fisher-Yates shuffle null on both folds without recovering the
plaintext. So for the searched many-to-one case, "candidate survived all three gates"
certifies non-randomness plus cross-fold generalization, not decode-correctness — the
verdict over-claims.

**Decision (2026-06-28):** the fold-vs-fold fix is correct and stays. The committed
`solve-two` / `solve-six` / `solve-eyes-reading-layer` records were never regenerated
after this fix, so they are stale (pre-fix wording and values), but their
"no surviving candidate" headline is still the correct decode conclusion. They are left
un-regenerated rather than shipped with a misleading "candidate survived" headline over
gibberish. Deferred follow-up (not a merge blocker): harden the many-to-one survival
semantics (margin scaled to mapping freedom, word-level readability, anti-collapse,
and/or a known-answer crib), with puzzle two (known English) as the regression fixture,
then regenerate the records.
