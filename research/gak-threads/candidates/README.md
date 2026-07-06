# GAK-attack eye candidate records

This directory holds the machine-written record, named from a stable
run-config/seed label (no wall-clock), of the latest Step-3 run for each config
that points the matured GAK attack at the real eye corpus (Thread 4, Unit 2c,
the eyes Step 3). It is the highest honesty-risk artifact in the project, so the
protocol below is binding on humans and agents alike.

The expected, fully-reportable outcome of every eyes run is no surviving
candidate. A clean honest negative is a success here, not a failure: the spec
states up front that, given the eyes' near-`S_83` group and very little text, "it
might be unrealistic to expect chaining to ever work for the eyes." Documenting the
negative is the point — there are no silent caps.

## Why a "candidate cleartext" can only ever be speculative

The GAK attack recovers structure (visible-coset actions / chain-link
constraints), not cleartext. Even a full recovery of the eye group structure
yields abstract plaintext-letter indices, not readable text, because turning
those indices into letters needs the letter→action assignment — which *is* the
key (there is no fixed symbol→meaning table to find; the cipher is
polyalphabetic) — a method/cipher-family disclosure, or known plaintext, none of
which is in hand (reframed per maintainer feedback, 2026-07-06). So any
"candidate cleartext" can only arise by additionally hypothesizing that key. The
cleartext path is therefore speculative, gated, and never primary.

## The kill order (every candidate is a hypothesis until it survives all of these)

1. **Held-out isomorphs.** Recover on a subset of eye isomorphs / chain links; the
   recovered structure must correctly predict held-out isomorphs / chain links it
   was not trained on, and must beat a matched within-message shuffle null
   (`null::fisher_yates` + `null::add_one_p_value`, identical pipeline/population).
   An unconstrained fit that cannot predict held-out structure is coincidence.
2. **Thread-3 perfect-isomorphism consistency.** The candidate's implied model must
   be consistent with `perfect_isomorphism`'s scan: no manufactured true conflicts
   (`robust_internal_violations == 0`), and chaining only within Thread-3's safe
   isomorph extents (never crossing allomorphic boundaries / over-extending).
3. **(LAST, speculative) cleartext plausibility.** Only for a candidate that already
   survived (1) and (2): as an explicitly-labelled speculative step, an implied
   plaintext may be scored under the `language.rs` Finnish and English models behind
   a matched null — but the symbol→letter mapping is a hypothesis, never recovered,
   and this is never primary evidence. If (1) or (2) fails (the expected case), this
   is not run and no candidate is reported.

## The trap (verbatim, from the spec)

> A "solution" on the eyes with no synthetic-ground-truth validation and no
> held-out check ... is almost certainly a coincidence. Do not report it as a
> decode.

## Record protocol

- Each Step-3 run writes one record file, named from a stable label derived from
  the run config/seed (no wall-clock timestamp — records must be reproducible).
- Every record captures: what was attempted; how much aligned-isomorph structure
  the eyes actually have and how much was recovered; the held-out verdict and the
  matched-null p-value; the Thread-3 consistency verdict; and the explicit
  hypothesis-not-decode label.
- **If any candidate cleartext emerges — in English or Finnish (Noita is a Finnish
  game; weight Finnish highly) — it must be written here verbatim with its scores
  and caveats for human review, even if low-confidence / failing.**
- The expected record is a "no candidate surfaced — decode remains blocked" entry.
  Write that honestly.

## Files

- `eyes-*.md` — one machine-written record per Step-3 run (this code never commits;
  records are committed separately for human review).
- `solve-*.md` — one machine-written record per solve-pipeline run,
  named from a stable run label + seed (no wall-clock). Same protocol binds:
  the hypothesis-not-decode label, all three independent gates (cipher
  round-trip, held-out mapping score, matched null),
  Finnish and English scores, and any candidate cleartext verbatim for human
  review. The expected record on the eyes is "no surviving candidate."
  - **Codec records (brief 04a).** When a codec/transduction stage runs (the
    `--codec` / `--codec-search` paths that widen a small cipher alphabet so a
    symbol→letter mapping can host the language), the record additionally carries
    the chosen codec's `name()` (`Top candidate codec: …`) and the codec
    round-trip verdict (`Gate 1b codec round-trip` — codec/cipher consistency,
    not a decode) alongside the existing gates, so all four structural
    verdicts (cipher round-trip, codec round-trip, held-out, matched null) are
    shown. The eyes' codec is `identity` (83 ≥ 29; no widening), and their
    expected record is unchanged ("no surviving candidate").
  - **Practice-corpus records.** `solve-one`/`solve-two`/`solve-six` are codec
    hypothesis records for the external practice puzzles
    (`research/data/practice-puzzles/`): `one` is an honest negative (no in-budget
    codec partitions its 266-digit / differenced-265 stream while clearing the
    29-symbol floor); `two` survives all three gates (round-trip; held-out
    generalizes with score -3.192 vs matched-null held-out mean -3.533; beats its
    in-sample null) and is logged as a labelled hypothesis; `six`'s base-6 grouping
    reinserts its preserved word-boundary spaces into the rendered cleartext but
    fails gate 3. None is a decode — each is a labelled hypothesis pending human
    confirmation against (for `two`, withheld) ground truth.
    - **Reproduce.** Each record's `## Provenance (reproducible)` section carries
      the exact, clock-free command that regenerates it byte-for-byte (deterministic
      SplitMix64 — no wall-clock; re-running diffs empty). They are, verbatim:

      ```sh
      make run ARGS='solve --input-file research/data/practice-puzzles/one --alphabet 01234 --codec-search --restarts 4 --iterations 2000 --null-trials 16 --seed 0x0000736f6c766504 --label one --candidates-dir research/gak-threads/candidates'
      make run ARGS='solve --input-file research/data/practice-puzzles/two --alphabet ABCDEFGHIJKL --codec-search --restarts 4 --iterations 2000 --null-trials 16 --seed 0x0000736f6c766504 --label two --candidates-dir research/gak-threads/candidates'
      make run ARGS='solve --input-file research/data/practice-puzzles/six --alphabet 123456 --codec-search --restarts 4 --iterations 2000 --null-trials 16 --seed 0x0000736f6c766504 --label six --candidates-dir research/gak-threads/candidates'
      ```

      `--codec-search` auto-enables the mapping search (one-line stderr note).
      None of these older `solve` records is a decode — `one` surfaces no codec
      candidate (honest negative); `two` survives all three gates (beats its
      in-sample null and generalizes to the held-out fold, -3.192 vs -3.533) and
      is logged as a labelled hypothesis;
      `six` fails gate 3 — each a hypothesis, never a decode. The runbook and the
      in-record provenance agree by construction.

      Reproducibility is verified on demand by re-running the embedded command
      (no CI test pins it byte-for-byte: a faithful reproduction would have to write
      back into this very directory and re-run the full caesar-family codec search).
      It rests on the deterministic `SplitMix64` PRNG plus the crate-wide no-wall-clock
      and `unsafe`-forbidden rules; if the solve/null/codec path ever gains threaded
      or clock-dependent nondeterminism, regenerate and re-commit these three records.
