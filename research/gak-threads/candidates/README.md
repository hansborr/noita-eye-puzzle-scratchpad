# GAK-attack eye candidate records

This directory holds the **machine-written record, named from a stable
run-config/seed label (no wall-clock), of the latest Step-3 run for each config
that points the matured GAK attack at the real eye corpus** (Thread 4, Unit 2c,
the EYES Step 3). It is the highest honesty-risk artifact in the project, so the
protocol below is binding on humans and agents alike.

## The claim ceiling (absolute, every record)

The strongest defensible statement about the eyes is, verbatim:

> deterministic, engine-generated, strikingly structured data of unknown meaning;
> unsolved; no primary developer source confirms recoverable plaintext.

**Nothing written here may be stronger.** The standing conclusion — the eye decode
is **BLOCKED on the unknown symbol→meaning mapping** — does **not** change unless a
candidate survives ALL of the held-out checks below, and even then it is a
**HYPOTHESIS, never a decode**.

The expected, fully-reportable outcome of every eyes run is **NO surviving
candidate**. A clean honest negative is a SUCCESS here, not a failure: the spec
states up front that, given the eyes' near-`S_83` group and very little text, "it
might be unrealistic to expect chaining to ever work for the eyes." Documenting the
negative is the point — there are no silent caps.

## Why a "candidate cleartext" can only ever be speculative

The GAK attack recovers **structure** (visible-coset actions / chain-link
constraints), **not** cleartext. Even a full recovery of the eye group structure
yields abstract plaintext-letter **indices**, NOT readable text, because mapping
symbols→letters needs an external **anchor** — which is exactly the standing
blocker. So any "candidate cleartext" can only arise by ADDITIONALLY hypothesizing
a symbol→letter mapping, which the claim ceiling forbids inventing as a finding.
The cleartext path is therefore **SPECULATIVE, gated, and never primary**.

## The kill order (every candidate is a HYPOTHESIS until it survives ALL of these)

1. **Held-out isomorphs.** Recover on a SUBSET of eye isomorphs / chain links; the
   recovered structure must correctly PREDICT held-out isomorphs / chain links it
   was NOT trained on, and must beat a **matched within-message shuffle null**
   (`null::fisher_yates` + `null::add_one_p_value`, identical pipeline/population).
   An unconstrained fit that cannot predict held-out structure is coincidence.
2. **Thread-3 perfect-isomorphism consistency.** The candidate's implied model must
   be consistent with `perfect_isomorphism`'s scan: no manufactured TRUE conflicts
   (`robust_internal_violations == 0`), and chaining ONLY within Thread-3's safe
   isomorph extents (never crossing allomorphic boundaries / over-extending).
3. **(LAST, SPECULATIVE) cleartext plausibility.** ONLY for a candidate that already
   survived (1) and (2): as an explicitly-labelled SPECULATIVE step, an implied
   plaintext MAY be scored under the `language.rs` Finnish AND English models behind
   a matched null — but the symbol→letter mapping is a HYPOTHESIS, never recovered,
   and this is never primary evidence. If (1) or (2) fails (the expected case), this
   is NOT run and no candidate is reported.

## The trap (verbatim, from the spec)

> A "solution" on the eyes with no synthetic-ground-truth validation and no
> held-out check ... is almost certainly a coincidence. Do not report it as a
> decode.

## Record protocol

- Each Step-3 run writes ONE record file, named from a **stable label derived from
  the run config/seed** (no wall-clock timestamp — the harness cannot call the
  clock and records must be reproducible).
- Every record captures: what was attempted; how much aligned-isomorph structure
  the eyes actually have and how much was recovered; the held-out verdict and the
  matched-null p-value; the Thread-3 consistency verdict; and the explicit
  **HYPOTHESIS-not-decode** label and claim ceiling.
- **If ANY candidate cleartext emerges — in English OR FINNISH (Noita is a Finnish
  game; weight Finnish highly) — it MUST be written here verbatim with its scores
  and caveats for human review, even if low-confidence / failing.**
- The expected record is a "NO candidate surfaced — decode remains blocked" entry.
  Write that honestly.

## Files

- `eyes-*.md` — one machine-written record per Step-3 run (committed by the
  orchestrator; this code never commits).
