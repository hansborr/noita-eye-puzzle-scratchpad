# Handoff — crack practice puzzle `one`'s codec

## ✅ SOLVED (2026-07-01) — this handoff is closed

`one` decodes to **`Permutation Representation Destination`**: the ±1 walk's
direction bits, unmasked by a deterministically alternating orientation bit
(`b_i = i mod 2` — *not* feedback hidden state), read as 7-bit ASCII; verified by
an exact 266/266 ciphertext round-trip. (Calling this "the dihedral GAK over C5
of the author's hints" is our hint-consistent interpretation, not
author-confirmed — the mechanism is what the round-trip verifies.) Instrument: `maskdecode`
(planted positives + matched null + `--self-test`). Authoritative write-up,
including why every negative below stands as scoped and how the convention
closure + crib-window discriminator found the untested carrier:
`CODEC-RESULTS.md` § "`one`: alternating orientation + 7-bit ASCII". The backlog
below (external anchor / `anchorfit`,
evolving tables, 2-D layouts) is obsolete for `one`; everything below is kept as
the historical record of the attack ladder.

## UPDATE (2026-07-01) — author hints received; the dihedral hidden-1-bit model; exhaustion is the measured read

The puzzle's author supplied five hints (relayed by the maintainer). They reframe
`one` from "transparent ±1 walk, no hidden state, only the codec is unknown" (the
"Why `one` is the right target" section below is **superseded on that point**) to a
**dihedral / hidden-1-bit-orientation GAK over C5**: a hidden chirality bit flips
each letter's up/down reading (hint h4), which is *why* every memoryless/static codec
family here is an honest negative rather than a near-miss. The 2-symbol reduction
`b_{i+1} = ¬obs_i` recovers exactly the direction-blind run-length carrier, so the
carrier diagnosis stands — the model explains it. This handoff preserves the
full hint list and historical honest-scope labeling; `CODEC-RESULTS.md` keeps the
current verified mechanism. Net: the principled codec families are closed, and
`codecpower`/`bigramcodec` show the gate is underpowered at `one`'s length, so the
measured next lever is backlog #1 — the **external anchor / `anchorfit`** on the
maintainer's withheld `one` snippet — not another codec search. The dihedral model is
our reverse-engineering (fits all five hints), not creator-confirmed.

## UPDATE (this session) — carrier re-diagnosed; memoryless codecs excluded; `rlcodec` landed

The codec is **not** a memoryless transduction of the bit/magnitude stream. Two
results tighten the search:

1. **The carrier is the direction-blind run-length *magnitude* sequence `M`**
   (135 values in `1..=5`), not the raw bits. Forced by a *bit-complemented* 26-run
   repeat `M[16..42] == M[69..95]` (opposite run-direction parity), invisible to the
   bit-level scan this handoff was written against. This strengthens the
   `gcd(265,84)=1` argument into hard exclusions: **no fixed even/odd pairing into
   letters** (the repeat can't be pair-aligned at both parities) and **no bit-level
   fixed-width / ASCII codec** (polarity-dependent). So angle #3 below (fixed-width
   with leftover, ASCII `k=7`) is **dead**, and any Polybius/grid pairing is **dead**.

2. **Every memoryless magnitude codec is an honest negative** (`rlcodec` instrument,
   below). The variable-length comma/prefix family (angle #1 below — the prior #1
   lead) scores *near* English under a free substitution hill-climb but **does not
   beat a matched symbol-stream order-1 Markov null** (every codec `z < 0`, robust to
   search budget at restarts=16/iters=4000/nulls=200). Its seductive fragments
   (`VERIETYOUARTMORETHETYOU`, `LUMBERECEISBETHENED`) are substitution-freedom
   pareidolia on an 18–35-symbol stream — the gate blind-spot, now shown in-engine.
   **Scope (honest):** the null preserves first-order (bigram) structure, so this is
   "no detectable *above-bigram* English signal", not "not English"; at these short
   lengths the test is **underpowered**, so it excludes a strong/searchable codec
   signal, not a short genuine message.

**The instrument:** `rlcodec` (`src/attack/rlcodec/` + the `rlcodec` subcommand) —
file-driven, self-validating (planted-English-via-comma positive control + matched
null + `--self-test`). Reproduces the census + the exclusion battery. This
handoff preserves the detailed campaign record; `CODEC-RESULTS.md` §`one` keeps
the durable result and scope.

**What's left (the live regime).** A memoryless reading of `M` is excluded. The
remaining hypotheses are **codecs with memory / non-transduction readings of the
run-length sequence**: e.g. the run-length sequence as the operand of a *keyed* or
*stateful* transform, a 2-D / interleaved layout, or a reading where the magnitudes
index a table that itself evolves. The cribs are still the lever (26-run @16/69;
the 19-run tail @116 = @72 = @19) — under any correct codec both occurrences must
decode consistently. Also still open: confirm `one`'s language (English assumed
from the corpus; the maintainer holds `two`'s English, not `one`'s).

**The lever is now an instrument: `cribfit`.** The crib-consistency idea above is
landed as `cribfit` (`src/attack/cribfit/` + the `cribfit` subcommand), a sibling
of `rlcodec` that reuses its carrier, census, English model, and matched-null gate
(`rlcodec::gate_symbol_stream`). It turns the cribs into a *derived structural
constraint*: `gcd(run-gaps) = 1` (so no nontrivial run-periodic key is admissible)
and `gcd(bit-gaps) = 21` (so any bit-periodic key / cumulative-sum modulus must
divide 21 → {1, 3, 7, 21}). The filter distinguishes three states — consistent,
*excluded* (aligned + inconsistent), and *inapplicable* (token boundaries don't
align across the cribs, set aside ≠ excluded): per-run single-magnitude
move-to-front is **excluded** (its two len-26 crib windows agree on only 22/26
outputs — not identical), while the chunked / paired MTF tokenizations are
**inapplicable**. The one English-viable crib-consistent candidate (cumsum mod 21)
is a bounded-increment walk and scores below its matched null: **honest negative +
the 21-bit / run-period-1 constraint.** Next agent: search the
*bit-periodic-period-|21* and *evolving-table* families this narrows to, using
`cribfit` as the consistency pre-filter before any language scoring (and remember
a misaligned tokenization is set aside, not refuted). The detailed result is
preserved in this handoff; the current synthesis is in `CODEC-RESULTS.md` §`one`.

**UPDATE: bit-periodic keyed substitution lead closed as an honest negative.**
`cribfit` now instantiates `BitPeriodicSubst(p)` as the free substitution on
augmented `(magnitude, bit-coset)` symbols. The crib-admissible English-viable
periods `p=3` (alphabet 14) and `p=7` (alphabet 24) both score below their matched
nulls; `p=21` is reported as monoalphabetic-infeasible (alphabet 47 > 26), not
dropped. That closes the per-run keyed-substitution lead. The remaining live regime
is **non-substitution memoryful readings**: evolving-table codes beyond
single-magnitude MTF, plus 2-D / interleaved layouts. Same caveat: at this length
the gate excludes a searchable above-bigram codec signal, not a short genuine
message.

## Next leads (codex consult 2026-06-30)

`codecpower` has now measured the gate ceiling directly: at the carrier≈135
operating point for `Comma{sep=4}`, the actual `rlcodec` matched-null gate has
power 0.000 on the built-in English calibration sweep, with aggregate
non-English false-positive rate 0.018. Treat this as underpowering at `one`'s
length, not as a plaintext claim.

`rankcodec` has now tested the bounded-order predictive-rank family. It decodes
`M[i]` as the rank of the next plaintext letter under deterministic order-1/2/3
English predictors (all below the order-4 quadgram scorer), with a matched null
that Markov-resamples `M`, pins the crib windows, and reruns the identical
order-`k` decode. Real `one` is an honest negative: no order is crib-admissible
after the allowed `<=k` transient, and the built-in English source is not fully
representable in ranks `<=5` under any swept order (best coverage 98.6%, still
4/285 letters above rank 5). The tertiary gate has no survivor and remains
underpowered by the `codecpower` result. This handoff preserves the detailed
`rankcodec` result; `CODEC-RESULTS.md` §`one` keeps its durable scope.

`mdlcodec` has now tested the final planned in-engine lever: a crib-synchronous
MDL-like affine running-key family `idx[i] = (a*S_i + b*i) mod R`, with
`o_0=0`, unit-scaling canonicalization, deduped densified index streams, effective
alphabet `L_codec`, and a **post-selection** crib-pinned magnitude null that
recomputes crib eligibility from each null draw's own bit-gaps. Real `one`'s best
cell is `R=14,a=1,b=7,k=13` with `MDL=1988.56` bits and a candidate string, but it
does **not** beat the null p05 survivor rule (`Delta=-54.89`, `z=-0.61`,
survivor no). This is a candidate, not a decode. The detailed `mdlcodec` result
is preserved here; `CODEC-RESULTS.md` §`one` keeps its durable scope.

Ranked backlog for `one`:

1. **External anchor / `anchorfit` known-crib.** Escalate here once the power
   ceiling, bounded-order rank family, and affine MDL family all fail or remain
   under-determined; the maintainer-held withheld `one` snippet is the right
   anchor if available.
2. **Other evolving-table layouts.** `rankcodec` closes the direct predictive-rank
   reading, and `mdlcodec` closes the enumerated affine running-key family, but
   neither covers every possible emitted-symbol-history or synchronization
   convention. State that as an out-of-scope bound, not as total exhaustion.
3. **2-D / interleaved carrier layouts.** The current instruments are one-dimensional
   over the run sequence; a layout change could move the crib alignment question.

For `two`: next leads are eps-pair codec projection, full-D0 `ctakscan`, and a
full-symbol-feedback CSP. `two` currently looks structurally walled: the transparent
rotor repeats are real, but the deck/full-symbol channel has not yielded a
computable signal under the tested regimes.

---
(original handoff below; angles #1 and #3 are now tested/excluded as noted above)

**For the next agent.** Goal: recover the English (or Finnish) plaintext of
`research/data/practice-puzzles/one`. Read `AGENTS.md` first — the honesty
discipline (matched null + firing positive control, never present a high n-gram
score as a decode) is binding here.

## Why `one` is the right target

`one`'s **cipher is already fully solved** — there is no key search and no hidden
state left. It is a transparent ±1 walk on `C5`: all 265 transitions are ±1 mod 5,
so the plaintext is a recovered **265-bit up/down stream**. The *only* unknown is
the **binary→language codec**. So this is a pure transduction problem, not
cryptanalysis. (Contrast: `two`'s codec sits behind a genuine hidden-state GAK
deck — see `research/findings/ctak-feedback-discriminator.md` — which is why `one`
is the tractable codec testbed. If you crack `one`'s codec it likely reveals the
setter's encoding family.)

## The recovered plaintext (reproduce, don't trust)

```python
d = [int(c) for c in open("research/data/practice-puzzles/one").read().strip()]   # 266 base-5 digits
steps = [(d[i]-d[i-1]) % 5 for i in range(1, len(d))]                              # all in {1,4}
bits  = [1 if s == 1 else 0 for s in steps]                                        # 265 bits; up=+1
```

- 265 bits, `#up(+1)=125`, `#down(-1)=140`.
- **Try both bit polarities** (up=1 and up=0) and both walk directions — the codec
  could use either; the assignment above is arbitrary.
- bitstream (up=1): `0001011001111010011110001110100000101111001101001011110011110010001010111011000101000001111001111010010110110000110000101100101100001000100010000110010110100001100001101110101000100111010111011100110000101100101000011000011011101110010110100001100001101110101000100`

## The load-bearing new constraint: the codec is NOT fixed-width

There is an **exact 36-bit repeat at bit positions 145 and 229** (gap 84) — a real
repeated plaintext word (`isoscan --delta-mod 5` finds it; significant vs the
order-1 Markov null, longest 36 vs ceiling ~22). For a fixed-width-`k` codec, an
*exact bit-level* repeat of a word forces both occurrences to the same bit phase,
i.e. **`k | 84`** (`84 = 2²·3·7`). For the message to tile 265 bits into whole
letters, **`k | 265`** (`265 = 5·53`). But **`gcd(265, 84) = 1`**, so no `k>1`
satisfies both → **no fixed-width codec can both tile the message and phase-align
the repeat.** This is consistent with the failed fixed-code battery below, and it
redirects the search:

- the codec is **variable-length** (prefix/Huffman/Fibonacci–Zeckendorf/Morse-like),
  **or**
- it is fixed-width with **padding / a partial final letter** (then `k ∤ 265` is
  fine; `k | 84` still constrains it to `k ∈ {4,6,7,12,...}` with a few leftover
  bits — note `k=7` is ASCII-width, `k=6`/`k=4` are plausible), **or**
- (less likely) the 36-bit repeat is a non-letter-aligned coincidence — but 36 exact
  bits is long, so treat it as a genuine word repeat and a **known-plaintext crib**.

## Already tried — DO NOT just repeat (honest negatives)

Per this dated campaign record: Baconian (5-bit),
ITA2, ASCII, Gray, bignum, transposition, run-length — all give gibberish, **flat
IoC at every grouping**. Quick re-check this session: 4/6/7/8-bit fixed groupings
with a full phase+order sweep stay at the uniform floor (k=4 pair-IoC 0.070 ≈
uniform-16 0.0625; k=6 0.028; k=7 0.039) — no English spike. The matched-null
codec-search (`cargo run -- solve --codec-search` on `one`) returns 0 survivors and
correctly rejects a 32→29 binary-move overfit.

## Promising untried angles (ranked)

1. **Variable-length / prefix codes.** Decode the bit-stream greedily under
   candidate code trees (Morse with the run-structure as separators; an English-
   frequency Huffman; Fibonacci/Zeckendorf). Score with a held-out quadgram LM
   against a matched null; build it as a file-driven instrument, not a one-off.
2. **Run-length as the message.** 135 runs, values 1–5, dist `{1:64,2:34,3:17,4:18,5:2}`.
   The run-length sequence (or (up-run,down-run) pairs) may be the carrier rather
   than the raw bits.
3. **Fixed-width with leftover.** Test `k ∈ {4,6,7,12}` (the `k|84` set) allowing a
   1–N-bit offset/leftover and both polarities, gated on the 36-bit crib aligning to
   a letter boundary.
4. **Use the crib.** The repeated 36-bit word is a known-plaintext anchor: under a
   correct codec it must decode to the *same letters* at 145 and 229. Use that to
   filter codec hypotheses before scoring the whole stream.

## Discipline + where to record

- A high n-gram score is **not** a decode. Require a firing planted positive control
  + a matched null + held-out scoring; a `--codec-search` survivor on a transition-
  structured stream must be read with the rendered text, not the gate count (a
  first-order Markov null can't separate a transition law from first-order language —
  see `research/attack-methodology.md` §1). Use a **trigram/quadgram**
  objective.
- Build a reusable file-driven CLI instrument (`--input-file`/`--stdin` + a planted
  control + matched null), not a throwaway script. Record results in
  `CODEC-RESULTS.md` (the authoritative `one`/`two` codec record).
- If you recover candidate cleartext, log it as a HYPOTHESIS under
  `research/gak-threads/candidates/` (per the maintainer's standing directive).
- The maintainer holds `two`'s English (not `one`'s, as far as recorded); there is
  no in-repo ground truth, so a scored candidate is never a decode until checked.

## Related context

- `research/data/practice-puzzles/CODEC-RESULTS.md` — concise current results for
  `one`/`two`, including the superseded-model boundaries.
- `research/findings/ctak-feedback-discriminator.md` — why `two` is blocked (hidden
  state); `one` is the cleaner codec target.
- Instruments: `isoscan` (repeats + null), `solve --codec-search` (the codec layer,
  `src/attack/codec/` + `src/attack/solve/`), `keydiff` (one → constant-additive Δ,
  consistent with C5).
