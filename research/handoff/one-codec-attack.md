# Handoff — crack practice puzzle `one`'s codec

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
null + `--self-test`). Reproduces the census + the exclusion battery. Authoritative
write-up: `CODEC-RESULTS.md` § "`one` — direction-blind run-length carrier +
memoryless-codec exclusion".

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
divide 21 → {1, 3, 7, 21}). Move-to-front over `M` is excluded directly (the two
len-26 crib windows agree on only 22/26 outputs — not identical). The one
English-viable crib-consistent candidate (cumsum mod 21) is a bounded-increment
walk and scores below its matched null: **honest negative + the 21-bit /
run-period-1 constraint.** Next agent: search the *bit-periodic-period-|21* and
*evolving-table* families this narrows to, using `cribfit` as the consistency
pre-filter before any language scoring. Write-up: `CODEC-RESULTS.md` §
"`one` — crib-consistency filter (cribfit)".

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

Per `research/data/practice-puzzles/CODEC-RESULTS.md` (§ `one`): Baconian (5-bit),
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
  see CODEC-RESULTS.md § "Why the gate is fooled"). Use a **trigram/quadgram**
  objective.
- Build a reusable file-driven CLI instrument (`--input-file`/`--stdin` + a planted
  control + matched null), not a throwaway script. Record results in
  `CODEC-RESULTS.md` (the authoritative `one`/`two` codec record).
- If you recover candidate cleartext, log it as a HYPOTHESIS under
  `research/gak-threads/candidates/` (per the maintainer's standing directive).
- The maintainer holds `two`'s English (not `one`'s, as far as recorded); there is
  no in-repo ground truth, so a scored candidate is never a decode until checked.

## Related context

- `research/data/practice-puzzles/CODEC-RESULTS.md` — the `one`/`two` codec record
  (transparent-rotor leak, isoscan crib anchors, the gate blind-spot).
- `research/findings/ctak-feedback-discriminator.md` — why `two` is blocked (hidden
  state); `one` is the cleaner codec target.
- Instruments: `isoscan` (repeats + null), `solve --codec-search` (the codec layer,
  `src/attack/codec/` + `src/attack/solve/`), `keydiff` (one → constant-additive Δ,
  consistent with C5).
