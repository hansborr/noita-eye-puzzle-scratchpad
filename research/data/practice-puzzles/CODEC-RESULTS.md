# Codec-search results — digit puzzles (one / two / six)

Attack on the small-alphabet *digit* puzzles, which a direct symbol→letter
substitution cannot carry (5 < 26, 12 < 26): they need the codec/transduction
layer to widen the alphabet first. Result: **`one` is SOLVED** (2026-07-01, exact
ciphertext round-trip — see its section); `two` and `six` remain **honest
negatives**, with `two` also documenting a limitation of the matched-null gate
itself.

> Honesty ceiling (binding): a high n-gram score (or "surviving the gates") is not
> a decode. Except for `one`'s round-trip-verified solve, nothing here is a
> recovered message. The negatives are claims only about the codecs, mappings,
> and nulls actually searched.

## Headline

| Puzzle | Verdict | Notes |
| --- | --- | --- |
| `one` | **SOLVED (2026-07-01)** — `Permutation Representation Destination` | alternating-orientation dihedral GAK over C5 + 7-bit ASCII; verified by an exact 266/266 ciphertext round-trip (`maskdecode`); see § "`one` — SOLVED" below. The prior honest negatives (`rlcodec`, `cribfit`, `rankcodec`, `mdlcodec`, `bigramcodec`) all stand *as scoped* — they attacked direction-blind reductions forced by a hidden-state assumption the actual cipher does not satisfy |
| `two` | honest negative — gate "survivors" are **transition-law artifacts**, not decodes | exposes a bigram/Fisher-Yates gate blind spot (below) |
| `six` | honest negative (0 survivors) | base-6, spaces preserved |

## The structural finding: `one` and `two` are ±1-walk-on-Cn encodings

- **`one`** (266 base-5 digits): every one of the 265 transitions is exactly ±1
  mod 5 — a walk on the pentagon C5. The ciphertext *is* the running sum (mod 5)
  of a 265-bit up/down stream.
- **`two`** (698 letters A..L, base 12): the forbidden-successor law is
  `s[i+1] mod 3 != s[i] mod 3` (every symbol has exactly 8 of 12 allowed
  successors; the 4 forbidden share its residue mod 3). Fractionating
  `s = (q = s//3 base 4, r = s%3 base 3)`, the **r-channel is a ±1 walk on C3** —
  structurally identical to `one`'s C5 walk. The q-channel is a near-uniform,
  unconstrained base-4 stream.

This is the same family fingerprint the eyes show: deterministic state-machine
structure (±1 walks, forbidden successors) that is the cipher *mechanism*, not the
plaintext. Supporting evidence (IoC is invariant under substitution **and**
transposition, so a value below English ≈ 0.067 rules out any clean
substitution/anagram into English):

| Probe | `one` | `two` |
| --- | --- | --- |
| Marginal `H1` | 2.321 / log₂5 = 2.322 | 3.578 / log₂12 = 3.585 |
| Codec-stream IoC | 5-bit groups 0.025 (below uniform-26 = 0.038) | q-pairs 0.062 ≈ uniform-16; r-walk 5-bit 0.041 |
| Per-period coset IoC | flat | flat at every period 1..24 (no Vigenère key length) |
| Channel independence | — | q ⟂ r (χ² ≈ df) |

## The transparent rotor channel and crib anchors (`isoscan`)

The C3 walk above is not just structure — in the hidden-state GAK reading it is a
**transparent channel that leaks plaintext with no key**, and it carries exact
repeated spans that locate where the plaintext repeats.

### The rotor leaks ~1/3 of the plaintext key-free

Read `two` as a `C3 × S4` hidden-state group-autokey (convention B: the visible
symbol is the deck's top-card image, post-composed). Because `C3` is a **direct
product** factor, the rotor updates `r += eps` *independently* of the hidden deck.
So the observed rotor increment

    eps[i] = (class[i] - class[i-1]) mod 3,  class = symbol mod 3

equals the plaintext symbol's own `eps` **exactly — zero cipher noise**. Writing
the octal plaintext symbol as `(eps-1)*4 + t`, the high bit (`sym // 4 = eps - 1`)
is public: roughly **one plaintext bit in three leaks with no key at all**. Only
the 2-bit top-card image `t` stays hidden behind `S4`. This is the cryptographic
meaning of the "r-channel is a ±1 walk on C3" fact above.

The `mod 3` rotor is **forced, not assumed**: every symbol has exactly 8 of 12
successors, the 48 forbidden pairs are exactly the three residue classes
`{ADGJ, BEHK, CFIL}`, and that transition graph admits **only one** balanced
3-coloring. (Independently confirmed by codex.)

### Crib anchors: exact repeats in the difference channel

The transparent channel `d[i] = (v[i+1] - v[i]) mod 3` is mapping-independent (a
global symbol offset cancels), so a repeated plaintext span leaves a **literal
exact repeat** there — the translate-isomorph fingerprint of a GAK cipher. The
`isoscan` instrument finds them and calibrates the longest repeat against an
order-1 Markov (transition-preserving) null — the same discipline the gate
blind-spot section demands, *not* a Fisher-Yates shuffle:

| Stream | Projection | Longest repeat | Null ceiling (200 trials) | p | Anchors (pos1/pos2, gap) |
| --- | --- | --- | --- | --- | --- |
| `two` | `--delta-mod 3` | **68** | 29 | 0.005 | 68 @231/351 (120); 51 @5/555; 41 @352/506; 37 @108/572; 34 @22/108 |
| `one` | `--delta-mod 5` | **36** | 22 | 0.005 | 36 @145/229 (84) |
| `two` | raw (no projection) | 7 | 8 | 0.11 | none — not significant |

The raw-vs-difference contrast is the GAK signature: the full ciphertext shows
**no** significant repeat (the hidden deck differs at each occurrence, scrambling
the literal symbols), but the transparent rotor channel does. A length-68
difference-channel repeat is about **34 repeated plaintext letters**.

### Honesty framing (binding)

An anchor is a **structural candidate, never a decode**. It locates *where* the
plaintext repeats — a crib / known-plaintext anchor to seed a key recovery — not
*what* it says. Two caveats bound how far this reading can be pushed:

- **Not forced to `S4`.** `C3 × D4` (2 hidden states) and `C3 × A4` (3 hidden
  states) reproduce the `mod 3` law and out-degree 8 identically; `S4` is only the
  maximal member. A smaller hidden group means less deck slack and an easier
  solve, so the current solver may be over-parameterized on real `two`. The
  cheapest discriminator is an isomorph chaining-graph element-order (cycle-length)
  scan.
- **The free 4-class projection is not English-diagnostic.** Its above-null
  sequential structure is the period-2 codec artifact (the same `eps` signature
  that makes even positions ~72% "down", odd ~54% "up"), not language — it lacks
  the conditional-entropy drop genuine English projection carries. It is usable as
  a key-free codec *constraint*, not a crack.

### The instrument

`isoscan` (`src/analysis/translate_isomorph` + the `isoscan` subcommand) is
file-driven and self-validating: an order-1 Markov matched null plus a planted
positive control (`isoscan --self-test`). It reproduces every figure above and
generalizes to the eyes. This moves the crib-anchor analysis **in-engine** (the
structural/null figures elsewhere in this doc were produced out-of-engine).

```sh
# two — the rotor (transparent) channel
cargo run -- isoscan --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL --delta-mod 3
# one — its C5 walk channel
cargo run -- isoscan --input-file research/data/practice-puzzles/one \
  --alphabet 01234 --delta-mod 5
# raw two — no significant repeat (deck scrambles it)
cargo run -- isoscan --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL
# planted positive control
cargo run -- isoscan --self-test
```

**Next leads (ranked):** (1) crib-anchored deck-key recovery over the length-68
span, where the plaintext is constant and the deck permutation can be solved
locally; (2) a `D4`/`A4`/`S4` structure discriminator via isomorph chaining-graph
element orders; (3) the quadgram-in-octal codec objective the gate blind-spot
section recommends.

## Hidden-group discriminator (`groupscan`)

The `isoscan` honesty framing left the hidden group `H ⊆ S4` undetermined: the
`mod 3` law and out-degree 8 are reproduced identically by `C3 × D4`, `C3 × A4`,
and `C3 × S4`, so `S4` is only the maximal member. `groupscan` (lead #2 above) is
the cheapest discriminator — an element-order scan over the deck channel that
constrains *which* group `H` is, never recovered plaintext.

### The idea: disjoint giveaway cycle types

Read `two` as the `C3 × H` hidden-state group-autokey: the rotor `r = symbol % 3`
is the transparent `C3` factor, and `H` acts on a 4-card deck with values
`q = symbol // 3`. As subgroups of `S4` the three candidates have **disjoint
giveaway cycle types**:

| Group | Has 3-cycle? | Has 4-cycle? |
| --- | --- | --- |
| `D4` (order 8) | no | yes |
| `A4` (order 12) | yes | no |
| `S4` (order 24) | yes | yes |

So a single observed 3-cycle **rules out `D4`**, and a single observed 4-cycle
**rules out `A4`**. Element orders are read off the deck channel via the same
repeated-plaintext anchors `isoscan` finds: at a difference-channel anchor the
plaintext is (claimed) constant, so the induced top-card permutation's cycle type
**is** the order of the corresponding group element. A clean 3-cycle or 4-cycle in
the deck channel is therefore a structural giveaway for `H`.

### Null gate

The verdict is gated on a **matched null**: the deck channel is decoupled from the
rotor under an order-1 Markov law and significance is required at `p < 0.05` using
an add-one Monte-Carlo estimator. An apparent cycle that the deck-decoupled null
reproduces as easily as the real channel is not a giveaway — it is the period-2
codec artifact leaking into the deck readout, the same trap the `isoscan` 4-class
caveat warns about.

### Real-`two` result (NoDeckSignal, robust)

- 698 symbols over a 12-symbol alphabet; channels: rotor `mod 3` (transparent) +
  deck channel of 4 card values.
- 16 difference-channel anchors (len ≥ 8) examined; **0** consistent
  deck-channel contexts; observed deck-channel cycle lengths `[]`.
- matched null (deck channel decoupled, order-1 Markov, 200 trials): mean
  consistent 0.07, ceiling 1, **p-value 1.0000**.
- **VERDICT: `NoDeckSignal`** — no *significant* deck-channel signal versus the
  deck-decoupled null.
- Longest clean deck-channel prefix across anchors: **13** (anchor len 37 at
  108/572). The corrected all-offset scan raised the longest clean prefix from 7
  (old bounded scan) to 13 but still recovered **no determined permutation**, so
  the negative is **robust, not a prior false negative**.

### Honest interpretation (binding)

Under the top-card readout the `isoscan` crib anchors are **eps-only (rotor-only)
repeats at the deck level**: the rotor / high-bit plaintext repeats where the
deck / low-2-bit plaintext does not. So the length-68 crib span (anchor 231/351)
is a **constant-`eps` span, not a constant-full-plaintext span** at the deck
level — which **weakens the crib-recovery lead** (lead #1 above): a deck-key
recovery seeded by it stands on little, because the plaintext it would treat as
constant is constant only in the transparent rotor bit. A `groupscan` verdict is a
**structural discriminator over the hidden group `H`, never recovered plaintext.**

### The instrument

`groupscan` (`src/analysis/group_order` + the `groupscan` subcommand) is
file-driven and self-validating: planted `D4`/`A4`/`S4` controls plus an eps-only
matched-null rejection (`groupscan --self-test`).

```sh
# two — the deck channel under the C3 × H reading
cargo run -q -- groupscan --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL
# planted D4/A4/S4 controls + eps-only matched-null rejection
cargo run -q -- groupscan --self-test
```

### Readout convention and the autokey-family boundary

The top-card vs marked-position readout question is **redundant** — no new
instrument is warranted. `groupscan`'s `read_context` fits a fixed permutation
directly on the *observed* deck channel `q = symbol // 3`, and is blind to whether
`q` means `deck[0]` (top-card readout) or `deck⁻¹[0]` (marked-position / position-of-marked-card
readout). The two self-consistent passive-deck **plaintext-autokey** models are
inverse-relabelings of each other — (right-multiplication deck update, top-card
readout), the convention the `hidden_state_solver` generator uses, and
(left-multiplication update, marked-position readout), the sibling G1b
generator's convention. Over a repeated-plaintext span the two anchor occurrences
differ by a single constant group element `K`, and **both readouts expose a `q`
that transforms by a constant permutation** between occurrences
(`q_{b+s} = K(q_{a+s})` for top-card, `q_{b+s} = K⁻¹(q_{a+s})` for
marked-position). `groupscan` already recovers exactly this relation and already
validates a positive control for it, so real `two`'s `NoDeckSignal` robustly
excludes passive-deck structure under **both** readouts — it is not a top-card
artifact, and a marked-position instrument would recompute the identical
statistic. (The mismatched pairings, e.g. right-mult + marked-position, yield no
fixed-permutation relation under *either* readout — the coverage-collapse already
documented above as `two`'s honest negative.)

The remaining **untested** regime is a noted open lead. `groupscan`'s premise that
the two anchor occurrences differ by a *single constant* `K` holds **only** for
plaintext-autokey with a passive deck. If real `two` is instead
**ciphertext-autokey** — the deck advance feeds back the emitted symbol — then no
readout yields a constant-`K` fixed-permutation relation and `groupscan`'s
positive-control premise itself collapses. That regime is untested by `groupscan`
and is a candidate explanation for `two`'s honest negative; settling it needs a
**feedback-aware attack/discriminator**, not a readout-convention instrument. This
is structural reasoning about the hypothesis space, never recovered plaintext.

> **RESOLVED (ctakscan):** the feedback-aware discriminator was built
> (`src/analysis/ctak_feedback/`, the `ctakscan` subcommand;
> `research/findings/ctak-feedback-discriminator.md`). Under ciphertext-autokey the
> deck trajectory is computable from the observed ciphertext, so the search
> collapses to the advance map `g: card -> S4` alone (`24^4`, fully general for the
> `D0`-cancelling forward/right convention). Gated on whether one `g` reproduces the
> *real* ~34-letter rotor repeat across **all** `isoscan` anchors jointly (a single
> overfit anchor cannot satisfy the joint minimum), with a null that reruns the
> entire search on a deck-resampled stream: real `two` is a **`NoFeedbackSignal`**
> at the random floor (joint min-run 4 = chance, p≈1.0, all four conventions). So
> ciphertext-autokey single-symbol-feedback is **excluded too**, within the scope in
> the findings doc (`g` on the 4-valued card channel, ≤4-card deck). Combined with
> the passive-deck exclusion, **no computable-deck reading reproduces the genuine
> deck-channel repeat** — `two`'s deck carries true hidden state, the eye-cipher wall
> at small scale. (The length-68 rotor repeat is confirmed a *real* repeated phrase,
> not the period-2 codec artifact: it clears a period-2-preserving null, max 25 vs
> 68.)

## What was built: the `Project` codec

`AnyCodec::Project { input_base, output_base, op: Modulo | Div{divisor}, then }` —
a **total**, null-safe per-symbol reduction onto a residue (`Modulo`) or quotient
(`Div`) channel, declaring the channel base. It unifies two readings the engine
could not previously express:

- **binary-move** (the ±1-walk reading): `Delta(base) → Project(Modulo 2) →
  group base 2`. This makes `one` testable at all — the old codec search returned
  **0 candidates** on `one` because `group_len 3` does not divide 266,
  `group_len 2` in base 5 (= 25) is below the 29-letter floor, and base-2 grouping
  was unreachable (the enumeration grouped only in base = cipher-alphabet-size).
  A planted-English positive control proves the gate can *fire* through this lossy
  path (`binary_move_search_recovers_plant_and_survives`).
- **fractionation**: project to each proper-divisor channel, then group. **Off by
  default** — see the `two` finding below.

The projection is lossy (it discards the complementary channel), so it honestly
reports `codec_round_trip_ok = false`; survival never depended on that gate.

### The divisibility wall (honest limitation, not silent truncation)

The *meaningful* base-4 / base-3 fractionation of `two` is not groupable into a
≥ 29-symbol alphabet: 698 = 2 × 349 and the delta length 697 = 17 × 41 admit no
usable `group_len`, and base-4 pairs (16) / base-3 triples (27) fall below the 29
floor. The engine logs every ungroupable codec as `Untransducible` rather than
dropping symbols; the base-4/base-3 readings are covered by the IoC/independence
analysis above (negative).

## `one` — direction-blind run-length carrier + memoryless-codec exclusion (`rlcodec`)

> Supersedes the bit-level framing of the "`one` — honest negative" section below.
> The `solve --codec-search` binary-move result there still stands; this adds the
> carrier re-diagnosis and a matched-null exclusion of the variable-length family
> the prior handoff ranked first.

### The carrier is the direction-blind run-length *magnitude* sequence

`one`'s 265 `±1`-moves run-length-encode to a **magnitude sequence `M`** of 135
values in `1..=5` (distribution `{1:64, 2:34, 3:17, 4:18, 5:2}`). `M` discards the
up/down *direction* of each run. That direction-blind reading is **forced, not
assumed**: `M` carries an exact 26-magnitude repeat `M[16..42] == M[69..95]` whose
two occurrences begin on **opposite run-direction parity** (run 16 is a down-run,
run 69 an up-run) — i.e. it is a *bit-complemented* repeat, invisible to a raw-bit
scan. A repeat that survives polarity inversion can only live in the magnitudes, so
the codec reads magnitudes, not bits.

This **strengthens the `gcd(265, 84) = 1` no-fixed-width argument** already recorded
below into two hard exclusions:

- **No fixed even/odd pairing into letters.** A Polybius/grid pairing makes each
  letter a fixed (row, col) pair of runs; a repeated letter-string then requires
  both occurrences to start on the same pairing parity. The 26-run repeat starts on
  *opposite* parity, so it cannot be pair-aligned at both occurrences — pairing-into-
  letters is structurally impossible (not merely unobserved).
- **No bit-level fixed-width / ASCII codec.** Those are polarity-dependent; a
  bit-complemented repeat would decode to two *different* letter strings, so a
  genuine repeated word cannot appear complemented under any bit-width code.

Secondary repeats corroborate the structure: `M[116..135]` (the message tail)
`== M[72..91] == M[19..38]`, plus several shorter complemented anchors. The longest
repeat is **census-significant** against an order-1 Markov (transition-preserving)
null: observed 26 vs null mean 8.4 / ceiling 13, p = 0.0050. (A significant repeat
is a **structural candidate, not a decode** — it locates *where* the plaintext
repeats, not *what* it says.)

### Every memoryless magnitude codec is an honest negative

`rlcodec` decodes `M` through a battery of memoryless families — `Direct`,
`Polybius` (both phases), `Base5Group` (pairs/triples, all offsets), `Comma{sep}`
and `Term{t}` (variable-length comma/terminator codes over the magnitudes, the
prior handoff's #1 lead), and `PairSub` — then hill-climbs each to the best
English-quadgram substitution and gates it against a **matched null**. **No codec
survives** (overall verdict: honest negative).

The matched null is the load-bearing choice, and it is the one the "Why the gate is
fooled" section above prescribes: an **order-1 Markov resample of each codec's
*decoded symbol stream***, re-run through the *same* substitution search. This holds
the decoded alphabet size, length, and symbol-*bigram* structure fixed and asks only
whether the real ordering carries **above-first-order** (quadgram-over-bigram)
English that a bigram-matched reordering cannot. The variable-length `Comma`/`Term`
codecs score *near* English under a free substitution (mean quadgram ≈ −8.3 to −9.3,
versus English ≈ −7 and uniform ≈ −11) and render seductive fragments
(`Term{t=2}` → `VERIETYOUARTMORETHETYOU…`, `Comma{sep=4}` → `LUMBERECEISBETHENED`),
but **none beats its null** (every codec `z < 0`; `Comma{sep=4}` z = −2.71,
`Term{t=2}` z = −1.11). That near-English text is **substitution-freedom pareidolia
on an 18–35-symbol stream**, exactly the gate blind-spot — now demonstrated
in-engine rather than argued.

The negative is **robust to search budget**: re-running real `one` at
restarts = 16 / iters = 4000 / null-trials = 200 (above the positive control's
budget) keeps every codec below its null (z from −0.37 to −1.81). So the negative is
not a stingy-search artifact.

**Why a magnitude-level null is wrong here (recorded so it is not re-tried):**
resampling or shuffling the *magnitudes* drifts the decoded alphabet size and
destroys the census-significant carrier repeat, which the variable-length codecs
faithfully transmit as a repeated decoded symbol. Real `one` then "beats" such a
null with a spurious z ≈ 2–4 — re-detecting the repeat, **not** finding English. The
symbol-stream Markov null preserves the repeat's bigram contribution, so the gate
asks the right question. (The *census* null above is the opposite, correct choice:
it is magnitude-level precisely because the question there is repeat-length
significance, for which preserving the transition law is the right reference.)

### Honest scope of the negative

Because the matched null preserves bigram structure, the gate fires only for genuine
English whose quadgram structure exceeds its bigrams *and* whose decoded stream is
long / low-freedom enough for the substitution search to recover it (the planted
positive control — a 285-letter, 12-symbol English passage through `Comma{sep=4}` —
fires at z ≈ 5–8). At the short lengths of `one`'s `Comma`/`Term` decodes (n ≈ 18–35)
the test has **limited power**. So the result is precisely: **no detectable
above-first-order English signal under any memoryless magnitude codec** — it
excludes the "search overfits to manufacture English" failure mode the handoff
warned about, but it does **not** prove `one` is non-English; a short genuine message
would also read as below-null. The remaining live regime is a codec with memory / a
non-memoryless reading of the run-length sequence.

### The instrument

`rlcodec` (`src/attack/rlcodec/` + the `rlcodec` subcommand) is file-driven and
self-validating: a planted-English-via-comma positive control that *must* clear the
matched null (and recovers the planted partition, relabel-invariantly) plus the
real-`one` honest negative that *must not*, both checked by `rlcodec --self-test`.

```sh
# one — the magnitude census + memoryless-codec battery
cargo run -- rlcodec --input-file research/data/practice-puzzles/one --alphabet 01234
# planted positive control (must fire) + real-one negative (must not)
cargo run -- rlcodec --self-test
```

## `one` — codec detection-power ceiling (`codecpower`)

> Calibrates the **method**, not the plaintext. `codecpower` plants known English
> through the same comma encoder used by `rlcodec`'s positive control, decodes it
> with `RlCodec::Comma{sep=4}`, and then reuses the actual
> `rlcodec::gate_symbol_stream` matched-null gate. It asks: at a carrier budget
> comparable to `one`'s `|M| = 135`, how often would this gate detect a genuine
> comma-coded English message?

Run recorded for this build:

```sh
cargo run -- codecpower --alphabet 01234
```

Built-in English source: the 285-letter planted-control passage (same quadgram
model that the gate scores; this is a calibration of the gate's own notion of
English, not a held-out generalization claim). Gate budget:
`null_trials=80`, `restarts=10`, `iters=1500`, seed `0x726c636f64656301`.

| L | mean `|M|` | power | detections | mean z | mean p | non-English controls |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 18.9 | 0.250 | 2/8 | +0.54 | 0.3904 | 0/8 |
| 12 | 30.1 | 0.000 | 0/8 | -0.69 | 0.7238 | 1/8 |
| 16 | 40.2 | 0.000 | 0/8 | -0.94 | 0.7608 | 0/8 |
| 24 | 62.0 | 0.000 | 0/8 | -1.61 | 0.9120 | 0/8 |
| 32 | 83.9 | 0.000 | 0/8 | -1.81 | 0.9568 | 0/8 |
| 48 | 129.0 | 0.000 | 0/8 | -0.74 | 0.6574 | 0/8 |
| 64 | 171.9 | 0.375 | 3/8 | +0.30 | 0.4707 | 0/8 |

Size control: aggregate non-English false-positive rate **0.018** (1/56), close
to and below the nominal `alpha = 0.05` gate size. The gate is therefore not
firing indiscriminately; the low power at short carrier budgets is not hidden by an
inflated false-positive rate.

Operating point: the row closest to `one`'s carrier size is **L≈48** with
mean `|M| = 129.0`; the measured power there is **0.000** (0/8). No swept length
reaches the default detectable-length floor of 0.8.

**Honest reading:** the memoryless-comma negative on real `one` is not strong
evidence that a comma-coded English message is absent at the 135-magnitude budget.
It says the actual matched-null gate has essentially no measured power at that
budget under this calibration. The `rlcodec` negative still excludes a strong,
searchable above-bigram signal in the tested codec families, but a genuine short
message could fall below the null. This is the measured trigger for escalating to
an external anchor rather than continuing to treat near-English failures as
decodes.

The instrument is `codecpower` (`src/attack/codecpower/` + the `codecpower`
subcommand). It is file-driven (`--input-file` / `--stdin`), has a required
uniform-letter size control, and self-validates with `codecpower --self-test`. The
comma encoder is shared with `rlcodec` as `rlcodec::encode_comma`, so the
positive control and this calibration cannot drift.

## `one` — crib-consistency filter (`cribfit`)

> Attacks the **codec-with-memory regime** `rlcodec` leaves open. `rlcodec`
> excluded every *memoryless* reading of `M`; the live regime is a keyed/stateful
> codec. This instrument applies the lever the prior handoff flagged: `M`'s
> census-significant repeats (the cribs) almost certainly mark repeated *plaintext*
> spans, so for **any codec whose tokens align to the crib (plaintext-token)
> boundaries, every occurrence must decode identically** — a language-free necessary
> condition that prunes the stateful space and **derives the admissible state/key
> period**.
>
> **The alignment precondition is load-bearing.** A tokenization whose boundaries do
> *not* line up across the cribs (a chunk straddles a window edge, or a dropped
> separator leaves a gap) is **inapplicable** — the test sets that candidate aside,
> it does **not** exclude it. Every candidate is therefore in one of three states:
> *applicable + consistent* (survives the filter), *applicable + inconsistent*
> (excluded), or *inapplicable* (set aside). This matters because a real codec could
> carry the same repeated plaintext with shifted token boundaries; treating
> misalignment as exclusion would be a false negative.

### The cribs' geometry (verified)

The carrier `M` (135 magnitudes) has two census-significant exact repeats
(observed longest 26 vs order-1 Markov null ceiling 14, p = 0.0050): the
26-magnitude `M[16..42] == M[69..95]` and the 19-magnitude triple
`M[19..38] == M[72..91] == M[116..135]`. Each repeat pair has a **run-gap**
(`second − first`) and a **bit-gap** (`Σ M[first..second]`, the carrier-bit
distance):

| pair | run-gap | bit-gap |
| ---- | ------- | ------- |
| (16, 69) len 26 | 53 | 105 |
| (19, 72) len 19 | 53 | 105 |
| (72, 116) len 19 | 44 | 84 |
| (19, 116) len 19 | 97 | 189 |

**`gcd(run-gaps) = 1`** and **`gcd(bit-gaps) = 21`** (`= 3·7`). These two numbers
are the whole constraint:

- **Run-periodic key** (state advances once per run): consistent ⟺ its period
  divides every run-gap ⟺ it divides `gcd(run-gaps) = 1` ⟹ **only period 1**
  (the memoryless case). *No nontrivial run-periodic keyed codec is
  crib-consistent* — reported analytically, no decode needed.
- **Bit-periodic key / cumulative-sum modulus** (state advances per carrier bit):
  consistent ⟺ the period/modulus divides every bit-gap ⟺ it divides
  `gcd(bit-gaps) = 21` ⟹ admissible set **{1, 3, 7, 21}**.

### Per-family verdict

- **CumulativeSumMod(n)** (`output[i] = (Σ M[0..=i]) mod n`): per-run aligned, so
  the filter applies; crib-consistent for every `n | 21`. The output is a
  **bounded-increment walk** (consecutive symbols differ by `M[i] ∈ 1..=5 mod n`) —
  a *strong structural constraint* on what English it could carry, but **not** a
  proof of impossibility. Only `n = 21` is English-viable (alphabet 21 ∈ [8, 26]);
  it is language-gated and the **matched null is the actual evidence**: it scores
  **below its null** (real −11.49 vs null mean −11.03, z = −1.64, p = 0.99 — an
  honest negative; its near-English fragments are the preserved crib repeats under
  free substitution, not a decode).
- **RunPeriodicKey**: reported as the analytic admissible period set above ({1}):
  no nontrivial run-periodic keyed codec is crib-consistent.
- **BitPeriodicSubst(p)**: a bit-periodic keyed substitution over the per-run
  single-magnitude tokenization is exactly a free monoalphabetic substitution on
  the augmented symbol `(magnitude, bit-coset)`, where the bit-coset is the
  exclusive prefix sum modulo `p`. The admissible periods are {1, 3, 7, 21}; `p=1`
  is memoryless (alphabet 5), `p=21` is **monoalphabetic-infeasible** (alphabet 47 >
  26) and is reported rather than dropped, and the two English-viable periods are
  language-gated. Both are honest negatives: `p=3` (alphabet 14) scores real −9.978
  vs null mean −9.848 / null max −9.414 (z = −0.54, p = 0.7037), and `p=7`
  (alphabet 24) scores real −10.219 vs null mean −10.122 / null max −9.431
  (z = −0.32, p = 0.5802). This completes the per-run crib-admissible
  bit-periodic keyed-substitution family: per-run is the crib-forced tokenization;
  pair/chunk tokenizations are inapplicable under this filter.
- **EvolvingTableMtf(tokenization)** (move-to-front rank code over single
  magnitudes / pairs / comma / terminator chunkings): the verdict depends on
  whether the tokenization aligns to the cribs.
  - **Single-magnitude MTF is per-run aligned, and genuinely crib-INCONSISTENT ⟹
    excluded.** Its two len-26 windows agree on only **22 / 26** output positions —
    *not* identical (the carrier value is 22/26, not the 0/26 a coarser model would
    predict: the small 5-value alphabet plus the dominance of magnitude 1 keeps MTF
    nearly stationary, yet the 4 disagreements still break occurrence-equality).
  - **The pair / comma / terminator tokenizations are INAPPLICABLE** (set aside, not
    excluded): the odd run-gaps shift the pair phase across the cribs, and the comma
    chunking drops separator runs, so their token boundaries do not line up across
    the repeats. The filter cannot judge them.

### Honest verdict

**No English survivor** (honest negative) **plus the derived structural
constraint:** any surviving codec-with-memory must key on a period that divides
`gcd(bit-gaps) = 21` (bit-periodic) and, if it advances per run, must be
memoryless (`gcd(run-gaps) = 1`). The concrete gated candidates are cumsum mod 21
and `BitPeriodicSubst(p)` at `p=3` and `p=7`; all are below their matched nulls.
Scope caveat: this is "no above-bigram English under a per-(magnitude, bit-coset)
substitution at the crib-admissible periods 3 and 7"; at ~33 bytes of entropy the
test is underpowered, so it excludes a searchable codec signal, not a short genuine
message. Among the move-to-front readings, the per-run **single-magnitude MTF is
excluded**, while the **chunked / paired tokenizations are inapplicable** under
this filter (set aside, not excluded — their boundaries don't align to the cribs).
This narrows the live regime without claiming a decode.

### The instrument

`cribfit` (`src/attack/cribfit/` + the `cribfit` subcommand) reuses `rlcodec`'s
carrier derivation, census, English model, and — crucially — the **same**
matched-null gate (`rlcodec::gate_symbol_stream`, promoted from `evaluate_codec`
so the two cannot drift). It is file-driven and self-validating: a planted-English
positive control that *must* fire through the gate, a discrimination control (a
constructed carrier whose matching-modulus cumsum is accepted but whose
move-to-front is rejected — proving the filter is neither pass-all nor
reject-all), and the real-`one` honest negative with its documented anchors, all
checked by `cribfit --self-test`.

```sh
# one — crib geometry + per-family consistency + the gated honest negative
cargo run -- cribfit --input-file research/data/practice-puzzles/one --alphabet 01234
# planted positive + discrimination control + real-one negative
cargo run -- cribfit --self-test
```

## `one` — bounded-order predictive-rank codec (`rankcodec`)

> Tests the remaining bounded-memory / evolving-table idea: read each magnitude
> `M[i]` as the rank of the next plaintext letter in a deterministic order-`k`
> English predictor's next-letter list. The predictor orders swept here are
> `k = 1, 2, 3`, strictly below the order-4 quadgram scorer, so the decoder is not
> allowed to manufacture exactly the structure the scorer measures.

Run recorded for this build:

```sh
cargo run -- rankcodec
```

Default predictor source: the built-in `rlcodec` planted-control passage (285
letters after filtering). Target: embedded practice puzzle `one`, whose carrier
is `|M| = 135` with distribution `{1:64, 2:34, 3:17, 4:18, 5:2}`. Gate budget:
`null_trials=80`, `restarts=10`, `iters=1500`, seed `0x72616e6b900d0001`.

The matched null is specific to this memoryful decoder: an order-1 Markov
resample of `M` with the crib windows pinned, followed by the **identical
order-`k` decode** and the same substitution/quadgram gate finalization as
`rlcodec`. The code pins the crib windows and resamples only the non-crib
positions, so the null keeps the same carrier-repeat structure while cancelling
the decoder's baseline higher-order language-like output. As with `codecpower`,
the gate is **TERTIARY only and underpowered at 135 magnitudes**.

Primary results:

| order `k` | English ranks `<=5` | representable? | crib verdict / locked tails | gate z | gate p | survivor |
| ---: | ---: | --- | --- | ---: | ---: | --- |
| 1 | 244/285 = 85.6% | no | excluded; len26 15/25, len19 11/18, 12/18, 11/18 | -1.19 | 0.9136 | no |
| 2 | 280/285 = 98.2% | no | excluded; len26 4/24, len19 0/17, 0/17, 10/17 | +0.05 | 0.4691 | no |
| 3 | 281/285 = 98.6% | no | excluded; len26 17/23, len19 13/16, 12/16, 12/16 | -0.02 | 0.4938 | no |

Expected rank-hit distributions on the English source:

- `k=1`: `1:102, 2:51, 3:39, 4:29, 5:23, >5:41`
- `k=2`: `1:177, 2:55, 3:29, 4:15, 5:4, >5:5`
- `k=3`: `1:237, 2:32, 3:6, 4:4, 5:2, >5:4`

**Honest verdict:** no swept order is crib-admissible. The crib-consistency filter
is the primary exclusion: every order fails at least one required locked tail
after the allowed `<=k` transient. Independently, the feasibility control says the
built-in English source is **not fully representable** in ranks `<=5` for any
bounded order swept here (best coverage is 98.6%, still with 4/285 letters needing
rank `>5`). This feasibility figure is an **optimistic best case**: the predictor is
trained on the very passage it then rank-encodes (a self-fit), so a real unknown
plaintext would overflow rank `>5` at least this often, not less — the exclusion is
if anything stronger for `one`'s actual message. The statistical gate adds no
positive evidence and is explicitly underpowered at this 135-magnitude budget (see
`codecpower`). No candidate text is reported as a recovered plaintext.

The instrument is `rankcodec` (`src/attack/rankcodec/` + the `rankcodec`
subcommand). It is self-validating: `rankcodec --self-test` checks the encode /
decode round trip, a planted rank-coded positive with a repeated crib that must
lock and clear the matched null, and a crib-inconsistent control that must be
excluded.

## `one` — crib-synchronous MDL affine running-key search (`mdlcodec`)

> Last in-engine computational lever before an external anchor. This searches the
> affine running-key family `idx[i] = (a*S_i + b*i) mod R`, with `o_0 = 0`, over
> the direction-blind run-length carrier `M`. For a fixed `(R,a,b)`, the index
> stream is fully determined, so the best key `pi` is exactly the existing
> `rlcodec::substitution_search` on the **densified** visited residues. The raw
> residues are kept for the crib arithmetic.

Run recorded for this build:

```sh
cargo run -- mdlcodec
```

Default budget: rings `10..=26`, `coeff_max=8`, `null_trials=24`,
`restarts=6`, `iters=900`, seed `0x6d646c636f640001`. The effective alphabet
floor is `k >= 8`; `L_codec` is still charged on the actual effective `k` plus
`log2` of the canonical searched grid.

Crib modular check: each cell must satisfy
`R | (a*bit_gap + b*run_gap)` for every census-derived anchor. The `a=1,b=0`
cross-check agrees with `cribfit`'s admissible cumsum set and includes `R=21`.

Cell coverage on real `one`: **searched 595 / eligible 35 / feasible 6 /
deduped 5**. The post-selection null reruns the whole eligible grid on each
crib-pinned Markov-resampled carrier and recomputes crib eligibility from that
draw's own bit-gaps. In this bounded run, 14/24 null draws produced a finite
English-feasible best cell; finite best-null MDL had mean **2043.46**, p05
**1926.86**, and range **1926.86..2263.66** bits. The survivor rule is
`real MDL <= null p05` (lower MDL is better).

Top MDL-like cells:

| rank | R | a | b | k | L_codec | L_text | MDL | Delta vs null mean | z | survivor |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 14 | 1 | 7 | 13 | 65.06 | 1923.50 | 1988.56 | -54.89 | -0.61 | no |
| 2 | 12 | 1 | 3 | 12 | 61.26 | 1931.08 | 1992.33 | -51.12 | -0.56 | no |
| 3 | 16 | 2 | 6 | 8 | 45.09 | 1997.74 | 2042.84 | -0.62 | -0.01 | no |
| 4 | 21 | 1 | 0 | 21 | 90.69 | 2171.56 | 2262.25 | +218.80 | +2.41 | no |
| 5 | 24 | 1 | 3 | 24 | 96.60 | 2204.13 | 2300.72 | +257.27 | +2.84 | no |

Global winner: `R=14,a=1,b=7,k=13`, with `L_codec=65.06`,
`L_text=1923.50`, `MDL=1988.56`, `Delta=-54.89`, `z=-0.61`, survivor **no**.
Under-determination count at `epsilon=2.0` bits: **1** cell (spread 0.00 bits).

**Honest verdict:** this enumerated affine running-key family is exhausted or
under-determined at 33 bytes. The winner is below the finite null mean but does
not beat the post-selection null p05, so the search has selected a candidate
rather than recovered plaintext. Emitted-symbol-history codecs are **out of
scope** for this instrument; `rankcodec` tested only the bounded predictive-rank
subfamily, not every possible emitted-history codec.

CANDIDATE (MDL-selected affine codec `R=14,a=1,b=7`), **not** a recovered
plaintext:

```text
LMISEATERMENTERTERSEAMITERSEITENDOTENDWAMISMEATERMISERMEATERMOTEATENDERSEAMITERSEITENDOTENDWAMISCASEATERMOTERSEITENDEAMITERSEITENDOTEND
```

The instrument is `mdlcodec` (`src/attack/mdlcodec/` + the `mdlcodec`
subcommand). It self-validates with `mdlcodec --self-test`: a planted affine
English positive recovers exactly and beats the post-selection null, a random
repeated-block control remains a non-survivor with near ties, and the `a=1,b=0`
crib modular check matches `cribfit`.

## `one` — bigram-order codec gate (`bigramcodec`)

Chases a puzzle-author hint ("look at the bigrams"). Two readings, both closed:

**Encoding-unit reading (dead structurally).** Read the walk as symbol *pairs*.
Because every adjacent digit differs by ±1 mod 5, both overlapping and
non-overlapping digit-bigrams collapse to only **10 distinct values** (the ten
directed edges of the pentagon = 5 vertices × 2 directions) — too few to carry
26-letter English. Run-length **magnitude**-pairs reach a 25-symbol alphabet but
`one` populates only ~14 of them. All three token streams are alphabet-capped.

**Scoring reading (measured honest negative).** For each stream, anneal the best
injective symbol→letter map under the English/Finnish **bigram** mean-log-
likelihood (the converse of `rlcodec`'s quadgram-over-bigram battery), then gate
against **two** nulls: order-0 (unigram-preserving shuffle — has power for token
ordering but is confounded by the walk/GAK-repeat) and order-1 (Markov transition-
preserving — the confound control). Verdict keys on a **readability crib
heuristic**, not the nulls.

| stream (alphabet) | best decode | order-0 z | order-1 z | readable | verdict |
| --- | --- | --- | --- | --- | --- |
| digit-pairs (10) EN | `HEELELOOHOITOII…` | +3.18 | −1.26 | 0 | artifact |
| edges (10) EN | `HERARASERASOUTUT…` | +23.56 | −0.76 | 0 | artifact |
| **mag-pairs (14/25) EN** | `STHEHCERYDEIYHIS…` | **−0.39** | −2.63 | 0 | **negative** |

No stream yields readable text. The two 10-symbol streams beat *only* the
confounded order-0 null — the huge edge z is the ±1-walk's structural correlation
(overlapping edges share a vertex), not language. The only alphabet-rich stream
(`mag-pairs`) beats **neither** null.

**The load-bearing measurement (why this closes the lever, not just fails it):**
the order-1 gate is *provably* powerless for a bigram objective. The `--self-test`
plants genuine English through the `mag-pairs` codec and recovers it **verbatim**
(`THERAINONTHEROAD…`), yet that perfect English scores order-1 **z ≈ +0.6,
p ≈ 0.33** — it does *not* clear the gate. So a bigram objective cannot see past
the transition matrix the order-1 null preserves; readability, not a null, is the
only discriminator here. This is the bigram-level analog of `codecpower`. The
self-test asserts: positive is readable + beats order-0 + does **not** clear
order-1, and real `one` is non-readable — a symmetric, non-vacuous control.

The instrument is `bigramcodec` (`src/attack/bigramcodec/` + the `bigramcodec`
subcommand), file-driven and self-validating (`bigramcodec --self-test`).

## `one` — honest negative (`solve --codec-search` binary-move)

`solve --codec-search` now yields 12 evaluated candidates (cipher round-trip held);
**0 survive**. The top candidate is the binary-move codec
(`delta → project → base-32 group`):

- in-sample −2.063, matched null −2.075 → `beats_null: false`
- held-out −3.502, null held-out −3.483 → `generalizes: false`
- rendered text `THEHANDSHERSE...` — the *signature* of a many-to-one overfit: a
  32→29 search manufactures English-looking bigrams in-sample (above real English)
  that neither beat the null nor generalize. The gate correctly rejects it.

## `one` — the author hints and the dihedral hidden-1-bit model (hypothesis)

**Provenance.** On 2026-07-01 the maintainer relayed five hints from the puzzle's
author. They are creator-supplied and reliable *as hints*; the model below that
fits them is our reverse-engineering, **not** creator-confirmed.

- **h1** — "it is a GAK cipher made for practice solving the eyes." (`one` is a
  group-autokey, the same family as the eyes — not a static transduction.)
- **h2** — "look at the bigrams." (Chased by `bigramcodec`, above.)
- **h3** — reversibility ⟹ each state has a distinct allowed-successor set. (This
  *is* the crisp ±1 law already observed: from digit `c`, only `c±1` is legal.)
- **h4** — the plaintext-letter → direction mapping **flips with a hidden 1-bit
  orientation**: the same letter reads "up" here and "down" there.
- **h5** — "especially simple settings limit the bigrams": a minimal 1-bit hidden
  state + ±1 generators ⇒ only the 10 ±1 pentagon edges ever occur.

**The model these imply (hypothesis).** `one` is the *simplest* GAK — a **dihedral /
hidden-1-bit-orientation (chirality) group-autokey over C5**. This corrects the
earlier "`one`'s cipher is fully solved, no hidden state left" framing (see
`research/handoff/one-codec-attack.md`): the ±1 walk is the *observable*, but a
hidden 1-bit orientation sits behind it. h4 is the crux — because a hidden bit flips
each letter's up/down reading, **no memoryless or static codec can be correct**,
which is exactly why every family tested above (`rlcodec`, `cribfit`, `rankcodec`,
`mdlcodec`, `bigramcodec`) is an honest negative rather than a near-miss.

**It reduces to the carrier we already have (verified).** A 2-symbol dihedral GAK
with orientation update `b_{i+1} = ¬obs_i` emits, as its recovered per-step symbol,
"did the direction change" — which *is* the direction-blind run-length structure of
§ "`one` — direction-blind run-length carrier". So the dihedral model does not
overturn the carrier diagnosis; it **explains** it (direction is blind because it is
absorbed into the hidden bit) and it explains the bit-*complemented* 26-run repeat
(the two occurrences carry opposite orientation).

**Plaintext structure under the model.** The census triple
`M[19..38] == M[72..91] == M[116..135]` (≈40% of the message) reads as a **phrase
repeated three times** over a reduced (~14-symbol) alphabet. This is *not* passively
recoverable at `one`'s length: a free substitution search over the repeated,
small-alphabet stream produces **repeat-inflated pareidolia** (the map never locks —
`HERETIS` in one run, `HEREDIT` in the next), and a *planted* positive control (a
known English phrase repeated ×4, clean substitution) **fails to recover** under the
same search. Short + repetitive + small-alphabet = under-determined, independent of
the gate's power.

**Why this is the exhaustion point (measured, not asserted).** `bigramcodec`'s
self-test proves the magnitude-pair carrier *is* solvable for long English (a
~222-token plant recovers verbatim), so `one`'s failure is an **unknown hidden-state
trajectory + a short ~67-token length**, not an unsolvable carrier. Combined with the
`codecpower` result (the matched-null gate has ≈0 power at the 135-magnitude budget)
and its bigram-order analog, the principled low-parameter codec families are closed
*and* the statistical gate is demonstrably underpowered at this length. The honest
next lever is therefore **not another codec search** but the **external anchor**: the
maintainer-held withheld `one` snippet → an `anchorfit` known-crib attack (align the
snippet to the carrier, back the codec out of known input/output, verify on the
rest — needs no statistical power). Because the phrase repeats 3×, even its first
word would lock most of the message.

**Honesty scope (binding).** The five hints are creator-supplied; the dihedral /
1-bit model is *our* reverse-engineering that fits all five and reduces correctly to
the observed carrier — treat it as the leading hypothesis, not a confirmed setting.
No candidate cleartext is claimed. The reduction `b_{i+1} = ¬obs_i` → run structure
is verified; the letter-level settings are not recovered.

> **SUPERSEDED (2026-07-01, same day):** the "measured exhaustion → external anchor"
> synthesis above was correct about the tested families but wrong about the next
> lever. The orientation bit is *deterministic* (alternates every step), not
> feedback-driven hidden state, and the puzzle fell to a zero-parameter readout.
> See the next section.

## `one` — SOLVED: alternating-orientation dihedral GAK + 7-bit ASCII (`maskdecode`)

**Plaintext (verified decode, 2026-07-01):**

```text
Permutation Representation Destination
```

**The cipher (verified mechanism).** The orientation bit is not hidden state at
all — it **alternates deterministically every step**, `b_i = i mod 2`. The
plaintext is the 7-bit-ASCII bit stream `m` (MSB-first) of the 38-character
message above (266 bits). Each step emits direction `o_i = m_{i+1} XOR b_i` and the
ciphertext digit walks `±1` on C5 from starting digit `4` (up for `o=1`). The 265
steps carry message bits 2..266; the leading bit of `P` is not carried by any step
(observation: an implicit predecessor digit `0` would carry it consistently —
recorded as a note, not a claim). Reading this mechanism as "the dihedral /
1-bit-orientation GAK of the author's hints (h1/h4/h5) in its simplest setting"
is our **interpretation** — it fits all five hints, but only the mechanism above
is what the round-trip verifies; the family label is not author-confirmed.

**Verification (why this clears the claim ceiling).** This is not a scored
candidate: the readout has **zero free parameters** beyond a small enumerated grid
(mask ∈ {static, alternating} × width × offset × bit-order × polarity × direction),
and the decode is gated on an **exact ciphertext round-trip** — re-encoding
`Permutation Representation Destination` under the stated model reproduces **all
266/266 digits exactly**. All 37 full 7-bit chunks are ASCII letters/space (letter
fraction 1.0 vs ≈0.41 chance baseline; the whole sweep is ~10² cells, so a
full-letter English readout surviving by chance is ≲10⁻¹²), and the 6 recovered
head bits `010000` uniquely complete to `P` among printable options (`0x50` vs the
unprintable `0x10`). Per this corpus's discipline the maintainer/author check is
still the formal ground truth, but the round-trip makes this a verified decode,
not a hypothesis.

**Consistency with the census (retrodiction).** Under `b_i = i mod 2` the phrase
windows at bit starts 42/147/231 (the 19-run triple) become **literally identical**
(34/34, 34/34), and the model *forces* the observed polarity law: repeats at odd
bit-gap appear direction-complemented (occ1↔occ2, gap 105), repeats at even
bit-gap appear direction-exact (occ2↔occ3, gap 84). All 9 maximal run-magnitude
repeats of length ≥ 6 obey the parity prediction (0 violations). The
`...ation`/`...ntation` suffixes shared by the three words *are* the census
repeats: `M[16..42]==M[69..95]` (47 bits ≈ `-ntation `) and the triple
`M[19..38]==M[72..91]==M[116..135]` (34 bits ≈ `tation `-grade suffix), which is
why they read as a "phrase repeated 3×" at the carrier level. The crib bit-gap
`gcd = 21 = 3·7` was the codec width in plain sight.

**How it was found (and why every prior negative was right-but-scoped).** The
2026-07-01 hints prompted a closure enumeration of the 1-bit orientation updates
`b_{i+1} = f(b_i, p_i, o_i)` (16 boolean functions, collapsing to five families):

| family | update | derived plaintext stream | verdict on real `one` |
| --- | --- | --- | --- |
| static | `b' = b` | `o` (± complement) | excluded (occ1↔occ2 complemented ⇒ no literal repeat) |
| conv-C | `b' = f(o)`, `b' = b⊕p` | `d` / magnitudes `M` | consistent; the already-attacked carrier |
| conv-P | `b' = f(p)` | `p_i = d_i ⊕ p_{i-2}` (4 seeds) | **excluded** — crib-window discriminator |
| conv-A | `b' = b⊕o` | prefix-parity of `o` (2 seeds) | **excluded** — crib-window discriminator |
| **conv-alt** | `b' = ¬b` | `o ⊕ 0101…` | **live → solved** |

The discriminator: a repeated-plaintext span must survive as a literal repeat in
the true convention's derived stream. Polarity-blind window agreement on the
phrase windows is 0.50 (chance) for the odd-gap pair under conv-P/conv-A
reconstructions of real `one` but ~1.0 under planted conv-P/conv-A positive
controls — so those conventions cannot host the 3×-repeated phrase. The
alternating stream was the one convention whose derived carrier
(`|runs|=131`, max 6) no battery had ever seen, and literal ASCII fired on it
immediately. The prior negatives are all still correct *as scoped*: they attacked
the direction-blind carrier `M`, which is the right reduction only for
state-dependent (feedback) hidden bits. A deterministic mask keeps polarity
meaningful, which resurrected exactly the family ("bit-level fixed-width /
ASCII") the earlier complemented-repeat argument had excluded — that argument
was proven against raw `o`, and silently over-generalized to all bit-level
readings. Process lesson recorded in `research/attack-methodology.md`.

**The instrument.** `maskdecode` (`src/attack/maskdecode/` + the `maskdecode`
subcommand) is file-driven and self-validating: planted alternating-mask and
static-mask positives that must recover verbatim with exact round-trips, a
SplitMix64 random-walk matched null that must stay negative, a `NotAWalk`
inapplicability verdict, and the real-`one` regression. It generalizes the readout
(any ±1 walk alphabet, widths 5..=8, both masks, all offsets/orders/polarities/
directions) and gates any full-letter readout on the exact re-encode round-trip.

```sh
# one — the verified decode (defaults to the embedded puzzle)
cargo run -q -- maskdecode
# arbitrary input
cargo run -q -- maskdecode --input-file research/data/practice-puzzles/one --alphabet 01234
# planted positives + matched null + NotAWalk + real-one regression
cargo run -q -- maskdecode --self-test
```

**Implications for the eyes (hypothesis, clearly labeled).** Two transferable
leads, neither a claim about the eyes: (1) the author's practice cipher realized
"hidden 1-bit orientation" as a *deterministic alternation* — when attacking the
eyes' GAK layer, cheap deterministic-convention sweeps (periodic masks) deserve to
run **before** assuming true feedback hidden state, because they are exactly
solvable; (2) the recovered plaintext `Permutation Representation Destination` is
itself group-theory-flavored and may be an author meta-hint about the eye cipher's
intended framing — recorded verbatim, no interpretation claimed. (`six` was
checked and is *not* a ±1 walk — this scheme does not transfer there directly.)

## `two` — honest negative, and a gate blind spot

`solve --codec-search` (default: fractionation off) yields 52 candidates; the
gate reports **2 "survivors"** — but they are **transition-law artifacts, not
decodes**. The top is a base-12 pair grouping (144 → ~29 many-to-one), Finnish:

- in-sample −2.502 vs null −2.662 → `beats_null: true`
- held-out −3.192 vs null held-out −3.533 → `generalizes: true`
- rendered text `AITTEAHISTOTEMMENOÖKTTTESALAT...` — gibberish (heavy T/Ä/A, no
  words), not language.

### Why the gate is fooled (the methodological crux)

The matched null is a Fisher-Yates shuffle, which **destroys the `mod 3`
transition law**. The real stream keeps that law in *both* train and test folds,
so a many-to-one mapping fit on the train fold transfers to the test fold (it
"generalizes") and scores above the structure-free shuffle — without being
language. Two controls confirm the "signal" is the transition law, not English:

1. **Markov (transition-preserving) null** on the `s % 6` residue channel: the
   real channel beats the Fisher-Yates null at **z ≈ 6.0** but a first-order
   Markov null (which *preserves* the `mod 3` law) at only **z ≈ 0.7**. The signal
   is entirely first-order transition structure.
2. **The objective is the limit, not the null.** A first-order Markov null cannot
   be used as a gate: it preserves the bigram statistics that *are* the objective,
   so genuine English does not beat its own Markov null either (measured z ≈ −2
   to −0.7). **A bigram objective cannot distinguish a first-order transition law
   from first-order language signal.** Separating them requires a higher-order
   (trigram/quadgram) objective.

This is why **fractionation is off by default** (it projects the `mod 3` law onto
a clean channel and would add more such artifacts), and why `two`'s base-12
"survivors" are reported as artifacts rather than a decode. (The earlier committed
record showed 0 survivors only because of a since-fixed held-out-null comparison
bug that was over-strict; the corrected gate now passes these marginal artifacts.)

**Recommended follow-up:** a higher-order (quadgram) discriminator for codec-search
survivors — real language clears it, a first-order transition law does not. The
existing `attack/quadgram.rs` model is a starting point (A..Z; a Finnish quadgram
model would be needed too). Until then, codec-search survivors on
transition-structured ciphers must be read with the rendered text, not the gate
count alone.

## Provenance

Reproducible commands are embedded in each
`research/gak-threads/candidates/solve-{one,two,six}-*.md` record. Structural and
null-control figures above were produced out-of-engine (NumPy-style probes) and
cross-checked against the engine's own gates.
