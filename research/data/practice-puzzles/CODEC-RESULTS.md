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
| `two` | honest negative — gate "survivors" are **transition-law artifacts**, not decodes | exposes a bigram/Fisher-Yates gate blind spot (below); live attack surface as of 2026-07-01 — see §"`two` — rotor-carrier campaign" (pair-letter 4-class model) |
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
  > **REFINED (2026-07-01):** at the *pair-token* level this caveat does not
  > hold: non-overlapping eps-pair tokens carry an above-first-order
  > conditional-entropy drop that survives an order-1 Markov (transition- and
  > artifact-preserving) null at p = 0.025/0.005 — see §"`two` — rotor-carrier
  > campaign" below.

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

## `two` — rotor-carrier campaign (2026-07-01): deterministic-readout exclusions and the pair-letter 4-class model

> Post-`one`-solve transfer of the process lesson: exhaust cheap deterministic
> conventions before believing true hidden state, and treat the *transparent*
> channel as a message carrier in its own right, not only as a crib locator.
> Everything in this section is scratch-level (Python probes over the derived
> streams) unless it names an engine instrument; the campaign state and exact
> derivations live in `research/handoff/two-pairclass-attack.md`.

### Deterministic-readout exclusions (all honest negatives)

The rotor channel `r = symbol mod 3` is a clean ±1 walk on C3 (697 direction
bits `eps`). Attacks on it as a *direct* bit carrier, all negative:

- **`maskdecode` on the rotor walk** (the literal transfer of the `one` solve):
  416 cells (mask {static, alternating} × widths 5..8 × offsets × bit order ×
  polarity × direction) — **Negative**, best cell 57/98 letters. Coverage note:
  `maskdecode`'s gate is raw-ASCII letters/space, so `A=0..25`-style letter codes
  at widths 5-6 are structurally invisible to it; a scratch sweep of `A+v` maps
  (widths 4-8, same axes, plus alternating mask) found no cell above 90% valid
  either (width-4 "hits" are vacuous — every 4-bit value is < 26).
- **Morse / data-marker interleaves** of the direction bits (data bit on one
  parity, letter-boundary marker on the other; 16 conventions): high Morse
  validity is pareidolia (E/T spam), no language, no convention distinguished.
- **Fixed pair-token codebooks**: non-overlapping pair-token k-grams (k=2,3, all
  phases) populate 15-16/16 and 39-42/64 distinct values — no ≤26-value codebook;
  letters are not rigid 2- or 3-pair-token codes.
- **Deterministic periodic deck schedules, period ≤ 24** (extends `groupscan`'s
  constant-K test, which is the p=1 case): under a deterministic deck of period
  `p`, a full-plaintext repeat at an anchor forces `q_second = K_{phase mod p}
  (q_first)` — a phase-periodic family of permutation relations. Tested on all
  231 anchor sample pairs (five verified-exact anchors, below): real consistency
  is at or *below* a q-shuffled null's mean at **every** p in 1..24 (e.g. p=1:
  48/231 vs null mean 59; p=2: 45 vs 60). The deck channel has no deterministic
  schedule relation at the anchors; combined with `groupscan` + `ctakscan`, `q`
  is either genuinely plaintext-fed hidden state or not message-bearing at all.
  Scope: assumes the anchor spans repeat the full plaintext (true under the
  pair-letter model below); instrument not yet landed (scratch probe).

Anchor verification: all five `isoscan` anchors re-checked exact and maximal in
`eps` (231..298==351..418 len 68, 5..55==555..605 len 51, 352..392==506..546
len 41, 108..144==572..608 len 37, 22..55==108..141 len 34; extensions fail on
both sides).

### The structure findings (measured, gate-clearing)

- The eps stream's **only** periodicity is period 2 (phase-bias χ² = 49.6 on
  1 df; even steps 54.4% up, odd steps 28.2% up; no residual signal at p=3..32
  beyond period-2 inheritance).
- Non-overlapping eps *pairs* (348 tokens over {0..3}; phase-0 marginals
  107/51/143/47, IoC 0.301): within-pair bits are ~independent, but the token
  sequence carries real sequential structure. Conditional-entropy drops (plug-in):
  drop1 = 0.083 / drop2 = 0.251 bits (phase 0), 0.043 / 0.256 (phase 1), vs a
  marginal-preserving token-shuffle null (200 trials) drop1 max 0.065 / drop2 max
  0.175.
- **The load-bearing gate:** drop2 survives an order-1 Markov token resample
  (transition-preserving, 200 trials): **p = 0.025 (phase 0), p = 0.005
  (phase 1)**. The public 4-class channel carries **above-first-order sequential
  structure** that a transition-law artifact cannot produce. This supersedes, at
  the pair level, the earlier isoscan caveat that the free 4-class projection
  "lacks the conditional-entropy drop genuine English projection carries".
  Scope: the exact repeated anchor spans contribute to the above-null signal —
  they are plaintext repeats under any reading, but a crib-pinned Markov null
  (as in `rlcodec`) has not yet been run to isolate their share.
- No dedicated space class: reading any one token value as a word separator
  fails an English word-length fingerprint badly (best χ² ≈ 53 on 12 df, mean
  "word" length 6.6-7.2).

### The pair-letter model (hypothesis, clearly labeled)

**One plaintext letter per two ciphertext symbols** (~348-349 letters): each
letter fixes its eps pair (public) and its `q` pair (hidden behind the deck), so
the token stream is the image of the plaintext under an unknown 4-coloring of
the alphabet — a 348-letter, 4-class cryptogram attackable with zero deck
knowledge. Independent consistency points: exact period-2 eps bias =
letter-internal position statistics; within-pair independence; cross-pair
dependence = letter bigrams; **all five anchor gaps even** = letter-aligned
repeats; the Markov-gated drop2 above. The two stagger conventions (boundary
eps belonging to the preceding vs following letter) are exactly the two token
phases, so the phase sweep covers both. Under this model the anchors are
full-plaintext repeats, and the deck's non-repeat there says the deck hides the
`q` bits — consistent with the eye-wall reading of `groupscan`/`ctakscan`, but
no longer load-bearing for recovering the message.

### The 4-class cryptogram attack, round 1 (codex): UNDERPOWERED, not negative

Coloring hill-climb (100 restarts, 26- and 27-symbol models) maximizing the
projected class-4-gram likelihood (English stats from
`research/data/lang/english-corpus-large.txt`), gated on 50 order-1 Markov token
resamples. **The planted positive control is the result:** 0/6 held-out
348-char English plants through random 4-colorings clear p ≤ 0.05 (median z
0.14; coloring accuracy 0.42-0.66) — the search+gate has **measured power ≈ 0**
at this length, so the real-stream non-survivals (z: phase0-fwd 1.22, phase1-fwd
1.36, phase0-rev 0.84, phase1-rev 0.44; all p ≥ 0.137) are **uninformative**,
not an exclusion. Directional notes for the record: both forward streams score
above both reversed streams and above the control median; letters+space beats
letters-only on every stream. Unconstrained LM decodes are explicitly
non-candidates (readable-ish word salad, anchor-tie violations on the main
34-letter repeat).

Why the power is zero, and the escalation (arithmetic, not hope): the channel
preserves H ≈ 1.85 bits/char of the plaintext; an order-3/4 letter LM carries
~2.1 bits/char (negative margin — under-determined), while a word-level model
carries ~1.4-1.6 (positive margin), and the 54-bit coloring key amortizes to
0.16 bits/char over 348 chars.

### Round 2 (codex): joint word-aware decipherment — STILL UNDERPOWERED (controls-first stop)

Word-pattern lattice decoder with implicit segmentation; beam state carries the
partial coloring plus live repeated-span letter variables, with the anchor ties
enforced *during* decoding (phase 0: 59 tie groups removing 96 free positions;
phase 1: 61/97). Vocab 6,858 words / 132,660 training words from the in-repo
corpus, char-LM prefilter. **Controls-first result:** on 6 planted 348-letter
English controls with the anchor topology planted and enforced, mean coloring
accuracy 0.365 (chance 0.25, best 0.58), mean letter recovery **0.072** (max
0.103), 0/6 at the ≥0.5 bar — so per the mandated discipline the real streams
were **never scored** (the tie-topology assertions passed for both phases
before the stop). Two independent objectives now have measured power ≈ 0 on
plants at this length; the partial coloring signal exists but the letter-decode
stage fails. Caveat bounding the verdict: the vocab was small and the beam
budget fixed — a materially stronger word LM is the one untested classical
escalation. A round-3 diagnostic is the decisive next split: measure
**oracle-coloring decode power** (true coloring given) with an upgraded 50k
frequency-list LM — if even oracle decode fails on plants, the surface is
*decode-limited* (no coloring search can ever read it out at 348 tokens and the
honest close is the withheld-snippet external anchor); if oracle decode works,
the failure is the outer search and stronger search/LM still has room.

### Round 3 (codex): oracle diagnostic — NOT decode-limited; the wall is the coloring search

With the TRUE coloring given and a 50k OpenSubtitles frequency word LM (top 20k
used), plant letter recovery averages **0.534 with anchor ties** (six plants:
0.704/0.586/0.537/0.509/0.468/0.397, all tie-consistent) and 0.569 without ties
(two plants) — above the 0.5 bar, with substantially readable output. **The
4-class channel at 348 tokens is readable in principle; the campaign is not
decode-limited and the external-anchor escalation is not yet forced.** Stage B
(unknown coloring) still failed controls (recovery 0.059, coloring accuracy
0.302) — but at a visibly tiny budget (10 restarts × 16 anneal moves over a
4^26 space, narrow beam). Two more calibration facts: oracle scores sit well
above found-coloring scores on the same plants, so the objective *separates*
true colorings from found ones — the search simply isn't reaching them; and
ties help the inner decode little (0.534 vs 0.569), so the anchors' value is in
constraining/scoring the *outer* search. Round 4 (below) scaled the outer
search accordingly.

### Round 4 (codex): scaled coloring search — search-still-failing-at-scale

The outer search was scaled to a real budget: exhaustive 4^8 structured seeding
over the top-8 letters with greedy completion, 112 restarts × 1000 annealing
moves, 16 worker processes, score caching, an anchor-span LM bonus in the cheap
objective, and the round-3 inner decode (20k-word LM, `word_beam=180`) for
final rescoring (~2h16m wall). **Controls-first stop fired: mean plant letter
recovery 0.133 (bar ≥0.4; oracle ceiling 0.534), mean coloring accuracy 0.432.
Real streams were never scored.** Verdict: **search-still-failing-at-scale** —
more of the same annealing is not a justified path to a candidate.

The per-plant table carries the campaign's sharpest remaining diagnostic: the
best control reached coloring accuracy **0.730** yet only **0.221** letter
recovery, versus 0.534 at accuracy 1.0 (round-3 oracle). Decode quality falls
off a cliff within ~7 wrong letters of the true coloring, so the objective
gives annealing almost no gradient in exactly the region it must traverse —
scale alone cannot fix that. What's left classically is a qualitatively
different searcher (CSP/branch-and-bound over the coloring with word-lattice
constraint propagation, where the anchor ties prune exactly); failing that, the
honest close for `two` is the withheld-snippet external anchor (under the
pair-letter model a ~10-letter crib pins classes directly, and the 34-letter
repeated phrase amplifies it across ~40% of the text). Round-4 details:
`round4-results.json` / FINDINGS.md §Round 4 in the scratch dir (see
`research/handoff/two-pairclass-attack.md`).

### Rounds 5/5b (codex): exact CSP beam search — truth beam-pruned at the string head; left-to-right ordering excluded

The CSP escalation was built as designed: dictionary-propagation search over the
348 letter positions through a word trie, coloring induced incrementally with
backtracking on class conflicts, anchor ties as hard letter equalities. Round 5
ran it at a token budget (beam ≤420, ~1 min/plant) — its negative (recovery
0.060) was rejected as underpowered, the round-3-Stage-B trap. Round 5b re-ran
it at the real budget (iterative beams 1k/5k/20k, 1000 candidates/position, 16
workers) and was **interrupted by host OOM** after 3 of 6 controls (the beam-20k
stage peaked near ~11 GB RSS and took the container down; ~65-75 min/control).

The three measured controls are nonetheless decisive on the attribution the
round existed to make: the true path was **BEAM-PRUNED, never out-scored** — at
positions 10 / 9 / 4 of 348, with only 1-2 truth-consistent states alive at the
cut, and the prune position essentially does not move with beam width (420 →
20,000). At the string head there is no accumulated coloring/tie evidence, so
the truth's prefix ranks below tens of thousands of locally-likelier word
starts; truth only becomes distinguishable after long-range pins accumulate,
which a left-to-right beam never survives to see. Beam growth is the wrong
axis — the required width at the head is plausibly exponential in the ambiguous
prefix length.

**Crib-free ledger after rounds 1-5b:** score-guided local search over
colorings fails (objective cliffs near truth, no gradient — round 4);
left-to-right exact beam fails (truth pruned at the head regardless of width —
round 5b); the inner decode is NOT the problem (oracle 0.534, readable — round
3). The one untried classical idea is changing the *search order*:
constraint-density-first (start inside the tied spans — the 34-letter repeated
phrase is doubly constrained — and expand outward), or branch-and-bound over
the coloring with an admissible bound. Resource reality: these runs cost
multi-hour, ~11 GB attempts on this host and have crashed the container twice;
further rounds need hard memory caps and maintainer sign-off. The alternative
close remains the withheld-snippet anchor. Partial data:
`round5b-results.json` + `round5b-progress.json` in the scratch dir (no
FINDINGS §5b was written — the run died first); RESUME-NOTES.md there records
the crash forensics.

### The `pairclass` instrument (Rust): the campaign tool, memory-bounded by construction

The round-5 CSP was ported from the discarded scratch Python into a persistent,
file-driven CLI instrument — `pairclass` (`src/attack/pairclass/`, commit
`0a9111a`) — so the capability survives and the OOM that killed rounds 5b is
structurally impossible. The port keeps the same algorithm (residue-walk pair
tokens → tie anchors → dictionary beam with incremental coloring induction and
hard tie equalities → truth tracking that reports BEAM-PRUNED vs OUT-SCORED)
and adds the fix the Python lacked: candidate expansions stream through a
bounded top-K heap (never more than `beam` survivors) and the solver estimates
its peak up front and refuses to start past `--max-mem-mib`. The Python
beam-20k worker that peaked at ~11 GB is a ~6 MiB run here at the same
expansion count. It self-validates (`pairclass --self-test`: planted positive
recovery 1.0, matched Markov null, forced-prune instrumentation, walk gate, the
embedded-`two` regression) and reproduces the campaign result exactly — at a
small beam the controls fail the 0.4 bar with truth BEAM-PRUNED at the string
head, and controls-first refuses to score the real stream:

```sh
# derivation only (embedded two): 348 tokens, marginals [107,51,143,47],
# the 33-token phase-0 repeat run at token positions 116 == 176
cargo run -q -- pairclass
# controls-first power measurement + real solve behind a passing bar:
cargo run -q -- pairclass --wordlist <freq-list> --plant-text-file <english> \
  --plants 6 --beam 20000 --null-trials 10 --max-mem-mib 4096
```

This is the vehicle for the remaining live fork (search-order change): the
memory bound means a middle-out / constraint-density-first expansion order can
now be tried at full beam without risking the host. The Rust port is *equal*
to the Python at left-to-right ordering (same BEAM-PRUNED verdict), so it does
not by itself reopen the crib-free result — it makes the next experiment safe
and cheap to run.

### Round 6 (codex): anchor-seeded two-phase search — original verdict corrected after window-boundary bug

The approved search-order fork was implemented in `pairclass` as an
anchor-seeded two-phase mode:

- Phase 1 harvests distinct 26-slot colorings from a window spanning *both*
  occurrences of the longest token tie, with the local tie equalities active.
- Phase 2 runs the existing full-stream solver once per harvested coloring,
  pre-pinning letter classes through `SolveInput.seed_coloring`.
- The same library path powers the CLI and tests; `pairclass --self-test` now
  includes an anchor mechanism leg: truth coloring as a seed reproduces the
  oracle decode, and a mid-word harvest window surfaces truth.

**Correction:** the first round-6 record was confounded. A cross-family audit
found that the phrase harvest reused full-stream final-state semantics: a
harvest window ending inside a word was dropped unless the final state ended a
gap or a complete lexicon word. That made `truth_seed_rank = None` a possible
window-boundary artifact, not evidence for score-pruning/LM label-bias. The
old mean recovery 0.064 / mean coloring 0.268 table is retained only in git
history; do not use its "saturated + not harvested => label-bias" verdict as a
finding.

The fix is harvest-only: `SolveInput.accept_partial_final = true` for Phase 1
accepts interior trie nodes as valid coloring sources without adding a final
word bonus. Full-stream decodes remain strict. Plant harvests now also track
truth's *window* fate before Phase 2, distinguishing `BEAM-PRUNED`,
`INFEASIBLE`, and survived-but-not-harvested cases.

Self-test command:

```sh
cargo run -q -- pairclass --self-test
```

Headline output:

```text
anchor-seed mechanism (oracle 1.000, midword truth-seed #1, harvest 1, occupancy 4 open): PASS
SELF-TEST: PASS
```

The requested serious control gate was then run with the 12 GiB memory cap,
phrase beam 1,000,000, phrase top 5,000, and full beam 20,000. The lexicon was
derived from the committed public-domain corpus
`research/data/lang/english-corpus-large.txt`; it contains exactly that corpus's
11,419 distinct words, so corpus-sourced plant controls have no lexicon-coverage
confound. A larger downloadable English frequency list would only sharpen a
future REAL-stream power number; it is not a blocker or a held maintainer
resource.

```sh
LC_ALL=C tr -cs 'A-Za-z' '\n' < research/data/lang/english-corpus-large.txt \
  | tr '[:upper:]' '[:lower:]' \
  | awk 'NF { count[$1]++ } END { for (word in count) print word, count[word] }' \
  | sort -k2,2nr -k1,1 > /tmp/pairclass-english-unigram.txt

cargo run --release -q -- pairclass --anchor-seed \
  --wordlist /tmp/pairclass-english-unigram.txt --vocab-cap 50000 \
  --plant-text-file research/data/lang/english-corpus-large.txt --plants 6 \
  --phrase-beam 1000000 --phrase-top 5000 --beam 20000 \
  --plant-bar 0.5 --max-mem-mib 12288 --null-trials 20
```

The corrected controls failed before any real-stream scoring, as required:

```text
Controls-first anchor power (6 plants, bar 0.500):
  plant  0: recovery 0.069  coloring 0.348  truth-seed not-harvested  window truth BEAM-PRUNED @ pos 24 (-25.9 < cutoff -25.0)  harvest 381 seeds 381  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 0
  plant  1: recovery 0.037  coloring 0.182  truth-seed not-harvested  window truth BEAM-PRUNED @ pos 5 (-12.6 < cutoff -7.2)  harvest 241 seeds 241  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 0
  plant  2: recovery 0.190  coloring 0.320  truth-seed not-harvested  window truth INFEASIBLE @ pos 6  harvest 288 seeds 288  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 1
  plant  3: recovery 0.043  coloring 0.217  truth-seed not-harvested  window truth INFEASIBLE @ pos 5  harvest 137 seeds 137  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 1
  plant  4: recovery 0.046  coloring 0.091  truth-seed not-harvested  window truth BEAM-PRUNED @ pos 6 (-10.7 < cutoff -7.2)  harvest 261 seeds 261  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 0
  plant  5: recovery 0.040  coloring 0.273  truth-seed not-harvested  window truth INFEASIBLE @ pos 5  harvest 269 seeds 269  occupancy 1000000/1000000 SATURATED  full truth INFEASIBLE @ pos 0
  mean recovery 0.071  mean coloring 0.238  BELOW BAR

VERDICT: ControlsFailed — mean plant recovery 0.071 < bar 0.500; the real stream was NOT scored (controls-first). ladder: mixed truth-window failures; coverage/gap/lexicon limits and score-pruning/LM label-bias.
```

Interpretation: after fixing the trailing window boundary, the two-occurrence
window is now a fairer test, and it still fails the controls under this
11,419-word LM/gap policy. The clean attribution is mixed: three plants are
truth-window infeasible by positions 5-6 (coverage/gap/lexicon limit), and
three are truth-window beam-pruned despite a saturated million-state phrase
beam (score-pruning/LM label-bias). The real stream was not scored and the
requested null gate therefore did not run. This is not evidence for a `two`
plaintext.

The next classical lever is not simply "more phrase beam": avoid score-ranking
the phrase harvest itself by enumerating/ranking class-signatures plus internal
repeat patterns across both tied occurrences, or use branch-and-bound over
colorings with a bound that cannot evict the true phrase before constraints
arrive.

### Round 7 (codex, audit-corrected): LM-free complete-DP anchor-window harvest — measured occ1 saturation, real stream NOT scored

This replaces the confounded Round 7 record in place. Credit to the independent
audit: v1 was a non-merging exponential DFS, and v2 was still confounded by
**both** (1) an exponential `DpKey.tie_letters` augmentation that carried occ1's
letter sequence through the main DP and (2) a 10k/layer coverage frontier that
was a beam and could evict truth. Do not cite either earlier Round 7 outcome as
a retention or tractability finding.

The corrected (a') harvest mode remains `--harvest-mode enumerate`, alongside
the existing score-beam harvest. This run used the reformulation's recommended
variant B: enumerate the full anchor window with occ2 parsed as ordinary
dictionary tokens, merge completely on `(node, gap_len, gaps_used, gap_node,
classes, pinned)`, and then post-filter each surviving coloring against the
full active tie exactly. The post-filter carries source letters only inside the
verifier and requires the tied parse to induce the same 26-slot coloring. There
is no coverage beam and no final coloring cap/eviction in the enumerate
collector.

The trie is used for membership only (`word_logp` is only the word-end
predicate). Leading partials are constrained as lexicon-word suffixes, trailing
partials are accepted as trie prefixes, and the run is harvest-only /
controls-first: no Phase-2 seeded solve, no real `two` scoring, no null. This is
still a bounded instrument: if the complete DP hits its deterministic transition
budget, the result is saturation, not an exhaustive anchor-negative. The
enumeration is over one anchor window, not `4^26`; classes are assigned only
through lexicon-compatible letters, and the control plants are corpus-sourced
and fully in-vocab (the 11,419-word lexicon is the full corpus vocabulary; there
is no maintainer-held 50k list).

The 2026-07-02 measurement instrument records `max_occupancy`,
`saturation_position`, the last completed layer width at saturation, the partial
next-layer width already built when the parse budget was first hit, and the
observed occ1 layer widths. `saturation_position < span_len` means the complete
DP saturated during occ1, before occ2 and before the active tie can matter.

Command:

```sh
LC_ALL=C tr -cs 'A-Za-z' '\n' < research/data/lang/english-corpus-large.txt \
  | tr '[:upper:]' '[:lower:]' \
  | awk 'NF { count[$1]++ } END { for (word in count) print word, count[word] }' \
  | sort -k2,2nr -k1,1 > /tmp/pairclass-english-unigram.txt

cargo run --release --locked -q -- pairclass --anchor-seed \
  --harvest-mode enumerate --harvest-only \
  --wordlist /tmp/pairclass-english-unigram.txt --vocab-cap 50000 \
  --plant-text-file research/data/lang/english-corpus-large.txt --plants 6 \
  --phrase-beam 1000000 --phrase-top 50000 --beam 20000 \
  --plant-bar 0.5 --max-mem-mib 12288 --null-trials 20

cargo run --release --locked -q -- pairclass --anchor-seed \
  --harvest-mode enumerate --harvest-only \
  --wordlist /tmp/pairclass-english-unigram.txt --vocab-cap 50000 \
  --phrase-beam 1000000 --phrase-top 50000 --beam 20000 \
  --plant-bar 0.5 --max-mem-mib 12288 --null-trials 20
```

Controls-first retention measurement:

| plant | truth retained? | finals | window | span | saturation position | in occ1? | max occupancy | completed width | partial width | cap hit? | budget hit? |
|---:|:---:|---:|---:|---:|---:|:---:|---:|---:|---:|:---:|:---:|
| 0 | no | 0 | 149 | 33 | 5 | yes | 44,588,006 | 6,266,925 | 44,588,006 | no | yes |
| 1 | no | 0 | 149 | 33 | 5 | yes | 71,298,092 | 9,368,690 | 71,298,092 | no | yes |
| 2 | no | 0 | 149 | 33 | 5 | yes | 49,654,147 | 7,277,930 | 49,654,147 | no | yes |
| 3 | no | 0 | 149 | 33 | 5 | yes | 49,766,212 | 7,357,363 | 49,766,212 | no | yes |
| 4 | no | 0 | 149 | 33 | 6 | yes | 47,303,303 | 47,303,303 | 9,514,561 | no | yes |
| 5 | no | 0 | 149 | 33 | 5 | yes | 64,178,437 | 8,831,754 | 64,178,437 | no | yes |

Observed occ1 layer widths before saturation:

| case | widths |
|---:|---|
| plant 0 | 0:1, 1:52, 2:1,867, 3:41,252, 4:603,185, 5:6,266,925 |
| plant 1 | 0:1, 1:52, 2:1,867, 3:41,043, 4:568,670, 5:9,368,690 |
| plant 2 | 0:1, 1:52, 2:1,867, 3:41,043, 4:594,197, 5:7,277,930 |
| plant 3 | 0:1, 1:52, 2:1,867, 3:41,252, 4:615,142, 5:7,357,363 |
| plant 4 | 0:1, 1:52, 2:1,938, 3:30,570, 4:308,334, 5:4,085,324, 6:47,303,303 |
| plant 5 | 0:1, 1:52, 2:1,938, 3:29,792, 4:488,363, 5:8,831,754 |

Real `two` harvest-only measurement:

| case | finals | window | span | saturation position | in occ1? | max occupancy | completed width | partial width | cap hit? | budget hit? |
|---|---:|---:|---:|---:|:---:|---:|---:|---:|:---:|:---:|
| real two | 0 | 93 | 33 | 5 | yes | 86,172,847 | 8,987,580 | 86,172,847 | no | yes |

Observed real occ1 layer widths before saturation: 0:1, 1:52, 2:1,867,
3:41,043, 4:568,670, 5:8,987,580.

Verdict: `HarvestSaturatedMiss`, specifically **complete-DP transition
saturation inside occ1 before finals**, not a decisive retention fork and not a
genuine anchor-negative. All six controls and the real `two` window hit the
100,000,000-transition budget before the complete un-beamed enumeration produced
final colorings for the exact post-filter to retain or reject. Therefore "truth
not retained" here means "truth not reached before honest saturation," not
"truth absent from the complete tied coloring set."

The dispositive number is the saturation position: 5 for five controls and the
real window, 6 for the remaining control, with `span_len = 33` in every case.
The observed peak layer width is already inside occ1; for plant 4 the completed
position-6 layer itself is the peak, and for the others the partial position-5
next layer is the peak seen at budget exhaustion. Occ1 is free dictionary text
in any complete formulation because its letters must be discovered before occ2
can be tied or verified. This generalizes the bounded-tractability result beyond
variant B: a tie-aware formulation cannot avoid the measured occ1 state-space
explosion, and a modestly larger budget will not reach the end of the
33-token free span. The real stream was harvested only; it was NOT scored and no
null ran.

Next work, if (a') remains worth pursuing: change the hard-constraint surface or
selection goal without reintroducing a beam or score key, for example
flanking-context widening or LM-free marginal-fit selection after a complete
superset exists. Do not revive the v2 coverage frontier or word-LM ranking as a
harvest selector.

**Reframe (2026-07-02) — the search walls may be the wrong problem's difficulty.**
Rounds 1–7 all measured coloring-*search* difficulty on **random-coloring
plants**, but the real coloring is a C3-rotor *codec artifact* — a deterministic
per-letter map that may be simple (the `one` lesson; the wiki's "structured, not
random" key evidence and its `p = c⁻¹` hand-puzzle convention). If so, the walls
do not apply: enumerate the convention and oracle-decode (`two` is NOT
decode-limited). The ranked untried levers — structured-coloring enumeration
(build first), a repeated-span pattern-crib scan, soft-coloring EM, a
demoted-to-filter moment matcher, an external-solver QAP variant, and the codec
round-trip as verifier — are laid out with a two-model consult record in
`research/handoff/two-fresh-avenues.md`.

### Round 8 (codex + claude orchestration, 2026-07-03): Avenue A — structured-coloring enumeration; instrument hardening and the controls redesign

Avenue A from `research/handoff/two-fresh-avenues.md` was built into `pairclass`
as `--coloring-family` (structured mode): enumerate deterministic 26→4 coloring
families (rank/Gray/affine bit projections, ASCII variants, historical 5-bit
codes, simple partitions, keyword-permuted alphabets; ×4 stream variants ×
relabels), oracle-decode every candidate, controls-first. Getting the instrument
to an honestly runnable state took three measured failures, each of which is a
result in its own right:

1. **Two-tier decode (commits `3cfbafd`, `fc3cbb2`).** A full-beam decode of the
   whole family at every control stage projected to ~200 h. Fix: all gate
   statistics (positives, random negatives, nulls, real ranking, verdict) are
   computed on one consistent rank-beam surface (`--structured-rank-beam`,
   default 400); the full `--beam` (20000) is confirm-rendering only for the
   top-K. If the rank beam is too weak to surface truth, the positive control
   fails honestly. A review round hardened the gate: every plant's truth must
   decode at rank-beam (a silently dropped truth ⇒ `ControlsFailed`).
   Calibration (`--plants 1 --null-trials 1`, 384 extras): positive fired
   (recovery 0.635, truth decoded), random negative quiet, real stream best
   −532.41 vs random-negative best −504.52 ⇒ `NullArtifact`, ~24 min wall.
2. **Relabel-level coverage hole (commit `15ffaf6`).** The 6-plant run failed
   with 3/6 planted truths *not enumerated*: plants draw (base, relabel) from
   the full family, but the decode set guaranteed only each base's best-L1
   relabel + budget extras, and at N=348 the marginal-L1 ranking of relabels is
   noise-dominated (measured: winning relabels at L1 0.056–0.148 vs truth at
   0.116–0.196). Fix: a guaranteed near-best relabel band per base (top
   marginal-pass relabels + just-over-threshold within `13/N` L1 and +9.0 χ²,
   calibrated on the failing plants).
3. **The gate architecture itself was unsound (measured 2026-07-03).** With
   coverage fixed, all six positives fired by recovery (mean 0.584) — but the
   random-coloring negative fired 6/6: junk best-of-family scores on truth-free
   streams (−486..−543) all cleared the positives' cross-stream score floor
   (−555.62). Two load-bearing findings: (a) **absolute LM scores are not
   comparable across streams** (each stream has its own junk-fit level), so any
   positive-floor-vs-other-stream gate is unsound by construction; (b) at the
   broadened family size (~23k decoded colorings/stream), **the max over junk
   colorings outscored planted truth within-stream in 3/6 plants** —
   multiple-comparisons swamping caps score-ranking power at ~50 % at this
   breadth. (The pre-broadening ~1.5k family had truth best-of-family in the
   one measured plant.)

**Controls redesign (commits `91c3ba3`, `9ced20a`), two-model consult record:**
codex (`gpt-5.5` xhigh, resumed instrument session) and Gemini 3.1 Pro (copilot
consult) independently converged on: remove every cross-stream score
comparison; judge each stream only against matched order-1 Markov nulls of that
stream run through the *identical* candidate surface (add-one empirical
`p_emp = (null_ge+1)/(k+1)`); split the attack into a **curated primary tier**
(pre-broadening family as `--coloring-family core-curated`; 6 plants ×19 nulls,
per-plant p ≤ 0.05 + truth top-3 + recovery ≥ bar ⇒ POWERED; 3 negatives ×19;
real ×49 nulls, `Candidate` iff p ≤ 0.02) and a **broad coverage tier** (`core`,
~23k surface; 6 plants ×2 nulls as measured-power report, 6 negatives ×2, real
×20 nulls, `Candidate` iff `null_ge==0`). Verdict vocabulary:
`Candidate / NoCandidate / LowPowerNoExclusion / ControlsFailed`; a broad
negative is always reported with its measured power, never as family exclusion.
A statistical-wiring review caught two P1s before the definitive runs (nulls
decoding per-variant got a wider extras surface than the observed stream;
curated low-power short-circuited to `ControlsFailed` instead of scoring the
real stream and capping the claim at `LowPowerNoExclusion`).

Wordlist derivation and both definitive invocations:

```sh
LC_ALL=C tr -cs 'A-Za-z' '\n' < research/data/lang/english-corpus-large.txt \
  | tr '[:upper:]' '[:lower:]' \
  | awk 'NF { count[$1]++ } END { for (word in count) print word, count[word] }' \
  | sort -k2,2nr -k1,1 > /tmp/pairclass-english-unigram.txt

# curated primary tier
cargo run --release --locked -q -- pairclass \
  --wordlist /tmp/pairclass-english-unigram.txt --vocab-cap 50000 \
  --plant-text-file research/data/lang/english-corpus-large.txt \
  --coloring-family core-curated --plants 6 --negative-controls 3 \
  --control-null-trials 19 --null-trials 49 --plant-bar 0.4 \
  --structured-rank-beam 400 --structured-marginal-l1 0.16 \
  --structured-max-decodes 384 --beam 20000 --top 5 --max-mem-mib 12288

# broad coverage tier
cargo run --release --locked -q -- pairclass \
  --wordlist /tmp/pairclass-english-unigram.txt --vocab-cap 50000 \
  --plant-text-file research/data/lang/english-corpus-large.txt \
  --coloring-family core --plants 6 --negative-controls 6 \
  --control-null-trials 2 --null-trials 20 --plant-bar 0.4 \
  --structured-rank-beam 400 --structured-marginal-l1 0.16 \
  --structured-max-decodes 4096 --beam 20000 --top 5 --max-mem-mib 12288
```

**Definitive run results: PENDING (runs in flight 2026-07-03).** This entry is
committed before the verdicts so the instrument-hardening findings survive the
session; the verdicts and their honest claim ceilings will be appended when the
runs complete.

## Provenance

Reproducible commands are embedded in each
`research/gak-threads/candidates/solve-{one,two,six}-*.md` record. Structural and
null-control figures above were produced out-of-engine (NumPy-style probes) and
cross-checked against the engine's own gates. The 2026-07-01 `two`
rotor-carrier campaign figures are scratch probes recorded in
`research/handoff/two-pairclass-attack.md` (with exact stream derivations);
the `maskdecode` rotor run is engine-reproducible:

```sh
python3 - <<'EOF'  # derive the rotor stream
s = open('research/data/practice-puzzles/two').read().strip()
print(''.join(str((ord(c)-ord('A'))%3) for c in s), end='')
EOF
# then: cargo run -q -- maskdecode --input-file <rotor-stream> --alphabet 012
```
