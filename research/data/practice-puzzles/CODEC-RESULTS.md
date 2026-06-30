# Codec-search results — digit puzzles (one / two / six)

Attack on the small-alphabet *digit* puzzles, which a direct symbol→letter
substitution cannot carry (5 < 26, 12 < 26): they need the codec/transduction
layer to widen the alphabet first. As with the letter-puzzle battery
(`KEYSTREAM-RESULTS.md`), the result is **honest negatives** — and, for `two`, a
documented limitation of the matched-null gate itself.

> Honesty ceiling (binding): a high n-gram score (or "surviving the gates") is not
> a decode. Nothing here is a recovered message. The negatives are claims only
> about the codecs, mappings, and nulls actually searched.

## Headline

| Puzzle | Verdict | Notes |
| --- | --- | --- |
| `one` | honest negative (0 survivors) | now *testable* via the new binary-move codec; was 0 candidates before |
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

## `one` — honest negative

`solve --codec-search` now yields 12 evaluated candidates (cipher round-trip held);
**0 survive**. The top candidate is the binary-move codec
(`delta → project → base-32 group`):

- in-sample −2.063, matched null −2.075 → `beats_null: false`
- held-out −3.502, null held-out −3.483 → `generalizes: false`
- rendered text `THEHANDSHERSE...` — the *signature* of a many-to-one overfit: a
  32→29 search manufactures English-looking bigrams in-sample (above real English)
  that neither beat the null nor generalize. The gate correctly rejects it.

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
