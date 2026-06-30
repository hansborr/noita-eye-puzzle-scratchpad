# The Toboter predicate battery + multiple-comparisons meta-analysis (Thread C)

**Status:** file-driven, self-validated structural instrument; every per-predicate
p below is **recomputed** by the tool against the repo's `SplitMix64` matched
nulls, not the community's self-reported number.
**Claim ceiling:** the **meta-analysis is the deliverable**, not any single
predicate. A surviving predicate is a structural discriminator over the value
stream, **never recovered plaintext**. Every number is conditional on the accepted
honeycomb reading order. The eyes remain unsolved.
**Code:** `src/analysis/predicates/` (library) + the `predscan` CLI subcommand
(`src/cli/commands/predscan.rs`). Reproduce:

```sh
cargo run -q -- predscan            # eye corpus, accepted honeycomb order
cargo run -q -- predscan --self-test   # planted controls + both null shapes
```

---

## 1. What it measures

Community analysts (Toboter and others, ingested firsthand in
`community-docs-firsthand-digest.md` §5) listed ~6 arithmetic "surprising facts"
about the 83-symbol / 1036-trigram eye messages, several with a self-reported
chance probability. Thread C recomputes each against the repo's own matched null
and then runs the multiple-comparisons meta-analysis the community write-ups omit:
**given how many predicates were tested, how many "hits" would chance produce, and
which survive a family-wise correction?**

The five battery predicates (all operating on the per-message reading **value**
streams; the two deferred predicates are noted in §5):

| id | predicate | null shape | community claim |
| --- | --- | --- | --- |
| **a** | only missing recurrence-gap size is 1 **[strong]** | within-message shuffle | load-bearing `[likely]`; rules out `(char + N·pos) mod 83` |
| b | all starting trigrams > 26 | value-resample | stated regularity (Työskentely Juho) |
| c | decimal trigram-sum has `abab` shape (4040/5656/4545) | value-resample | 3 of 9 (E1/E3/E5) (SaltyOutcome) |
| d | no trigram-sum has a two-digit prime factor | value-resample | ~0.4% by chance (Toboter) |
| e | no message's first two trigrams have gcd 1 | value-resample | ~6.5% (Naugam) |

**Two null shapes, one per family (the load-bearing methodological choice).**
- Predicate (a) is an order/gap predicate: its correct surrogate is exactly "keep
  the multiset, destroy the order" — a **within-message Fisher-Yates shuffle**
  (`nulls::null::WithinMessageShuffle`). (This is *not* the prohibited
  Fisher-Yates-for-isomorph-significance: a shuffle is the textbook null for a gap
  predicate.)
- Predicates (b)-(e) are **shuffle-invariant** (a permutation does not change a
  sum, a magnitude, or a coprimality of the first pair), so a shuffle null would
  give a degenerate p. They are scored against a **pooled value-resample** null
  (`nulls::null::random_index_below` over the pooled empirical multiset, message
  lengths matched), which makes each surrogate's sums/values genuinely change while
  preserving the corpus's marginal value distribution (hence matched sum
  magnitudes).

Each predicate maps a draw to a `usize` statistic whose **upper tail is the
surprising direction**; the empirical p is the add-one estimator
`(hits + 1)/(trials + 1)` (`nulls::null::add_one_p_value`).

### The strong predicate (a), stated honestly

The literal community phrasing "the only missing gap size is 1" does **not**
reproduce over the full realized range: under the accepted order the realized
recurrence distances run contiguously `2..=36` but the large-distance tail thins
out (full missing set `{1, 37, 69, 74, 85, …, 111}` over `1..=114`), which is
expected — few value pairs sit at huge distances. The genuinely testable
discriminant is the **only-1-missing run length** `M`: the largest `m` for which
`missing_gap_sizes(.., m) == {1}` (distance 1 — a doubled trigram — absent, and
every distance `2..=m` realized). On the corpus **M = 36**. This is what rules out
the `(char + N·pos) mod 83` family: that family recurs only at multiples of 83, so
it could never produce a dense contiguous low-gap run with no doubles. The shared
gap primitive `missing_gap_sizes()` (`src/analysis/predicates/mod.rs`) is built
directly on `orders::count_message_recurrence`, extended well past the `OrderStats`
`d ≤ 6` cap, and is the primitive a future `modscan` (Thread D) will consume.

---

## 2. Results on the eye corpus (recomputed)

Accepted honeycomb order `standard36-u012-d012`, alphabet 83, seed
`0x707265647363616e`, shuffle null 1000 trials, resample null 5000 trials. All
`[order-conditional]`.

| id | observed | holds | **recomputed p** | community # | Bonferroni (K=5) | survives FWER 0.05 | robust to K ≤ |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **a** | run M=36 | yes | **0.00100** | (qualitative) | 0.00500 | **yes** | ~50 |
| b | 9/9 | yes | 0.02400 | — | 0.11998 | **no** | ~2 |
| c | 3/9 | yes | 0.00020 | 3 of 9 | 0.00100 | yes | ~250 |
| d | 9/9 | yes | 0.00280 | ~0.4% | 0.01400 | yes | ~17 |
| e | 9/9 | yes | 0.00060 | ~6.5% | 0.00300 | yes | ~83 |

Notes on the recomputation (the point of Thread C — trust the null, not the
report):
- (d) reproduces Toboter's ~0.4% closely (recomputed 0.28%).
- (e)'s recomputed p (0.06%) is **~100× more significant** than the community's
  ~6.5% — under the actual pooled values (which include 0, with `gcd(0,x)=x`), all
  nine first-pairs being non-coprime is rarer than the community model assumed.
- (b) is genuinely mild (p ≈ 0.024) and is the one predicate that **fails** the
  family-wise correction even at the optimistic K=5.

### The meta-analysis (the deliverable)

```
K predicates tested:          5   — a LOWER BOUND (see §3)
expected survivors  Σ pₖ:     0.0286
observed hits (claim holds):  5 of 5
survive Bonferroni @ 0.05:    a, c, d, e
survive Šidák @ 0.05:         a, c, d, e
```

So at the **lower-bound** K=5, four of five predicates survive and the expected
number of chance survivors is ≈0.03 — i.e. five hits is far more than chance *if 5
is the true family size*. It is not.

---

## 3. Honesty / caveats (binding)

1. **K=5 is a lower bound, and that is the whole story.** The ~5-6 predicates are
   the *survivors* of a much larger **undisclosed** search — the digest's
   dead-end catalog (`community-docs-firsthand-digest.md` §6 and the ruled-out
   modular forms in §5). The true K (hence the correction) is materially larger
   than 5. The report prints each predicate's **`alpha/p` = the largest K at which
   it still clears Bonferroni**: (a) survives to K≈50, (c) to ≈250, (e) to ≈83,
   (d) only to ≈17, (b) to ≈2. At a realistic true K the harsher correction
   removes the weaker predicates first; (b) is already gone, and (d) goes next.
2. **Individually-weak predicates are NOT findings.** Even though (c)/(d)/(e) have
   low nominal p and clear K=5, they are individually-cherry-picked facts pulled
   from that larger search and are **not reported as standalone findings**. Only
   (a) pairs a low p with an **independent mechanistic rationale** (it excludes an
   entire cipher family), which is why it is the one defensible discriminant.
3. **Circularity on (a).** The gap structure is the *same* property family that
   selected the accepted reading order, so (a)'s uniqueness/significance is order-
   and plaintext-model-conditional (`03-confirmed-vs-speculation.md:161`). Its p is
   "strong **under** the accepted order," not raw-order fact.
4. **Order-conditional throughout.** On the raw stored order the no-doubles and
   gap structure do not hold; the entire quantitative block is conditional on the
   community-inferred (not developer-confirmed) honeycomb reading.

---

## 4. Self-test (controls)

`predscan --self-test` (10 controls, both null shapes). For every predicate it
plants a surrogate **forced** to satisfy the predicate (a gap set planted as
exactly `{1}` missing; sums coerced to `abab` / two-digit-prime-free targets;
first-pairs coerced non-coprime) and confirms detection at low p, plus a matched
**non-satisfying** control (an injected doubled trigram, low starts, non-`abab`
sums, prime-factored sums, coprime first-pairs) that the detector must leave
un-flagged at high p. The controls call the same library functions the CLI's
battery calls, exercised through `#[cfg(test)]` in
`src/analysis/predicates/tests.rs`.

---

## 5. Deferred (next steps, not built)

- **Dr Cats**: "for all messages except West 4, the first eye is one greater than
  the second eye of the following message in internal order" — this is an
  **orientation-layer** relation, not a value-stream predicate, so it needs a
  different substrate.
- **Toboter**: "16 trigrams with no trigram that only occurs after them" vs an
  expected ~8 — a successor-graph predicate; better fitted to the
  `conditional`/`chaining-graph` instruments than to this arithmetic battery.

---

## 6. One-line read

Under the repo's own matched nulls, **only the gap predicate (a) is a defensible
discriminant** — a strong (p≈0.001), order-conditional, mechanistically-grounded
"no doubles + dense low-gap run" that excludes the `(char + N·pos) mod 83` family;
the arithmetic predicates (b)-(e) are survivors of a larger undisclosed search
whose apparent significance is an artifact of multiple comparisons, and the
meta-analysis exists precisely to say so.
