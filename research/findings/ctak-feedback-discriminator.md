# The ciphertext-autokey (feedback) deck discriminator

**Status:** file-driven, self-validated structural instrument; the practice-puzzle
verdict below is computed by the tool, not hand-transcribed.
**Claim ceiling:** a verdict is a **structural discriminator over the
feedback-deck family, never recovered plaintext.** A positive recovers the deck
*mechanism* (an advance map reproducing the crib), not language — the digit→letter
codec is a separate unknown. The eyes remain unsolved.
**Code:** `src/analysis/ctak_feedback/` (library) + the `ctakscan` CLI subcommand
(`src/cli/commands/ctakscan.rs`). Reproduce: `cargo run -q -- ctakscan --self-test`.

---

## 1. The boundary this closes

`groupscan` (`group_order/`) and `keydiff` (`key_difference/`) both assume a
**passive deck**: between two occurrences of a repeated plaintext span the deck
differs by one *constant* group element `K`. That premise holds only for
**plaintext-autokey** (the deck advances on the recovered plaintext symbol). Their
robust verdicts on real `two` — `NoDeckSignal` and *constant-Δ plaintext-autokey
excluded* — therefore leave exactly one regime untested, the one
the earlier passive-deck analysis, now summarized in `CODEC-RESULTS.md` §`two`,
flagged:

> **ciphertext-autokey** — the deck advance is keyed on the *emitted ciphertext*,
> not the plaintext. There no readout exposes a constant `K`, so the passive-deck
> instruments' positive-control premise collapses.

This instrument settles that regime.

## 2. Why feedback is attackable, and the codec-free statistic

Under ciphertext-autokey the deck trajectory is **computable from the observed
ciphertext** plus the initial deck:

```text
D_i = D0 ∘ g(q_0) ∘ g(q_1) ∘ … ∘ g(q_{i-1}),    t_i = readout(D_i, q_i)
```

where `q_i = symbol / rotor_mod` is the observed deck channel (4 card values for
`two`) and `g: card-value -> S_deck` is the advance map. So the search collapses
from the plaintext-autokey `6^8` per-coset key space to the advance map `g` alone
(`(deck!)^deck = 24^4 = 331_776` for `two`) — a few hundred thousand deterministic
forward passes. **Two** of the four conventions have `D0` **cancel** from every
crib equality, so their `g`-search at `D0 = identity` is *fully general*:
`forward/right` (`t_i = D0(A_i(q_i))`, `D0` outside) and `inverse/left`
(`t_i = D0^{-1}(A_i^{-1}(q_i))`, `D0^{-1}` outside) — a crib equality is invariant
under the common bijection. For `forward/left` and `inverse/right` the `D0` factor
lands *inside* the readout (applied to the differing `q`), so it does not cancel and
those two are the `D0 = identity` representative slice.

**The crib-anchored, codec-free statistic.** `isoscan` locates
rotor-difference-channel anchors — spans where the plaintext *really repeats*. The
`two` length-68 anchor is a **genuine ~34-letter repeated phrase**, not a codec
artifact: it clears not only the order-1 Markov null (`isoscan`) but a
**period-2-preserving** null (even/odd-phase Bernoulli at the empirical `eps`
rates), whose longest repeat tops out at ~25 over 60 trials versus the observed
68. If `two` is a feedback deck, the correct `g` must make the recovered deck
channel `t` **repeat at every anchor at once**. The gated statistic is therefore
the **joint minimum** crib run across all significant anchors: a spurious `g` can
overfit one anchor but cannot satisfy the minimum across all of them.

**The matched null absorbs the multiple comparisons.** Each null trial redraws the
deck channel `q` under its order-1 Markov law (preserving the deck transition
structure, breaking the cross-occurrence alignment with the fixed rotor anchors)
and **reruns the entire `g`-search**, so the exhaustive search's
optimised-over-`331_776`-maps inflation is reproduced inside the null itself. A
convention fires only when its observed joint minimum **strictly clears the null
ceiling** at the **Bonferroni-corrected** `p < 0.05/4 = 0.0125` (the firing gate,
not just a printed caveat). Anchors
themselves are the `isoscan`-significant repeats (above the difference-channel
Markov ceiling), so chance repeats — which no `g` can satisfy and which would
collapse the joint minimum — are never used as cribs.

## 3. Real-`two` result — `NoFeedbackSignal` (emphatic)

```sh
cargo run --release -q -- ctakscan --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL --null-trials 200
```

The `isoscan` gate keeps **5 significant** rotor anchors (difference-channel Markov
null ceiling 24): lengths **68, 51, 41, 37, 34** at ciphertext positions
`232/352, 6/556, 353/507, 109/573, 23/109`. Every convention's exhaustive `24^4`
search lands on the **random floor**:

| convention | generality | joint min-run | per-anchor runs | null (mean, ceiling) | p |
| --- | --- | --- | --- | --- | --- |
| right/forward | `D0`-free (general) | **4** | `[5,5,4,4,4]` | 4.0, 5 | 1.000 |
| left/forward | `D0=id` slice | 4 | `[4,5,4,6,4]` | 4.0, 5 | 0.980 |
| right/inverse | `D0=id` slice | 4 | `[4,5,4,6,4]` | 4.0, 5 | 0.995 |
| left/inverse | `D0`-free (general) | 4 | `[5,5,4,4,4]` | 4.0, 5 | 1.000 |

(200 null trials; the default 100-trial run is identical to two significant
figures. Firing is gated at the Bonferroni-corrected `p < 0.05/4 = 0.0125`; every
convention here is at `p ≈ 1`, so the verdict is unambiguous.)

A joint minimum of **4** over a 4-card deck is exactly the chance level (a random
map matches each aligned position with probability `1/4`, longest run ≈ 4), and the
deck-resample null reproduces it (ceiling 4–5). **VERDICT: `NoFeedbackSignal`** —
no convention's advance map reproduces the genuine ~34-letter plaintext repeat in
the deck channel above the matched null. (The single-anchor statistic looked
marginal — best run 13 vs null 12–14 — but that is pure exhaustive-search
overfitting on one span; the joint-minimum requirement that *one* `g` satisfy all
five anchors collapses it to the floor.)

**What this means, with passive-deck plaintext-autokey already excluded
(`groupscan`/`keydiff`):** no *computable-deck* reading of `two` — neither a passive
plaintext-keyed deck nor a ciphertext-fed deck — reproduces the real repeat. The
deck channel therefore carries **genuine hidden state not determined by the
plaintext or the ciphertext alone**. That is precisely the eye-cipher wall ("no
known way to take deltas in GAK ciphers with hidden states"): `two` faithfully
reproduces the eyes' core difficulty at a small, known-answer scale, which is why
it is the standing first-class miniature (G1b).

### Scope of the negative (binding honesty)

The exclusion is for a **single-card-channel-symbol-feedback deck on a ≤4-card
deck**, the natural ciphertext-autokey realisation. Two of the four conventions
(`forward/right`, `inverse/left`) are searched fully generally; the run does **not**
exclude:

- an advance map keyed on the **full 12-valued ciphertext symbol** (`24^12`, beyond
  exhaustive search) rather than the 4-valued card channel `q`;
- the two non-`D0`-cancelling conventions (`forward/left`, `inverse/right`) at a
  **non-identity `D0`** (they are searched only at `D0 = identity`);
- a hidden deck group **larger than `S4`** or a different readout/codec coupling.

These are labeled limitations, not covered by this run.

## 4. The instrument (self-validating)

`ctakscan --self-test` plants a 3-card (`S3`) feedback deck with a repeated word —
encrypted so the *literal* deck channel does **not** repeat (the deck state differs
at the two occurrences, exactly as real `two`) — and asserts the search recovers a
crib-consistent advance map reproducing the full repeat, while a no-feedback
control (the same anchor-bearing rotor channel woven onto a structureless deck
channel) yields `NoFeedbackSignal`. The `deck_size = 4` search is covered by a
fast planted-recovery unit test. All figures reproduce from the CLI:

```sh
# the four-convention feedback search on two (publication: --null-trials 200)
cargo run -q -- ctakscan --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL
# planted feedback-deck positive control + no-feedback negative control
cargo run -q -- ctakscan --self-test
```

## 5. Honesty framing (binding)

A verdict is a structural discriminator, never a decode. The `NoFeedbackSignal`
here is a **negative within the scope of §3** — it closes the ciphertext-autokey
single-symbol-feedback regime the passive-deck instruments left untested, and
sharpens `two`'s honest negative into a positive structural statement (genuine
hidden state), but it does not recover plaintext and does not exclude the
labeled-limitation regimes. The crib-reality check (the length-68 repeat clears a
period-2-preserving null, so it is a real repeated phrase, not a codec artifact)
and the joint-minimum-vs-rerun-null gate (the exhaustive search's overfitting is
reproduced inside the null) are the load-bearing discipline. Had a convention
fired, the recovered advance map would have been the deck *mechanism* only — the
digit→language codec is a separate, still-unbroken layer.

See `CODEC-RESULTS.md` §`two` for the current route, this document for the lead it
resolved, `key-difference-discriminator.md` for the additive sibling, and
`group_order` / `groupscan` for the passive-deck sibling.
