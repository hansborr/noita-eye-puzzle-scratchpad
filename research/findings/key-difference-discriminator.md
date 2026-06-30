# The isomorph key-difference discriminator (Thread B)

**Status:** file-driven, self-validated structural instrument; the practice-puzzle
verdicts below are computed by the tool, not hand-transcribed.
**Claim ceiling:** a verdict is a **structural discriminator over the
keystream-difference family, never recovered plaintext.** It reports the additive
order of the key difference behind an isomorph relabelling; it makes no plaintext
claim. The eyes remain unsolved.
**Code:** `src/analysis/key_difference/` (library) + the `keydiff` CLI subcommand
(`src/cli/commands/keydiff.rs`). Reproduce: `cargo run -q -- keydiff --self-test`.

---

## 1. What it measures

CodeWarrior0's isomorph theorem: a relabelled ciphertext repeat (an isomorph)
appears between two occurrences of the same plaintext **iff** the two occurrences'
keystreams differ by a *constant* — the signature of ciphertext-autokey /
progressive-alphabet / Wadsworth ciphers. `groupscan`
(`src/analysis/group_order/`) is the non-additive sibling: it recovers the
relabelling *permutation* `π` and classifies it by cycle type. `keydiff` recovers
the same relabelling's *additive realisation* `Δ` and classifies it by
**finite-difference order**.

For two equal-length windows at starts `a`, `b`, the per-position key difference is
`Δ[j] = (c[b+j] − c[a+j]) mod m`. Its order is read off the difference channels of
the whole stream, since a constant offset cancels under one differencing:

| `Δ` shape | fires on | verdict | cipher family |
| --- | --- | --- | --- |
| `Δ ≡ 0` | raw stream (order 0) | identical key | Vigenère, gap a period multiple |
| constant | 1st-difference channel (order 1) | constant additive | classical autokey / Wadsworth / progressive |
| linear | 2nd-difference channel (order 2) | linear additive | accelerating progressive |
| non-additive permutation | no order, but a *significant* (null-cleared) gap-pattern certificate | irregular | deck / GAK / self-modifying |

The verdict is the **lowest order** that fires *significantly* — clearing the
order-1 Markov matched null (the `isoscan` significance test, reused per channel,
not eyeballed). The `Irregular` verdict additionally requires a **null-calibrated**
gap-pattern isomorph certificate: the observed count of repeated informative
signatures ([`detect_isomorphs`]) at the firing window must exceed its **own**
order-1 Markov null ceiling at `p < 0.05` — the same discipline the additive
channels use. A merely-present, chance-level certificate (random mod-12 streams
carry one essentially always at window 8) is **not** enough, so an *absence* of
additive structure is never reported as a positive deck claim on a structureless
stream. Within the constant (order 1) bucket, a modular regression of the per-pair
offset `δ` on the gap `g` splits the family: a single shared slope `δ ≡ r·g (mod
m)` across distinct gaps is progressive-alphabet; a content-driven `δ` is classical
autokey.

## 2. The four positive controls + matched null

`keydiff --self-test` plants one stream per family boundary and asserts the
verdict, each gated against the per-channel order-1 Markov null:

- **ciphertext-autokey** (`keystream::encrypt`, length-1 primer): a planted
  plaintext repeat ⇒ a constant `Δ` (the 1st-difference channel of a length-1
  primer CTAK stream *is* the plaintext) ⇒ **order 1**. ✔
- **Vigenère** with the repeat at a period-multiple gap ⇒ `Δ ≡ 0` ⇒ **order 0**. ✔
- **additive-progressive** (`k[i] = k0 + r·i`, one phrase planted at three distinct
  gaps, none a multiple of `m`) ⇒ constant `Δ = r·g` ⇒ **order 1** *and* the
  regression recovers the shared slope ⇒ **progressive-alphabet**. ✔
- **non-additive deck relabel**: a long phrase (120 symbols) planted twice with
  the second occurrence passed through a fixed non-additive permutation (a seeded
  `fisher_yates` shuffle of the alphabet). The two occurrences share an equality
  pattern long enough to be a **significant** gap-pattern certificate — its
  repeated-signature count clears the certificate's order-1 Markov null at the
  firing window (observed ≈ 90–104 vs null ceiling ≈ 62–72 across the self-test
  seeds) — while the relabelling is neither additive nor the identity ⇒ no additive
  order fires ⇒ **irregular**. ✔ (The phrase was lengthened from the original 40 so
  the relabelled repeat clears the *null-calibrated* certificate; a length-40 phrase
  is swamped by the window-8 baseline. The fix is a faithfully longer isomorph,
  never a weaker null.)
- **matched-null agreement**: the constant-`Δ` controls clear the per-channel null
  (their firing is significant); the deck control manufactures no additive firing
  **and** its certificate clears its own raw-stream Markov null (a significant
  relabelled repeat, not a chance-level one). ✔

### Deviation from the spec's suggested deck control (documented)

The spec proposed reusing a dihedral GCTAK fixture
(`gak_attack::generate_fixture`) for the irregular control. It **does not
reproduce**, for a structural reason worth recording: the GCTAK readout is
bijective (trivial hidden subgroup), so a small dihedral group (order 8) makes the
ciphertext periodic — repeated phrases collide on entry states and produce
*identity* relabellings, which read as a raw repeat (`IdenticalKey`), not
`Irregular`. A group large enough to avoid the entry-state collisions pushes the
difference-channel windows all-distinct, destroying the gap-pattern certificate.
The fixed-permutation relabel above is the robust positive control for the same
non-additive class (a passive deck's occurrence-to-occurrence relabelling *is* a
fixed permutation, which is exactly what it realises). A real deck-stabilizer GAK
fixture (`|H| > 1`, many-to-one readout) is the more elaborate alternative and is
left as a next-step.

## 3. Practice-puzzle results

```sh
cargo run -q -- keydiff --input-file research/data/practice-puzzles/two --alphabet ABCDEFGHIJKL
cargo run -q -- keydiff --input-file research/data/practice-puzzles/one  --alphabet 01234
```

### `one` — constant additive Δ (order 1)

Order 0 is **not** significant (longest raw repeat 22 < null ceiling 24); order 1
fires at length **36** (anchor 145/229, gap 84) — the same repeat `isoscan
--delta-mod 5` finds. So the key difference between the two occurrences is a
**constant**: an additive / commutative (autokey-family / Wadsworth) relabelling,
**not** a non-additive deck. This is consistent with `one`'s reading as a `C5`
(cyclic, hence commutative-additive) GAK. The family is **indeterminate** —
only one distinct gap is observed, so the progressive-vs-classical-autokey split is
underdetermined (constant `Δ` is still established). Orders 2 and 3 also fire (the
constant-`Δ` repeat survives further differencing); the verdict takes the lowest
firing order. (The null-calibrated gap-pattern certificate is *absent* at window 8
here — observed 47 vs null ceiling 64 over the small mod-5 alphabet — so the order-1
firing alone drives the verdict; the certificate is not load-bearing for `one`.)

### `two` — non-additive on the full alphabet (marginal order-2 firing)

Over the full mod-12 alphabet, orders 0 and 1 are **not** significant (longest
repeats 7 and 6, below the null ceilings of 8–9). **The famous length-68
rotor-channel (mod-3) repeat does not survive to the full alphabet** — confirming
it is an *eps-only* (rotor-only) repeat where the deck does not repeat, the same
finding behind `groupscan`'s robust `NoDeckSignal`. So `two` carries **no
identical-key and no constant-additive structure on the full alphabet**: a
passive-additive-deck / plaintext-autokey reading is **not supported**.

The only additive firing is a **marginal length-10 order-2 repeat** (anchor
181/333, gap 152), just above the null ceiling of 8 (`p = 0.005`, robust across
null seeds). At the default `--min-anchor-len 8` the tool therefore labels `two`
*linear additive (order 2)*; raise the threshold to `--min-anchor-len 11` and the
firing drops out (length 10 < 11), flipping the verdict to **`Irregular`**. The
length-10 order-2 signal is too short to support a confident "accelerating
keystream" claim and is most consistent with the period-2 codec artifact the
`CODEC-RESULTS.md` `isoscan` caveat warns about.

**The gap-pattern certificate is now null-calibrated**, and its behaviour on `two`
is informative. At the **default firing window 8** the certificate is **not
significant** (observed 136 repeated signatures vs null ceiling 138, the
chance-level the reviewer flagged) — so if the marginal order-2 firing were dropped
*at window 8*, `two` would read `NoSignal`, not `Irregular`. The certificate only
becomes significant at **windows ≥ 10** (window 10: 135 vs 94; window 11: 125 vs
37; window 12: 115 vs null ceiling 9–14, robust across null seeds, `p = 0.005`):
`two`'s full-alphabet stream carries far more repeated equality-pattern signatures
at those windows than an order-1 Markov null produces. So at `--min-anchor-len ≥
11` the `Irregular` verdict is now backed by a **genuinely significant** certificate
rather than the near-vacuous one.

**Substantive reading for `two`:** the full-alphabet key difference is
**non-additive** — neither identical nor constant nor convincingly linear; the
constant-`Δ` plaintext-autokey hypothesis is **excluded** (orders 0/1 never fire on
the full alphabet). **The famous length-68 mod-3 rotor repeat still does not survive
to the full alphabet** (the `NoDeckSignal` finding). The now-significant certificate
says only that there is repeated relabelled-structure *beyond first-order chaining*
— it does **not** distinguish a genuine non-additive deck from the **period-2 codec
artifact** (the order-1 Markov null models adjacent transitions but not the codec's
sustained period-2 regularity, so the codec alone inflates the longer-window
signature counts). It is consistent with the **untested
ciphertext-autokey-feedback / non-additive-deck regime** flagged in
`CODEC-RESULTS.md` ("Readout convention and the autokey-family boundary") *and* with
the codec artifact, and it recovers **no plaintext** and affirms **no deck**.

## 4. Honesty framing (binding)

A verdict is a structural discriminator, never a decode. Every order's firing is
gated against the matched null; the `Irregular` verdict requires the **null-gated**
gap-pattern certificate (the repeated-signature count must clear its own order-1
Markov null at `p < 0.05`), so the absence of additive structure is never sold as a
positive deck claim on a structureless stream — a chance-level certificate yields
`NoSignal`, not `Irregular`. The `two` verdict is threshold-sensitive at the margin
(linear at `--min-anchor-len ≤ 10`, irregular at `≥ 11`); that sensitivity is itself
reported rather than hidden, and the robust conclusion is the *absence* of additive
structure on the full alphabet (constant-`Δ` plaintext-autokey excluded), not the
marginal order-2 firing. Where the calibrated certificate *is* significant for `two`
(windows ≥ 10), that is honestly reported as significant non-additive
relabelled-repeat structure beyond first-order chaining — consistent with the
period-2 codec artifact and the feedback/deck regime alike, affirming neither a deck
nor any plaintext.

## 5. Next step (labeled limitation)

The single-stream path shipped here recovers and classifies `Δ` on one stream.
The **eye-corpus cross-message path** — pairing a "a relabelled repeat exists here"
certificate (`detect_isomorphs`, or `perfect_isomorphism`'s column-aligned
cross-message `SafeIsomorphExtent` spans) with the additive-order-absence from the
difference channels, plus the eye-corpus reading-order alignment between the two
detectors — is **not yet wired up** and is left as a clearly-labeled next-step
rather than rushed; an eye-corpus irregular verdict is not emitted without a
passing cross-message control.
