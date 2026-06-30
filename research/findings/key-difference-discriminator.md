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
| non-additive permutation | no order, but a gap-pattern certificate exists | irregular | deck / GAK / self-modifying |

The verdict is the **lowest order** that fires *significantly* — clearing the
order-1 Markov matched null (the `isoscan` significance test, reused per channel,
not eyeballed). The `Irregular` verdict additionally requires a gap-pattern
isomorph certificate ([`detect_isomorphs`]) so an *absence* of additive structure
is never reported as a positive deck claim on a structureless stream. Within the
constant (order 1) bucket, a modular regression of the per-pair offset `δ` on the
gap `g` splits the family: a single shared slope `δ ≡ r·g (mod m)` across distinct
gaps is progressive-alphabet; a content-driven `δ` is classical autokey.

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
- **non-additive deck relabel**: the same phrase planted twice with the second
  occurrence passed through a fixed non-additive permutation (a seeded
  `fisher_yates` shuffle of the alphabet). The two occurrences share an equality
  pattern (certificate present) but the relabelling is neither additive nor the
  identity ⇒ no additive order fires ⇒ **irregular**. ✔
- **matched-null agreement**: the constant-`Δ` controls clear the null (their
  firing is significant); the deck control manufactures no additive firing. ✔

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
firing order.

### `two` — non-additive on the full alphabet (marginal order-2 firing)

Over the full mod-12 alphabet, orders 0 and 1 are **not** significant (longest
repeats 7 and 6, below the null ceilings of 8–9). **The famous length-68
rotor-channel (mod-3) repeat does not survive to the full alphabet** — confirming
it is an *eps-only* (rotor-only) repeat where the deck does not repeat, the same
finding behind `groupscan`'s robust `NoDeckSignal`. So `two` carries **no
identical-key and no constant-additive structure on the full alphabet**: a
passive-additive-deck / plaintext-autokey reading is **not supported**.

The only firing is a **marginal length-10 order-2 repeat** (anchor 181/333, gap
152), just above the null ceiling of 8 (`p = 0.005`, robust across null seeds). At
the default `--min-anchor-len 8` the tool therefore labels `two` *linear additive
(order 2)*; raise the threshold by two (`--min-anchor-len 12`) and the firing drops
out, flipping the verdict to **`Irregular`**. The length-10 order-2 signal is too
short to support a confident "accelerating keystream" claim and is most consistent
with the period-2 codec artifact the `CODEC-RESULTS.md` `isoscan` caveat warns
about.

**Substantive reading for `two`:** the full-alphabet key difference is
**non-additive** — neither identical nor constant nor convincingly linear. This is
the **untested ciphertext-autokey-feedback / non-additive-deck regime** flagged in
`CODEC-RESULTS.md` ("Readout convention and the autokey-family boundary"): if the
deck advance feeds back the emitted symbol, no readout yields a constant-`K`
relation and `groupscan`'s positive-control premise collapses. `keydiff` measures
exactly that absence of additive structure on the full alphabet, and a tightened
threshold reads it as irregular outright. Either way the constant-`Δ`
plaintext-autokey hypothesis is excluded; the result points at the feedback/deck
regime, never at recovered plaintext.

## 4. Honesty framing (binding)

A verdict is a structural discriminator, never a decode. Every order's firing is
gated against the matched null; the `Irregular` verdict requires the gap-pattern
certificate so the absence of additive structure is never sold as a positive deck
claim on a structureless stream. The `two` verdict is threshold-sensitive at the
margin (linear at `--min-anchor-len 8`, irregular at `12`); that sensitivity is
itself reported rather than hidden, and the robust conclusion is the *absence* of
additive structure on the full alphabet, not the marginal order-2 firing.

## 5. Next step (labeled limitation)

The single-stream path shipped here recovers and classifies `Δ` on one stream.
The **eye-corpus cross-message path** — pairing a "a relabelled repeat exists here"
certificate (`detect_isomorphs`, or `perfect_isomorphism`'s column-aligned
cross-message `SafeIsomorphExtent` spans) with the additive-order-absence from the
difference channels, plus the eye-corpus reading-order alignment between the two
detectors — is **not yet wired up** and is left as a clearly-labeled next-step
rather than rushed; an eye-corpus irregular verdict is not emitted without a
passing cross-message control.
