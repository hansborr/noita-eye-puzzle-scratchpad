# Exhaustive exclusion of the AGL(1,83)-GAK cipher family

**Status:** rigorous structural exclusion (exhaustive enumeration + algebraic
lemma), under the stated point-stabilizer GAK model.
**Claim ceiling:** this rules out one candidate *group family*; it says nothing
about recoverable plaintext. The eyes remain deterministic, engine-generated,
strikingly structured data of unknown meaning, and unsolved.
**Code:** `src/attack/agl_gak.rs` (Rust workbench); CLI subcommand `agl-gak`.

This note converts the wiki's *tentative* exclusion of the AGL(1,83) Group-Autokey
(GAK) families into a rigorous one. It is self-contained and intended to be
postable to the community wiki.

---

## 1. What AGL(1,83)-GAK is

In the [Group-Autokey (GAK)](Group-Autokey-(GAK)) framework, the cipher state is
an element of a finite group `G` whose order is a multiple of the 83-symbol
ciphertext alphabet. Each plaintext letter is assigned a group element; the state
advances cumulatively by that element; and each emitted ciphertext symbol is the
*coset* of a fixed **hidden subgroup** (the [hidden state](Hidden-State)). For the
action to produce the consistent isomorphs the eyes show, the group's action on
the 83 symbols must be **transitive**, which leaves
[exactly six groups](The-Transitivity-Restriction-(6-Groups-for-83)).

Two of those six are **AGL(1,83)** and one of its subgroups. `AGL(1,n)` is the
group of affine maps

```
x  ↦  a·x + b   (mod n),   gcd(a, n) = 1
```

under composition. Its order is `n·φ(n)`; for prime `n = 83` that is
`|AGL(1,83)| = 83 · 82 = 6806` elements (83 translations × 82 multipliers). It is
the semidirect product `C₈₃ ⋊ (C₈₃)ˣ`; for prime `n` the multiplier group
`(C₈₃)ˣ ≅ C₈₂`. As permutations of the alphabet, AGL(1,83) is exactly the
rotations and decimations of the 83 symbols (non-commutative for `n > 2`).

Two multiplier subgroups are tested, matching the two wiki candidates:

| Code label | Multipliers | Subgroup of `C₈₂` | `\|G\|`  | Hidden states |
| ---------- | ----------- | ----------------- | ------ | ------------- |
| **C83:C82** (Full)               | all 82 units `{1,…,82}`            | `C₈₂`         | 6806 | 82 |
| **C83:C41** (Quadratic Residues) | the 41 quadratic residues mod 83   | `C₄₁` ≤ `C₈₂` | 3403 | 41 |

### The point-stabilizer (right-multiplication / left-coset) model

The implementation fixes the exact GAK readout it is testing, so the claim cannot
silently drift:

- **State**: an AGL element `g = (a, b)`.
- **Update**: right-multiplication, `state' = compose(state, element)`
  (`agl_compose`).
- **Readout**: the image of a fixed **reference point** `x₀ = 0` under the current
  state, `symbol = agl_apply(state, x₀) = b`. The hidden subgroup is therefore the
  **point stabilizer** `Stab(0) = { (a, 0) }` (order 82 / 41); its 83 cosets are
  indexed by `b`, i.e. by "where the reference point lands." This is the code's
  *"right-multiplication / left-coset"* framing (`agl_gak.rs:460-483`).

This is what makes the obstruction below exact: a ciphertext symbol *is* the moved
reference point, so symbol-agreement between two parties is a statement about a
*fixed point* of their discrepancy.

> Scope note: this is the **point-stabilizer, single-shared-running-key** GAK
> model. It is the natural AGL-GAK reading, but it is a model; see §7.

---

## 2. The wiki's current stance, and what we strengthen

From [Explanation of Progress](Explanation-of-Progress), the six transitive
candidates are listed, and the AGL pair is dispatched only *tentatively*:

> "$C_{83}:C_{82}$ and $C_{83}:C_{41}$, an affine general linear group (AGL) and
> one of its subgroups, with 82 or 41 hidden states, **tentatively ruled out
> based on isomorphs in the last 3 messages**."

We **strengthen "tentatively ruled out" to "exhaustively excluded."** Two things
do the strengthening:

1. an **algebraic lemma** (a non-identity affine map over `ℤ/83` fixes at most one
   point), and
2. an **exhaustive enumeration** confirming that lemma over *every* candidate
   discrepancy in both subgroups (no sampling, no model fitting),

combined with the eyes' observed **varying shared runs after differing starts**.
The exclusion no longer rests on the last three messages alone: it rests on the
**all-nine global shared prefix** plus a complete enumeration.

---

## 3. The fixed-point lemma

**Lemma.** Let `p = 83` (prime), so `ℤ/p` is a field. For an affine map
`f(x) = a·x + b (mod p)`:

- if `a ≠ 1`, then `f` has **exactly one** fixed point;
- if `a = 1` and `b ≠ 0`, then `f` has **no** fixed point;
- if `a = 1` and `b = 0`, then `f` is the identity (every point fixed).

Consequently, **any non-identity affine map fixes at most one point**, and
equivalently **a map fixing two distinct points is the identity**.

**Proof.** A fixed point solves `a·x + b ≡ x`, i.e. `(a − 1)·x ≡ −b`.
- If `a ≠ 1`, then `a − 1 ≠ 0` is a unit of the field `ℤ/p`, so the equation has
  the unique solution `x ≡ −b·(a − 1)⁻¹`.
- If `a = 1`, the equation is `0 ≡ −b`: no solution when `b ≠ 0`, and every `x`
  when `b = 0` (the identity). ∎

This is exactly what the code computes: `fixed_point_of` returns
`(b · (1 − a)⁻¹) mod 83` when `a ≠ 1` and `None` when `a = 1`, and the brute-force
`fixed_point_count` agrees with it on the enumerated set (every non-identity
element). The two functions disagree on exactly one element — the **identity**
`(a = 1, b = 0)`, where `fixed_point_of` returns `None` (zero denominator) while
`fixed_point_count` returns 83 — but the identity is excluded by construction,
since the enumeration ranges over `b ∈ {1, …, 82}`. The enumeration's headline
`max_fixed_points = 1` is the computational witness of the lemma.

---

## 4. The kill mechanism: varying shared runs are impossible

### 4.1 A discrepancy is a constant left factor

Suppose two eye messages run the **same key** (same letter→element map) and the
**same plaintext** through a [shared section](Shared-Sections), but their states
differ. Write the difference as a left factor at the start of the run:
`right₀ = compose(d, left₀)`. Because both then apply the *same* element `e` on the
right, associativity propagates `d` unchanged:

```
right₁ = compose(right₀, e) = compose(compose(d, left₀), e)
       = compose(d, compose(left₀, e)) = compose(d, left₁),  etc.
```

So throughout a shared-plaintext run the two states differ by one **constant
discrepancy** `d`.

### 4.2 Symbol-agreement ⇔ the discrepancy fixes that point

At any step let `p = agl_apply(left, 0) = left.b` be the symbol the left party
emits. The right party emits

```
agl_apply(compose(d, left), 0) = d.a · left.b + d.b = d.a·p + d.b = agl_apply(d, p).
```

Hence **the two parties emit the same symbol at a step ⇔ `d` fixes the point `p`
the left party emits there.** This bridge identity is verified algebraically and
spot-checked in `agreement_check` (0 violations over 40 000 random
configurations).

### 4.3 The contradiction

A **shared run of length L** therefore means `d` fixes all `L` of the left party's
output points over the run. The run is **varying** when those output points are
*not all equal* — at least two **distinct** symbols appear. By the Lemma (§3), a
map fixing two distinct points is the identity. But `d` is **not** the identity:
the run begins **after a differing start**, i.e. the parties disagree at the
preceding position, so `d` does *not* fix the predecessor's point. Contradiction.

> **A varying shared run after a differing start is impossible under
> AGL(1,83)-GAK.** The eyes' shared runs vary → AGL is excluded.

### 4.4 Tied to the all-nine global shared prefix

The code locks the verdict to the **tightest** instance: the all-nine **global
shared prefix**. The nine messages begin with nine *distinct* first symbols

```
east1:50  west1:80  east2:36  west2:76  east3:63  west3:34  east4:27  west4:77  east5:33
```

and then *all nine* share the same length-2 run at offset 1:

```
shared prefix: start 1, len 2, values [66, 5], distinct 2/2
```

Take any two eyes. Their predecessors (the distinct first symbols) differ, so
their discrepancy `d` is non-identity; yet they then agree on a run containing two
distinct symbols (66 and 5). That would force `d` to fix both 66 and 5 — two
distinct points — making `d` the identity. Impossible. The CLI reports this as the
first obstruction:

```
obstruction: east1/west1 start 1 len 2 distinct 2/2 after predecessors 50 vs 80
```

This single feature, shared by all nine messages, is enough; the longer pairwise
varying runs (e.g. `east4/west4` length 20, 18 distinct) only reinforce it.

---

## 5. The exhaustive enumeration (the rigorous strengthening)

`fixed_point_enumeration` (`agl_gak.rs:804`) does not sample and does not fit a
key. It enumerates **every candidate discrepancy consistent with a differing
start** and counts fixed points for each. "Consistent with a differing start"
means the discrepancy **moves the reference point**, i.e. `b ≠ 0`
(`agl_apply(d, 0) = b ≠ 0`). Equivalently, the enumerated set is
`G \ Stab(0)` — every group element *except* those that fix the reference point.

The enumeration ranges over every multiplier `a` in the subgroup and every nonzero
translation `b ∈ {1, …, 82}`:

| Subgroup | multipliers × nonzero translations | discrepancies | `\|G\| − \|Stab(0)\|` |
| -------- | ---------------------------------- | ------------- | -------------------- |
| **C83:C82** | 82 × 82 | **6724** | 6806 − 82 = 6724 |
| **C83:C41** | 41 × 82 | **3362** | 3403 − 41 = 3362 |

Reproduced result (test `fixed_point_enumeration_counts_reproduce`, and the CLI):

| Subgroup | discrepancies | fixing ≥ 2 points | max fixed points |
| -------- | ------------- | ----------------- | ---------------- |
| **C83:C82** (Full) | **6724** | **0** | **1** |
| **C83:C41** (QR)   | **3362** | **0** | **1** |

Among all 6724 (resp. 3362) discrepancies that could follow a differing start, **0
fix two or more points** and the **maximum number of fixed points is 1** — exactly
the Lemma, verified by exhaustion rather than asserted. (The 82 pure-translation
cases `a = 1, b ≠ 0` contribute 0 fixed points each; every `a ≠ 1` case
contributes exactly 1. The decimation maps `a ≠ 1, b = 0` are correctly *excluded*
from this family because they fix the reference point — they correspond to a
*non*-differing start — and in any case also fix only their single point.)

This is the rigorous content. It is corroborated by two non-exhaustive checks that
are **not** load-bearing: the agreement spot-check (0/40000), and a forward
simulation that found **0 varying shared runs** out of its sampled trials (with a
small number of trials the add-one upper-tail p-value is weak, e.g.
`p = 0.030303` at 32 trials — this is a sanity null, not the proof).

---

## 6. Reproduction

From the workbench root (`--locked` everywhere; the enumeration test is
seed-independent and exhaustive):

```sh
# Exhaustive enumeration: 6724/0/1 (Full) and 3362/0/1 (QR)
cargo test --locked fixed_point_enumeration_counts_reproduce

# CLI end-to-end exclusion (verdicts, obstruction, controls)
cargo run --locked -- agl-gak --null-trials 32 --seed 123

# CLI integration test (exclusion + honesty caveats present)
cargo test --locked --test agl_gak_cli
```

Expected CLI verdict block:

```
subgroup verdicts
  group    verdict      agreement          forward fixed>=2/universe      max fixed controls
  C83:C82  excluded      0/40000        0/32             0/6724                   1 ok
    obstruction: east1/west1 start 1 len 2 distinct 2/2 after predecessors 50 vs 80
  C83:C41  excluded      0/40000        0/32             0/3362                   1 ok
    obstruction: east1/west1 start 1 len 2 distinct 2/2 after predecessors 50 vs 80
```

**Pointers (`src/attack/agl_gak.rs`):**
- `fixed_point_enumeration` (≈ line 804) and its test
  `fixed_point_enumeration_counts_reproduce` (≈ line 1180).
- `fixed_point_of` / `fixed_point_count` (≈ line 973) — the Lemma in code.
- `agreement_check` (≈ line 825) — the §4.2 bridge identity, spot-checked.
- `first_obstruction` / `global_prefix_obstruction` (≈ line 651) — the all-nine
  prefix kill in §4.4.
- Interpretation + claim-ceiling text (≈ lines 460-483).
- Cipher primitives `agl_compose` / `agl_apply` / `agl_coset_symbol` /
  `quadratic_residues_mod` in `src/ciphers/mod.rs` (≈ lines 2299-2349).
- CLI integration test: `tests/agl_gak_cli.rs`.

---

## 7. Claim ceiling (what is and isn't covered)

**What this establishes.** Under the point-stabilizer AGL-GAK model of §1 —
right-multiplication state update, a single shared running key, ciphertext symbol =
moved reference point — both **C83:C82** and **C83:C41** are **rigorously and
exhaustively excluded** for the eyes. The exclusion is a theorem (the Lemma) plus a
complete enumeration plus an observed, transcription-checked structural feature
(varying shared runs after differing starts, witnessed by the all-nine prefix). It
narrows the six transitive GAK candidates. Those six (for prime degree 83) are
`C₈₃`, `D₁₆₆`, `C₈₃:C₄₁`, `C₈₃:C₈₂` (= AGL), `A₈₃`, `S₈₃`. Removing the AGL pair
(this doc) and `D₁₆₆` (ruled out separately by the community via implied element
orders) leaves **{C₈₃, A₈₃, S₈₃}** — note this doc does *not* eliminate `C₈₃`, the
cyclic "wheel" / standard CTAK; it is disfavored separately by our structural
battery, leaving the `A₈₃`/`S₈₃` deck ciphers as the live worst case.

**What it does *not* cover.**
- It does not address **non-GAK** affine constructions, nor an AGL-GAK with a
  **different hidden subgroup** (a non-point-stabilizer readout), nor multiple /
  non-shared running keys.
- It says **nothing about recoverable plaintext**. AGL being out does not make any
  other group "in," and the remaining candidates (`A₈₃`, `S₈₃` deck ciphers) have
  no known mapping-recovery attack.
- The eyes remain deterministic, engine-generated, strikingly structured data of
  **unknown meaning** — **unsolved**. No primary developer source confirms
  recoverable plaintext.
- As always, **transcription is the underlying risk**: the obstruction depends on
  the nine distinct first symbols and the `[66, 5]` shared prefix in the verified
  corpus under the accepted honeycomb reading order. The exclusion is exact
  *given* that data; a single mis-read glyph in the prefix region would need
  re-checking.
