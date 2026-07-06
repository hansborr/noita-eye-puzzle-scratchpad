# Thread 1A — Proof note: exactly 6 transitive groups act on 83 points

Scope. This note independently and adversarially re-derives, from first
principles, the wiki's central counting claim and records the worked argument so
the repo does not take it on faith. It is a *correctness audit of a theorem*, not
a measurement and not a decode. Nothing here depends on plaintext meaning or a
letter-to-action key; it is pure group theory keyed only to the alphabet size
`n = 83`.

Claim under test (from
`The-Transitivity-Restriction-(6-Groups-for-83).md`, content current to
2026-01-16):

> Because 83 is prime, exactly 6 transitive permutation groups act on 83 points:
> `C₈₃`, `D₁₆₆`, `C₈₃:C₄₁`, `C₈₃:C₈₂ (= AGL(1,83))`, `A₈₃`, `S₈₃`.

The wiki page presents this as a hard narrowing of the GAK state group (see
`Group-Autokey-(GAK).md` for why the GAK state group must be one transitive group
on the 83 ciphertext symbols, with the visible alphabet in bijection with the
right cosets of a hidden subgroup `H`, `|C| = |G|/|H|`).

Verdict: the count of 6 holds. Re-derived two ways below (divisor argument +
2-transitive exclusion), and the *method* is cross-checked against four
firmly-known small-prime counts that it reproduces exactly. Confidence: high — see
the confidence statement at the end for the precise scope and the one external
fact this rests on.

---

## 0. Tooling note (count cross-check via primitive groups)

The thread doc originally suggested cross-checking with GAP's transitive-groups
library. That route is unavailable: `NrTransitiveGroups(83)` returns `fail`
because the transitive-groups library does not reach degree 83 [Lymm]. GAP is
also not installed in this environment. On this machine `gap` is a shell alias
for `git apply`, not the GAP computer-algebra system:

```
$ alias gap
gap='git apply'
$ command -v gap   # no GAP binary on PATH
```

The count does have a machine-independent cross-check route. At prime degree,
every transitive group is primitive, and the OEIS A000019 b-file fetched
2026-07-06 gives `a(83)=6` (`a(82)=10`, `a(81)=155`) [verified]. This matches the
audited theorem application below. It closes the tooling cross-check gap for the
count, but the non-solvable part still rests on the CFSG-dependent classification
of 2-transitive groups of prime degree. I also sanity-checked the *method* by
hand-deriving `NrTransitiveGroups(p)` for `p ∈ {5,7,11,23}` and confirming it
matches the well-established library values (Section 4).

---

## 1. The reduction: Burnside on transitive groups of prime degree

Burnside's theorem (transitive groups of prime degree). A transitive
permutation group `G` of prime degree `p` is either

- **(a) solvable**, in which case `G` is (permutation-isomorphic to) a subgroup of
  the one-dimensional affine group `AGL(1,p) = C_p ⋊ C_{p−1}` that contains the
  regular normal subgroup `C_p`; or
- **(b) 2-transitive**.

This is classical (Burnside, 1900s) and needs no CFSG. The dichotomy is the whole
engine: it splits the enumeration into a finite, completely explicit solvable
list (Section 2) and a 2-transitive case that the modern classification pins down
(Section 3).

A note on the regular `C_p`: in any transitive `G` of prime degree, a Sylow
`p`-subgroup has order `p` (since `p ‖ |G|` exactly once, as `|G|` divides `p!`
and `p² ∤ p!`), and it acts regularly. In the solvable case this `C_p` is normal,
giving the `C_p ⋊ (point stabilizer)` structure with the stabilizer embedding into
`Aut(C_p) = C_{p−1}`.

---

## 2. Solvable case — the divisor argument, worked for p = 83

A solvable transitive `G` of degree `p` is `C_p ⋊ H` where `H ≤ C_{p−1}` is the
point stabilizer acting (faithfully, fixed-point-freely on the nonzero points) by
multiplication. Because `C_{p−1}` is cyclic, it has exactly one subgroup of
each order `d` dividing `p−1`, and these are all of its subgroups. Hence the
solvable transitive groups of degree `p` are in bijection with the divisors of
`p−1`:

> one group `C_p ⋊ C_d` per divisor `d | (p−1)`, of order `p·d`.

(There is no double-counting: distinct `d` give non-isomorphic groups — different
orders — and conjugate stabilizers of the same order give the *same* permutation
group up to permutation isomorphism, so "one per divisor" is exact. The cyclicity
of `C_{p−1}` is load-bearing: if `p−1` instead admitted several subgroups of the
same order they could give inequivalent groups. It does not, so the map is a clean
bijection.)

**For `p = 83`:** `p` is prime (checked), and

```
p − 1 = 82 = 2 · 41   (both prime)
divisors of 82 : {1, 2, 41, 82}      (τ(82) = 4)
```

so there are exactly four solvable transitive groups:

| divisor `d` | group        | structure              | order `p·d` |
| ----------: | ------------ | ---------------------- | ----------: |
|         `1` | `C₈₃`        | regular cyclic         |        `83` |
|         `2` | `C₈₃ ⋊ C₂`   | `= D₁₆₆` (dihedral)    |       `166` |
|        `41` | `C₈₃ ⋊ C₄₁`  | metacyclic Frobenius   |      `3403` (`= 83·41`) |
|        `82` | `C₈₃ ⋊ C₈₂`  | `= AGL(1,83)` (full)   |      `6806` (`= 83·82`) |

These are precisely the wiki's first four. `D₁₆₆` is the `d=2` case (`C₂` is the
order-2 subgroup of `C₈₂`, i.e. the reflection / decimation-by-82 subgroup, matching
`Dihedral-Group.md`). `AGL(1,83)` is the `d = p−1 = 82` case, the full affine
group `{x ↦ ax + b : a ∈ (ℤ/83)*, b ∈ ℤ/83}`, matching
`Affine-General-Linear-Group-(AGL).md`. Its order is `|AGL(1,p)| = p·(p−1) =
83·82 = 6806` (`83` translations × `φ(83) = 82` units), which is exactly the
`d = 82` row above and the AGL page's "all rotations and decimations" count. (The
AGL page writes the general-`n` order as `φ(n)·(n−1)`; that formula is for the
*units-times-nonzero* count it uses there. For prime `n = p` the standard affine
order is `p·(p−1)`, i.e. `83·82 = 6806` — the value used throughout this note.)

Adversarial check on the divisor step. Is any divisor mishandled? `82`'s only
factorizations are `1·82` and `2·41`; the divisor lattice is exactly
`{1,2,41,82}`, a "diamond" (`82` is squarefree with two prime factors, so τ = 2²
= 4). No divisor is missed and none is spurious. In particular there is no
`d = 4` (`4 ∤ 82`), so there is no extra Frobenius group of order `332` — a natural
place an over-eager enumeration might invent one. The four solvable groups are
complete.

---

## 3. Non-solvable case — only A₈₃ and S₈₃

By Burnside (Section 1), every non-solvable transitive group of degree 83 is
2-transitive. The 2-transitive groups of *prime* degree `p` are completely
classified (this is the one place CFSG enters; see Feit, "Some consequences of the
classification of finite simple groups," and the table in Dixon–Mortimer,
*Permutation Groups*, Thm 7.3–7.4). Their socles are exactly:

| # | socle family            | degree it acts on (prime)       | reaches 83? |
|---|-------------------------|---------------------------------|-------------|
| A | `C_p` (affine)          | `p`, any prime                  | already in §2 (solvable) |
| B | `A_p` (alternating)     | `p`, any prime                  | **yes → A₈₃, S₈₃** |
| C | `PSL(d,q)`, `d ≥ 2`     | `(qᵈ−1)/(q−1)` when that is prime | only if 83 has this form |
| D | `PSL(2,11)` (excep.)    | `11`                            | no |
| E | `M₁₁`                   | `11`                            | no |
| F | `M₂₃`                   | `23`                            | no |

Family A is the affine case: a 2-transitive affine group of prime degree `p`
needs its point stabilizer to act *transitively* on the `p−1` nonzero points;
since the stabilizer is cyclic `≤ C_{p−1}`, only the full `C_{p−1}` does this,
giving `AGL(1,p)` — which is solvable and already counted in Section 2 (the
`d = 82` row). So family A contributes nothing new and, notably, nothing
non-solvable.

Family B gives, for every prime `p`, exactly the two groups `A_p` and `S_p`
(`S_p` is `A_p` extended by an odd permutation; both are 2-transitive, indeed
`(p−2)`-transitive). For `p = 83`: `A₈₃` and `S₈₃`. These are the wiki's
fifth and sixth groups.

The exclusions (the adversarial core). Families C–F are the only way to get an
*extra* non-solvable 2-transitive group beyond `A_p, S_p`. Each requires `p` to
have a special arithmetic form. I checked all three:

- **Mathieu / sporadic exceptions (D, E, F).** The 2-transitive groups with
  sporadic socle of *prime* degree occur only at degrees `11` and `23`
  (`PSL(2,11)` and `M₁₁` at 11; `M₂₃` at 23). The full Mathieu degree set is
  `{11,12,22,23,24}`. `83 ∉ {11,23}` and `83 ∉ {11,12,22,23,24}`. Excluded.

- **Projective (C).** `PSL(d,q)` (and the chain up to `PΓL`) acts 2-transitively
  on the `(qᵈ−1)/(q−1)` points of `PG(d−1,q)`; this is an *extra* family exactly
  when that count is the prime in question. I searched all prime powers `q`
  and all `d ≥ 2` with `(qᵈ−1)/(q−1) = 83`:

  ```
  for prime power q ≤ 10000, d ≥ 2:   (q^d − 1)/(q − 1) = 83  →  NO SOLUTION
  ```

  (For `d = 2` this is `q + 1 = 83 ⇒ q = 82 = 2·41`, not a prime power; for
  `d ≥ 3` the value jumps past or skips 83 — e.g. `q=2`: 3,7,15,31,63,127;
  `q=3`: 4,13,40,121; etc. — 83 never appears.) So no projective family of
  degree 83 exists. Excluded.

There is no remaining 2-transitive family: symplectic `Sp(2d,2)` and unitary
actions have composite degrees (`2^{2d−1} ± 2^{d−1}`, `(q³+1)`, …), the
Suzuki/Ree families have composite degrees `q²+1`, `q³+1`, and the
Higman–Sims/Conway-type sporadics have composite degrees (176, 276, …). None is a
prime, let alone 83.

Therefore the only non-solvable transitive groups of degree 83 are `A₈₃` and
`S₈₃`.

---

## 4. Sanity check on the method (small primes, by hand)

To guard against a flawed *method* rather than a flawed arithmetic, I hand-derived
`NrTransitiveGroups(p)` for the small primes where every 2-transitive socle family
can be enumerated explicitly, using the *same* recipe (solvable list = τ(p−1)
groups; plus `A_p, S_p`; plus any projective/Mathieu/sporadic extra). These match
the well-established GAP transitive-groups library values exactly:

| `p` | solvable `τ(p−1)`            | `+A_p,S_p` | extras (source)                  | total | known |
|----:|-----------------------------|-----------:|----------------------------------|------:|------:|
| `5` | 3  `{C5, D10, AGL(1,5)}`     |        `+2`| 0 — `PSL(2,4)=A5` already counted |  `5`  | `5` ✓ |
| `7` | 4  `{C7, D14, C7:C3, AGL}`   |        `+2`| +1 `PSL(3,2)` (proj `q=2,d=3`)   |  `7`  | `7` ✓ |
| `11`| 4  `{C11, D22, C11:C5, AGL}` |        `+2`| +2 `PSL(2,11)`, `M₁₁`            |  `8`  | `8` ✓ |
| `23`| 4  `{C23, D46, C23:C11, AGL}`|        `+2`| +1 `M₂₃`                          |  `7`  | `7` ✓ |

The method reproduces `5, 7, 8, 7` — the canonical counts — and, crucially, every
"extra" beyond `τ(p−1)+2` is traceable to a *named* projective/Mathieu/sporadic
source. (I deliberately do not rely on half-remembered library values for
larger primes like 17/29/31; the four cases above are fully hand-derivable and
suffice to validate the recipe.)

For `p = 83` the recipe gives:

```
τ(82) solvable groups + {A₈₃, S₈₃} + (no projective)(no Mathieu)(no sporadic)
   =        4          +       2     +              0
   =        6
```

So the wiki's "exactly 6" is confirmed, with the extras column provably empty
because 83 is not a projective, Mathieu, or sporadic 2-transitive degree.

---

## 5. The six groups, with orders and GAK hidden-subgroup sizes

In a GAK cipher the visible alphabet (83 symbols) is in bijection with the right
cosets of a hidden subgroup `H ≤ G`, so `|C| = |G|/|H|`, i.e. `|H| = |G|/83`
(`Group-Autokey-(GAK).md`). The hidden-subgroup *sizes* the thread doc lists as
`{1, 2, 41, 82, …}` are exactly these `|G|/83` values:

| group                  | order `|G|`         | hidden `|H| = |G|/83` | nature / GAK reading                         |
| ---------------------- | ------------------: | --------------------: | -------------------------------------------- |
| `C₈₃`                  | `83`                | `1`                   | regular, **commutative** → ruled out by observed chaining conflicts (`Cyclic-Group.md`) |
| `D₁₆₆`                 | `166`               | `2`                   | `C₈₃⋊C₂`, hidden `C₂` (two hidden states) → excluded within-model by Full AGL subsumption [verified]; Thread 1B corroborates |
| `C₈₃:C₄₁`              | `3403` (`83·41`)    | `41`                  | metacyclic Frobenius; excluded by the AGL fixed-point lemma |
| `C₈₃:C₈₂` = `AGL(1,83)`| `6806` (`83·82`)    | `82`                  | full affine; exhaustively excluded by the AGL fixed-point lemma |
| `A₈₃`                  | `83!/2`             | `82!/2`               | alternating; survives |
| `S₈₃`                  | `83!`               | `82!`                 | symmetric; survives |

Correction worth flagging. The thread/wiki shorthand `{1, 2, 41, 82, …}` for
hidden-subgroup sizes is exact only for the four affine groups. The "`…`" hides
the fact that for `A₈₃` and `S₈₃` the hidden subgroups are *enormous* — `|H| =
82!/2` and `82!` respectively, the full point stabilizers `A₈₂`/`S₈₂` — not small
numbers continuing the `1,2,41,82` pattern. The six *group orders* are
`{83, 166, 3403, 6806, 83!/2, 83!}` as the thread states; the six *hidden sizes*
are `{1, 2, 41, 82, 82!/2, 82!}`. Anyone reading "…" as "and a couple more small
divisors" would be wrong; the survivors are the maximal, hardest cases. This is
consistent with — and sharpens — the wiki's own conclusion that "what remains are
the alternating and symmetric groups consisting of general permutations, rather
than one of the smaller groups that would have made this much easier to solve."

---

## 6. Confidence statement

Confidence: high, with the following precise scope.

- The solvable count of 4 (Section 2) is elementary and certain: it is exactly
  `τ(82) = 4`, a finite hand-check, resting only on Burnside's prime-degree
  dichotomy (classical, pre-CFSG) and the cyclicity of `C₈₂`.
- The non-solvable count of 2 (Section 3) rests on the classification of
  2-transitive groups of prime degree, which is a CFSG-dependent theorem
  (Burnside + Feit; tabulated in Dixon–Mortimer, *Permutation Groups*, §7.7). This
  is the single external fact the result leans on. I did not reprove CFSG; I
  *applied* the published classification and verified its arithmetic side
  conditions for 83 myself (83 is prime; 83 is not a Mathieu degree; 83 is not a
  projective degree `(qᵈ−1)/(q−1)` for any prime power `q` and `d ≥ 2` — searched
  exhaustively). Conditional on that standard theorem, the count of 6 is exact.
- The method was independently validated against four firmly-known small-prime
  counts (`5→5, 7→7, 11→8, 23→7`), each fully hand-derived with named sources for
  every extra, so the recipe is not folklore.
- **Machine count cross-check:** the direct GAP `NrTransitiveGroups(83)` route is
  unavailable (`fail`, per maintainer-run GAP) [Lymm], but at prime degree
  transitive implies primitive, and the OEIS A000019 b-file fetched 2026-07-06
  gives `a(83)=6` [verified]. That closes the count cross-check gap; a future
  `NrPrimitiveGroups(83)` run would be another machine check, not a change in
  scope.

Bottom line for the puzzle. This is a correctness audit, not a decode and not a
statistic. It confirms the transitivity restriction the rest of the GAK thread
relies on: the GAK state group (if the cipher is GAK on a transitive group, which
itself is a *hypothesis* the wiki marks as "most likely," not established) is one
of exactly six groups `{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}`. Subsequent
structural work prunes `C₈₃` by non-commuting chaining evidence, the two affine
variants by the AGL fixed-point lemma, and `D₁₆₆` within the same model by
subsumption in the Full AGL sweep [verified], leaving `{A₈₃, S₈₃}` under the
shared-plaintext and one-global-configuration assumptions. None of this says
anything about what the glyphs *mean*: the eyes remain deterministic,
engine-generated, strikingly structured data of unknown meaning, unsolved, with no
primary developer source confirming recoverable plaintext.
