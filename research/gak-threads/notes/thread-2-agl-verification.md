# Thread 2 — AGL conceptual-model + wiki-exclusion verification

Scope. Verify (1) the AGL(1,83)-GAK conceptual model as stated in
`thread-2-agl-stress-test.md`, and (2) whether the wiki's tentative AGL
exclusion is a *sound necessary-condition argument* or a *hand-wave*. Derive the
exact resync condition for the Python feasibility agent.

Honesty banner. This is mapping-independent structural work. We use only
ciphertext-symbol equality and group/coset structure. No symbol→meaning
mapping is asserted. Where an arbitrary plaintext→element assignment is used, it
is only to confirm the *output-function semantics* and to construct existence
witnesses — never to claim a decode. All brute-force checks are over the full
AGL(1,83) state group (6,806 elements) or its subgroups; nothing here is
statistical estimation, it is exhaustive enumeration. The strongest claim about
the eyes themselves remains: deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source
confirms recoverable plaintext.

Scratch scripts: `scratchpad/agl_verify2.py`, `agl_resync2.py`, `agl_multi.py`,
`agl_null.py` (in this session's scratch dir; throwaway).

---

## Part 1 — The AGL(1,83)-GAK model: verified, with one convention correction

### 1a. Group and action (matches thread + AGL wiki)

`G = AGL(1,83)`, elements `g = (a,b)` with `a ∈ Z₈₃*`, `b ∈ Z₈₃`, acting on
`Z₈₃` by `x ↦ a·x + b`. `|G| = φ(83)·83 = 82·83 = 6806`. Non-abelian, semidirect
product `C₈₃ ⋊ C₈₂`. Confirmed against
`Affine-General-Linear-Group-(AGL).md` (`φ(n)(n-1)` order, semidirect product,
units `C_{n-1}` for prime `n`).

`C₈₃:C₄₁` is the index-2 subgroup that restricts the multiplier `a` to the
unique order-41 subgroup of `Z₈₃*` (the quadratic residues); `|C₈₃:C₄₁| = 41·83
= 3403`. Confirmed consistent with
`The-Transitivity-Restriction-(6-Groups-for-83).md` (the six transitive groups:
`C₈₃`, `D₁₆₆`, `C₈₃:C₄₁`, `C₈₃:C₈₂`, `A₈₃`, `S₈₃`, hidden-subgroup sizes
1, 2, 41, 82, 82!/2, 82!).

### 1b. Hidden subgroup = point stabilizer (order 82 / 41). Confirmed

`H = Stab(x₀)`, the maps fixing a chosen reference point `x₀`. Taking `x₀ = 0`,
`H = {(a,0) : a ∈ Z₈₃*}`, order 82. Its cosets ↔ the 83 points; `|C| = |G|/|H| =
6806/82 = 83`. For `C₈₃:C₄₁`, restrict `a` to the order-41 subgroup → `|H| = 41`,
`|G|/|H| = 3403/41 = 83`. This matches `Hidden-State.md` (hidden subgroup must be
non-normal — a point stabilizer in AGL is non-normal, since translation
conjugates it to the stabilizer of another point).

### 1c. Output function = the moved reference point (the coset). Confirmed — and the convention pairing matters

The thread's pitfall ("ciphertext is the **coset**, the moved reference point,
not the raw group element") is correct, but there is a convention subtlety
that the Python agent must get right or it will get a wrong answer:

- The orbit map `g ↦ g.x₀` (image of the reference point) is constant on left
  cosets `gH` — because `H` stabilizes `x₀`, so `(g·h).x₀ = g.(h.x₀) = g.x₀`.
  Brute-checked: `c(g)=g.x₀` is constant on `gH` (True) and not constant on
  the right cosets `Hg` (False). (`agl_verify2.py`.)
- The *main* GAK definition in `Group-Autokey-(GAK).md` uses the left-mult
  update `g_{i+1} = p(aᵢ)∘gᵢ` with `c` constant on right cosets `Hg`.
- These are incompatible as written. The wiki itself supplies the fix
  (Group-Autokey-(GAK).md, line 34): *"Equivalently, you can also act by right
  multiplication, and `c` will need to be constant on left cosets instead."*

**The self-consistent AGL-GAK model with output = moved reference point is the
right-multiplication / left-coset variant:**

```
  state update:   g_{i+1} = g_i · p(aᵢ)         (RIGHT multiplication)
  CT output:      c_i      = g_{i+1}.x₀          (image of fixed ref point x₀)
  coset frame:    c is constant on LEFT cosets gH
  c(g)=c(g')  ⟺  gH = g'H  ⟺  g⁻¹g' ∈ H
```

Brute-verified in this convention: perfect isomorphism holds (`c(a·k)=c(a) ⟺
c(b·k)=c(b)` for all initial states `a,b` and contexts `k`, 0 violations over
2000 random triples), matching `Proof-that-GAK-has-perfect-isomorphism.md`.
Reversibility/no-doubles follow from the standard GAK proofs (distinct cosets
for distinct PT letters), unaffected by the L/R convention.

> **Note for the Python agent.** If you instead use the left-mult update
> `g_{i+1}=p(aᵢ)·gᵢ` you must define the CT symbol as the **right-coset label**
> (`Hg`), which is the *pre-image* point `g⁻¹.x₀`, **not** `g.x₀`. Mixing
> left-mult update with the `g.x₀` output is the exact mis-model the thread warns
> about. Validate on a hand-checked tiny example before trusting the eyes.

**Verdict Part 1:** the conceptual model in `thread-2-agl-stress-test.md` is
correct on every claimed point (state order 83·82, action `ax+b`, hidden subgroup
= point stabilizer order 82, output = coset = moved reference point, C₈₃:C₄₁ =
order-41 multiplicative subgroup with hidden subgroup 41), with the single
clarification that the output-as-moved-point reading forces the right-mult /
left-coset convention.

---

## Part 2 — The wiki exclusion: partly sound, but weaker than the wiki states

### 2a. Exact precise condition (derived, then exhaustively brute-verified)

Setup. Two messages `M`, `N`. Per-message initial states `s_M, s_N`. First
(possibly differing) PT letters `u, w`; then a common shared plaintext suffix
`a₂, a₃, …`. Post-first-letter states `g^M_1 = s_M·p(u)`, `g^N_1 = s_N·p(w)`.
The shared running key is `K_t = p(a₂)·p(a₃)···p(a_{t+1})` and (right-mult)
`g^M_{1+t} = g^M_1·K_t`, `g^N_{1+t} = g^N_1·K_t`.

Let `D := (g^M_1)⁻¹ · g^N_1` (the state discrepancy after the first letter).

- **Differing first symbol** ⟺ `c(g^M_1) ≠ c(g^N_1)` ⟺ `D ∉ H`.
- **Agreement at run-step `t`** ⟺ `c(g^M_1·K_t) = c(g^N_1·K_t)` ⟺
  `(g^M_1·K_t)⁻¹(g^N_1·K_t) = K_t⁻¹ D K_t ∈ H` ⟺ `D ∈ K_t H K_t⁻¹ = Stab(K_t.x₀)`
  ⟺ `D` fixes the running-key point `z_t := K_t.x₀`, i.e. `D.z_t = z_t`.

Because `D=(d_a,d_b)` is an affine map, its fixed-point set is:
`{ d_b/(1−d_a) }` (a single point `y*`) if `d_a≠1`; empty (pure translation)
if `d_a=1, d_b≠0`; all of `Z₈₃` only if `D=identity` (excluded, that's `D∈H`).

> **AGL shared-section-after-differing-start of length `L` is achievable IFF:**
> **(i)** the post-first-letter discrepancy `D=(g^M_1)⁻¹g^N_1` is **not a pure
> translation** (`d_a ≠ 1`), so it has a unique fixed point `y* = d_b/(1−d_a)`;
> **and (ii)** the shared running key keeps the reference point pinned to that
> fixed point for the whole run: `K_t.x₀ = y*` for **all** `t = 1…L`.

Equivalently and operationally (the form the Python agent should enumerate):
the first shared letter must send `x₀ → y*` (resync), and every subsequent
shared letter must lie in `H = Stab(x₀)` (keep `x₀` fixed so the running image
stays at `y*`). In coset language: `g^M_1` and `g^N_1` lie in the same left
coset of `Stab(y*)`, and the shared key, after one resync step, stays inside
the stabilizer frame.

This is literally a one-character resync: the differing first letters `u,w`
are exactly what must be "fine-tuned" so that `D` fixes the point the shared key
parks the reference at. So the wiki's *qualitative* description ("fine-tuned to
allow for an immediate resync") is directionally correct — the resync is a
genuine necessary condition.

### 2b. Brute-force confirmation of the condition (exhaustive, not statistical)

- Over 20,145,760 (discrepancy `D` ∉ H) × (context `K`) pairs, the
  agreement-⟺-`D`-fixes-`K.x₀` rule had 0 violations (`agl_resync2.py`,
  `agl_resync.py`).
- **Pure-translation `D`** (`d_a=1`): 0 agreements across all 82 such `D` and
  all 6806 contexts → confirms a pure-translation discrepancy makes shared
  sections impossible.
- Explicit witnesses constructed: a length-6 pairwise shared run and a
  length-7 *triple*-shared run (three messages, all three first symbols
  distinct: e.g. `5, 51, 14`) — `agl_resync2.py`, `agl_multi.py`. Break test:
  inserting one shared letter that is *not* in `H` after resync breaks the match
  at exactly that step.

### 2c. Where the wiki overstates — the exclusion is weaker than written

The wiki ( `The-Transitivity-Restriction…`, `Message-Starts.md`,
`Isomorphic-Cipher-Hierarchy.md` line 19) frames the resync as a *pathological*
fine-tuning that AGL "is not generally able" to do. Two enumeration results
weaken that:

1. **The condition is generic, not rare, once the key map is free.** A GAK key
   *includes* the plaintext→element map. Given any differing-first-symbol
   discrepancy `D` with a fixed point, condition (ii) is always
   satisfiable — pick the first shared letter to map `x₀→y*`, the rest in `H`.
   So feasibility reduces to condition (i) alone: `D` not a pure translation.
   Among all 6724 differing-first-symbol discrepancies, only 82 (= 1/82 ≈
   1.2%) are pure translations; 98.78% admit a shared section with a tuned
   key (`agl_null.py`). The "fine-tuning" is therefore not a measure-zero
   knife-edge — it is the typical case.

2. **First-symbol values are barely constrained.** A *single* point-stabilizer
   coset `Stab(y*)` realizes 82 of the 83 possible first-symbol values
   (`agl_multi.py`). So requiring all messages to share a common stabilizer frame
   does not force their first symbols to be similar — they can be "all over
   the place," exactly as `Message-Starts.md` observes for the eyes.

What the wiki gets right. The resync *is* necessary; AGL cannot produce a
shared section after a differing start "for free" the way the large-hidden-state
`A₈₃/S₈₃` "delayed hidden state" can (no per-message state fine-tuning needed
there). The required structure — all messages' post-first-letter states in one
common point-stabilizer coset — is a real, falsifiable constraint, and it must
hold simultaneously across all nine messages, not just one pair (the thread's
honesty note). That simultaneous-9-message constraint is the genuine test and is
left to the Python feasibility agent.

What the wiki overstates. Calling it a "special exception" / pathological
"fine-tuning" undersells it: per pair it is the *generic* outcome (98.78%), with
near-total freedom in first-symbol values. The exclusion as written is therefore
a tentative, partially-sound necessary-condition sketch, not a proof. It does
not rigorously exclude AGL. It correctly identifies the *mechanism* (one-char
resync ⟺ shared common stabilizer coset) but does not show that mechanism is
inconsistent with the full nine-message corpus.

### 2d. The genuinely rigorous AGL test (what would actually settle it)

The dihedral exclusion (`Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md`)
is rigorous because it bounds element orders (2, 83) and derives a chaining
contradiction. The analogous rigorous AGL test is element-order / chaining,
not message-starts:

- In `AGL(1,83)`, element orders divide `|G|=2·41·83`. Translations (`a=1`) have
  order 83; a multiplier of multiplicative order `m` gives an element of order
  `m | 82`. The induced chaining-graph permutation of a context has cycle lengths
  dividing the element's order. If the eyes' isomorph chaining graphs exhibit a
  context whose cycle structure is incompatible with every AGL element order — or
  a pair of long-chain (order-83, hence translation, hence mutually commuting)
  contexts that nonetheless conflict — AGL is excluded the same way `D₁₆₆` was.
  Translations form the abelian normal `C₈₃`, so two order-83 contexts in AGL
  commute; a chaining conflict between two >2-length chains would be the AGL
  analogue of the dihedral contradiction.
- For `C₈₃:C₄₁`, multiplier orders divide 41, further restricting allowed
  non-83 cycle lengths.

This element-order route (Thread 1 / Thread 5 territory) is the path to a
*rigorous* exclusion; the message-starts argument alone is not. Recommend the
Python agent (Part A) test the 9-message common-stabilizer-coset consistency
to falsify by message-starts, and flag that a clean kill more likely comes from
chaining-graph element orders.

---

## Verdict

- **Part 1 (conceptual model):** holds. Every claim verified; one convention
  clarification (output = moved ref point ⇒ right-mult / left-coset), which is the
  exact mis-model the thread flagged.
- **Part 2 (wiki AGL exclusion):** the wiki's exclusion is a sound necessary
  condition stated too strongly — directionally correct (resync ⟺ common
  point-stabilizer coset is genuinely required) but not rigorous: per message
  pair the resync is the *generic* (98.78%) case with near-free first symbols, so
  it does not exclude AGL. AGL is not rigorously excluded by message-starts;
  it remains a brute-forceable candidate pending the 9-message simultaneous test
  and (more decisively) a chaining-graph element-order argument.
