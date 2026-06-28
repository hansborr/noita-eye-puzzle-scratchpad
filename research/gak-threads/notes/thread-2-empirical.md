# Thread 2 — AGL(1,83) GAK feasibility: empirical prototype results

Honesty banner. Mapping-independent structural work: only ciphertext-symbol
equality and group/coset structure are used. No symbol→meaning mapping is
asserted. All checks below are exhaustive enumeration over the finite AGL state
group / its discrepancy set, not statistical estimation. The strongest claim
about the eyes themselves remains: deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source
confirms recoverable plaintext. This note reports a structural *exclusion* of a
candidate cipher family, not a decode.

Scratch (throwaway): `scratchpad/agl_gak.py` (validated primitive),
`agl_feasibility.py`, `agl_feasibility2.py`, `agl_debug.py`, `agl_proof_check.py`,
`agl_poscontrol.py`, `agl_final.py`.

Wiki pages tested: `Affine-General-Linear-Group-(AGL).md`, `Message-Starts.md`,
`Shared-Sections.md` (and the model/convention from `Group-Autokey-(GAK).md`,
`Hidden-State.md`). Input data: `scratchpad/streams.json` = the nine
Experiment-0-verified corpus streams (values 0..82), order `standard36-u012-d012`.

---

## 1. The AGL(1,83)-GAK primitive — implemented and validated

`agl_gak.py` implements both `C83:C82` and `C83:C41`:

- `G = AGL(1,83)`, elements `(a,b)`, action `x ↦ a·x + b mod 83`; product
  `(a1,b1)·(a2,b2) = (a1a2, a1b2+b1)` (so `.apply` is a genuine left action).
- Hidden subgroup `H = Stab(x0)`, `x0 = 0` (maps `(a,0)`). Output (ciphertext)
  symbol = moved reference point `c(g) = g.x0` — the coset label, *not* the
  raw element. Per the verification note this forces the right-multiplication /
  left-coset convention: `g_{i+1} = g_i · p(letter)`, `ct = c(g_{i+1})`.
- `C83:C82`: multiplier `a ∈ Z₈₃*` (|G|=6806, |H|=82). `C83:C41`: `a` restricted
  to the order-41 multiplicative subgroup = quadratic residues (|G|=3403, |H|=41).
  Both give a CT alphabet of all 83 points.

**Validation harness (all green):** group axioms + left-action on 2000 random
triples; `c` constant on left cosets `gH` (500/500) and non-constant on right
cosets `Hg` (correct convention); |G| and |C|=83 for both variants; perfect
isomorphism spot-check (0/3000 violations); and a hand-checked coset sequence
— initial state `(1,0)`, plaintext elements `(1,5),(1,7),(3,0)` → CT `[5,12,12]`,
final state `(3,12)` (matches by-hand computation). Round-trip determinism
confirmed.

---

## 2. The observed message-start structure (CT-equality only)

All nine first symbols are distinct (the "differing first trigram"). Columns 1
and 2 are shared by all nine (values 66, then 5). Then the corpus splits into
nested CT-equal groups. Two are long, clean, contiguous shared runs:

| Group | members | shared cols | run length L | distinct symbols in run |
|-------|---------|-------------|--------------|--------------------------|
| A | east1, west1, east2 | 1..24 | 24 | **20 / 24 → varying** |
| B | east4, west4, east5 | 1..20 | 20 | **18 / 20 → varying** |

The shared runs are varying sequences (e.g. group A: `66,5,48,62,13,75,29,…`),
not constant stutters. This distinction is decisive (§3).

**Tightest clinching instance:** columns 1–2 are `(66, 5)` — already a length-2
varying run (66 ≠ 5) shared by all nine messages, immediately after their
nine distinct first symbols. This single feature alone is AGL-impossible (a
discrepancy `D` would have to fix two distinct running-key points ⇒ `D = identity`
⇒ equal first symbols), so the exclusion does not even depend on the long
group-A/B runs.

---

## 3. Feasibility verdict — AGL is rigorously excluded by the varying shared runs

### The condition (achievability iff)

> **AGL(1,83)-GAK can produce a shared run after a differing immediately-preceding
> symbol IFF that shared run is CONSTANT (a stutter, one repeated symbol). A
> shared run that VARIES over ≥2 columns is impossible.**

Derivation (exhaustively re-confirmed against the cipher): within an identical
shared run the running key is common, so the two messages' states differ by a
fixed discrepancy `D = h_i⁻¹ h_j`. By the resync algebra (re-verified here:
0 violations / 40000 per variant), agreement at run-step `t` ⟺ `D` fixes the
running-key point `z_t = K_t.x0`. A differing preceding symbol ⟺ `D ∉ Stab(x0)`
⟺ `D` is non-identity-on-the-reference, i.e. (in `(a,b)` form) `b ≠ 0`. Such an
affine `D` fixes at most one point (exactly one if `a≠1`; none if `a=1`, a
pure translation). Agreeing over ≥2 columns with distinct running-key points
would require `D` to fix ≥2 points ⇒ `D = identity` ⇒ preceding symbol equal —
contradiction. Hence the only surviving shared run keeps `z_t` pinned to `D`'s
single fixed point, giving a constant CT.

### Exhaustive / forward confirmation

- Over all 6724 (resp. 3362) differing-discrepancy elements `D` in `C83:C82`
  (resp. `C83:C41`): number fixing ≥2 points = 0; max fixed points = 1.
- Random forward simulation (the cipher itself, no algebra): in 2,000,000
  tries per variant of (differing first symbols + arbitrary shared 3-letter key),
  varying shared runs of length ≥2 found = 0.
- **Positive control fires:** an explicit length-6 constant shared run after a
  differing first symbol is constructed and forward-verified in both variants
  (e.g. first symbols `1 vs 69`, shared run `[42,42,42,42,42,42]`). So the
  machinery accepts the case AGL genuinely *can* do — its rejection of the eyes is
  not vacuous.
- **Matched negative:** a length-2 varying shared run after a differing start
  is exhaustively impossible in both variants.

### Nine-message simultaneity

The obstruction is per-pair and indexing-robust, so it holds a fortiori for all
nine messages at once: no consistent assignment of per-message initial states +
single plaintext→element map reproduces groups A and B. The joint constraint
solver (`agl_feasibility2.py`, modelling the all-nine shared cols 1–2 plus the
group runs as one coupled CSP over the folded identity `CT_i[t]=a_i·z_t+b_i`)
returns infeasible for both variants, consistent with the algebra.

**Verdict:** *AGL message-starts are achievable iff the post-differing-start
shared run is a constant stutter; the eyes' shared runs are varying; therefore
inconsistent with the nine-message start pattern.* No `AGL(1,83)` GAK
(neither `C83:C82` nor `C83:C41`) reproduces the eyes' message-start +
shared-section pattern. AGL is excluded — exhaustively, not statistically.
This is a stronger, rigorous result, not the "back as a brute-forceable
candidate" outcome.

---

## 4. Relation to the wiki and the prior verification note

- `Message-Starts.md` / `Shared-Sections.md`: the wiki's tentative exclusion
  ("AGL not generally able … unless initial states are fine-tuned for an immediate
  resync") is directionally right but for a subtly wrong reason, and it
  understates the kill. The genuine obstruction is not that resync is
  fine-tuned/rare — it is that AGL's affine resync can pin the reference point to
  only one value, so the shared run it produces is necessarily constant.
  The eyes' shared runs are varying, which AGL structurally cannot make after
  a differing start. (The wiki correctly notes deck ciphers / large-hidden-state
  `S₈₃` *can* produce varying shared runs — they have no single-fixed-point
  bottleneck.)
- **Correction to `notes/thread-2-agl-verification.md`:** that note's "explicit
  witnesses … length-6 pairwise shared run … length-7 triple-shared run" and its
  "98.78% generic resync" are about constant shared runs (single common
  stabilizer-coset point). They do not witness the eyes' *varying* runs. So
  the note's conclusion "AGL is **not** rigorously excluded by message-starts"
  over-conceded: once the shared runs are required to be *varying* (as the
  eyes' are), message-starts do rigorously exclude AGL. The note's flagged
  chaining-graph element-order route remains a valid independent confirmation, but
  is not needed for the kill — the varying-shared-run argument suffices.

---

## 5. Caveats (honesty)

- "Excluded" = the AGL GAK *family with output = moved reference point and a
  single shared running key over a shared run* cannot produce the observed pattern.
  This is the model the thread and wiki specify. It does not speak to non-GAK
  affine constructions or to GAK with a different (non-point-stabilizer) hidden
  subgroup — but a non-point-stabilizer choice is not the AGL candidate under test.
- The exclusion is structural and mapping-independent. It says nothing about the
  plaintext's meaning, and it is not a decode.
- Candidate set after this thread: the AGL pair is removed on a *rigorous* basis,
  leaving `{A₈₃, S₈₃}` (the large-hidden-state groups, which *can* make varying
  shared runs) as the remaining transitive GAK candidates per
  `The-Transitivity-Restriction-(6-Groups-for-83).md`.
