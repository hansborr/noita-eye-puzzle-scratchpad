# Community frontier — what the #silmä-cryptography effort needs

*Read-first reference. Condensed from a full read of the community wiki
(Lymm's eye-messages wiki, github.com/Lymm37/eye-messages/wiki) against the question: where can a
computational workbench actually be useful? Cited by the thread docs.*

The Noita eye puzzle has two community tracks: #silmä-novel (in-game hints / novel
approaches) and #silmä-cryptography (treat the eyes as a cipher). The math need is the
cryptography track, and it is doing exactly two things — both levered by the isomorphs,
"the main property of the cipher that leaks information."

---

## Goal 1 — find a GAK attack (recover information)

GAK (Group-Autokey, developed by Lymm & Simplesmiler) reproduces the eyes' properties
under two assumptions: the cipher produces perfect isomorphs, and each plaintext letter
corresponds to a distinct cipher-state action. The deck cipher is a notable physical
interpretation. The surviving group family for the eyes (83 symbols) is {A₈₃, S₈₃} (with
D₁₆₆ conditional); cyclic C₈₃ is killed by chaining conflicts, dihedral by an element-order
argument, and AGL is tentatively ruled out.

The blocker is being actively re-characterized on the wiki (struck-through
`~~lack a GAK attack~~`) to the sharper: "no known way to take deltas in GAK ciphers with
hidden states." The recoverable quantity is precise — each isomorph pair exposes a concrete
group element `a⁻¹b` acting by right-multiplication on right cosets of the hidden subgroup
`H` (chaining-graph edge color = Schreier coset graph). Three named sub-problems gate the attack:

1. **Order-conflict reconciliation** — safely adding inferred chaining edges without contradiction.
2. **Edge-overlap certification** — how many overlapping edges certify that two partial graphs
   are the *same* transformation. The wiki ties this directly to the group's transitivity
   degree on cosets of `H`: worst case (S₈₃ / S₈₂) needs *all* edges to match; dihedral may
   need ~2.
3. **Geometric graph chaining** — finish it and validate on small known-ground-truth GAK.

**Live tractable lead:** shared sections after a differing first character imply the per-letter
permutations are only a few swaps from a shared base permutation (allomorph analysis gives a
*tentative* ≤~4 swaps/letter upper bound) — turning a one-time-pad-sized key space into a small
near-identity neighborhood, not all of S₈₃.

**Open caveat the community states plainly:** it "might be unrealistic to expect chaining to ever
work for the eyes" given ~1036 trigrams vs a near-S₈₃ group — but nobody has quantified that
ceiling. Converting that soft pessimism into a number is itself a contribution (see G3).

---

## Goal 2 — disprove GAK

The wiki is explicit that frequency, isomorph production, doubles-avoidance, and
no-true-conflicts are all reproducible by GAK — so none of them can disprove it. The eye
landmarks (the Caboose, the Funny-looking Obstacle, the Stutter section) have each
been *demonstrated reproducible by deck ciphers*, so they support GAK rather than falsify it.

The single live whole-family falsifier is isomorph imperfection. GAK is *proven* to
produce perfect isomorphs:

> `c(ga) = c(a)  ⇔  c(gb) = c(b)`  (the CT map partitions the group into right cosets of `H`).

So one robust same-plaintext isomorph that *breaks* where repeated plaintext predicts a
match — and is not explainable as a word boundary — would eject the eyes from the entire
perfectly-isomorphic region (CTAK < GCTAK < GAK < XGAK ≤ perfectly-isomorphic). This can't be
settled with certainty absent plaintext, and the eyes currently look "at least very close" to
perfect — but pushing for a violation is the most decisive possible result, and is mapping-
independent. The wiki also asks for new imperfectly-isomorphic cipher families to populate
the alternative-hypothesis space ("we don't know how to categorize imperfectly isomorphic ciphers").

---

## What we may have under-weighted (per the wiki)

- The isomorph leak is the load-bearing object, and its information-theoretic ceiling is an
  open, wiki-flagged question that nobody has quantified. → G3.
- Edge-overlap certification as a function of transitivity degree is a stated, half-solved
  research problem; clean and mapping-independent. → G4/T6.
- AGL is only "tentatively" ruled out, with a *testable* discriminator (AGL needs fine-tuned
  per-message resync vs the deck's natural delayed hidden state — a prediction about the first
  trigram). We hold an exhaustive AGL exclusion (`agl_gak.rs`, 0/6724 and 0/3362) — a
  community-grade result currently sitting as a finished internal artifact. → publish (threads-eyes).
- The base-5 first-trigram structure (Message-Starts) is an explicitly open, unclaimed thread
  needing only the 9 values already verified in `corpus.rs`. → near-free (threads-eyes).

---

## What this means for tooling (transfer)

- **GAK / eyes / isomorph machinery is directly on-frontier.** `isomorph.rs` *is* the leak
  encoding; `perfect_isomorphism.rs` *is* the Goal-2 falsifier; `chaining_graph.rs` is the
  Schreier substrate every Goal-1 step consumes; `gak_attack/` is the only recovery-shaped code.
  Its one structural weakness: every positive control validates against fixtures it generated
  itself — the weakest validation, exactly what the wiki warns against (→ G1 fixes this).
- **Classical / sample-puzzle machinery: methodology transfers, attack code does not.** The
  matched-null discipline, firing-positive-control doctrine, and held-out gating are genuinely
  shared (the eyes Gate-1 is the same shape). But quadgram/beam/SA search over a ≤29-letter
  language alphabet is a *different mathematical object* from recovering a permutation-group
  action with hidden state from isomorph structure. A proving ground for the wrong machine is
  low community value even when it "succeeds." See `threads-proving-ground.md`.
