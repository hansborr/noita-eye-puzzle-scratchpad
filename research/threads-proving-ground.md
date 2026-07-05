# Proving-ground threads — the community sample puzzles

*Self-contained brief. The sample puzzles are community-sourced and serve as a proving
ground: solving known-tractable puzzles validates whether our tooling is trustworthy — run in
parallel with the eyes work, not gated behind it. The key discipline (see `frontier.md`): make
sure we're validating the right machine. Index: `NEXT-STEPS.md`.*

---

## Sample-puzzle inventory (GAK vs classical)

| Puzzle | Type | Family | Notes |
| ------ | ---- | ------ | ----- |
| `one`   | **GAK** | cyclic GCTAK (±1 walk on C5) | provenance `gak_cipher_example`; **external** (not ours). **SOLVED (2026-07-01):** plaintext "Permutation Representation Destination" — alternating-orientation dihedral GAK over C5 + 7-bit ASCII, verified by an exact 266/266 ciphertext round-trip via the `maskdecode` instrument (`research/data/practice-puzzles/CODEC-RESULTS.md`). G1 earlier validated the keystream-**structure** layer. |
| `two`   | **GAK** (hypothesis) | 12 symbols; full-stream readout — isomorph column-maps close to an **order-48 observable shadow of a reported order-96 group** | provenance `gak_example_two`; **maintainer holds the English cleartext** (not in-repo) → a known-answer positive control (needs a codec layer, 12<26). **ROUTE RESET (2026-07-04, `research/handoff/two-cross-agent-recon.md`):** the live surface is the full 12-symbol stream; earlier readings are superseded. Uncracked; standing first-class target (G1b). |
| `three` | classical | aperiodic polyalphabetic | word-boundary-preserving, flat-IoC |
| `four`  | classical | aperiodic polyalphabetic | "" |
| `five`  | classical | aperiodic polyalphabetic | the z≈2.4 running-key lead (T3) |
| `seven` | classical | aperiodic polyalphabetic | the `#` puzzle (T5) |
| `six`   | classical | base-6 codec | |

> The GAK-vs-classical distinction (verify against the repo if in doubt). `one` and `two` are
> GAK, and the classical `solve` pipeline (Identity/Caesar/Transposition + mono mapping)
> structurally cannot represent a GCTAK keystream — so a classical honest-negative on them
> validates *classical* tooling and says nothing about our GAK tooling. The highest-value
> proving ground is validating the GAK/isomorph machinery against a known-answer GAK puzzle,
> and that is now happening: G1 validated the GAK keystream-structure recovery on `one`, and
> the `maskdecode` instrument then carried it to a full solve (266/266 round-trip). `two`
> remains the open known-answer GAK target → G1b.

The four classical letter puzzles are aperiodic polyalphabetic, word-boundary-preserving,
flat-IoC; mono/periodic/keyword-Ragbaby/general-Ragbaby are ruled out. English is maintainer-
confirmed for the letter puzzles. Context: `research/data/practice-puzzles/{KEYSTREAM,RAGBABY}-RESULTS.md`.

---

## G1 — point the GAK machinery at `one`/`two` *(highest value · done @b681c35)*

- **Category:** proving-ground · **Effort:** S · **Serves:** validates the GAK recovery path the
  *eyes* attack depends on, on a known answer. · **Status:** done (2026-06-26, commit
  `b681c35`; test-only `src/attack/gak_attack/known_answer.rs`; full write-up in
  `research/gak-threads/G1-RESULTS.md`; `make verify` green).
- **Result:** `one` recovered cleanly — fed through `solve_gctak`, the machinery recovered the
  C5 keystream structure completely (both `+1`/`-1` generators; recovered partition byte-for-byte
  vs ground truth; all 265 transitions decode; matched null reproduced it 0/12). This is the
  first known-answer positive control for the GCTAK recovery gate, and it passes — validating
  the cyclic/GCTAK path on a real external sample, not the *hidden-state* machinery. G1 itself
  did not attempt the English/codec decode; that decode was later completed (2026-07-01) by the
  `maskdecode` instrument — plaintext "Permutation Representation Destination", exact 266/266
  round-trip (`research/data/practice-puzzles/CODEC-RESULTS.md`). `two` (12 symbols; repo-verified out-degree-8
  many-valued readout; *hypothesized* hidden-state GAK) → honest GCTAK negative (not a
  hidden-state-attack positive): recovery dies at the seeding stage — the readout is many-valued
  (out-degree 8 on all 12 symbols = the hidden-state signature), so 0 functional seed columns
  survive and no per-letter permutation is built. This is the *predicted structural
  wall* (GCTAK's bijective-readout assumption fails against true hidden state), not a bug — and it
  is the eyes' blocker in miniature (the wiki's "no known way to take deltas in GAK with hidden
  states"). Minor documented warts: `one` needs a genuine C5 entry state (a self-loop entry injects
  a spurious fixed point); the solver lacks a post-completion bijectivity/dedup filter (harmless here).
- **Why this is #1:** it gives our GAK tooling its first non-self-generated validation — the
  wiki explicitly demands validation on known-answer small GAK before scaling — and the code is
  already landed (`solve_gctak`, `chaining_graph.rs`). Largest credibility payoff for least new work.
- **Steps:**
  1. Wire `one` (then `two`) into the GAK recovery path (`solve_gctak` / `chaining_graph`),
     mirroring how synthetic positive controls and the eyes are driven. Minimal change — a test
     and/or thin CLI subcommand consistent with existing patterns; reuse, don't duplicate.
  2. Run on `one`: confirm recovery of the C5 cyclic-GCTAK keystream/structure on real data.
     `one` is the exact family `solve_gctak` provably cracks → expect a pass; a pass is the first
     real positive control.
  3. Run on `two` (12-state): test recoverability. A failure is a legitimate result — report
     precisely *where* recovery dies (hidden-state size, text scarcity, group size).
- **Honesty / scope:** G1's scope was the keystream-structure layer (the GAK recovery step),
  not the full English decode. Per the authoritative maintainer note (2026-06-25), neither
  sample is "messageless": `one` is *external* and has since been solved to English
  ("Permutation Representation Destination", 266/266 round-trip via `maskdecode`; see
  `research/data/practice-puzzles/CODEC-RESULTS.md`), and `two` has maintainer-held English
  cleartext. G1 validated the cipher/keystream layer in isolation. Never present a score on the
  wrong structure as a recovery; the positive control must actually fire (it did, on `one`).
- **G1b — `two` hidden-state attack + codec (promoted to a first-class ladder thread —
  the single biggest underweight):** `two` is a known-answer hidden-state GAK
  (maintainer holds the cleartext, not in-repo) that our GCTAK solver cannot yet crack — the
  single best *verifiable* proving-ground analog of the eyes (a hidden-state GAK with a *known*
  solution). Current surface, post **route reset (2026-07-04, `research/handoff/two-cross-agent-recon.md`):**
  the live readout is the full 12-symbol stream, whose isomorph column-maps close to an order-48
  observable shadow of a reported order-96 group; the earlier readings are superseded (they
  survive only as model-free measurements). Push a hidden-state-capable GAK attack + codec layer
  at `two`: it directly exercises the "deltas-under-hidden-state" method the eyes need, on a case
  where success is checkable against withheld ground truth. Coordinate with the codec/mapping
  track. On the ladder it runs before the eyes-scale T6/T7, in parallel with G2.
- **Dependencies:** none (code landed). **Conflicts with:** other `gak_attack/`-editing threads.

---

## T1 — held-out gate fold-vs-fold fix *(done)*

- **Status:** DONE — see `research/findings/T1-heldout-gate-fix.md`. The survival gate's held-out
  check now compares the candidate's odd-index fold against the matched null's *fold* mean
  (apples-to-apples, so a true decode no longer falsely fails on non-contiguous English), across
  ragbaby, keystream, and the `solve` pipeline (`solve` module) via a shared helper in
  `src/nulls/heldout.rs`. Planted-decode regression tests guard it.

---

## T3 / T4 / T5 — classical sample decodes *(demoted to opportunistic)*

Keep the proving ground running in parallel, but bias it toward the transferable GAK samples
(G1), not these. A successful classical decode is a nice win with low community value to the
silmä-cryptography effort — its attack code does not carry into the eyes' group-autokey setting
(see `frontier.md`, transfer). Say so plainly in any write-up. Each adds a subcommand under
`src/cli/` (an arg struct + a `Command` variant + a `commands/` handler wired through
`dispatch.rs`; `main.rs` stays untouched).

- **T3 — running-key two-stream beam on `five`** (M). The z≈2.43 lead (the lone non-zero signal
  in the battery) — never engine-ified. Implement a two-stream joint-quadgram beam mirroring
  `keystream.rs`; widen beam; add crib/word constraints; gate with the matched null; validate on
  a *planted* running-key first. *Classical; non-transferring cipher math.*
- **T4 — plaintext long-autokey (recurrence `p_i = c_i − p_{i−L}`)** (M). The ciphertext-autokey
  leak is already exhaustively negative; the plaintext recurrence (key = the L-length primer)
  is untried. Implement + planted positive control + matched-null gate. *Note: the eyes' autokey is
  ciphertext-side (CTAK/GCTAK per the wiki); plaintext-autokey is a different, non-transferring
  branch — not the abelian special case the eyes need. Classical, low community value.*
- **T5 — `seven`'s `#` as an Alberti rotation index** (M). `#` as deletable null / word-break is
  already negative; remaining interpretation: `#` marks an Alberti disk rotation. Implement +
  positive control + gate. *Lowest priority of the three — Alberti is explicitly ruled out for
  the eyes on the wiki; pure classical validation.*
