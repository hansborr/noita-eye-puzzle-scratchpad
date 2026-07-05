# GAK Threads — completed campaign (reference)

> **Status — COMPLETE (as of 2026-06-24).** The six-thread GAK campaign is
> DONE: every thread (1A/1B/2/3/4/5/6) has landed. See
> [`PROGRESS.md`](PROGRESS.md) section 6 for the Rust modules that shipped, and
> the result records
> [`G1-RESULTS.md`](G1-RESULTS.md) /
> [`G1b-RESULTS.md`](G1b-RESULTS.md) /
> [`G2-isomorph-imperfection.md`](G2-isomorph-imperfection.md) /
> [`G3-leak-ceiling.md`](G3-leak-ceiling.md).
> This folder is now a **completed campaign / reference**, not a next-work
> queue: do not dispatch a cold agent to "pick an assigned thread" — the threads
> are finished. The convergence narrative and glossary below stand as reference;
> the per-thread briefs, priorities, and sequencing are preserved further down as
> the historical hand-off record that produced those landings.

Source of the material: Lymm's eye-messages wiki
(github.com/Lymm37/eye-messages/wiki), content current to 2026-01-16.

---

## Why these threads exist: the convergence

Two independent lines of work have arrived at the same answer.

- **Our workbench** (the 2026-06-24 structural battery + Pyry's-conditions
  capstone) concluded: the eyes look like a non-commutative, self-modifying,
  plaintext-driven permutation cipher; of the families we encoded, only
  autokey/Alberti survive all nine of Pyry's conditions.
- **The wiki** has built that intuition into a rigorous group-theory framework
  and lands in the same place: the eyes are most likely a Group Autokey (GAK)
  cipher whose state group is the symmetric group `S₈₃` (or its alternating
  subgroup `A₈₃`), most plausibly realized as a "deck cipher" — an 83-card
  deck where each plaintext letter triggers a specific shuffle and the top card is
  emitted as ciphertext.

GAK *is* the generalization of autokey to non-abelian groups, so this is genuine
mutual corroboration, not coincidence. None of this conflicts with our
binary-confirmation finding (the message *content* is hardcoded `u32` constants in
`noita.exe`): Petri would have authored the messages with whatever cipher, then
hardcoded the resulting trigram constants. The cipher question is about how those
constants were *produced*, which the binary does not reveal.

## The reframe (important — it changes our standing conclusion)

Our memory has long said decode is blocked on the unknown 83-symbol→meaning
mapping, recoverable only via an external in-game/developer anchor. The wiki's
framing shows that claim is too strong. Their stated open problem is a GAK
attack — there is no known way to "take deltas" in a GAK cipher with hidden
states. A *working* GAK attack would recover the plaintext→permutation mapping
from the isomorph structure alone, with no in-game anchor. So decode is
blocked on *the attacks tried so far*, not in principle. Thread 4 chases exactly
this.

---

## Shared ground rules (apply to every thread)

- **Mapping-independence is the point.** Threads 1, 2, 3, 5 use only ciphertext
  *symbol equality* and group structure — they never need the symbol→meaning
  mapping, so they sidestep the decode blocker entirely. Thread 4 *produces* a
  candidate mapping rather than consuming one.
- **Data lives in `src/data/corpus.rs`** — the nine verified messages, cross-checked
  byte-for-byte against the ngraham20 transcription and Xkeeper0's base-7
  transcoder. Use `corpus::messages()` / `corpus::combined_sequence()`. The
  accepted reading layer is the honeycomb base-5 trigram stream (`0..=82`).
- **`make verify` must stay green** (fmt + clippy `-D` + tests + rustdoc `-D` +
  cargo-deny). `unsafe` is forbidden; no `unwrap`/`panic`/`indexing_slicing` in
  library/CLI code (relaxed in tests). Document every public item. See `AGENTS.md`.
- **Every negative needs a null; every positive control must fire on known
  signal.** This is the house style — do not report a structural result without
  the matched null distribution, and validate new tooling against a synthetic
  cipher with known ground truth before pointing it at the eyes.
- **Never overclaim.** The strongest defensible statement remains: *the eyes are
  deterministic, engine-generated, strikingly structured data of unknown meaning;
  unsolved; no primary developer source confirms recoverable plaintext.* A thread
  that tightens or breaks a wiki claim should say exactly how strongly its
  construction supports the result, no more.
- **Cite the wiki page you are testing** (pages under
  github.com/Lymm37/eye-messages/wiki). Several wiki claims are explicitly
  "tentative" — preserve that uncertainty in what you build.

---

## Historical hand-off record (the original dispatch plan)

Everything from here down is the Wave-1 dispatch plan exactly as it was handed
to agents — the self-contained thread briefs, their priorities, the recommended
sequencing, and the Thread-4 go/no-go. Each `thread-N-*.md` was written to be
picked up cold. **All of it has since landed** (see the completion banner at the
top and `PROGRESS.md` section 6); it is retained for provenance and as the
method trail, not as live work. A cold reader should treat the priorities and
"start here" notes below as artifacts of the original plan, not instructions.

### The threads at a glance

| # | Thread | Priority (original) | Effort | Tested a wiki claim that was… | Build depended on |
| - | ------ | -------- | ------ | --------------------------- | ---------------- |
| 1 | [Dihedral impossibility + 6-group transitivity restriction](thread-1-dihedral-and-transitivity.md) | **High (start here)** | Low–Med | Load-bearing & central | — (foundational) |
| 2 | [AGL stress-test (the soft link)](thread-2-agl-stress-test.md) | **High** | Med | Only *tentative* | Thread 1 helpful |
| 3 | [Perfect-isomorphism / allomorph scan](thread-3-perfect-isomorphism-scan.md) | **High** | Med | *Unproven by their own admission* | `src/analysis/isomorph.rs` |
| 4 | [GAK attack prototype (the prize)](thread-4-gak-attack-prototype.md) | Med (high reward, high risk) | High | Their stated open problem | Thread 5 helpful |
| 5 | [Chaining-graph: conflicts + transitivity coverage](thread-5-chaining-graph.md) | Med (foundational) | Med | Asserted qualitatively | `src/analysis/isomorph.rs` |
| 6 | [Binary / game-data re-examination](thread-6-binary-game-data.md) | **Low (likely dead end)** | Low | n/a | Ghidra, game files |

### Recommended sequencing

1. **Thread 1** first — it is fast, bounded, and everything else builds on the
   6-group restriction. It either validates the central narrowing or finds a hole
   in it.
2. **Thread 5** next if anyone is going to attempt Thread 4 — it produces the
   chaining graph that Threads 1 and 4 both lean on, and quantifies the
   transitivity evidence the whole restriction rests on.
3. **Thread 3** in parallel — it decides whether the GAK *family* is even the
   right place to be looking (it hinges on perfect isomorphism, which the wiki
   cannot prove).
4. **Thread 2** in parallel — highest leverage if it breaks, because AGL is the
   one remaining candidate small enough to brute-force.
5. **Thread 4** is the research spike — only worth staffing once Threads 1/3/5
   have confirmed the family is right and the chaining graph exists. Treat it as a
   time-boxed spike with the go/no-go milestones in its brief.

Threads 1, 2, 3, 5 are independent and can run concurrently.

---

## On game data & Ghidra (answering the standing note)

We have the game files and a Ghidra project for `noita.exe`, and they remain
available. The honest assessment: they are not the bottleneck for any of
Threads 1–5. Those are structural/algorithmic questions about the cipher
mechanism, answerable from the ciphertext alone. The binary-confirmation work
already established that the message content is hardcoded `u32` constants
(`FUN_0061ed60`) and that the *storage layer has no symbol→meaning table* — so the
binary cannot hand us the decode. See Thread 6 for the one residual, low-priority
lead (the untraced `data.wak` Lua that consumes the decoded integers) and why we
expect it to stay a dead end.

The one place game data legitimately re-enters: post-hoc verification. If
Thread 4 ever yields a candidate plaintext, in-game lore and the relationships
between the nine messages become a corroboration resource — an *output* check, not
an *input*.

---

## Mini-glossary

- **Isomorph** — a repeated ciphertext segment with the same *gap pattern*
  (positions of repeats), even if the symbols differ. Evidence of repeated
  plaintext under a polyalphabetic cipher. (`src/analysis/isomorph.rs`)
- **Allomorph** — a place where two segments *fail* to be isomorphic, proving the
  underlying plaintext must differ there (under perfect isomorphism).
- **Perfect isomorphism** — same plaintext always yields the same gap pattern,
  for text of any length. The defining assumption of the GAK family.
- **Hidden state** — internal cipher state not visible in the output (e.g. the
  unseen part of the deck), which delays and obscures resynchronization.
- **CTAK / GCTAK / GAK** — ciphertext-autokey over a cyclic alphabet; its
  generalization to an arbitrary finite *group*; and the hidden-state extension
  where ciphertext symbols correspond to cosets of a hidden subgroup. Hierarchy:
  `CTAK < GCTAK < GAK < XGAK ≤ Perfectly Isomorphic`.
- **Transitivity restriction** — because 83 is prime, only 6 transitive
  permutation groups act on 83 points, so a GAK cipher with 83 ciphertext symbols
  must use one of them (Thread 1).
- **Deck cipher** — the `S₈₃`/`A₈₃` case of GAK: state is an 83-card permutation,
  each plaintext letter applies a shuffle, the top card is output.
